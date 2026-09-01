<template>
  <div class="timeline-events">
    <!-- 事件軸：與跨度條共用同一條刻度尺的座標系，每個事件一個刻痕 -->
    <div class="event-axis">
      <div
        class="axis-gutter"
        :style="{ width: `${gutter}px` }"
      >
        {{ $t('auditorWorkbench.events.axisLabel') }}
      </div>
      <div class="axis-track">
        <button
          v-for="mark in marks"
          :key="mark.id"
          type="button"
          class="axis-mark"
          :class="[`type-${mark.type}`, { 'is-focus': mark.id === focusId }]"
          :style="{ left: `${mark.percent}%` }"
          :title="mark.title"
          :aria-label="mark.title"
          @click="scrollToEvent(mark.id)"
        />
      </div>
    </div>

    <!-- 截斷警示壓成單行：這條警示常駐在事件明細正上方，四行的 el-alert
         會把主角（事件列表）推出初始視窗。語義三件事不減——短句留「尚未
         看到全部／總數核對處／如何取其餘」，完整長版由 tooltip 承載。
         nowrap + ellipsis 是硬保險：任何語系都不得換成第二行 -->
    <el-tooltip
      v-if="truncated"
      :content="$t('auditorWorkbench.events.truncated')"
      placement="top"
      popper-class="events-truncated-tip"
    >
      <p
        class="events-truncated"
        data-test="events-truncated"
      >
        <el-icon class="events-truncated-icon">
          <TriangleAlert />
        </el-icon>
        <span class="events-truncated-text">
          {{ $t('auditorWorkbench.events.truncatedBrief') }}
        </span>
      </p>
    </el-tooltip>

    <!-- 空狀態走共用 EmptyState：title＝狀態句、hint＝下一步指引。
         位址樞紐的空結果最容易被誤讀成「這個位址沒發生過事」——hint 要說出
         候選清單的口徑（只含成功登入或建線過的位址）與「任一位址可直接輸入」 -->
    <EmptyState
      v-if="events.length === 0"
      :title="$t(isIPPivot
        ? 'auditorWorkbench.events.emptyIpTitle'
        : 'auditorWorkbench.events.empty')"
      :hint="$t(isIPPivot
        ? 'auditorWorkbench.events.emptyIpHint'
        : 'auditorWorkbench.events.emptyHint')"
      data-test="events-empty"
    />

    <div
      v-else
      ref="listRef"
      class="event-list"
      data-test="event-list"
    >
      <div
        v-for="event in visibleEvents"
        :key="event.id"
        :ref="(el) => setRowRef(event.id, el)"
        class="event-row"
        :class="{
          'is-focus': event.id === focusId,
          'is-batch-start': event.id === batchStartId,
        }"
        :data-batch-start="event.id === batchStartId ? 'true' : null"
        data-test="event-row"
      >
        <span class="event-time">{{ formatDateTime(event.ts) }}</span>
        <el-tag
          size="small"
          class="event-type"
          :type="typeTagType(event.type)"
        >
          {{ typeLabel(event.type) }}
        </el-tag>
        <div class="event-body">
          <div class="event-summary">
            <span>{{ summaryText(event) }}</span>
            <el-tag
              v-if="abnormalStatus(event)"
              size="small"
              type="danger"
              class="event-flag"
            >
              {{ abnormalStatus(event) }}
            </el-tag>
            <el-tag
              v-if="event.severity"
              size="small"
              type="warning"
              class="event-flag"
            >
              {{ severityLabel(event.severity) }}
            </el-tag>
          </div>
          <div
            v-if="detailText(event)"
            class="event-detail"
          >
            {{ detailText(event) }}
          </div>
          <!--
            剪貼簿：內容刻意不入時間軸（跨場彙總畫面攤內容＝機密再擴散），
            SHALL NOT 嘗試顯示內容。取而代之給「檢視內容」入口——一鍵抵達
            該場會話詳情的剪貼簿調閱面並帶事件時刻（錄影同刻可對照）。
            逐列僅留單行短句（不攤內容＋指路＋留痕提醒），完整理由句掛
            tooltip——多筆剪貼簿事件時不再逐列重複 3 行長註記
          -->
          <div
            v-if="event.type === 'clipboard'"
            class="event-note"
          >
            {{ $t('auditorWorkbench.events.clipboardNoContentBrief') }}
            <el-tooltip
              :content="$t('auditorWorkbench.events.clipboardNoContent')"
              placement="top"
              popper-class="clipboard-note-tip"
            >
              <el-icon
                class="clipboard-note-hint"
                data-test="clipboard-note-hint"
              >
                <Info />
              </el-icon>
            </el-tooltip>
            <router-link
              v-if="clipboardContentRoute(event)"
              :to="clipboardContentRoute(event)"
              class="clipboard-content-link"
              data-test="clipboard-content-link"
            >
              {{ $t('auditorWorkbench.events.viewClipboardContent') }}
            </router-link>
          </div>
        </div>
        <SourceAddressCell
          class="event-source"
          :address="event.client_ip"
          :reason="event.client_ip_reason"
          :event-type="event.type"
          :link="addressLink(event)"
        />
        <!-- 位址樞紐下對造是**兩件事**：誰做的、在哪台。少一半就答不出
             「這個位址上發生了什麼」——無可歸屬使用者的列標為未認證來源。
             兩件事各自一行：擠在同一行時 1440 寬下三語都會撞到欄寬而被省略號
             吃掉後半（「哪台」正是本欄要交付的答案），逐行排則欄寬不必外擴 -->
        <span
          v-if="partyLines(event).length"
          class="event-counterpart"
          :title="partyText(event)"
          data-test="event-party"
        >
          <span
            v-for="line in partyLines(event)"
            :key="line"
            class="party-line"
          >{{ line }}</span>
        </span>
        <span class="event-links">
          <el-button
            v-if="event.refs && event.refs.session_id"
            link
            type="primary"
            size="small"
            @click="emit('open-session', event)"
          >
            {{ $t('auditorWorkbench.events.openSession') }}
          </el-button>
        </span>
      </div>
    </div>

    <!-- 捲動揭露的哨兵。列表自己的巢狀捲軸已移除（頁面單一捲動路徑），
         「捲到底再多渲染一批」因此改由這顆哨兵進入視窗時觸發 -->
    <div
      ref="sentinelRef"
      class="event-sentinel"
      data-test="event-sentinel"
      aria-hidden="true"
    />

    <div class="events-footer">
      <!-- 未顯示筆數獨立成句、只在真的還有沒看到的時才出現：讀者要的是
           「還有幾筆沒看到」，不是自己拿兩個數字相減 -->
      <span class="footer-hint">
        {{ $t('auditorWorkbench.events.shown', footerCounts)
        }}<span
          v-if="restCount > 0"
          class="footer-rest"
          data-test="events-rest"
        >{{ $t('auditorWorkbench.events.shownRest', footerCounts) }}</span>
      </span>
      <el-button
        v-if="canShowMore && !loadError"
        size="small"
        :loading="loadingMore"
        data-test="load-more"
        @click="onLoadMore"
      >
        {{ $t('auditorWorkbench.events.loadMore') }}
      </el-button>
    </div>

    <!-- 動作回饋。**與失敗告警刻意不同形態**：稽核靠形狀判斷，若「已無更多」
         與「載入失敗」都只是按鈕消失＋無訊息，前者會被讀成後者、後者會被讀成
         「我已看完全部」。aria-live：列表捲在視野外時，只有列數變化等於沒回饋 -->
    <p
      v-if="loadingMore || statusKind"
      class="events-status"
      role="status"
      aria-live="polite"
      data-test="events-status"
      :data-state="loadingMore ? 'loading' : statusKind"
    >
      <template v-if="loadingMore">
        {{ $t('auditorWorkbench.events.loadingMore') }}
      </template>
      <template v-else>
        {{ $t('auditorWorkbench.events.revealed', { count: revealedCount }) }}<span
          v-if="statusKind === 'exhausted'"
          class="status-all-shown"
          data-test="events-all-shown"
        >{{ $t('auditorWorkbench.events.allShown') }}</span>
      </template>
    </p>

    <el-alert
      v-if="loadError"
      class="events-alert"
      type="error"
      :closable="false"
      show-icon
      :title="$t('auditorWorkbench.events.loadFailed')"
      data-test="events-load-error"
    >
      <el-button
        size="small"
        :loading="loadingMore"
        data-test="load-more-retry"
        @click="onLoadMore"
      >
        {{ $t('common.retry') }}
      </el-button>
    </el-alert>
  </div>
</template>

<script setup>
import { ref, computed, watch, nextTick, onMounted, onBeforeUnmount } from 'vue'
import { useI18n } from 'vue-i18n'
import { Info, TriangleAlert } from 'lucide-vue-next'
import EmptyState from '@/components/EmptyState.vue'
import SourceAddressCell from './SourceAddressCell.vue'
import { buildAddressPivotLink } from './timelineQuery'
import { timeToPercent } from './timelineGeometry'
import {
  typeLabel,
  summaryText,
  detailText,
  abnormalStatus,
  severityLabel,
} from './timelineSummary'
import { formatDateTime } from '@/utils/format'

// 事件時間軸。虛擬滾動以**分批渲染**實現（等效路徑）：捲到底再多渲染
// 一批，避免單日數萬列一次進 DOM。不引入任何第三方清單／圖表相依
const props = defineProps({
  events: { type: Array, default: () => [] },
  from: { type: [String, Number, Date], required: true },
  to: { type: [String, Number, Date], required: true },
  focusId: { type: String, default: '' },
  truncated: { type: Boolean, default: false },
  hasMore: { type: Boolean, default: false },
  loadingMore: { type: Boolean, default: false },
  // 續頁失敗。**與「已無更多」分開表達**：兩者都用「按鈕消失、畫面無訊息」
  // 呈現時，稽核會把失敗讀成「已經看完了」而停手
  loadError: { type: Boolean, default: false },
  gutter: { type: Number, default: 200 },
  // 這段期間的**真實總筆數**（開啟中類別的 counts 加總，由父層算好傳入）。
  // events.length 只是「已抓回的頁數合計」、visibleEvents.length 只是分批
  // 渲染的批次量——兩者都不是總數，拿它們當總數會讓讀者在被截斷時
  // 誤信自己看完了全部
  total: { type: Number, default: 0 },
  // 窗內會話跨度（父層與 TimelineTableView 同一份）。剪貼簿「檢視內容」
  // 入口用它把事件時刻換算成會話相對秒數（回放定位錨點）
  spans: { type: Array, default: () => [] },
  // 當前樞紐與開啟中的類別：位址深連結要把這一段調查範圍原樣帶走
  subject: { type: String, default: 'user' },
  types: { type: Array, default: () => [] },
})
const emit = defineEmits(['load-more', 'open-session'])

const { t } = useI18n()

const BATCH = 80
const renderCount = ref(BATCH)
const listRef = ref(null)
const sentinelRef = ref(null)
const rowRefs = new Map()
let observer = null

// 動作回饋的三個狀態量：新批次起點列（畫面上的標記）、剛揭露幾筆、狀態種類
const batchStartId = ref('')
const revealedCount = ref(0)
const statusKind = ref('') // '' | 'revealed' | 'exhausted'
// 使用者按了按鈕而觸發的續抓：那一頁抵達時要自動揭露，而不是靜靜躺在記憶體裡
let awaitingPage = false

const visibleEvents = computed(() => props.events.slice(0, renderCount.value))

// 總數與未顯示筆數。
//
// **取 max 而非直接用 props.total**：total 缺席（父層未傳、或該次查詢沒有
// counts）時退回「已抓回的筆數」，寧可少宣稱也不可宣稱得比畫面上的還少——
// 「共 80 筆」卻列出 300 列，是自己拆自己的台
const totalCount = computed(() => Math.max(props.total || 0, props.events.length))
const restCount = computed(() => Math.max(0, totalCount.value - visibleEvents.value.length))

const footerCounts = computed(() => ({
  shown: visibleEvents.value.length,
  loaded: props.events.length,
  total: totalCount.value,
  rest: restCount.value,
}))

// 還揭露得出東西嗎。**判準不是 restCount**：restCount 取自 counts（整窗真實
// 總數），理論上可能大於實際取得得到的量，那會留下一顆按了無事發生的按鈕——
// 正是本 change 要修掉的那種按鈕。這裡只認「本地還有沒渲染的」或「後端還有頁」
const canShowMore = computed(() => renderCount.value < props.events.length || props.hasMore)

const marks = computed(() =>
  props.events
    .map((event) => {
      const percent = timeToPercent(event.ts, props.from, props.to)
      if (percent === null) return null
      return {
        id: event.id,
        type: event.type,
        percent,
        title: `${formatDateTime(event.ts)} ${summaryText(event)}`,
      }
    })
    .filter(Boolean)
)

const setRowRef = (id, el) => {
  if (el) rowRefs.set(id, el)
  else rowRefs.delete(id)
}

// 剪貼簿事件 → 會話詳情剪貼簿卡（clipboard-audit：時間軸一鍵抵達）。
// t＝事件時刻 − 會話起點取整秒（沿 AuditWorkbench openSessionByEvent 組法）；
// span 不在手（跨度未入窗）時退 at=絕對時刻，換算留給接收端（SessionDetail
// 既有 at 接收邏輯）。無會話參照時無入口——沒有目的地的連結是假話
const clipboardContentRoute = (event) => {
  const sessionId = event?.refs?.session_id
  if (!sessionId) return null
  const ts = new Date(event.ts)
  if (Number.isNaN(ts.getTime())) {
    return { path: `/sessions/${sessionId}`, hash: '#clipboard' }
  }
  const span = props.spans.find((s) => s.session_id === sessionId)
  if (span) {
    const offset = Math.max(0, Math.round((ts - new Date(span.start)) / 1000))
    return {
      path: `/sessions/${sessionId}`,
      query: { t: String(offset) },
      hash: '#clipboard',
    }
  }
  return {
    path: `/sessions/${sessionId}`,
    query: { at: ts.toISOString() },
    hash: '#clipboard',
  }
}

const counterpartText = (counterpart) =>
  counterpart.kind === 'asset'
    ? t('auditorWorkbench.events.counterpartAsset', {
        name: counterpart.name || `#${counterpart.id}`,
      })
    : t('auditorWorkbench.events.counterpartUser', {
        name: counterpart.name || `#${counterpart.id}`,
      })

const isIPPivot = computed(() => props.subject === 'ip')

// 位址樞紐的對造是「誰 · 哪台」：actor 與 counterpart 兩者。
// **未認證的列沒有 actor**（登入失敗、偽造票證兌換），那是位址樞紐才看得到
// 的一批列，顯示為「未認證來源」而不是留白——留白會被讀成「還沒載入」
const actorText = (event) => {
  if (!event?.actor) return t('auditorWorkbench.events.actorUnauthenticated')
  return t('auditorWorkbench.events.actorUser', {
    name: event.actor.name || `#${event.actor.id}`,
  })
}

// 對造格的內容以**行**為單位：人／資產樞紐只有一行（對造），位址樞紐是
// 「誰」與「哪台」兩行。逐行排是為了不被欄寬截斷——同一行時 zh 實測
// 195px > 欄寬 180px，en 更長，被吃掉的正好是後半的「哪台」
const partyLines = (event) => {
  const where = event.counterpart ? counterpartText(event.counterpart) : ''
  if (!isIPPivot.value) return where ? [where] : []
  return where ? [actorText(event), where] : [actorText(event)]
}

// 單行版：hover 的 title（一行讀完整句，與畫面上的兩行同義）
const partyText = (event) => partyLines(event).join(' · ')

// 位址深連結（人／資產樞紐）：帶當前時間窗與開啟中的類別，使點下去是
// **接續同一段調查**。位址樞紐下自身位址不加連結，未知來源亦然——
// 兩者都沒有可去的地方
const addressLink = (event) => {
  if (isIPPivot.value || !event?.client_ip) return null
  return buildAddressPivotLink(event.client_ip, {
    from: typeof props.from === 'string' ? props.from : '',
    to: typeof props.to === 'string' ? props.to : '',
    types: props.types,
  })
}

const typeTagType = (type) => {
  if (type === 'alert') return 'danger'
  if (type === 'session') return 'success'
  if (type === 'command') return 'warning'
  return 'info'
}

// 揭露下一批並讓結果**立刻看得出來**：列數變、頁尾「已顯示 N 筆」變、
// 視野移到新內容起點、狀態列說出剛才發生什麼。四者缺一都可能被讀成「壞掉」
//
// `startIndex` ＝ 這批新內容的第一筆在 events 中的位置：本地揭露時是目前的
// 渲染量；續頁抵達時是**續頁前的資料長度**（renderCount 可能大於它——資料少
// 於一批時 renderCount 仍是 80，此時拿 renderCount 當起點會算出負的新增筆數）
const revealMore = async (startIndex) => {
  const start = Math.max(0, Math.min(startIndex, props.events.length))
  renderCount.value = Math.max(renderCount.value, start + BATCH)
  revealedCount.value = Math.max(0, Math.min(renderCount.value, props.events.length) - start)
  statusKind.value = canShowMore.value ? 'revealed' : 'exhausted'

  const startEvent = props.events[start]
  batchStartId.value = startEvent?.id || ''
  if (!batchStartId.value) return
  await nextTick()
  // block: 'start' 而非捲到最底——把新批次的第一列擺到視野頂端，
  // 使用者尚未讀的部分不會被跳過
  rowRefs.get(batchStartId.value)?.scrollIntoView?.({ block: 'start' })
}

// 按鈕語義統一為「再顯示一批」：本地還有抓回但未渲染的就直接揭露（零網路、
// 同步可見）；本地用完了才向後端續抓，該頁抵達後自動揭露（見下方 watcher）。
// 修正前按鈕只做續抓，而渲染量只由捲動控制，於是「按了畫面毫無變化」
const onLoadMore = () => {
  if (props.loadingMore) return
  if (renderCount.value < props.events.length) {
    revealMore(renderCount.value)
    return
  }
  if (!props.hasMore) return
  awaitingPage = true
  emit('load-more')
}

// 捲到底再多渲染一批。**觀察哨兵而非監聽列表捲動**：列表不再有自己的
// 捲軸（頁面單一捲動路徑），原本掛在它身上的 scroll 事件永遠不會發生。
// 一批揭露完仍留在視窗內時要能連續觸發，故重新註冊觀察目標
const revealLocalBatch = () => {
  if (renderCount.value >= props.events.length) return
  renderCount.value += BATCH
  nextTick(() => {
    const el = sentinelRef.value
    if (!observer || !el) return
    observer.unobserve(el)
    observer.observe(el)
  })
}

const startSentinel = () => {
  if (typeof IntersectionObserver === 'undefined') return
  observer = new IntersectionObserver((entries) => {
    if (entries.some((entry) => entry.isIntersecting)) revealLocalBatch()
  })
  if (sentinelRef.value) observer.observe(sentinelRef.value)
}

onMounted(startSentinel)

onBeforeUnmount(() => {
  observer?.disconnect()
  observer = null
})

const scrollToEvent = async (id) => {
  const index = props.events.findIndex((e) => e.id === id)
  if (index < 0) return
  if (index >= renderCount.value) renderCount.value = index + BATCH
  await nextTick()
  rowRefs.get(id)?.scrollIntoView?.({ block: 'center' })
}

// 深連結 focus：捲到該事件並高亮（入口會帶 focus=<type>:<id> 進來）。
// 換一批資料時先重置渲染批次再重新聚焦——兩件事寫在同一個 watcher 裡，
// 拆成兩個會因註冊順序而互相覆蓋（重置把聚焦擴充的批次又縮回去）。
//
// **游標續頁（append）不重置**：使用者按「載入更多」是要往下看，
// 把畫面彈回前 80 筆等於把他剛才捲的距離全部沒收
let lastFirstId = null
let lastLength = 0
watch(
  () => props.events,
  async (list) => {
    const appended = list.length > lastLength && list[0]?.id === lastFirstId
    const prevLength = lastLength
    lastFirstId = list[0]?.id ?? null
    lastLength = list.length
    if (!appended) {
      renderCount.value = BATCH
      rowRefs.clear()
      batchStartId.value = ''
      statusKind.value = ''
      revealedCount.value = 0
      awaitingPage = false
    } else if (awaitingPage) {
      // 使用者按鈕觸發的那一頁到了：立刻揭露，否則新資料只是進了記憶體，
      // 畫面上仍是原來的 80 列
      awaitingPage = false
      await revealMore(prevLength)
    }
    if (!props.focusId) return
    await nextTick()
    scrollToEvent(props.focusId)
  },
  { immediate: true }
)

watch(
  () => props.focusId,
  async (id) => {
    if (!id) return
    await nextTick()
    scrollToEvent(id)
  }
)

// totalCount／restCount 一併對外：文案接上之前，它們是「還有幾筆沒看到」這件事唯一可斷言的表面
defineExpose({ scrollToEvent, totalCount, restCount, revealedCount, statusKind })
</script>

<style scoped>
.timeline-events {
  display: flex;
  flex-direction: column;
}

.event-axis {
  display: flex;
  align-items: center;
  height: 22px;
}

.axis-gutter {
  flex: none;
  padding-right: var(--ot-space-sm);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  white-space: nowrap;
  overflow: hidden;
}

.axis-track {
  position: relative;
  flex: 1;
  height: 100%;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.axis-mark {
  position: absolute;
  top: 4px;
  width: 2px;
  height: 12px;
  padding: 0;
  border: none;
  background-color: var(--ot-text-secondary);
  cursor: pointer;
}

.axis-mark.type-alert {
  background-color: var(--ot-danger);
  height: 16px;
  top: 2px;
}

.axis-mark.type-command {
  background-color: var(--ot-warning);
}

.axis-mark.type-session {
  background-color: var(--ot-success);
}

.axis-mark.type-clipboard {
  background-color: var(--ot-info);
}

.axis-mark.is-focus {
  background-color: var(--ot-primary-hover);
  width: 3px;
  height: 18px;
  top: 0;
}

.events-alert {
  margin: var(--ot-space-sm) 0;
}

/* 單行截斷警示：24px 內容 + 4px 上下留白 = 32px，取代原本會換到第四行
   的 el-alert（64px + 8px gap）。不用 el-alert 是因為它的 padding 與
   14px 字級在單行下仍逼近 40px */
.events-truncated {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  margin: var(--ot-space-xs) 0;
  padding: 0 var(--ot-space-sm);
  height: 24px;
  border-radius: var(--ot-radius-sm);
  background-color: rgba(217, 169, 62, 0.12);
  color: var(--ot-warning);
  font-size: var(--ot-font-size-xs);
  line-height: 24px;
  cursor: help;
}

.events-truncated-icon {
  flex: none;
  font-size: var(--ot-font-size-md);
}

.events-truncated-text {
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
}

/* 事件明細是本頁主角：**不得置於自身固定高度的巢狀捲軸內**（版面資訊層級
   規格）。原本 460px 的小窗把 2400px 深處的列表縮成一個窺孔，捲動路徑
   也分裂成兩條。列表隨內容長，捲動由頁面單一捲軸承擔 */
.event-list {
  overflow: visible;
}

/* 哨兵本身不佔視覺高度，只需在列表末端可被觀察到 */
.event-sentinel {
  height: 1px;
}

.event-row {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-xs) var(--ot-space-xs);
  border-bottom: 1px solid var(--ot-border-subtle);
  font-size: var(--ot-font-size-sm);
}

/* 新揭露批次的起點：按下「載入更多」之後，視野會停在這一列，
   左緣色條標出「這批從這裡開始」，使變化不只發生在頁尾的數字上 */
.event-row.is-batch-start {
  border-left: 3px solid var(--ot-primary);
  padding-left: calc(var(--ot-space-xs) - 3px);
}

.event-row.is-focus {
  background-color: var(--ot-primary-dim);
  outline: 1px solid var(--ot-primary);
}

.event-time {
  flex: none;
  width: 168px;
  color: var(--ot-text-secondary);
  font-variant-numeric: tabular-nums;
}

.event-type {
  flex: none;
}

.event-body {
  flex: 1;
  min-width: 0;
}

.event-summary {
  color: var(--ot-text-primary);
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  flex-wrap: wrap;
}

.event-detail {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  word-break: break-all;
}

.event-note {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
}

/* 單行短句尾的完整說明入口（tooltip 觸點） */
.clipboard-note-hint {
  vertical-align: -2px;
  margin-left: 2px;
  color: var(--ot-text-disabled);
  cursor: help;
}

/* 註記末尾的「檢視內容」入口：與說明同行，形態為連結（可另開分頁） */
.clipboard-content-link {
  margin-left: var(--ot-space-xs);
  color: var(--ot-primary);
  text-decoration: none;
  white-space: nowrap;
}

.clipboard-content-link:hover {
  text-decoration: underline;
}

/* 位址格次於摘要：固定寬、等寬字，讓同一欄的位址可逐段對齊比對 */
.event-source {
  flex: none;
  width: 150px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 對造格：**不省略**。原本單行 ellipsis 在 1440 寬下把「哪台」吃掉，
   而那是位址樞紐要交付的答案；改為逐行排列並允許長名稱換行，
   欄寬維持 180px——外擴會從摘要欄借位，換成另一欄被壓 */
.event-counterpart {
  flex: none;
  width: 180px;
  display: flex;
  flex-direction: column;
  gap: 2px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.4;
}

/* 位址樞紐下資產名可能長過欄寬：換行而非省略（名稱本身無空白，
   故 anywhere；斷在哪裡都比看不到後半好） */
.party-line {
  overflow-wrap: anywhere;
}

.event-links {
  flex: none;
  width: 96px;
  text-align: right;
}

.events-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-top: var(--ot-space-sm);
}

.footer-hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

/* 還沒看到的部分要比「已顯示幾筆」更醒目——它才是會讓人停手或繼續的那半句 */
.footer-rest {
  color: var(--ot-warning);
}

.events-status {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

/* 「已顯示全部」是中性訊息，刻意不用紅色——紅色是留給載入失敗的形態 */
.status-all-shown {
  margin-left: var(--ot-space-xs);
  color: var(--ot-text-primary);
}
</style>

<style>
/* tooltip popper 掛在 body 下，scoped 樣式構不著（同 OIDCProviders
   col-header-tip 做法）；長句要限寬換行，否則整句撐成一行超出視窗 */
.clipboard-note-tip {
  max-width: 420px;
  line-height: 1.6;
}

/* 截斷警示的長版全文（單行短句的完整承載處），同樣需要限寬換行 */
.events-truncated-tip {
  max-width: 420px;
  line-height: 1.6;
}
</style>
