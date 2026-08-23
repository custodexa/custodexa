<template>
  <div class="audit-workbench">
    <PageHeader
      :title="$t('menu.auditWorkbench')"
      :description="$t('auditorWorkbench.headerDesc')"
    >
      <template #actions>
        <el-button
          type="primary"
          plain
          :disabled="!canExport"
          :title="canExport ? undefined : $t('auditorWorkbench.export.unavailable')"
          data-test="open-export"
          @click="exportOpen = true"
        >
          <el-icon><Download /></el-icon>
          {{ $t('auditorWorkbench.export.button') }}
        </el-button>
        <el-button
          data-test="goto-checkpoint"
          @click="goCheckpoint(null)"
        >
          {{ $t('auditorWorkbench.actions.checkpoint') }}
        </el-button>
        <el-button
          :loading="loading"
          data-test="refresh"
          @click="load(true)"
        >
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 樞紐、主體、時間窗（全部狀態進 query string，可貼連結還原） -->
    <div class="filter-bar">
      <el-radio-group
        v-model="subject"
        data-test="pivot-switch"
      >
        <el-radio-button value="user">
          {{ $t('auditorWorkbench.pivot.user') }}
        </el-radio-button>
        <el-radio-button value="asset">
          {{ $t('auditorWorkbench.pivot.asset') }}
        </el-radio-button>
      </el-radio-group>

      <SubjectPicker
        v-model="subjectId"
        :subject-type="subject"
        @change="onSubjectPicked"
      />

      <el-date-picker
        v-model="timeRange"
        type="datetimerange"
        data-test="time-range"
        :range-separator="$t('auditorWorkbench.range.separator')"
        :start-placeholder="$t('auditorWorkbench.range.start')"
        :end-placeholder="$t('auditorWorkbench.range.end')"
        format="YYYY-MM-DD HH:mm"
        value-format="YYYY-MM-DDTHH:mm:ssZ"
        style="width: 360px"
      />

      <el-button-group>
        <el-button
          size="small"
          data-test="shortcut-today"
          @click="applyShortcut('today')"
        >
          {{ $t('auditorWorkbench.range.today') }}
        </el-button>
        <el-button
          size="small"
          data-test="shortcut-24h"
          @click="applyShortcut('last24h')"
        >
          {{ $t('auditorWorkbench.range.last24h') }}
        </el-button>
        <el-button
          size="small"
          data-test="shortcut-30m"
          @click="applyShortcut('around30m')"
        >
          {{ $t('auditorWorkbench.range.around30m') }}
        </el-button>
      </el-button-group>

      <el-radio-group
        v-model="view"
        size="small"
        class="view-switch"
        data-test="view-switch"
      >
        <el-radio-button value="timeline">
          {{ $t('auditorWorkbench.view.timeline') }}
        </el-radio-button>
        <el-radio-button value="table">
          {{ $t('auditorWorkbench.view.table') }}
        </el-radio-button>
      </el-radio-group>
    </div>

    <div class="wb-body">
      <aside class="wb-side">
        <CategoryPanel
          v-model="types"
          :counts="counts"
          :coverage="coverage"
        />
      </aside>

      <section
        v-loading="loading"
        class="wb-main"
      >
        <el-alert
          v-if="!subjectId"
          type="info"
          :closable="false"
          show-icon
          data-test="no-subject"
          :title="$t('auditorWorkbench.subject.required')"
        />
        <el-alert
          v-else-if="rangeInvalid"
          type="error"
          :closable="false"
          show-icon
          data-test="range-invalid"
          :title="$t('auditorWorkbench.range.invalid')"
        />
        <template v-else>
          <CoverageNotices
            :coverage="coverage"
            :counts="counts"
            :active-types="types"
            @open-checkpoint="goCheckpoint"
          />

          <el-alert
            v-if="focus && focusMissing"
            type="warning"
            :closable="false"
            show-icon
            data-test="focus-missing"
            :title="$t('auditorWorkbench.events.focusNotFound')"
          />

          <TimelineTableView
            v-if="view === 'table'"
            :events="events"
            :spans="spans"
            :subject="subject"
            :focus-id="focus"
          />

          <div
            v-else
            class="panel"
          >
            <!-- 跨度條與事件軸共用這一條刻度尺。sticky：會話多時列表很長，
                 刻度捲出畫面等於跨度條失去座標軸 -->
            <TimelineScale
              class="sticky-scale"
              :from="from"
              :to="to"
              :gutter="GUTTER"
            >
              <template #gutter>
                {{ $t('auditorWorkbench.spans.title') }}
              </template>
            </TimelineScale>

            <SessionSpanBars
              :spans="spans"
              :from="from"
              :to="to"
              :subject="subject"
              :gutter="GUTTER"
              @open-session="openSessionById"
            />

            <TimelineEvents
              :events="events"
              :from="from"
              :to="to"
              :focus-id="focus"
              :total="totalCount"
              :truncated="truncated"
              :has-more="Boolean(nextCursor)"
              :loading-more="loadingMore"
              :load-error="loadMoreFailed"
              :gutter="GUTTER"
              @load-more="loadMore"
              @open-session="openSessionByEvent"
            />
          </div>
        </template>
      </section>
    </div>

    <!-- 匯出事件報告：範圍由下方 exportParams 帶入，與時間軸查詢同源 -->
    <ExportReportDialog
      v-model="exportOpen"
      :params="exportParams"
      :subject="subject"
      :subject-name="subjectName"
      :from="from"
      :to="to"
      :types="types"
      :counts="counts"
      :coverage="coverage"
      :truncated="truncated"
    />
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Download, Refresh } from '@element-plus/icons-vue'
import PageHeader from '@/components/PageHeader.vue'
import CategoryPanel from '@/components/audit/CategoryPanel.vue'
import CoverageNotices from '@/components/audit/CoverageNotices.vue'
import ExportReportDialog from '@/components/audit/ExportReportDialog.vue'
import SessionSpanBars from '@/components/audit/SessionSpanBars.vue'
import SubjectPicker from '@/components/audit/SubjectPicker.vue'
import TimelineEvents from '@/components/audit/TimelineEvents.vue'
import TimelineScale from '@/components/audit/TimelineScale.vue'
import TimelineTableView from '@/components/audit/TimelineTableView.vue'
import { getAuditTimeline } from '@/api/auditTimeline'
import {
  buildWorkbenchQuery,
  parseWorkbenchQuery,
  sameQuery,
  shortcutRange,
} from '@/components/audit/timelineQuery'

// 稽核調查工作台（auditor-workbench）。
//
// **唯讀且不出具完整性證明**：本頁把六類稽核紀錄併到同一條時間軸上供調查，
// 完整性主張只由 /checkpoint-verification 出具。頁內文案 SHALL NOT
// 出現「完整」「未被竄改」這類斷言。
//
// **並存不取代既有六頁**：告警審閱、每日簽核、會話終止與監看、檢查點驗證
// 各有其作業心智模型，工作台是第七頁＋多入口。

const route = useRoute()
const router = useRouter()

const GUTTER = 200
const PAGE_LIMIT = 500
// 深連結 focus 落在後面幾頁時自動續抓的上限：無上限會讓一個壞掉的 focus
// 參數把整個窗抓完
const MAX_FOCUS_PAGES = 5

const initial = parseWorkbenchQuery(route.query)
const subject = ref(initial.subject)
const subjectId = ref(initial.subjectId)
const timeRange = ref(
  initial.from && initial.to ? [initial.from, initial.to] : shortcutRange('today')
)
const types = ref(initial.types)
const focus = ref(initial.focus)
const view = ref(initial.view)

const loading = ref(false)
const loadingMore = ref(false)
const events = ref([])
const spans = ref([])
const coverage = ref([])
const counts = ref({})
const nextCursor = ref('')
const loadMoreFailed = ref(false)
const truncated = ref(false)
const focusMissing = ref(false)

const from = computed(() => timeRange.value?.[0] || '')
const to = computed(() => timeRange.value?.[1] || '')
const rangeInvalid = computed(
  () => Boolean(from.value && to.value) && new Date(to.value) <= new Date(from.value)
)

// 這段期間的事件總筆數＝**開啟中類別的 counts 加總**。
//
// counts 不受單次查詢上限影響（`timeline_service.go:263-271` 每頁整窗重算），
// 是窗內真實總數；events.length 只是已抓回的頁數合計。事件軸底部若拿後者
// 當總數，稽核會在被截斷的情況下誤信自己看完了全部（與截斷提示疊加
// 時是本頁最危險的一處）。
//
// 以 types 逐項取值而非 Object.values(counts) 加總：關閉的類別不進查詢也不
// 該計入總數，而 counts 是上一次查詢的殘值時可能還留著它
const totalCount = computed(() =>
  types.value.reduce((sum, type) => sum + (Number(counts.value?.[type]) || 0), 0)
)

const currentQuery = () =>
  buildWorkbenchQuery({
    subject: subject.value,
    subjectId: subjectId.value,
    from: from.value,
    to: to.value,
    types: types.value,
    focus: focus.value,
    view: view.value,
  })

const syncUrl = () => {
  const next = currentQuery()
  if (sameQuery(route.query, next)) return
  router.replace({ query: next }).catch(() => {})
}

const resetData = () => {
  events.value = []
  spans.value = []
  coverage.value = []
  counts.value = {}
  nextCursor.value = ''
  loadMoreFailed.value = false
  truncated.value = false
  focusMissing.value = false
}

const queryParams = (cursor = '') => {
  const params = {
    subject: subject.value,
    subject_id: subjectId.value,
    from: from.value,
    to: to.value,
    limit: PAGE_LIMIT,
    // 關閉的類別不送查詢——types 隨開關縮減，關掉的來源後端不會去查
    types: types.value.join(','),
  }
  if (cursor) params.cursor = cursor
  return params
}

// —— 匯出事件報告（出口三）——
//
// **範圍必須是畫面上的那一個**：exportParams 與 queryParams 讀同一組 ref
//（樞紐、對象、起訖、開啟中的類別），使用者按下匯出拿到的就是他正在看的
// 那一段，不是「全部」也不是預設值。匯出端點的樞紐 id 沿用 user_id／asset_id，
// 這是本頁與該端點之間唯一的參數形態差異
const exportOpen = ref(false)

const exportParams = computed(() => {
  const params = {
    subject: subject.value,
    start_time: from.value,
    end_time: to.value,
    types: types.value.join(','),
  }
  params[subject.value === 'asset' ? 'asset_id' : 'user_id'] = subjectId.value
  return params
})

// 沒有對象、沒有區間或一類都沒開時不給按：那三種情況下「目前的調查範圍」
// 並不存在，端點也會回 400。按鈕上以 title 說明為何不能按
const canExport = computed(() =>
  Boolean(
    subjectId.value && from.value && to.value && !rangeInvalid.value && types.value.length
  )
)

// 對象顯示名：選擇器選過就用它給的名字；深連結進來（選擇器沒觸發過 change）
// 時退回跨度條上的同一對象名，再退回 id。報告範圍是給人讀的，只給 id 讀不出
// 自己查的是誰
// 存整個選項而非只存名字：URL 換了對象（上一頁／深連結）時 id 對不上，
// 舊名字就自動失效——留著會在報告範圍上掛別人的名字
const picked = ref(null)
const onSubjectPicked = (option) => {
  picked.value = option || null
}
const subjectName = computed(() => {
  if (picked.value?.id === subjectId.value && picked.value?.name) return picked.value.name
  const span = spans.value.find((s) =>
    subject.value === 'asset' ? s.asset_id === subjectId.value : s.user_id === subjectId.value
  )
  const name = subject.value === 'asset' ? span?.asset_name : span?.user_name
  return name || (subjectId.value ? `#${subjectId.value}` : '')
})

const applyPage = (res, append) => {
  const page = res || {}
  events.value = append ? [...events.value, ...(page.events || [])] : page.events || []
  // spans／coverage／counts 每頁都是整窗重算，覆寫即可（不可累加）
  spans.value = page.spans || []
  coverage.value = page.coverage || []
  counts.value = page.counts || {}
  nextCursor.value = page.next_cursor || ''
  truncated.value = Boolean(page.truncated)
  // 拿到任何一頁就代表上一次失敗已被越過，錯誤形態不該留在畫面上
  loadMoreFailed.value = false
}

const hasFocusEvent = () =>
  !focus.value || events.value.some((e) => e.id === focus.value)

// 一次請求只回一頁；深連結指定的事件可能落在後面幾頁，續抓到找到為止（有上限）
const chaseFocus = async () => {
  let pages = 0
  while (!hasFocusEvent() && nextCursor.value && pages < MAX_FOCUS_PAGES) {
    pages += 1
    const res = await getAuditTimeline(queryParams(nextCursor.value))
    applyPage(res, true)
  }
  focusMissing.value = !hasFocusEvent()
}

let lastKey = ''

const load = async (force = false) => {
  const key = JSON.stringify([
    subject.value,
    subjectId.value,
    from.value,
    to.value,
    [...types.value].sort(),
  ])
  if (!force && key === lastKey) {
    // 查詢條件沒變、只換了 focus（同窗深連結再次跳入）：不重查，
    // 但仍要確認被指定的事件是否在已載入範圍內
    if (focus.value) await chaseFocus()
    return
  }
  lastKey = key

  if (!subjectId.value || !from.value || !to.value || rangeInvalid.value) {
    resetData()
    return
  }
  // 一個類別都沒開：不送查詢（送出去等於「全部類別」，會回一份使用者
  // 明明關掉了的資料）
  if (types.value.length === 0) {
    resetData()
    return
  }

  loading.value = true
  try {
    const res = await getAuditTimeline(queryParams())
    applyPage(res, false)
    await chaseFocus()
  } catch (_e) {
    // 全域攔截器已出 toast；此處只確保畫面不留上一次主體的殘影
    resetData()
  } finally {
    loading.value = false
  }
}

// 續頁失敗**不清空游標**。清掉等於把按鈕收走，於是「失敗」與「已經沒有更多」
// 在畫面上完全同形，稽核會據此認為自己看完了全部；且游標沒了之後，其餘部分
// 在技術上也再也取不到（只能整頁重查）。改為留著游標、另立失敗旗標供重試
const loadMore = async () => {
  if (!nextCursor.value || loadingMore.value) return
  loadingMore.value = true
  loadMoreFailed.value = false
  try {
    const res = await getAuditTimeline(queryParams(nextCursor.value))
    applyPage(res, true)
  } catch (_e) {
    // 全域攔截器已出 toast；此處只保留可重試的狀態並讓畫面明示失敗
    loadMoreFailed.value = true
  } finally {
    loadingMore.value = false
  }
}

const applyShortcut = (kind) => {
  timeRange.value = shortcutRange(kind)
}

const openSessionById = (sessionId) => {
  if (sessionId) router.push(`/sessions/${sessionId}`)
}

// 事件 → 會話詳情。已知該會話的起點時，一併帶上相對秒數（回放定位錨點）
const openSessionByEvent = (event) => {
  const sessionId = event?.refs?.session_id
  if (!sessionId) return
  const span = spans.value.find((s) => s.session_id === sessionId)
  const offset = span
    ? Math.max(0, Math.round((new Date(event.ts) - new Date(span.start)) / 1000))
    : null
  router.push({
    path: `/sessions/${sessionId}`,
    query: offset === null ? {} : { t: String(offset) },
  })
}

// purged 區間帶 → 檢查點驗證頁（工作台只給連結，任何驗證與完整性判定
// 都在那一頁進行）
const goCheckpoint = (seqRange) => {
  const query = seqRange
    ? { seq_from: String(seqRange.from), seq_to: String(seqRange.to) }
    : {}
  router.push({ path: '/checkpoint-verification', query })
}

// 樞紐切換：主體 id 與 focus 在另一個樞紐下沒有意義，一併清掉
watch(subject, () => {
  subjectId.value = null
  focus.value = ''
  picked.value = null
})

watch([subject, subjectId, timeRange, types, view, focus], () => {
  syncUrl()
  load()
})

// 外部導覽（六頁深連結、上一頁／下一頁）→ 還原畫面
watch(
  () => route.query,
  (q) => {
    if (sameQuery(q, currentQuery())) return
    const parsed = parseWorkbenchQuery(q)
    subject.value = parsed.subject
    subjectId.value = parsed.subjectId
    if (parsed.from && parsed.to) timeRange.value = [parsed.from, parsed.to]
    types.value = parsed.types
    focus.value = parsed.focus
    view.value = parsed.view
    load()
  }
)

onMounted(() => {
  // 預設時間窗（今天）也要寫回 URL，否則首屏的畫面複製出去無法還原
  syncUrl()
  load()
})
</script>

<style scoped>
.filter-bar {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

.view-switch {
  margin-left: auto;
}

.wb-body {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-md);
}

.wb-side {
  flex: none;
  width: 260px;
}

.wb-main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.sticky-scale {
  position: sticky;
  top: 0;
  z-index: 2;
  background-color: var(--ot-bg-surface);
}

.panel {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

@media (max-width: 1100px) {
  .wb-body {
    flex-direction: column;
  }

  .wb-side {
    width: 100%;
  }
}
</style>
