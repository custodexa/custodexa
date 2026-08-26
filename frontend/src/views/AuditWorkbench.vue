<template>
  <div class="audit-workbench">
    <PageHeader :title="$t('menu.auditWorkbench')">
      <template #actions>
        <!-- 頁首說明收進 popover：那段話一年只讀一次，卻天天佔著版面最上緣
             的三行。常駐載體（問號鈕）留著，完整句一點即得（語義不減） -->
        <el-popover
          placement="bottom-end"
          :width="520"
          trigger="click"
          popper-class="workbench-help-popper"
        >
          <template #reference>
            <el-button
              circle
              :aria-label="$t('auditorWorkbench.headerHelpLabel')"
              :title="$t('auditorWorkbench.headerHelpLabel')"
              data-test="header-help"
            >
              <el-icon><QuestionFilled /></el-icon>
            </el-button>
          </template>
          <p
            class="header-help-text"
            data-test="header-help-text"
          >
            {{ $t('auditorWorkbench.headerDesc') }}
          </p>
        </el-popover>
        <!-- 匯出入口留在頁首動作列的顯眼處，兩種包型各一顆並排（使用者裁決
             2026-08-25）：包型是取件方式與內容的分野（陳述／證物、同步／非同步），
             藏進對話框內的 radio 等於要使用者先按了才知道有另一種。
             兩顆開同一個對話框、各自預選對應包型，radio 仍可切 -->
        <el-button
          type="primary"
          plain
          :disabled="!canExport"
          :title="canExport ? undefined : $t(exportDisabledKey)"
          data-test="open-export"
          @click="openExport('event_report')"
        >
          <el-icon><Document /></el-icon>
          {{ $t('auditorWorkbench.export.buttonReport') }}
        </el-button>
        <el-button
          type="primary"
          plain
          :disabled="!canExport"
          :title="canExport ? undefined : $t(exportDisabledKey)"
          data-test="open-export-bundle"
          @click="openExport('evidence_bundle')"
        >
          <el-icon><Download /></el-icon>
          {{ $t('auditorWorkbench.export.buttonBundle') }}
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

    <!-- 樞紐、主體、時間窗、類別（全部狀態進 query string，可貼連結還原）。
         sticky：捲到事件列表深處時，篩選與類別選擇仍要伸手可及 -->
    <div class="filter-bar">
      <div class="filter-row">
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
          <el-radio-button value="ip">
            {{ $t('auditorWorkbench.pivot.ip') }}
          </el-radio-button>
        </el-radio-group>

        <SubjectPicker
          :model-value="pickerValue"
          :subject-type="subject"
          @update:model-value="onSubjectValue"
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

        <!-- 來源位址篩選只存在於人／資產樞紐：位址樞紐下再帶一個位址條件，
             後端回 400（樞紐本身就是那個位址）。
             C1：文字輸入 enter 或「搜尋」鈕觸發，一律配「重設」 -->
        <template v-if="!isIPPivot">
          <el-input
            v-model="ipFilterInput"
            class="ip-filter"
            clearable
            :disabled="unknownOnly"
            :placeholder="$t('auditorWorkbench.filter.clientIpPlaceholder')"
            data-test="ip-filter"
            @keyup.enter="applyIpFilter"
            @clear="applyIpFilter"
          />
          <el-button
            size="small"
            :disabled="unknownOnly"
            data-test="ip-filter-search"
            @click="applyIpFilter"
          >
            {{ $t('common.search') }}
          </el-button>
          <el-button
            size="small"
            data-test="ip-filter-reset"
            @click="resetIpFilter"
          >
            {{ $t('common.reset') }}
          </el-button>
          <!-- 與位址輸入互斥：兩者同時成立沒有語義（一個要求等於某位址、
               一個要求沒有位址），後端也只收一個 client_ip -->
          <el-tooltip
            :content="$t('auditorWorkbench.filter.unknownOnlyHint')"
            placement="top"
          >
            <el-checkbox
              v-model="unknownOnly"
              data-test="unknown-only"
            >
              {{ $t('auditorWorkbench.filter.unknownOnly') }}
            </el-checkbox>
          </el-tooltip>
        </template>

        <!-- 來源位址維度的口徑與邊界：每一條都同時說出情境與由什麼承擔。
             常駐一顆入口鈕（不是常駐三段文字），三樞紐皆可讀——每一列都有
             位址格，讀法的邊界對三個樞紐同時成立 -->
        <el-popover
          placement="bottom-start"
          :width="520"
          trigger="click"
          popper-class="ip-boundary-popper"
        >
          <template #reference>
            <el-button
              link
              type="primary"
              size="small"
              data-test="ip-boundary"
            >
              <el-icon><InfoFilled /></el-icon>
              {{ $t('auditorWorkbench.ipBoundary.label') }}
            </el-button>
          </template>
          <div
            class="ip-boundary"
            data-test="ip-boundary-text"
          >
            <p class="ip-boundary-title">
              {{ $t('auditorWorkbench.ipBoundary.title') }}
            </p>
            <ul>
              <li
                v-for="key in IP_BOUNDARY_KEYS"
                :key="key"
              >
                {{ $t(`auditorWorkbench.ipBoundary.${key}`) }}
              </li>
            </ul>
          </div>
        </el-popover>

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

      <!-- 類別選擇是篩選動作，不是常駐資訊面板：併入篩選列後左欄退場，
           事件區全寬。覆蓋狀態的完整說明句改掛在各 chip 的 popover 上 -->
      <CategoryChips
        v-model="types"
        :counts="counts"
        :coverage="coverage"
        @open-checkpoint="goCheckpoint"
      />
    </div>

    <!-- 左欄退場後事件區全寬：主角不再被 260px 側欄與巢狀捲軸夾成窺孔 -->
    <section
      v-loading="loading"
      class="wb-main"
    >
      <el-alert
        v-if="!hasSubject"
        type="info"
        :closable="false"
        show-icon
        data-test="no-subject"
        :title="$t(isIPPivot
          ? 'auditorWorkbench.subject.requiredIp'
          : 'auditorWorkbench.subject.required')"
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
          :from="from"
          :to="to"
          :types="types"
        />

        <div
          v-else
          class="panel"
        >
          <!-- 跨度條與事件軸共用這一條刻度尺。不再 sticky：篩選列已 sticky
               佔住頂端，刻度再黏一層會疊在它下面；且總覽兩層化後跨度條
               只佔一列到十餘列，刻度不會離開它服務的區塊太遠 -->
          <TimelineScale
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
            :spans="spans"
            :focus-id="focus"
            :total="totalCount"
            :truncated="truncated"
            :has-more="Boolean(nextCursor)"
            :loading-more="loadingMore"
            :load-error="loadMoreFailed"
            :gutter="GUTTER"
            :subject="subject"
            :types="types"
            @load-more="loadMore"
            @open-session="openSessionByEvent"
          />
        </div>
      </template>
    </section>

    <!-- 匯出（事件報告／證據包兩種包型，工具列兩顆入口各自預選）：
         範圍由下方 exportParams 帶入，與時間軸查詢同源 -->
    <ExportReportDialog
      v-model="exportOpen"
      :params="exportParams"
      :pack="exportPack"
      :subject="subject"
      :subject-name="subjectName"
      :from="from"
      :to="to"
      :types="types"
      :counts="counts"
      :coverage="coverage"
      :truncated="truncated"
      :ip-filtered="Boolean(clientIp)"
    />
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Document, Download, InfoFilled, QuestionFilled, Refresh } from '@element-plus/icons-vue'
import PageHeader from '@/components/PageHeader.vue'
import CategoryChips from '@/components/audit/CategoryChips.vue'
import ExportReportDialog from '@/components/audit/ExportReportDialog.vue'
import SessionSpanBars from '@/components/audit/SessionSpanBars.vue'
import SubjectPicker from '@/components/audit/SubjectPicker.vue'
import TimelineEvents from '@/components/audit/TimelineEvents.vue'
import TimelineScale from '@/components/audit/TimelineScale.vue'
import TimelineTableView from '@/components/audit/TimelineTableView.vue'
import { getAuditTimeline } from '@/api/auditTimeline'
import {
  UNKNOWN_SOURCE,
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

// 邊界說明的顯示順序：先講候選與口徑（讀者馬上會踩到的），
// 再講未知與 IPv6，最後講部署與匯出（不是每次調查都相關）
const IP_BOUNDARY_KEYS = [
  'candidates',
  'scope',
  'unknown',
  'ipv6',
  'proxy',
  'export',
  'exactMatch',
]

const initial = parseWorkbenchQuery(route.query)
const subject = ref(initial.subject)
const subjectId = ref(initial.subjectId)
// 位址樞紐的主體鍵是字串（位址）；與 subjectId 分開存，切樞紐時互不污染
const subjectIp = ref(initial.subjectIp)
// 已套用的來源位址篩選（含保留字 unknown）；ipFilterInput 是尚未送出的草稿
const clientIp = ref(initial.clientIp)
const ipFilterInput = ref(initial.clientIp === UNKNOWN_SOURCE ? '' : initial.clientIp)
const unknownOnly = ref(initial.clientIp === UNKNOWN_SOURCE)
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

const isIPPivot = computed(() => subject.value === 'ip')
// 「有沒有選定調查對象」在位址樞紐下問的是位址，不是整數 id——
// 沿用 subjectId 判斷會讓位址樞紐永遠停在「請先選擇對象」
const hasSubject = computed(() =>
  isIPPivot.value ? Boolean(subjectIp.value) : Boolean(subjectId.value)
)
const pickerValue = computed(() => (isIPPivot.value ? subjectIp.value : subjectId.value))

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
    subjectIp: subjectIp.value,
    clientIp: clientIp.value,
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
    from: from.value,
    to: to.value,
    limit: PAGE_LIMIT,
    // 關閉的類別不送查詢——types 隨開關縮減，關掉的來源後端不會去查
    types: types.value.join(','),
  }
  if (isIPPivot.value) {
    params.subject_ip = subjectIp.value
  } else {
    params.subject_id = subjectId.value
    // 位址篩選只在人／資產樞紐送出；空值不送（送空字串等於篩一個空位址）
    if (clientIp.value) params.client_ip = clientIp.value
  }
  if (cursor) params.cursor = cursor
  return params
}

// —— 來源位址篩選（C1：文字輸入 enter 或搜尋鈕、一律配重設）——
const applyIpFilter = () => {
  if (unknownOnly.value) return
  clientIp.value = ipFilterInput.value.trim()
}

const resetIpFilter = () => {
  ipFilterInput.value = ''
  unknownOnly.value = false
  clientIp.value = ''
}

// 勾選「只看未知來源」與位址輸入互斥：勾起時把草稿收走並改送保留字，
// 取消時退回草稿（使用者剛才打的字不該被沒收）
watch(unknownOnly, (on) => {
  clientIp.value = on ? UNKNOWN_SOURCE : ipFilterInput.value.trim()
})

// —— 匯出（出口三）——
//
// 兩種包型（事件報告同步直下／證據包發起非同步 job）在工具列各有一顆入口，
// 兩顆開同一個對話框、只差預選的包型（對話框內的 radio 仍可切）；本頁只負責
// 把「畫面上的範圍」交出去，參數形態的差異由 ExportReportDialog 承擔。
//
// **範圍必須是畫面上的那一個**：exportParams 與 queryParams 讀同一組 ref
//（樞紐、對象、起訖、開啟中的類別），使用者按下匯出拿到的就是他正在看的
// 那一段，不是「全部」也不是預設值。匯出端點的樞紐 id 沿用 user_id／asset_id，
// 這是本頁與該端點之間唯一的參數形態差異
const exportOpen = ref(false)
// 開對話框時預選的包型：使用者按了哪一顆，開起來就停在哪一種
const exportPack = ref('event_report')
const openExport = (pack) => {
  exportPack.value = pack
  exportOpen.value = true
}

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
// 並不存在，端點也會回 400。按鈕上以 title 說明為何不能按。
//
// **位址樞紐一律不給按**：匯出端點的範圍鍵只有 user_id／asset_id，位址不是
// 它接得住的樞紐。disabled 是真的不能——按下去只會拿到一份範圍不對的報告
const canExport = computed(
  () =>
    !isIPPivot.value &&
    Boolean(
      subjectId.value && from.value && to.value && !rangeInvalid.value && types.value.length
    )
)

// 停用原因分兩種，說法不同：位址樞紐是「這個樞紐沒有匯出」（指出替代路徑），
// 其餘是「範圍還沒選齊」
const exportDisabledKey = computed(() =>
  isIPPivot.value
    ? 'auditorWorkbench.export.unavailableIpPivot'
    : 'auditorWorkbench.export.unavailable'
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

// 選擇器對三個樞紐共用，但主體鍵的型別不同：位址是字串、人與資產是整數。
// 在這裡分流而非讓選擇器自己猜，避免 `Number('203.0.113.5')` 那條 NaN 路徑
const onSubjectValue = (value) => {
  if (isIPPivot.value) subjectIp.value = typeof value === 'string' ? value.trim() : ''
  else subjectId.value = value ?? null
}
const subjectName = computed(() => {
  // 位址樞紐的「對象名」就是位址本身——它沒有第二個名字
  if (isIPPivot.value) return subjectIp.value
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
    subjectIp.value,
    clientIp.value,
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

  if (!hasSubject.value || !from.value || !to.value || rangeInvalid.value) {
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

// 樞紐切換：主體鍵與 focus 在另一個樞紐下沒有意義，一併清掉。
// 位址篩選同理——它是「在這個人身上再限一個來源」，換樞紐後沒有指涉
watch(subject, () => {
  subjectId.value = null
  subjectIp.value = ''
  focus.value = ''
  picked.value = null
  ipFilterInput.value = ''
  unknownOnly.value = false
  clientIp.value = ''
})

watch([subject, subjectId, subjectIp, clientIp, timeRange, types, view, focus], () => {
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
    subjectIp.value = parsed.subjectIp
    clientIp.value = parsed.clientIp
    unknownOnly.value = parsed.clientIp === UNKNOWN_SOURCE
    ipFilterInput.value = unknownOnly.value ? '' : parsed.clientIp
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
/* 篩選列 sticky：捲到列表深處時仍要能改條件、開關類別（版面資訊層級規格）。
   z-index 高於頁面其餘內容，捲過時內容從它底下通過 */
.filter-bar {
  position: sticky;
  top: 0;
  z-index: 3;
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

/* 捲動容器（el-main）自帶 padding，sticky 元素黏在 padding 之上時，上方會
   露出一條讓內容穿過的縫。這片與頁面同色的遮片把那條縫補起來 */
.filter-bar::before {
  content: '';
  position: absolute;
  left: -1px;
  right: -1px;
  top: calc(var(--ot-space-lg) * -1 - 1px);
  height: var(--ot-space-lg);
  background-color: var(--ot-bg-page);
}

.filter-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
}

.view-switch {
  margin-left: auto;
}

.ip-filter {
  width: 200px;
}

.ip-filter :deep(.el-input__inner) {
  font-family: var(--ot-font-mono);
}

.wb-main {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.panel {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.header-help-text {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
  color: var(--ot-text-primary);
}
</style>

<style>
/* popover 掛在 body 下，scoped 樣式構不著（同 header-help-popper 做法） */
.ip-boundary-popper .ip-boundary-title {
  margin: 0 0 var(--ot-space-xs);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.ip-boundary-popper .ip-boundary ul {
  margin: 0;
  padding-left: 1.2em;
}

.ip-boundary-popper .ip-boundary li {
  margin-bottom: var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
  color: var(--ot-text-primary);
}
</style>
