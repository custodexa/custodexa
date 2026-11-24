<template>
  <!-- 每日簽核工作區：上方期間統計，中段待簽日（由最早排起），下段已簽紀錄。
       簽核在右側抽屜完成，不離開清單 -->
  <div
    class="dr-workspace"
    data-test="dr-workspace"
  >
    <div
      v-if="!canSign"
      class="dr-notice dr-notice--info"
      data-test="dr-readonly-notice"
    >
      {{ $t('dailyReview.workspace.readonlyNotice') }}
    </div>

    <!-- 功能未開啟：既有已簽紀錄照常列在下方 -->
    <div
      v-if="status && !status.enabled"
      class="dr-empty"
      data-test="dr-disabled"
    >
      <div class="dr-empty__title">
        {{ $t('dailyReview.workspace.disabledTitle') }}
      </div>
      <p>{{ $t('dailyReview.workspace.disabledBody') }}</p>
      <el-button
        v-if="canOpenPolicies"
        data-test="dr-disabled-link"
        @click="router?.push('/security-policies')"
      >
        {{ $t('dailyReview.workspace.disabledAdminLink') }}
      </el-button>
      <p v-else>
        {{ $t('dailyReview.workspace.disabledContact') }}
      </p>
    </div>

    <template v-else>
      <DailyReviewStats ref="statsRef" />

      <div
        v-if="overdueCount > 0"
        class="dr-notice dr-notice--warning"
        data-test="dr-overdue-banner"
      >
        {{ $t('dailyReview.workspace.overdueBanner', {
          count: pendingTotal,
          overdue: overdueCount,
          earliest: pending[0]?.date || status?.earliest_pending_date || '',
        }) }}
      </div>

      <div class="dr-section-head">
        <h3 class="dr-section-title">
          {{ $t('dailyReview.workspace.pendingTitle', { n: pendingTotal }) }}
        </h3>
        <span
          v-if="canSign && pendingTotal > 0"
          class="dr-sub"
          data-test="dr-multi-hint"
        >{{ $t('dailyReview.workspace.cross.hint') }}</span>
      </div>
      <div
        v-if="!pendingLoading && pendingTotal === 0"
        class="dr-empty"
        data-test="dr-all-done"
      >
        <CircleCheck
          :size="22"
          class="dr-empty__ok"
          aria-hidden="true"
        />
        <div class="dr-empty__title">
          {{ $t('dailyReview.workspace.allDoneTitle') }}
        </div>
        <p v-if="status?.timezone_state?.today?.date">
          {{ $t('dailyReview.workspace.allDoneHint', { date: status.timezone_state.today.date }) }}
        </p>
      </div>
      <div
        v-else
        class="list-card"
      >
        <!-- 多日簽核的批次列：勾選後出現 -->
        <BatchSelectionBar
          v-if="canSign && selection.selected.value.length"
          test-id="dr-batch-bar"
          :count-text="batchCountText"
          :clear-text="$t('alerts.batch.clear')"
          :limit-text="batchLimitText"
          @clear="selection.clear()"
        >
          <el-button
            v-if="selectedAlertDays.length"
            v-preview-write
            type="primary"
            :loading="crossLoading"
            data-test="dr-cross-open"
            @click="openCrossDay"
          >
            {{ $t('dailyReview.workspace.cross.open', { n: selectedAlertTotal }) }}
          </el-button>
          <el-button
            v-else
            v-preview-write
            type="primary"
            data-test="dr-multi-open"
            @click="multiDialogRef?.open()"
          >
            {{ $t('dailyReview.workspace.multi.open', { n: selection.selected.value.length }) }}
          </el-button>
        </BatchSelectionBar>
        <el-table
          v-loading="pendingLoading"
          :data="pending"
          data-test="dr-pending-table"
          style="width: 100%"
        >
          <el-table-column
            v-if="canSign"
            width="48"
          >
            <template #header>
              <BatchCheckbox
                test-id="dr-select-all"
                :checked="pageSelectState.checked"
                :indeterminate="pageSelectState.indeterminate"
                :disabled="pageSelectState.disabled"
                :label="$t('dailyReview.workspace.multi.selectAll')"
                @change="selection.toggleAll(pending, isDaySelectable)"
              />
            </template>
            <template #default="{ row }">
              <BatchCheckbox
                test-id="dr-select-cell"
                :data-id="row.date"
                :checked="selection.isSelected(row)"
                :disabled="!canToggleDay(row)"
                :label="dayBlockedText(row) || $t('dailyReview.workspace.multi.selectRow', { date: row.date })"
                @change="(checked) => selection.toggle(row, checked)"
              />
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('dailyReview.workspace.col.date')"
            :min-width="narrow ? 180 : 210"
          >
            <template #default="{ row }">
              <div class="dr-date">
                <span data-test="dr-pending-date">{{ dateWithWeekday(row.date) }}</span>
                <span
                  v-if="!row.overdue"
                  class="dr-sub"
                >{{ $t('dailyReview.yesterdayMark') }}</span>
                <el-tag
                  v-if="isInferredBasis(row.enabled_basis)"
                  size="small"
                  type="info"
                  data-test="dr-pending-inferred"
                >
                  {{ $t('dailyReview.enabledInferred.tag') }}
                </el-tag>
              </div>
              <div
                v-if="canSign && dayNoteText(row)"
                class="dr-blocked"
                data-test="dr-select-blocked"
              >
                {{ dayNoteText(row) }}
              </div>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('dailyReview.workspace.col.deadline')"
            :min-width="narrow ? 110 : 190"
          >
            <template #default="{ row }">
              <span :class="['dr-deadline', { 'dr-warn': row.overdue }]">
                {{ row.overdue
                  ? $t('dailyReview.workspace.deadlineLate', { n: row.late_days })
                  : row.signable === false
                    ? $t('dailyReview.workspace.deadlineSettling', { time: timeInZone(row.signable_at, row.timezone) })
                    : $t('dailyReview.workspace.deadlineOnTime', { time: timeInZone(lastMinuteBefore(row.due_at), row.timezone) }) }}
              </span>
            </template>
          </el-table-column>
          <el-table-column
            v-if="!narrow"
            :label="$t('common.loginFailures')"
            width="100"
          >
            <template #default="{ row }">
              {{ countText(row.counts?.login_failures, row.counts?.login_failures_source) }}
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('common.unreviewedAlerts')"
            :width="narrow ? 100 : 120"
          >
            <template #default="{ row }">
              <div
                :class="{ 'dr-warn': pendingAlertCount(row) > 0 }"
                data-test="dr-pending-alerts"
              >
                {{ pendingAlertCount(row) > 0
                  ? $t('dailyReview.workspace.alertCount', { n: pendingAlertCount(row) })
                  : countText(row.counts?.unreviewed_alerts, row.counts?.alerts_source) }}
              </div>
              <div
                v-if="pendingAlertCount(row) > 0 && Number.isInteger(row.unreviewed_alert_types)"
                class="dr-sub"
                data-test="dr-pending-alert-types"
              >
                {{ $t('dailyReview.workspace.alertTypes', { k: row.unreviewed_alert_types }) }}
              </div>
            </template>
          </el-table-column>
          <el-table-column
            v-if="!narrow"
            :label="$t('common.highRiskOps')"
            width="100"
          >
            <template #default="{ row }">
              {{ countText(row.counts?.high_risk_ops, row.counts?.high_risk_ops_source) }}
            </template>
          </el-table-column>
          <!-- 窄視窗：兩項供查閱的計數併成一欄，動作留在可見寬度內 -->
          <el-table-column
            v-if="narrow"
            :label="$t('dailyReview.workspace.col.reference')"
            width="130"
          >
            <template #default="{ row }">
              <div
                class="dr-ref"
                data-test="dr-pending-reference"
              >
                <span>{{ $t('dailyReview.workspace.refLogin', { n: countText(row.counts?.login_failures, row.counts?.login_failures_source) }) }}</span>
                <span>{{ $t('dailyReview.workspace.refHigh', { n: countText(row.counts?.high_risk_ops, row.counts?.high_risk_ops_source) }) }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('dailyReview.workspace.col.action')"
            width="120"
          >
            <template #default="{ row }">
              <el-button
                v-if="canSign && pendingAlertCount(row) > 0"
                type="primary"
                size="small"
                data-test="dr-pending-action"
                @click="openDay(row.date)"
              >
                {{ $t('dailyReview.workspace.actionHandleAlerts') }}
              </el-button>
              <el-button
                v-else-if="canSign"
                size="small"
                data-test="dr-pending-action"
                @click="openDay(row.date)"
              >
                {{ row.overdue ? $t('dailyReview.workspace.actionLate') : $t('dailyReview.workspace.actionSign') }}
              </el-button>
              <el-button
                v-else
                link
                type="primary"
                data-test="dr-pending-action"
                @click="openDay(row.date)"
              >
                {{ $t('dailyReview.workspace.actionView') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
        <div
          v-if="pendingTotal > PENDING_PAGE_SIZE"
          class="pagination"
        >
          <el-pagination
            v-model:current-page="pendingPage"
            :page-size="PENDING_PAGE_SIZE"
            :total="pendingTotal"
            layout="total, prev, pager, next"
            @current-change="loadPending"
          />
        </div>
      </div>
    </template>

    <DailyReviewSignedTable
      ref="signedRef"
      :active-timezone="activeTimezone"
      @open="openDay"
    />

    <DailyReviewDrawer
      ref="drawerRef"
      v-model="drawerOpen"
      :can-sign="canSign"
      @changed="refreshAfterChange"
      @open-alert-batch="openDayBatch"
    />

    <!-- 告警處置：單日抽屜與跨日處置共用一個對話框，一次請求送出 -->
    <AlertBatchReviewDialog
      v-if="canSign"
      ref="alertDialogRef"
      surface="daily-review-alerts"
      :current-user-id="currentUserId"
      :label-for="alertLabel"
      :result-note="alertResultNote"
      :next-text="alertNextText"
      :back-text="alertNextText ? $t('dailyReview.workspace.cross.back') : ''"
      @settled="onAlertBatchSettled"
      @next="openMultiAfterCross"
    />

    <!-- 多日簽核：逐日呼叫單日簽核端點（非原子），結果逐日列出 -->
    <DailyReviewMultiSignDialog
      v-if="canSign"
      ref="multiDialogRef"
      :selected="selection.selected.value"
      :current-user-id="currentUserId"
      @view="(date) => drawerRef?.openDay(date, { readOnlyFromBatch: true })"
      @settled="onMultiSettled"
      @finished="onMultiFinished"
    />
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { CircleCheck } from 'lucide-vue-next'
import { ElMessage } from 'element-plus'
import { t } from '@/i18n'
import { getDailyReviewDay, getDailyReviewPending, getDailyReviewStatus } from '@/api/dailyReviews'
import { useBatchSelection } from '@/composables/useBatchReview'
import { useRoles } from '@/composables/useRoles'
import BatchSelectionBar from '@/components/batch-review/BatchSelectionBar.vue'
import BatchCheckbox from '@/components/batch-review/BatchCheckbox.vue'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import DailyReviewStats from './DailyReviewStats.vue'
import DailyReviewSignedTable from './DailyReviewSignedTable.vue'
import DailyReviewDrawer from './DailyReviewDrawer.vue'
import DailyReviewMultiSignDialog from './DailyReviewMultiSignDialog.vue'
import AlertBatchReviewDialog from '@/components/batch-review/AlertBatchReviewDialog.vue'
import { alertTargetText, isSystemAlert, userLabel } from '@/components/batch-review/alertBulk'
import {
  DAILY_REVIEWS_CHANGED,
  countText,
  dateWithWeekday,
  isInferredBasis,
  isReviewDate,
  lastMinuteBefore,
  notifyDailyReviewsChanged,
  timeInZone,
} from './dailyReviewFormat'
import { PENDING_PAGE_SIZE, dayKey, isDaySelectable, pendingAlertCount } from './multiSign'

const props = defineProps({
  // 有簽核權限（alert:manage）；沒有時版面唯讀、動作為「查看」
  canSign: { type: Boolean, default: false },
  canOpenPolicies: { type: Boolean, default: false },
  // 網址帶入的所屬日：直接開該日抽屜
  openDate: { type: String, default: '' },
})

const router = useRouter()

const status = ref(null)
const pending = ref([])
const pendingTotal = ref(0)
const pendingPage = ref(1)
const pendingLoading = ref(false)
const statsRef = ref(null)
const signedRef = ref(null)
const drawerRef = ref(null)
const drawerOpen = ref(false)
const multiDialogRef = ref(null)
// currentUserId 只用來辨認「上一批是不是自己的」，不是授權
const { currentUserId } = useRoles()

// --- 多日勾選：以所屬日為識別，跨分頁保留，上限沿用既有批次功能。
// 有未審閱告警的日子也可以勾（先一起處置告警，處置完才能簽核）---
const selection = useBatchSelection({ keyOf: dayKey })
// 已勾選的日子即使之後變成不可勾，也要能取消勾選
const canToggleDay = (row) => selection.isSelected(row) || selection.canToggle(row, isDaySelectable)
const pageSelectState = computed(() => selection.pageState(pending.value, isDaySelectable))
const dayBlockedText = (row) => {
  if (row.signable === false) {
    return t('dailyReview.workspace.multi.blockedSettling', { time: timeInZone(row.signable_at, row.timezone) })
  }
  if (selection.atLimit.value && !selection.isSelected(row)) {
    return t('dailyReview.workspace.multi.blockedLimit', { limit: selection.limit })
  }
  return ''
}
// 所屬日下方的說明：有告警的日子寫筆數，其餘寫不能勾選的原因
const dayNoteText = (row) => {
  const n = pendingAlertCount(row)
  if (n > 0) return t('dailyReview.workspace.cross.dayNote', { n })
  return dayBlockedText(row)
}
const selectedAlertDays = computed(() => selection.selected.value.filter((row) => pendingAlertCount(row) > 0))
const selectedAlertTotal = computed(() => selectedAlertDays.value.reduce((sum, row) => sum + pendingAlertCount(row), 0))
const batchCountText = computed(() => {
  const picked = selection.selected.value
  const late = picked.filter((row) => row.overdue).length
  const onTime = picked.length - late
  let breakdown
  if (late && onTime) breakdown = t('dailyReview.workspace.multi.breakdownMixed', { late, onTime })
  else if (late) breakdown = t('dailyReview.workspace.multi.breakdownLate', { late })
  else breakdown = t('dailyReview.workspace.multi.breakdownOnTime', { onTime })
  const parts = [t('dailyReview.workspace.multi.selected', { n: picked.length }) + breakdown]
  const pageDates = new Set(pending.value.map(dayKey))
  const elsewhere = picked.filter((row) => !pageDates.has(dayKey(row))).length
  if (elsewhere) parts.push(t('dailyReview.workspace.multi.otherPages', { n: elsewhere }))
  return parts.join(' ')
})
const batchLimitText = computed(() => {
  const parts = []
  if (selectedAlertDays.value.length) {
    parts.push(t('dailyReview.workspace.cross.barAlerts', { a: selectedAlertDays.value.length, n: selectedAlertTotal.value }))
  }
  if (selection.atLimit.value || selection.truncated.value) {
    parts.push(t('dailyReview.workspace.multi.limitHint', { limit: selection.limit }))
  }
  return parts.join(' ')
})

// --- 窄視窗（1280 以下）：供查閱的兩欄合併，動作不需橫捲 ---
const NARROW_QUERY = '(max-width: 1279px)'
const narrow = ref(false)
let narrowMql = null
const onNarrowChange = () => { narrow.value = Boolean(narrowMql?.matches) }

// --- 告警處置對話框（單日抽屜與跨日共用） ---
const alertDialogRef = ref(null)
// 這一次處置的情境：day＝抽屜的單日；cross＝待簽清單勾選的多天
const alertContext = ref(null)
const crossLoading = ref(false)
const crossDone = ref({ clear: 0, still: 0 })

const alertLabel = (row) => {
  const time = timeInZone(row.triggered_at, row._tz)
  const parts = [row._day && alertContext.value?.kind === 'cross' ? `${row._day.slice(5)} ${time}` : time, userLabel(row, currentUserId.value)]
  const target = isSystemAlert(row) ? alertTargetText(row) : row.command || ''
  if (target) parts.push(isSystemAlert(row) ? t('dailyReview.drawer.alerts.target', { target }) : target)
  return parts.join('　')
}

function openDayBatch({ rows, date }) {
  const tz = drawerRef.value?.detail?.timezone
  alertContext.value = { kind: 'day', date }
  alertDialogRef.value?.open(rows.map((row) => ({ ...row, _day: date, _tz: tz })), { days: [date], dayOf: (r) => r._day })
}

// 跨日處置：逐日讀單日明細（所選至多上限天數，循序讀），合併後依類型排序
async function openCrossDay() {
  const dates = selectedAlertDays.value.map(dayKey).sort()
  if (!dates.length) return
  crossLoading.value = true
  try {
    const merged = []
    for (const date of dates) {
      const res = await getDailyReviewDay(date)
      const detail = res?.data || {}
      for (const row of detail.unreviewed_alerts || []) merged.push({ ...row, _day: date, _tz: detail.timezone })
    }
    if (!merged.length) {
      await refresh()
      return
    }
    // 清單順序＝所屬日由早到晚、同日依觸發時間（超過單次上限時，這一次處置的是前面的）
    const ordered = merged
    const days = [...new Set(merged.map((row) => row._day))]
    alertContext.value = { kind: 'cross', dates }
    crossDone.value = { clear: 0, still: 0 }
    alertDialogRef.value?.open(ordered, { days, dayOf: (r) => r._day })
  } catch (error) {
    console.error('載入所選日子的告警失敗:', error?.response?.status)
    ElMessage.error(t('dailyReview.workspace.cross.loadFailed'))
  } finally {
    crossLoading.value = false
  }
}

async function onAlertBatchSettled() {
  notifyDailyReviewsChanged()
  const ctx = alertContext.value
  if (ctx?.kind === 'day' && drawerOpen.value && drawerRef.value?.date === ctx.date) {
    await drawerRef.value.afterAlertBatch()
  }
  await refresh()
  if (ctx?.kind === 'cross') {
    // 勾選的日子換成重取後的列（簽核確認會再重取一次）
    const fresh = new Map(pending.value.map((row) => [row.date, row]))
    const picked = selection.selected.value.map((row) => fresh.get(row.date) || row)
    selection.selected.value = picked
    const alertDays = ctx.dates.map((d) => fresh.get(d)).filter(Boolean)
    crossDone.value = {
      clear: alertDays.filter((row) => pendingAlertCount(row) === 0).length,
      still: alertDays.filter((row) => pendingAlertCount(row) > 0).length,
    }
  }
}

const alertResultNote = computed(() => {
  const ctx = alertContext.value
  if (ctx?.kind === 'day') {
    const d = drawerRef.value?.detail
    return d && d.date === ctx.date && (d.unreviewed_alerts || []).length === 0 ? t('alerts.bulk.dayDone') : ''
  }
  if (ctx?.kind === 'cross' && crossSignable.value.length) {
    const picked = crossSignable.value
    const late = picked.filter((row) => row.overdue).length
    const text = t('dailyReview.workspace.cross.done', { a: crossDone.value.clear, d: picked.length, l: late, o: picked.length - late })
    return crossDone.value.still ? `${text}${t('dailyReview.workspace.cross.stillAlerts', { n: crossDone.value.still })}` : text
  }
  return ''
})
// 跨日處置後可以接著簽核的日子：勾選中、已沒有未審閱告警、可簽
const crossSignable = computed(() => selection.selected.value.filter((row) => row.signable === true && pendingAlertCount(row) === 0))
const alertNextText = computed(() => (alertContext.value?.kind === 'cross' && crossSignable.value.length
  ? t('dailyReview.workspace.cross.next', { d: crossSignable.value.length })
  : ''))

// 接著簽核：只帶已沒有未審閱告警的日子進入多日簽核的確認（確認框仍會逐日重取）
async function openMultiAfterCross() {
  selection.selected.value = crossSignable.value
  alertContext.value = null
  // 等勾選傳進確認框後再開（確認框以傳入的日子重取）
  await nextTick()
  multiDialogRef.value?.open()
}

const overdueCount = computed(() => status.value?.overdue_count ?? pending.value.filter((p) => p.overdue).length)
// 目前生效的切日時區：已簽紀錄據此判斷「當時以別的時區切日」要不要加註
const activeTimezone = computed(() => status.value?.timezone_state?.active || '')

async function loadStatus() {
  try {
    const res = await getDailyReviewStatus()
    status.value = res?.data || { enabled: false }
  } catch (error) {
    console.error('載入每日簽核狀態失敗:', error)
  }
}

async function loadPending() {
  pendingLoading.value = true
  try {
    const res = await getDailyReviewPending({ page: pendingPage.value, page_size: PENDING_PAGE_SIZE })
    pending.value = res?.data?.items || []
    pendingTotal.value = Number(res?.data?.total) || 0
    // 簽掉幾天後原本的最後一頁可能變空：回到最後一個有效頁
    const lastPage = Math.max(1, Math.ceil(pendingTotal.value / PENDING_PAGE_SIZE))
    if (!pending.value.length && pendingPage.value > lastPage) {
      pendingPage.value = lastPage
      const again = await getDailyReviewPending({ page: lastPage, page_size: PENDING_PAGE_SIZE })
      pending.value = again?.data?.items || []
      pendingTotal.value = Number(again?.data?.total) || 0
    }
  } catch (error) {
    console.error('載入待簽日失敗:', error)
  } finally {
    pendingLoading.value = false
  }
}

async function refresh() {
  await Promise.all([loadStatus(), loadPending(), signedRef.value?.load(), statsRef.value?.load()])
}

// 抽屜內簽核或處置告警後：清單、統計、已簽紀錄同步（徽章由事件重算）
async function refreshAfterChange() {
  await refresh()
}

function openDay(date) {
  drawerRef.value?.openDay(date)
}

// 多日簽核的逐日結果一出現：勾選已送出，清掉；清單、統計、已簽紀錄與徽章立刻重取，
// 不等使用者按「完成」
async function onMultiSettled() {
  selection.clear()
  notifyDailyReviewsChanged()
  await refresh()
}

// 按「完成」：提示這一批簽了幾天、還有幾天待簽（清單已在結果出現時重取）
function onMultiFinished(summary) {
  if (!summary) return
  const failed = summary.rejected + summary.notSent + summary.unconfirmed
  const head = failed
    ? t('dailyReview.multi.toastPartial', { n: summary.success, k: failed })
    : t('dailyReview.multi.toastDone', { n: summary.success })
  const remaining = pendingTotal.value
  const tail = remaining > 0
    ? t('dailyReview.drawer.result.remaining', { n: remaining })
    : t('dailyReview.drawer.result.noneLeft')
  ElMessage({ type: failed ? 'warning' : 'success', message: `${head}${tail}` })
}

// 別處（例如側欄）造成的變動也同步；自己派的事件已由 changed 處理，重複無害
const onExternalChange = () => {
  if (!drawerOpen.value) void loadPending()
}

watch(
  () => props.openDate,
  (date) => {
    if (isReviewDate(date)) openDay(date)
  },
  { flush: 'post' }
)

onMounted(() => {
  if (typeof window.matchMedia === 'function') {
    narrowMql = window.matchMedia(NARROW_QUERY)
    onNarrowChange()
    narrowMql.addEventListener?.('change', onNarrowChange)
  }
  void loadStatus()
  void loadPending()
  if (isReviewDate(props.openDate)) openDay(props.openDate)
  window.addEventListener(DAILY_REVIEWS_CHANGED, onExternalChange)
})

onUnmounted(() => {
  narrowMql?.removeEventListener?.('change', onNarrowChange)
  window.removeEventListener(DAILY_REVIEWS_CHANGED, onExternalChange)
})

defineExpose({ refresh, openDay, closeDrawer: () => { drawerOpen.value = false } })
</script>

<style scoped>
.dr-workspace {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.dr-section-head {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: var(--ot-space-xs) var(--ot-space-md);
}

.dr-blocked {
  margin-top: 2px;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-warning);
}

.dr-section-title {
  margin: var(--ot-space-sm) 0 0;
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-notice {
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-primary);
}

.dr-notice--warning {
  border-color: var(--ot-warning);
  background-color: color-mix(in srgb, var(--ot-warning) 10%, transparent);
}

.dr-notice--info {
  border-color: var(--ot-info);
  background-color: color-mix(in srgb, var(--ot-info) 10%, transparent);
}

.dr-empty {
  padding: var(--ot-space-lg) var(--ot-space-md);
  text-align: center;
  border: 1px dashed var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.dr-empty__title {
  margin: var(--ot-space-xs) 0;
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-empty__ok {
  color: var(--ot-success);
}

.dr-date {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs) var(--ot-space-sm);
}

.dr-sub {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.dr-warn {
  color: var(--ot-warning);
}

/* 窄欄換行時在標點與空白處斷開，不把「補簽」拆開 */
.dr-deadline {
  word-break: keep-all;
}

.dr-ref {
  display: flex;
  flex-direction: column;
  font-size: var(--ot-font-size-sm);
  line-height: 1.5;
}

.list-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.pagination {
  margin-top: var(--ot-space-md);
  display: flex;
  justify-content: flex-end;
}
</style>
