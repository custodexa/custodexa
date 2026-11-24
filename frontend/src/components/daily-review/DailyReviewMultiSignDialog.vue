<template>
  <!-- 多日簽核：先確認與填寫（逐日列出計數），送出後同一個對話框切到逐日進度，
       再切到結果。每一天各呼叫一次既有的單日簽核端點，不是一次完成的動作 -->
  <el-dialog
    :model-value="visible"
    data-test="dr-multi-dialog"
    :title="title"
    width="760px"
    class="mds-dialog"
    :top="`${CONFIRM_DIALOG_GAP}px`"
    :close-on-click-modal="false"
    :close-on-press-escape="phase === 'idle'"
    :show-close="phase === 'idle'"
    @update:model-value="(value) => { if (!value) formOpen = false }"
    @opened="fitList"
  >
    <div
      ref="bodyRef"
      class="mds-body"
    >
      <template v-if="phase === 'idle'">
        <p
          v-if="refetching"
          class="mds-hint"
          data-test="dr-multi-refetching"
        >
          {{ $t('dailyReview.multi.loading') }}
        </p>
        <p
          v-else-if="refetchError"
          class="mds-error"
          data-test="dr-multi-refetch-error"
        >
          {{ $t('dailyReview.multi.loadFailed') }}
        </p>
        <template v-else>
          <div
            v-if="removed.length"
            class="mds-banner mds-banner--warning"
            data-test="dr-multi-removed"
          >
            <div>{{ $t('dailyReview.multi.removedTitle', { n: removed.length }) }}</div>
            <ul class="mds-removed">
              <li
                v-for="item in removed"
                :key="item.date"
                data-test="dr-multi-removed-item"
                :data-date="item.date"
              >
                {{ item.text }}
              </li>
            </ul>
          </div>
          <p
            v-if="!days.length"
            class="mds-hint"
            data-test="dr-multi-all-removed"
          >
            {{ $t('dailyReview.multi.removedAll') }}
          </p>
          <template v-else>
            <p class="mds-intro">
              {{ $t('dailyReview.multi.intro') }}
            </p>
            <p
              class="mds-hint"
              data-test="dr-multi-as-of"
            >
              {{ $t('dailyReview.multi.asOf', { time: asOfText }) }}
            </p>
            <el-table
              ref="tableRef"
              :data="days"
              :max-height="listMaxHeight"
              size="small"
              data-test="dr-multi-table"
              style="width: 100%"
            >
              <el-table-column
                :label="$t('dailyReview.workspace.col.date')"
                min-width="140"
              >
                <template #default="{ row }">
                  <span data-test="dr-multi-date">{{ dateWithWeekday(row.date) }}</span>
                </template>
              </el-table-column>
              <el-table-column
                :label="$t('dailyReview.workspace.col.type')"
                min-width="130"
              >
                <template #default="{ row }">
                  <el-tag
                    v-if="row.overdue"
                    size="small"
                    type="warning"
                    data-test="dr-multi-type"
                  >
                    {{ $t('dailyReview.workspace.typeLate', { n: row.late_days }) }}
                  </el-tag>
                  <el-tag
                    v-else
                    size="small"
                    type="success"
                    data-test="dr-multi-type"
                  >
                    {{ $t('dailyReview.workspace.typeOnTime') }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column
                :label="$t('common.loginFailures')"
                min-width="96"
              >
                <template #default="{ row }">
                  <span data-test="dr-multi-login">{{ countText(row.counts?.login_failures, row.counts?.login_failures_source) }}</span>
                </template>
              </el-table-column>
              <el-table-column
                :label="$t('common.unreviewedAlerts')"
                min-width="96"
              >
                <template #default="{ row }">
                  <span data-test="dr-multi-alerts">{{ countText(row.counts?.unreviewed_alerts, row.counts?.alerts_source) }}</span>
                </template>
              </el-table-column>
              <el-table-column
                :label="$t('common.highRiskOps')"
                min-width="96"
              >
                <template #default="{ row }">
                  <span data-test="dr-multi-high">{{ countText(row.counts?.high_risk_ops, row.counts?.high_risk_ops_source) }}</span>
                </template>
              </el-table-column>
              <el-table-column
                width="110"
                align="right"
              >
                <template #default="{ row }">
                  <el-button
                    link
                    type="primary"
                    data-test="dr-multi-view"
                    @click="$emit('view', row.date)"
                  >
                    {{ $t('dailyReview.multi.viewDetail') }}
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
            <p
              v-if="days.length > LIST_SCROLL_AT"
              class="mds-hint"
              data-test="dr-multi-list-count"
            >
              {{ $t('dailyReview.multi.listCount', { n: days.length }) }}
            </p>
            <p
              v-if="purgedDates.length || partialDates.length"
              class="mds-hint"
              data-test="dr-multi-source-note"
            >
              <template v-if="purgedDates.length">
                {{ $t('dailyReview.multi.sourcePurged', { dates: purgedDates.join('、') }) }}
              </template>
              <template v-if="partialDates.length">
                {{ $t('dailyReview.multi.sourcePartial', { dates: partialDates.join('、') }) }}
              </template>
              {{ $t('dailyReview.multi.sourceSeeDetail') }}
            </p>
            <div
              v-if="lateDays.length"
              class="mds-banner mds-banner--warning mds-banner--icon"
              data-test="dr-multi-late-notice"
            >
              <TriangleAlert
                class="mds-banner__icon"
                aria-hidden="true"
                data-test="dr-multi-late-icon"
              />
              <span>{{ $t('dailyReview.multi.lateNotice', { n: lateDays.length }) }}</span>
            </div>

            <div class="mds-form">
              <template v-if="lateDays.length">
                <label
                  class="mds-label"
                  for="mds-delay"
                  data-test="dr-multi-delay-label"
                ><span
                  class="mds-required"
                  aria-hidden="true"
                  data-test="dr-multi-delay-required"
                >*</span>{{ delayLabel.main }}<span
                  v-if="delayLabel.aside"
                  class="mds-label__aside"
                >{{ delayLabel.aside }}</span></label>
                <div data-test="dr-multi-delay">
                  <el-input
                    id="mds-delay"
                    v-model="form.delayReason"
                    type="textarea"
                    :rows="3"
                    :maxlength="TEXT_MAX"
                    show-word-limit
                    :placeholder="$t('dailyReview.multi.delayPlaceholder')"
                    :class="{ 'mds-input--error': delayError }"
                    @input="delayError = false"
                  />
                </div>
                <p
                  v-if="delayError"
                  class="mds-error"
                  data-test="dr-multi-delay-error"
                >
                  {{ $t('dailyReview.drawer.delayRequired') }}
                </p>
                <p class="mds-hint">
                  {{ $t('dailyReview.drawer.delayWrittenTo') }}
                  <template v-if="purgedDates.length">
                    {{ $t('dailyReview.drawer.purgedDelayHint') }}
                  </template>
                  <template v-if="onTimeDays.length">
                    {{ $t('dailyReview.multi.delayOnTimeNote', { date: onTimeDays.map((d) => d.date).join('、') }) }}
                  </template>
                </p>
              </template>
              <label
                class="mds-label"
                for="mds-note"
              >{{ noteLabel.main }}<span
                v-if="noteLabel.aside"
                class="mds-label__aside"
              >{{ noteLabel.aside }}</span></label>
              <div data-test="dr-multi-note">
                <el-input
                  id="mds-note"
                  v-model="form.note"
                  type="textarea"
                  :rows="2"
                  :maxlength="TEXT_MAX"
                  show-word-limit
                />
              </div>
            </div>
            <p class="mds-hint">
              {{ $t('dailyReview.multi.partialHint') }}
            </p>
            <p class="mds-hint">
              {{ $t('dailyReview.drawer.signedAtNote') }}
            </p>
          </template>
        </template>
      </template>

      <template v-else>
        <p
          v-if="recovered && phase !== 'running'"
          class="mds-hint"
          data-test="dr-multi-recovered"
        >
          {{ $t('dailyReview.multi.recoveredLead') }}
        </p>
        <!-- 結果摘要與「沒簽成的日子」放在逐日清單上方（畫稿 Q-3）：50 天時不必捲到清單底
             才看得到哪幾天沒簽成。摘要由這裡呈現（常駐的 live region），共用清單不再印一次 -->
        <div
          class="mds-result-head"
          :class="{ 'mds-result-head--empty': phase !== 'result' }"
        >
          <p
            class="mds-summary"
            data-test="dr-multi-summary"
            aria-live="polite"
          >
            {{ phase === 'result' ? $t('dailyReview.multi.summary', summary) : '' }}
          </p>
          <p
            v-if="phase === 'result' && notDoneText"
            class="mds-not-done"
            data-test="dr-multi-not-done"
          >
            {{ notDoneText }}
          </p>
        </div>
        <BatchProgressList
          :phase="phase"
          :items="items"
          :progress-text="$t('dailyReview.multi.progress', { i: current, n: total })"
          summary-text=""
          :checking-text="$t('alerts.batch.checking')"
          :describe="describe"
        />
        <template v-if="phase === 'result'">
          <p
            v-if="hints.unconfirmed"
            class="mds-hint"
            data-test="dr-multi-unconfirmed-hint"
          >
            {{ $t('dailyReview.multi.unconfirmedHint') }}
          </p>
          <p
            v-if="hints.noneFound"
            class="mds-hint"
            data-test="dr-multi-none-found-hint"
          >
            {{ $t('dailyReview.multi.noneFoundHint') }}
          </p>
          <p
            v-if="hints.other"
            class="mds-hint"
            data-test="dr-multi-leftover-other"
          >
            {{ $t('dailyReview.multi.leftoverOther') }}
          </p>
          <p
            v-if="hints.alerts"
            class="mds-hint"
            data-test="dr-multi-leftover-alerts"
          >
            {{ $t('dailyReview.multi.leftoverAlerts') }}
          </p>
          <p
            v-if="summary.notSent"
            class="mds-hint"
            data-test="dr-multi-leftover-not-sent"
          >
            {{ $t('dailyReview.multi.leftoverNotSent') }}
          </p>
          <p
            class="mds-hint"
            data-test="dr-multi-refreshed"
          >
            {{ $t('dailyReview.multi.refreshedNote') }}
          </p>
        </template>
      </template>
    </div>
    <template #footer>
      <template v-if="phase === 'idle'">
        <el-button
          data-test="dr-multi-cancel"
          @click="formOpen = false"
        >
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          v-preview-write
          type="primary"
          data-test="dr-multi-submit"
          :disabled="!canSubmit"
          @click="submit"
        >
          {{ $t('dailyReview.multi.submit', { n: days.length }) }}
        </el-button>
      </template>
      <template v-else-if="phase === 'result'">
        <el-button
          v-if="summary.unconfirmed"
          data-test="dr-multi-recheck"
          @click="recheck"
        >
          {{ $t('alerts.batch.recheck') }}
        </el-button>
        <el-button
          type="primary"
          data-test="dr-multi-done"
          @click="done"
        >
          {{ $t('alerts.batch.done') }}
        </el-button>
      </template>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { TriangleAlert } from 'lucide-vue-next'
import { t } from '@/i18n'
import { getDailyReviewDay, signDailyReview } from '@/api/dailyReviews'
import { BATCH_STATE, classifyBatchError, useBatchReview } from '@/composables/useBatchReview'
import BatchProgressList from '@/components/batch-review/BatchProgressList.vue'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import { countText, dateWithWeekday, formatInZone, timeInZone } from './dailyReviewFormat'
import {
  CONFIRM_DIALOG_GAP,
  CONFIRM_LIST_MAX_HEIGHT,
  MULTI_SIGN_SURFACE,
  fetchPendingDays,
  fitListHeight,
  isDaySignable,
  pendingAlertCount,
} from './multiSign'

const TEXT_MAX = 500
// 清單超過這個天數時對話框內需要捲動：補一行總數，結果另列沒簽成的日子
const LIST_SCROLL_AT = 8
const CODE_ALREADY_SIGNED = 'CONFLICT_DAILY_REVIEW_SIGNED'
const CODE_ALERTS_PENDING = 'RULE_DAILY_REVIEW_ALERTS_PENDING'

const props = defineProps({
  // 勾選的待簽日（勾選當下的列；開啟確認時會重取）
  selected: { type: Array, required: true },
  currentUserId: { type: Number, default: null },
})
// settled：逐日結果已出現（呼叫端此時就重取清單、統計與徽章）；finished：使用者按「完成」；
// view：從確認清單查看某一天的明細（唯讀）
const emit = defineEmits(['settled', 'finished', 'view'])

const formOpen = ref(false)
const refetching = ref(false)
const refetchError = ref(false)
const days = ref([])
const removed = ref([])
const form = ref({ delayReason: '', note: '' })
const delayError = ref(false)
const recovered = ref(false)
const asOf = ref('')
const bodyRef = ref(null)
const tableRef = ref(null)
const listMaxHeight = ref(CONFIRM_LIST_MAX_HEIGHT)
let openSeq = 0

// 欄位標題拆成主名稱與括號說明：括號說明用次要字色。三語都以全形或半形括號開頭
const splitLabel = (text) => {
  const m = /^(.*?)(\s*[（(][\s\S]*)$/.exec(text)
  return m ? { main: m[1], aside: m[2] } : { main: text, aside: '' }
}

const userId = computed(() => props.currentUserId)

// 重新查詢：讀該日的簽核紀錄。本人簽的記成功、別人簽的記被拒並寫明對方，
// 查無紀錄維持待確認（不改寫成未送出：沒有回應不等於沒有送到）
const reconcile = async (entry) => {
  const pending = entry.items.filter((item) => item.state === BATCH_STATE.UNCONFIRMED)
  const updates = {}
  for (const item of pending) {
    let detail = null
    try {
      const res = await getDailyReviewDay(item.id, { skipErrorToast: true })
      detail = res?.data || null
    } catch {
      continue // 查不到：維持待確認
    }
    const review = detail?.review
    if (detail?.status === 'signed' && review) {
      const time = formatInZone(review.signed_at, review.timezone, { seconds: true })
      updates[item.id] = review.reviewer_id === entry.userId
        ? { state: BATCH_STATE.SUCCESS, late: Boolean(review.late), lateDays: review.late_days || 0, signedAt: time, rechecked: true }
        : { state: BATCH_STATE.REJECTED, code: CODE_ALREADY_SIGNED, params: { signer: review.reviewer_name, time } }
    } else {
      updates[item.id] = { state: BATCH_STATE.UNCONFIRMED, notFound: true }
    }
  }
  return updates
}

const { phase, items, current, total, summary, run, recover, recheck, finish } =
  useBatchReview({ surface: MULTI_SIGN_SURFACE, userId, reconcile })

const visible = computed(() => formOpen.value || phase.value !== 'idle')

watch(phase, (next) => {
  if (next === 'result') emit('settled')
})

const title = computed(() => {
  if (phase.value === 'idle') return t('dailyReview.multi.dialogTitle', { n: days.value.length })
  if (phase.value === 'running') return t('dailyReview.multi.runningTitle', { n: total.value })
  return t('dailyReview.multi.resultTitle')
})

const lateDays = computed(() => days.value.filter((d) => d.overdue))
const onTimeDays = computed(() => days.value.filter((d) => !d.overdue))
const sourcesOf = (d) => {
  const c = d.counts || {}
  return [c.login_failures_source, c.alerts_source, c.high_risk_ops_source]
}
const purgedDates = computed(() => days.value.filter((d) => sourcesOf(d).includes('purged')).map((d) => d.date))
const partialDates = computed(() => days.value
  .filter((d) => !sourcesOf(d).includes('purged') && sourcesOf(d).includes('partial'))
  .map((d) => d.date))
const asOfText = computed(() => timeInZone(asOf.value, days.value[0]?.timezone))

// 結果畫面依實際出現的種類給下一步
const hints = computed(() => {
  const list = items.value
  const rejectedWith = (code) => list.some((i) => i.state === BATCH_STATE.REJECTED && i.code === code)
  return {
    unconfirmed: list.some((i) => i.state === BATCH_STATE.UNCONFIRMED && !i.notFound),
    noneFound: list.some((i) => i.state === BATCH_STATE.UNCONFIRMED && i.notFound),
    other: rejectedWith(CODE_ALREADY_SIGNED),
    alerts: rejectedWith(CODE_ALERTS_PENDING),
  }
})
const notDoneText = computed(() => {
  if (total.value <= LIST_SCROLL_AT) return ''
  const left = items.value.filter((i) => i.state !== BATCH_STATE.SUCCESS)
  if (!left.length) return ''
  // 日期與狀態的組合與分隔符依語言（英文用半形括號與逗號）
  const list = left
    .map((i) => t('dailyReview.multi.notDoneItem', { date: i.id, state: t(`dailyReview.multi.stateWord.${i.state}`) }))
    .join(t('common.listSeparator'))
  return t('dailyReview.multi.notDoneList', { list })
})
const canSubmit = computed(() => !refetching.value && !refetchError.value && days.value.length > 0)
const delayLabel = computed(() => splitLabel(t('dailyReview.multi.delayLabel', { n: lateDays.value.length })))
const noteLabel = computed(() => splitLabel(t('dailyReview.multi.noteLabel')))

// 依視窗高度收放逐日清單，讓延遲原因、備註與按鈕留在視窗內（處置 8）。
// 量的是清單以外的高度（對話框高度扣掉清單高度），所以清單收放本身不影響結果
async function fitList() {
  await nextTick()
  if (!formOpen.value || phase.value !== 'idle') return
  const dialogEl = bodyRef.value?.closest('.el-dialog')
  const tableEl = tableRef.value?.$el
  if (!dialogEl || !tableEl) return
  listMaxHeight.value = fitListHeight({
    viewport: window.innerHeight,
    dialogHeight: dialogEl.offsetHeight,
    listHeight: tableEl.offsetHeight,
  })
}
watch([days, removed, delayError, refetching, formOpen], () => { void fitList() }, { flush: 'post' })
const onResize = () => { void fitList() }
onMounted(() => window.addEventListener('resize', onResize))
onBeforeUnmount(() => window.removeEventListener('resize', onResize))

const describe = (item) => {
  switch (item.state) {
    case BATCH_STATE.SUCCESS:
    {
      const result = item.late
        ? t('dailyReview.multi.signedLate', { n: item.lateDays || 0 })
        : t('dailyReview.multi.signedOnTime')
      return item.rechecked ? t('dailyReview.multi.signedBySelfAt', { result, time: item.signedAt || '' }) : result
    }
    case BATCH_STATE.REJECTED:
      if (item.code === CODE_ALREADY_SIGNED && item.params?.signer) {
        return t('dailyReview.multi.rejectedSignedBy', { signer: item.params.signer, time: item.params.time || '' })
      }
      if (item.code === CODE_ALERTS_PENDING && item.params?.count !== undefined) {
        return t('dailyReview.multi.rejectedAlerts', { n: item.params.count })
      }
      return t('alerts.batch.rejectedWith', { reason: item.reason || '' })
    case BATCH_STATE.NOT_SENT:
      return t('alerts.batch.state.notSent')
    case BATCH_STATE.UNCONFIRMED:
      return item.notFound ? t('dailyReview.multi.unconfirmedNone') : t('alerts.batch.state.unconfirmed')
    case BATCH_STATE.INFLIGHT:
      return t('alerts.batch.state.inflight')
    default:
      return t('alerts.batch.state.queued')
  }
}

// 已不在待簽清單的日子：查該日的簽核紀錄寫明誰在何時簽的；查不到紀錄時只說已不在清單
async function goneText(date) {
  try {
    const res = await getDailyReviewDay(date, { skipErrorToast: true })
    const review = res?.data?.status === 'signed' ? res.data.review : null
    if (review) {
      return t('dailyReview.multi.removedSigned', {
        date, signer: review.reviewer_name, time: formatInZone(review.signed_at, review.timezone, { seconds: true }),
      })
    }
  } catch {
    // 查不到：退回不指名的說法
  }
  return t('dailyReview.multi.removedGone', { date })
}

const removedText = (date, row) => {
  const n = pendingAlertCount(row)
  if (n > 0) return t('dailyReview.multi.removedAlerts', { date, n })
  return t('dailyReview.multi.removedSettling', { date, time: timeInZone(row.signable_at, row.timezone) })
}

// 開啟確認步驟時重取所選日子：已不在待簽清單或已變成不可簽的日子移出這一批，
// 取得前不能送出。不做版本比對：簽核紀錄記下的是受理當下重算的數字
async function refetch() {
  const seq = ++openSeq
  const dates = [...new Set(props.selected.map((row) => row.date))].sort()
  refetching.value = true
  refetchError.value = false
  days.value = []
  removed.value = []
  try {
    const found = await fetchPendingDays(dates)
    if (seq !== openSeq) return
    const keep = []
    const out = []
    for (const date of dates) {
      const row = found.get(date)
      if (row && isDaySignable(row)) keep.push(row)
      else out.push({ date, text: row ? removedText(date, row) : await goneText(date) })
    }
    if (seq !== openSeq) return
    asOf.value = new Date().toISOString()
    days.value = keep
    removed.value = out
  } catch {
    if (seq === openSeq) refetchError.value = true
  } finally {
    if (seq === openSeq) refetching.value = false
  }
}

function open() {
  if (phase.value !== 'idle' || !props.selected.length) return
  form.value = { delayReason: '', note: '' }
  delayError.value = false
  recovered.value = false
  formOpen.value = true
  void refetch()
}

async function submit() {
  if (!canSubmit.value) return
  const reason = form.value.delayReason.trim()
  if (lateDays.value.length && !reason) {
    delayError.value = true
    return // 一天都不送
  }
  const note = form.value.note.trim()
  const entries = days.value.map((row) => ({
    id: row.date,
    label: dateWithWeekday(row.date),
    late: Boolean(row.overdue),
    lateDays: row.late_days || 0,
  }))
  formOpen.value = false
  await run({
    kind: 'daily-review',
    params: {},
    entries,
    send: async (entry, batchId) => {
      const body = { review_date: entry.id, batch_id: batchId }
      if (note) body.note = note
      // 準時的日子不帶延遲原因
      if (entry.late) body.delay_reason = reason
      try {
        const res = await signDailyReview(body, { skipErrorToast: true })
        const row = res?.data || {}
        return { late: Boolean(row.late ?? entry.late), lateDays: entry.lateDays }
      } catch (error) {
        const outcome = classifyBatchError(error)
        // 沒有回應、逾時、5xx：交給執行器記為待確認
        if (outcome.state !== BATCH_STATE.REJECTED) throw error
        const params = error?.response?.data?.params || {}
        if (outcome.code === CODE_ALREADY_SIGNED) {
          return {
            ...outcome,
            params: { signer: params.signer || '', time: params.signed_at ? formatInZone(params.signed_at, params.timezone, { seconds: true }) : '' },
          }
        }
        return { ...outcome, params: { count: params.count } }
      }
    },
  })
}

function done() {
  const result = { ...summary.value }
  finish()
  recovered.value = false
  emit('finished', result)
}

// 重新載入同一個分頁後：顯示上一批的逐日結果並查詢實際狀態，不自動續送。
// 使用者身分還沒載入前不接手（避免把別人的批次當成自己的）
let recoverStarted = false
async function tryRecover() {
  if (recoverStarted || userId.value == null) return
  recoverStarted = true
  recovered.value = await recover()
}

watch(userId, () => { void tryRecover() })
onMounted(() => { void tryRecover() })

defineExpose({ open, refetch })
</script>

<style scoped>
.mds-body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

.mds-intro {
  margin: 0;
  line-height: 1.6;
}

.mds-hint {
  margin: 0;
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.mds-error {
  margin: 0;
  color: var(--ot-danger);
}

.mds-banner {
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  line-height: 1.6;
}

.mds-banner--warning {
  border-color: var(--ot-warning);
  background-color: color-mix(in srgb, var(--ot-warning) 10%, transparent);
}

.mds-removed {
  margin: var(--ot-space-xs) 0 0;
  padding-left: var(--ot-space-md);
}

.mds-form {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.mds-label {
  font-weight: 600;
}

.mds-input--error :deep(.el-textarea__inner) {
  box-shadow: 0 0 0 1px var(--ot-danger) inset;
}

.mds-banner--icon {
  display: flex;
  gap: var(--ot-space-sm);
  align-items: flex-start;
}

.mds-banner__icon {
  flex: none;
  width: 16px;
  height: 16px;
  margin-top: 0.2em;
  color: var(--ot-warning);
}

.mds-required {
  margin-right: 4px;
  color: var(--ot-danger);
}

.mds-label__aside {
  font-weight: 400;
  color: var(--ot-text-secondary);
}

.mds-result-head {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.mds-result-head--empty {
  display: none;
}

.mds-summary {
  margin: 0;
  font-size: var(--ot-font-size-md);
  font-weight: 600;
}

.mds-not-done {
  margin: 0;
  line-height: 1.6;
  color: var(--ot-warning);
}
</style>

<style>
/* el-dialog 的外框不在本元件的 scoped 範圍內：下緣留白與上緣（top）相同，
   清單高度的計算以上下各留 CONFIRM_DIALOG_GAP 為準 */
.el-dialog.mds-dialog {
  margin-bottom: 24px;
}
</style>
