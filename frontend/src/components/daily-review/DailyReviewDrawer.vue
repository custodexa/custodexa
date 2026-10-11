<template>
  <!-- 簽核抽屜：從待簽清單右側開啟，簽完在原處顯示結果與下一天，不離開清單。
       介面上停用按鈕只是提示，能不能簽最終由後端判定 -->
  <el-drawer
    :model-value="modelValue"
    size="560px"
    :with-header="false"
    append-to-body
    class="dr-drawer"
    data-test="dr-drawer"
    @update:model-value="(v) => $emit('update:modelValue', v)"
  >
    <div class="dr-drawer__body">
      <header class="dr-drawer__head">
        <div>
          <h2 class="dr-drawer__title">
            {{ headTitle }}
            <el-tag
              v-if="showLateTag"
              size="small"
              type="warning"
              data-test="dr-late-tag"
            >
              {{ $t('dailyReview.drawer.lateTag') }}
            </el-tag>
            <el-tag
              v-if="settling && mode === 'detail' && !isSigned"
              size="small"
              type="info"
            >
              {{ $t('dailyReview.drawer.settlingTag') }}
            </el-tag>
            <el-tag
              v-if="isInferredBasis(detail?.enabled_basis)"
              size="small"
              type="info"
            >
              {{ $t('dailyReview.enabledInferred.tag') }}
            </el-tag>
          </h2>
          <p
            v-if="detail?.window_start"
            class="dr-drawer__sub"
            data-test="dr-window"
          >
            {{ $t('dailyReview.drawer.windowLine', { window: windowText(detail.window_start, detail.window_end, detail.timezone) }) }}
            <template v-if="deadlineText">
              ・{{ deadlineText }}
            </template>
          </p>
        </div>
        <el-button
          text
          :aria-label="$t('dailyReview.drawer.close')"
          @click="close"
        >
          <el-icon><X /></el-icon>
        </el-button>
      </header>

      <div
        v-loading="loading"
        class="dr-drawer__content"
      >
        <p
          v-if="loadError"
          class="dr-drawer__error"
        >
          {{ $t('dailyReview.drawer.loadFailed') }}
        </p>

        <!-- 送出成功：結果與固化紀錄 -->
        <template v-if="mode === 'result' && resultRecord">
          <div
            class="dr-banner dr-banner--success dr-banner--icon"
            data-test="dr-result"
          >
            <CircleCheck
              :size="16"
              class="dr-banner__icon dr-banner__icon--success"
              aria-hidden="true"
              data-test="dr-result-icon"
            />
            <div>
              {{ resultRecord.late
                ? $t('dailyReview.drawer.result.late', { date: resultRecord.review_date })
                : $t('dailyReview.drawer.result.signed', { date: resultRecord.review_date }) }}
              {{ remainingText }}
            </div>
          </div>
          <DailyReviewRecord :record="resultRecord" />
        </template>

        <!-- 同一天已被他人簽核：說清楚這次沒存，改顯示對方的紀錄 -->
        <template v-else-if="mode === 'conflict'">
          <div
            class="dr-banner dr-banner--warning dr-banner--icon"
            data-test="dr-conflict"
          >
            <CircleAlert
              :size="16"
              class="dr-banner__icon dr-banner__icon--warning"
              aria-hidden="true"
              data-test="dr-conflict-icon"
            />
            <div>
              <div class="dr-banner__title">
                {{ $t('dailyReview.drawer.conflict.title', conflictText) }}
              </div>
              <div>{{ $t('dailyReview.drawer.conflict.body', conflictText) }} {{ remainingText }}</div>
            </div>
          </div>
          <DailyReviewRecord
            v-if="detail?.review"
            :record="detail.review"
          />
        </template>

        <template v-else-if="detail">
          <!-- 尚未結束／不在範圍：沒有可簽的內容 -->
          <p
            v-if="detail.status === 'not_ended' || detail.status === 'out_of_scope'"
            class="dr-drawer__plain"
            data-test="dr-not-signable"
          >
            {{ detail.status === 'not_ended'
              ? $t('dailyReview.drawer.notEnded', { date: detail.date })
              : $t('dailyReview.drawer.outOfScope', { date: detail.date }) }}
          </p>

          <template v-else>
            <div
              v-if="isInferredBasis(detail.enabled_basis)"
              class="dr-banner dr-banner--info"
              data-test="dr-inferred-notice"
            >
              <div class="dr-banner__title">
                {{ $t('dailyReview.enabledInferred.drawerTitle') }}
              </div>
              <div>{{ $t('dailyReview.enabledInferred.drawerNotice') }}</div>
              <div v-if="inferredReason(detail.enabled_basis)">
                {{ inferredReason(detail.enabled_basis) }}
              </div>
            </div>

            <!-- 已簽日：唯讀紀錄、簽核時與目前可查的對照 -->
            <template v-if="isSigned">
              <DailyReviewRecord
                v-if="detail.review"
                :record="detail.review"
                :show-counts="false"
              />
              <DailyReviewSignedCompare
                :signed-snapshot="detail.signed_snapshot || {}"
                :detail="detail"
                :legacy="detail.review?.coverage === 'until_signed'"
                @navigate="go"
              />
            </template>

            <template v-else>
              <div
                v-if="settling"
                class="dr-banner dr-banner--info"
                data-test="dr-settling"
              >
                <div class="dr-banner__title">
                  {{ $t('dailyReview.drawer.settlingTitle', { time: signableTime }) }}
                </div>
                <div>{{ $t('dailyReview.drawer.settlingBody', { date: detail.date }) }}</div>
              </div>
              <div
                v-if="sourceNotice"
                class="dr-banner dr-banner--warning"
                data-test="dr-source-notice"
              >
                {{ sourceNotice }}
              </div>
              <div
                v-if="willBeLate && canSign"
                class="dr-banner dr-banner--warning"
                data-test="dr-late-notice"
              >
                {{ $t('dailyReview.drawer.lateNotice', { due: dueText }) }}
              </div>

              <DailyReviewAlertsSection
                :alerts="alertsSource === 'purged' ? [] : (detail.unreviewed_alerts || [])"
                :source="alertsSource"
                :total="detail.counts?.alerts_total ?? 0"
                :benign="detail.counts?.alerts_benign ?? 0"
                :escalated="detail.counts?.alerts_escalated ?? 0"
                :timezone="detail.timezone"
                :can-sign="canSign"
                @reviewed="onAlertsReviewed"
              />
              <DailyReviewEventsSection
                kind="login_failures"
                :list="detail.login_failures || { total: 0, items: [] }"
                :count="detail.counts?.login_failures ?? null"
                :timezone="detail.timezone"
                :window-start="detail.window_start"
                :window-end="detail.window_end"
                @navigate="go"
              />
              <DailyReviewEventsSection
                kind="high_risk_ops"
                :list="detail.high_risk_ops || { total: 0, items: [] }"
                :count="detail.counts?.high_risk_ops ?? null"
                :timezone="detail.timezone"
                :window-start="detail.window_start"
                :window-end="detail.window_end"
                @navigate="go"
              />

              <!-- 簽核表單：只給有簽核權限的人 -->
              <div
                v-if="canSign"
                class="dr-form"
                data-test="dr-form"
              >
                <div class="dr-form__label">
                  {{ willBeLate ? $t('dailyReview.drawer.delayLabel') : $t('dailyReview.drawer.noteLabel') }}
                </div>
                <el-input
                  v-model="text"
                  type="textarea"
                  :rows="willBeLate ? 3 : 2"
                  :maxlength="TEXT_MAX"
                  show-word-limit
                  :class="{ 'dr-form__input--error': delayError }"
                  data-test="dr-text"
                  @input="delayError = false"
                />
                <p
                  v-if="delayError"
                  class="dr-form__error"
                  data-test="dr-delay-error"
                >
                  {{ $t('dailyReview.drawer.delayRequired') }}
                </p>
                <p
                  v-if="willBeLate"
                  class="dr-form__hint"
                >
                  {{ $t('dailyReview.drawer.delayWrittenTo') }}
                  <template v-if="alertsSource === 'purged' || logSource === 'purged'">
                    {{ $t('dailyReview.drawer.purgedDelayHint') }}
                  </template>
                  <template v-if="isInferredBasis(detail.enabled_basis)">
                    {{ $t('dailyReview.enabledInferred.delayHint') }}
                  </template>
                </p>
                <p class="dr-form__hint">
                  {{ $t('dailyReview.drawer.signedAtNote') }}
                </p>
              </div>
            </template>
          </template>
        </template>
      </div>

      <footer class="dr-drawer__foot">
        <template v-if="mode === 'result' || mode === 'conflict'">
          <el-button
            data-test="dr-back"
            @click="close"
          >
            {{ $t('dailyReview.drawer.back') }}
          </el-button>
          <el-button
            v-if="nextDate"
            type="primary"
            data-test="dr-next"
            @click="openDay(nextDate)"
          >
            {{ $t('dailyReview.drawer.next', { date: nextDate }) }}
          </el-button>
        </template>
        <template v-else-if="canSign && detail && !isSigned && signableStatus">
          <span
            v-if="blockText"
            class="dr-drawer__block"
            data-test="dr-block"
          >{{ blockText }}</span>
          <span
            v-else-if="!willBeLate"
            class="dr-drawer__hint"
          >{{ $t('dailyReview.drawer.onTimeHint') }}</span>
          <el-button
            type="primary"
            :loading="submitting"
            :disabled="signDisabled"
            data-test="dr-sign"
            @click="submit"
          >
            {{ willBeLate
              ? $t('dailyReview.drawer.lateButton', { date: detail.date })
              : $t('dailyReview.drawer.signButton', { date: detail.date }) }}
          </el-button>
        </template>
        <el-button
          v-else
          @click="close"
        >
          {{ $t('dailyReview.drawer.close') }}
        </el-button>
      </footer>
    </div>
  </el-drawer>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { CircleAlert, CircleCheck, X } from 'lucide-vue-next'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { getDailyReviewDay, getDailyReviewPending, signDailyReview } from '@/api/dailyReviews'
import DailyReviewAlertsSection from './DailyReviewAlertsSection.vue'
import DailyReviewEventsSection from './DailyReviewEventsSection.vue'
import DailyReviewRecord from './DailyReviewRecord.vue'
import DailyReviewSignedCompare from './DailyReviewSignedCompare.vue'
import {
  dateTimeInZone,
  dateWithWeekday,
  formatInZone,
  inferredReason,
  isInferredBasis,
  lastMinuteBefore,
  notifyDailyReviewsChanged,
  timeInZone,
  windowText,
} from './dailyReviewFormat'

const TEXT_MAX = 500

defineProps({
  modelValue: { type: Boolean, default: false },
  // 有簽核權限（alert:manage）才有處置、備註與簽核欄位
  canSign: { type: Boolean, default: false },
})

const emit = defineEmits(['update:modelValue', 'changed'])

const router = useRouter()

const date = ref('')
const detail = ref(null)
const loading = ref(false)
const loadError = ref(false)
// detail：明細與表單；result：送出成功；conflict：他人搶先簽核
const mode = ref('detail')
const resultRecord = ref(null)
const conflict = ref(null)
const text = ref('')
const delayError = ref(false)
// 後端判定已過準時期限（抽屜開著跨過期限的邊界情形）
const forceLate = ref(false)
// 後端回結算中時帶的可簽時刻
const settlingAt = ref('')
const submitting = ref(false)
const nextDate = ref('')
const remaining = ref(0)

const isSigned = computed(() => detail.value?.status === 'signed')
const signableStatus = computed(() => ['pending', 'settling'].includes(detail.value?.status))
const alertsSource = computed(() => detail.value?.sources?.command_alert || detail.value?.counts?.alerts_source || 'complete')
const logSource = computed(() => detail.value?.sources?.audit_log || 'complete')

const willBeLate = computed(() => {
  if (forceLate.value) return true
  const d = detail.value
  if (!d) return false
  if (d.overdue) return true
  const due = Date.parse(d.due_at)
  return Number.isFinite(due) && Date.now() >= due
})

const settling = computed(() => Boolean(settlingAt.value) || detail.value?.status === 'settling')
const signableTime = computed(() =>
  timeInZone(settlingAt.value || detail.value?.signable_at, detail.value?.timezone)
)

// 未審閱告警只能對現存的告警判定；來源已清除時不擋（後端同樣不擋）
const unreviewedCount = computed(() =>
  alertsSource.value === 'purged' ? 0 : (detail.value?.unreviewed_alerts || []).length
)

const blockText = computed(() => {
  if (settling.value) return t('dailyReview.drawer.settlingBlock', { time: signableTime.value })
  if (unreviewedCount.value > 0) return t('dailyReview.drawer.alertsBlock', { n: unreviewedCount.value })
  return ''
})

const signDisabled = computed(() => submitting.value || settling.value || unreviewedCount.value > 0)

const showLateTag = computed(() => {
  if (mode.value === 'result') return Boolean(resultRecord.value?.late)
  if (isSigned.value || mode.value === 'conflict') return Boolean(detail.value?.review?.late)
  return signableStatus.value && willBeLate.value
})

const headTitle = computed(() => {
  const label = dateWithWeekday(date.value)
  if (mode.value !== 'detail' || isSigned.value) return t('dailyReview.drawer.titleRecord', { date: label })
  return t('dailyReview.drawer.titleReview', { date: label })
})

const dueText = computed(() => dateTimeInZone(lastMinuteBefore(detail.value?.due_at), detail.value?.timezone))
const deadlineText = computed(() => {
  const d = detail.value
  if (!d?.due_at || !signableStatus.value || mode.value !== 'detail') return ''
  if (willBeLate.value) return t('dailyReview.drawer.duePassed', { due: dueText.value })
  return t('dailyReview.drawer.dueOnTime', { time: timeInZone(lastMinuteBefore(d.due_at), d.timezone) })
})

const sourceNotice = computed(() => {
  const worst = [logSource.value, alertsSource.value]
  if (worst.includes('purged')) return t('dailyReview.drawer.sourceNotice.purged')
  if (worst.includes('partial')) return t('dailyReview.drawer.sourceNotice.partial')
  return ''
})

// 送出或被搶先後還剩幾天待簽（取自重取的待簽清單）
const remainingText = computed(() => (remaining.value > 0
  ? t('dailyReview.drawer.result.remaining', { n: remaining.value })
  : t('dailyReview.drawer.result.noneLeft')))

const conflictText = computed(() => {
  const p = conflict.value || {}
  return {
    date: p.date || date.value,
    signer: p.signer || '',
    time: p.signed_at ? formatInZone(p.signed_at, p.timezone, { seconds: true }) : '',
  }
})

async function load() {
  if (!date.value) return
  loading.value = true
  loadError.value = false
  try {
    const res = await getDailyReviewDay(date.value)
    detail.value = res?.data || null
  } catch (error) {
    console.error('載入單日明細失敗:', error)
    loadError.value = true
  } finally {
    loading.value = false
  }
}

// 下一天＝剩餘待簽日中最早的一天（清單由最早排起）
async function loadNext() {
  try {
    const res = await getDailyReviewPending({ page: 1, page_size: 31 }, { skipErrorToast: true })
    const items = res?.data?.items || []
    const others = items.filter((item) => item.date !== date.value)
    nextDate.value = others[0]?.date || ''
    const total = Number(res?.data?.total) || 0
    remaining.value = Math.max(0, total - (others.length < items.length ? 1 : 0))
  } catch {
    nextDate.value = ''
  }
}

const changed = () => {
  notifyDailyReviewsChanged()
  emit('changed')
}

function reset(day) {
  date.value = day
  detail.value = null
  mode.value = 'detail'
  resultRecord.value = null
  conflict.value = null
  text.value = ''
  delayError.value = false
  forceLate.value = false
  settlingAt.value = ''
  nextDate.value = ''
  remaining.value = 0
}

async function openDay(day) {
  reset(day)
  emit('update:modelValue', true)
  await load()
}

function close() {
  emit('update:modelValue', false)
}

function go(location) {
  close()
  router?.push(location)
}

async function onAlertsReviewed() {
  await load()
  changed()
}

async function submit() {
  if (signDisabled.value || !detail.value) return
  const late = willBeLate.value
  const value = text.value.trim()
  if (late && !value) {
    delayError.value = true
    return
  }
  submitting.value = true
  try {
    const body = late
      ? { review_date: date.value, note: '', delay_reason: value }
      : { review_date: date.value, note: value, delay_reason: '' }
    const res = await signDailyReview(body, { skipErrorToast: true })
    resultRecord.value = res?.data || null
    mode.value = 'result'
    changed()
    await loadNext()
    // 回應沒有「晚幾天」：重取明細補上，簽核時間仍是伺服器寫入的那一個
    await load()
    if (detail.value?.review) resultRecord.value = { ...resultRecord.value, ...detail.value.review }
  } catch (error) {
    await handleSignError(error)
  } finally {
    submitting.value = false
  }
}

async function handleSignError(error) {
  const status = error?.response?.status
  const data = error?.response?.data || {}
  const params = data.params || {}
  switch (data.code) {
    case 'CONFLICT_DAILY_REVIEW_SIGNED':
      conflict.value = params
      mode.value = 'conflict'
      text.value = ''
      await Promise.all([load(), loadNext()])
      changed()
      return
    case 'VALIDATION_DAILY_REVIEW_DELAY_REASON_REQUIRED':
      // 抽屜開著時跨過了準時期限：切成補簽版面，已填的內容保留
      forceLate.value = true
      delayError.value = !text.value.trim()
      return
    case 'RULE_DAILY_REVIEW_DAY_SETTLING':
      settlingAt.value = params.signable_at || detail.value?.signable_at || ''
      return
    case 'RULE_DAILY_REVIEW_ALERTS_PENDING':
      await load()
      return
    default:
      if (status === 409) {
        mode.value = 'conflict'
        await Promise.all([load(), loadNext()])
        changed()
        return
      }
      ElMessage.error(resolveApiError(data, status))
  }
}

defineExpose({ openDay, close, detail, mode })
</script>

<style scoped>
.dr-drawer__body {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.dr-drawer__head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  padding-bottom: var(--ot-space-sm);
  border-bottom: 1px solid var(--ot-border-subtle);
}

.dr-drawer__title {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs) var(--ot-space-sm);
  margin: 0;
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-drawer__sub {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.dr-drawer__content {
  display: flex;
  flex-direction: column;
  flex: 1;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-md) 0;
  overflow-y: auto;
}

.dr-drawer__plain,
.dr-drawer__error {
  margin: 0;
  color: var(--ot-text-secondary);
}

.dr-drawer__error {
  color: var(--ot-danger);
}

.dr-drawer__foot {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: var(--ot-space-sm);
  padding-top: var(--ot-space-sm);
  border-top: 1px solid var(--ot-border-subtle);
}

.dr-drawer__foot :deep(.el-button + .el-button) {
  margin-left: 0;
}

.dr-drawer__block {
  flex: 1;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-warning);
}

.dr-drawer__hint {
  flex: 1;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.dr-banner {
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-primary);
}

.dr-banner--icon {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
}

.dr-banner__icon {
  flex-shrink: 0;
  margin-top: 3px;
}

.dr-banner__icon--success {
  color: var(--ot-success);
}

.dr-banner__icon--warning {
  color: var(--ot-warning);
}

.dr-banner__title {
  font-weight: 600;
}

.dr-banner--success {
  border-color: var(--ot-success);
}

.dr-banner--warning {
  border-color: var(--ot-warning);
}

.dr-banner--info {
  border-color: var(--ot-info);
}

.dr-form__label {
  margin-bottom: var(--ot-space-xs);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-form__input--error :deep(.el-textarea__inner) {
  box-shadow: 0 0 0 1px var(--ot-danger) inset;
}

.dr-form__error {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-danger);
}

.dr-form__hint {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}
</style>
