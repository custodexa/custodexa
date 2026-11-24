<template>
  <!-- 告警的處置對話框（告警頁、每日簽核單日與跨日共用）：依類型列出、本人觸發的單獨確認、
       理由必填，一次請求送出。填寫、處理中、結果是先後三個狀態，不並排 -->
  <el-dialog
    :model-value="visible"
    data-test="alerts-batch-dialog"
    :title="title"
    :width="days.length > 1 ? '860px' : '640px'"
    append-to-body
    :close-on-click-modal="false"
    :close-on-press-escape="phase === 'idle'"
    :show-close="phase === 'idle'"
    @update:model-value="(value) => { if (!value) cancel() }"
  >
    <div class="bulk">
      <!-- 填寫 -->
      <template v-if="phase === 'idle'">
        <div
          v-if="overLimit"
          class="bulk-box bulk-box--warning"
          data-test="bulk-over-limit"
        >
          <TriangleAlert
            :size="16"
            class="bulk-box__icon"
            aria-hidden="true"
          />
          <span>{{ $t('alerts.bulk.overLimit', { lim: limit, r: rows.length - batchRows.length }) }}</span>
        </div>
        <p
          class="bulk-lead"
          data-test="bulk-lead"
        >
          {{ leadText }}
        </p>
        <table
          class="bulk-table"
          data-test="bulk-types"
        >
          <thead>
            <tr>
              <th>{{ $t('alerts.bulk.colType') }}</th>
              <th class="bulk-table__sev">
                {{ $t('alerts.bulk.colSeverity') }}
              </th>
              <th class="bulk-table__num">
                {{ $t('alerts.bulk.colCount') }}
              </th>
              <th class="bulk-table__num">
                {{ $t('alerts.bulk.colSelf') }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="type in typeRows"
              :key="type.key"
              data-test="bulk-type-row"
            >
              <td>
                <div>{{ type.name }}</div>
                <div
                  v-if="type.days.length && days.length > 1"
                  class="bulk-muted"
                  data-test="bulk-type-days"
                >
                  {{ type.days.map((d) => `${shortDay(d.day)} ${d.count}`).join(' · ') }}
                </div>
              </td>
              <td :class="['bulk-table__sev', `bulk-sev--${type.severity}`]">
                {{ severityLabel(type.severity) }}
              </td>
              <td class="bulk-table__num">
                {{ type.count }}
              </td>
              <td class="bulk-table__num">
                {{ type.selfCount }}
              </td>
            </tr>
          </tbody>
        </table>
        <el-button
          link
          type="primary"
          size="small"
          data-test="bulk-toggle-list"
          @click="showList = !showList"
        >
          {{ showList ? $t('alerts.bulk.hideList') : $t('alerts.bulk.showList') }}
        </el-button>
        <ul
          v-if="showList"
          class="bulk-list"
          data-test="bulk-list"
        >
          <li
            v-for="row in batchRows"
            :key="row.id"
          >
            {{ labelFor(row) }}
          </li>
        </ul>

        <!-- 本人觸發：單獨一段、要勾確認 -->
        <div
          v-if="selfCount > 0"
          :class="['bulk-box', errors.ack ? 'bulk-box--error' : 'bulk-box--self']"
          data-test="bulk-self"
        >
          <div class="bulk-box__title">
            <UserRound
              :size="14"
              aria-hidden="true"
            />
            {{ $t('alerts.bulk.selfTitle', { s: selfCount }) }}
          </div>
          <p
            v-if="serverSelf !== null"
            class="bulk-box__body"
            data-test="bulk-self-mismatch"
          >
            {{ $t('alerts.bulk.selfMismatch', { s: selfCount }) }}
          </p>
          <p
            v-else
            class="bulk-box__body"
          >
            {{ $t('alerts.bulk.selfBody', { list: selfBreakdown }) }}
          </p>
          <el-checkbox
            v-model="form.ack"
            data-test="bulk-self-ack"
            @change="errors.ack = false"
          >
            {{ $t('alerts.bulk.selfAck', { s: selfCount }) }}
          </el-checkbox>
          <p
            v-if="errors.ack"
            class="bulk-error"
            data-test="bulk-self-error"
          >
            {{ $t('alerts.bulk.selfAckRequired', { s: selfCount }) }}
          </p>
        </div>

        <el-form
          label-position="top"
          class="bulk-form"
          @submit.prevent
        >
          <el-form-item
            :label="$t('alerts.bulk.dispositionLabel')"
            required
          >
            <el-radio-group v-model="form.disposition">
              <el-radio
                value="benign"
                data-test="batch-disposition-benign"
              >
                {{ $t('alerts.dispositionBenign') }}
              </el-radio>
              <el-radio
                value="escalated"
                data-test="batch-disposition-escalated"
              >
                {{ $t('alerts.dispositionEscalated') }}
              </el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item
            :label="$t('alerts.batch.noteLabel')"
            required
          >
            <div
              :class="['batch-note', { 'batch-note--error': errors.note }]"
              data-test="batch-note"
            >
              <el-input
                v-model="form.note"
                type="textarea"
                :rows="2"
                :maxlength="NOTE_MAX"
                show-word-limit
                :placeholder="$t('alerts.batch.notePlaceholder')"
                @input="errors.note = false"
              />
            </div>
            <p
              v-if="errors.note"
              class="bulk-error"
              data-test="bulk-note-error"
            >
              {{ $t('alerts.bulk.noteRequired') }}
            </p>
          </el-form-item>
        </el-form>
        <p
          v-if="failedOnce"
          class="bulk-box bulk-box--error"
          data-test="bulk-failed"
        >
          {{ $t('alerts.bulk.failed') }}
        </p>
        <p
          v-if="rejectedText"
          class="bulk-box bulk-box--error"
          data-test="bulk-rejected"
        >
          {{ rejectedText }}
        </p>
        <p class="bulk-hint">
          {{ $t('alerts.bulk.howItWorks') }}
        </p>
        <p
          v-if="selfCount > 0"
          class="bulk-hint"
          data-test="bulk-audit-mark"
        >
          {{ $t('alerts.bulk.auditMark') }}
        </p>
      </template>

      <!-- 處理中：一次請求拿不到逐筆進度，只有不確定長度的進度條 -->
      <template v-else-if="phase === 'running'">
        <p
          class="bulk-lead"
          data-test="bulk-running"
        >
          {{ $t('alerts.bulk.runningBody', { n: total, k: runningTypes }) }}
        </p>
        <el-progress
          :percentage="50"
          :indeterminate="true"
          :show-text="false"
          :duration="3"
        />
        <p class="bulk-hint">
          {{ $t('alerts.bulk.runningNotice') }}
        </p>
      </template>

      <!-- 結果 -->
      <template v-else>
        <p
          v-if="phase === 'reconciling'"
          class="bulk-hint"
        >
          {{ $t('alerts.batch.checking') }}
        </p>
        <p
          class="bulk-summary"
          data-test="batch-summary"
          aria-live="polite"
        >
          {{ summaryText }}
        </p>
        <ul class="bulk-result">
          <li
            v-for="group in successGroups"
            :key="group.key"
            class="bulk-result__row"
            data-test="bulk-success-row"
          >
            <div>
              <div class="bulk-result__main">
                {{ $t('alerts.bulk.typeCount', { type: group.name, n: group.count }) }}
              </div>
              <div class="bulk-muted">
                {{ selfLine(group) }}
              </div>
            </div>
            <span class="bulk-result__ok">{{ successText }}</span>
          </li>
          <li
            v-for="item in otherItems"
            :key="item.id"
            class="bulk-result__row"
            data-test="batch-item"
            :data-id="item.id"
            :data-state="item.state"
          >
            <div>
              <div class="bulk-result__main">
                {{ item.label }}
              </div>
              <div class="bulk-muted">
                {{ item.typeName }}
              </div>
            </div>
            <span class="bulk-result__warn">{{ describe(item) }}</span>
          </li>
        </ul>
        <p
          v-if="notAppliedHint"
          class="bulk-box bulk-box--info"
          data-test="bulk-not-applied-hint"
        >
          {{ notAppliedHint }}
        </p>
        <p
          v-if="summary.unconfirmed"
          class="bulk-box bulk-box--warning"
          data-test="bulk-unconfirmed-hint"
        >
          {{ $t('alerts.bulk.unconfirmedHint') }}
        </p>
        <p
          v-if="remainingRows.length && phase === 'result'"
          class="bulk-box bulk-box--info"
          data-test="bulk-remaining-hint"
        >
          {{ $t('alerts.bulk.remainingHint', { lim: total, r: remainingRows.length, k: remainingTypes }) }}
        </p>
        <p
          v-if="resultNote && phase === 'result'"
          class="bulk-box bulk-box--info"
          data-test="bulk-result-note"
        >
          {{ resultNote }}
        </p>
      </template>
    </div>

    <template #footer>
      <template v-if="phase === 'idle'">
        <el-button @click="cancel">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          v-preview-write
          type="primary"
          data-test="batch-submit"
          :disabled="!batchRows.length"
          @click="submit"
        >
          {{ $t('alerts.bulk.submit', { n: batchRows.length }) }}
        </el-button>
      </template>
      <template v-else-if="phase === 'running'">
        <el-button
          type="primary"
          disabled
          data-test="bulk-running-button"
        >
          {{ $t('alerts.bulk.runningButton') }}
        </el-button>
      </template>
      <template v-else>
        <el-button
          v-if="summary.unconfirmed"
          data-test="batch-recheck"
          :disabled="phase !== 'result'"
          @click="recheck"
        >
          {{ $t('alerts.batch.recheck') }}
        </el-button>
        <template v-if="remainingRows.length">
          <el-button
            data-test="bulk-stop"
            :disabled="phase !== 'result'"
            @click="done"
          >
            {{ $t('alerts.bulk.stopHere') }}
          </el-button>
          <el-button
            v-if="nextText && !summary.unconfirmed"
            data-test="bulk-next"
            :disabled="phase !== 'result'"
            @click="goNext"
          >
            {{ nextText }}
          </el-button>
          <el-button
            v-preview-write
            type="primary"
            data-test="bulk-continue"
            :disabled="phase !== 'result'"
            @click="continueRemaining"
          >
            {{ $t('alerts.bulk.handleRemaining', { r: remainingRows.length }) }}
          </el-button>
        </template>
        <template v-else-if="nextText && !summary.unconfirmed">
          <el-button
            data-test="batch-done"
            @click="done"
          >
            {{ backText || $t('alerts.batch.done') }}
          </el-button>
          <el-button
            type="primary"
            data-test="bulk-next"
            @click="goNext"
          >
            {{ nextText }}
          </el-button>
        </template>
        <el-button
          v-else
          type="primary"
          data-test="batch-done"
          :disabled="phase !== 'result'"
          @click="done"
        >
          {{ $t('alerts.batch.done') }}
        </el-button>
      </template>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { TriangleAlert, UserRound } from 'lucide-vue-next'
import { t } from '@/i18n'
import { batchReviewAlerts, searchAlerts } from '@/api/alerts'
import { resolveApiError } from '@/api/error'
import { useBatchReview, BATCH_STATE, BULK_OUTCOME } from '@/composables/useBatchReview'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import {
  ALERT_BULK_LIMIT,
  alertTypeKey,
  alertTypeName,
  groupAlerts,
  isDefiniteBulkFailure,
  isSelfTriggered,
  itemPatch,
  notAppliedText,
  NOT_APPLIED_REASON,
  reconcileAlertBulk,
  severityLabel,
  summarizeByType,
} from './alertBulk'

const NOTE_MAX = 500
const CODE_SELF_ACK = 'CONFLICT_ALERT_BATCH_SELF_ACK'
const CODE_TOO_LARGE = 'VALIDATION_ALERT_BATCH_TOO_LARGE'

const props = defineProps({
  currentUserId: { type: Number, default: null },
  // 列的說明（結果中逐筆列出沒有生效者時用）：時間、觸發者與對象
  labelFor: { type: Function, required: true },
  // 分頁暫存的面代號：不同頁面各自接手自己的批次
  surface: { type: String, default: 'alerts' },
  // 結果畫面的補充說明（例如背後的抽屜已更新、可以簽核）
  resultNote: { type: String, default: '' },
  // 結果畫面的下一步（例如跨日處置後接著簽核）；有值時「完成」改為 backText
  nextText: { type: String, default: '' },
  backText: { type: String, default: '' },
})
// settled：結果已出現（呼叫端此時就重取現況）；finished：使用者關閉結果；next：按下一步
const emit = defineEmits(['settled', 'finished', 'next'])

const formOpen = ref(false)
const rows = ref([])
const days = ref([])
let dayOf = null
const limit = ref(ALERT_BULK_LIMIT)
const form = ref({ disposition: 'benign', note: '', ack: false })
const errors = ref({ ack: false, note: false })
const serverSelf = ref(null)
const failedOnce = ref(false)
const rejectedText = ref('')
const showList = ref(false)
// 這一次開啟時排在上限之後、留待下一次的列（送完後「處置剩下的」用）
const remainingRows = ref([])
const userId = computed(() => props.currentUserId)

const reconcile = (entry) => reconcileAlertBulk(entry, { search: searchAlerts })

const { phase, batch, items, total, summary, runBulk, recover, recheck, finish } =
  useBatchReview({ surface: props.surface, userId, reconcile })

const visible = computed(() => formOpen.value || phase.value !== 'idle')

const batchRows = computed(() => rows.value.slice(0, limit.value))
const overLimit = computed(() => rows.value.length > limit.value)
const typeRows = computed(() => summarizeByType(batchRows.value, { me: props.currentUserId, dayOf }))
const localSelfRows = computed(() => batchRows.value.filter((row) => isSelfTriggered(row, props.currentUserId)))
// 伺服端核對過的本人觸發筆數優先（409 時回傳）
const selfCount = computed(() => serverSelf.value ?? localSelfRows.value.length)
const selfBreakdown = computed(() => groupAlerts(localSelfRows.value, props.currentUserId)
  .map((g) => t('alerts.bulk.typeCount', { type: g.name, n: g.rows.length }))
  .join(t('common.listSeparator')))

const shortDay = (day) => String(day || '').slice(5)

const leadText = computed(() => {
  const n = batchRows.value.length
  const k = typeRows.value.length
  if (days.value.length > 1) {
    const sorted = [...days.value].sort()
    return t('alerts.bulk.leadDays', { from: sorted[0], to: sorted[sorted.length - 1], a: days.value.length, n, k })
  }
  return t('alerts.bulk.lead', { n, k })
})

const runningTypes = computed(() => new Set(items.value.map((item) => item.typeKey)).size)
const dayCountOfBatch = computed(() => new Set(items.value.map((item) => item.day).filter(Boolean)).size)

const title = computed(() => {
  if (phase.value === 'idle') {
    return days.value.length > 1
      ? t('alerts.bulk.titleDays', { n: batchRows.value.length, d: days.value.length })
      : t('alerts.bulk.title', { n: batchRows.value.length })
  }
  if (phase.value === 'running') {
    return dayCountOfBatch.value > 1
      ? t('alerts.bulk.runningTitleDays', { n: total.value, d: dayCountOfBatch.value })
      : t('alerts.bulk.runningTitle', { n: total.value })
  }
  return t('alerts.bulk.resultTitle')
})

const successText = computed(() => (batch.value?.params?.disposition === 'escalated'
  ? t('alerts.batch.markedEscalated')
  : t('alerts.batch.markedBenign')))

const successGroups = computed(() => {
  const ok = items.value.filter((item) => item.state === BATCH_STATE.SUCCESS)
  const groups = new Map()
  for (const item of ok) {
    const g = groups.get(item.typeKey) || { key: item.typeKey, name: item.typeName, count: 0, selfCount: 0 }
    g.count += 1
    if (item.self) g.selfCount += 1
    groups.set(item.typeKey, g)
  }
  return [...groups.values()]
})
const otherItems = computed(() => items.value.filter((item) => item.state !== BATCH_STATE.SUCCESS))

const selfLine = (group) => {
  if (group.selfCount === group.count) return t('alerts.bulk.allSelf')
  if (group.selfCount === 0) return t('alerts.bulk.allOthers')
  return t('alerts.bulk.someSelf', { s: group.selfCount })
}

const summaryText = computed(() => {
  const ok = summary.value.success
  const ng = summary.value.notApplied
  const u = summary.value.unconfirmed
  return u
    ? t('alerts.bulk.summaryWithPending', { ok, ng, u })
    : t('alerts.bulk.summary', { ok, ng })
})

const notAppliedHint = computed(() => {
  const list = items.value.filter((item) => item.state === BATCH_STATE.NOT_APPLIED)
  if (!list.length) return ''
  const undelivered = list.filter((item) => item.reason === NOT_APPLIED_REASON.NOT_DELIVERED).length
  if (undelivered) return t('alerts.bulk.notDeliveredHint', { n: undelivered })
  return t('alerts.bulk.notAppliedHint', { n: list.length })
})

const remainingTypes = computed(() => new Set(remainingRows.value.map(alertTypeKey)).size)

const describe = (item) => {
  switch (item.state) {
    case BATCH_STATE.NOT_APPLIED:
      return t('alerts.bulk.notAppliedWith', { reason: notAppliedText(item) })
    case BATCH_STATE.UNCONFIRMED:
      return item.stillProcessing ? t('alerts.bulk.stillProcessing') : t('alerts.batch.state.unconfirmed')
    case BATCH_STATE.INFLIGHT:
      return t('alerts.batch.state.inflight')
    default:
      return ''
  }
}

watch(phase, (next) => {
  if (next === 'result') emit('settled', { ids: items.value.map((item) => item.id) })
})

/**
 * 開啟填寫畫面。
 * @param {Array} list  依清單順序的告警列（超過上限時這次只處置前面的）
 * @param {Object} [options]
 * @param {Array<string>} [options.days]  跨日處置時的所屬日（兩天以上時標題與類型表帶天數）
 * @param {(row) => string} [options.dayOf]  列的所屬日
 * @param {boolean} [options.carry]  沿用上一次的處置與理由（只在同一次處置分次送出時）
 */
function open(list, options = {}) {
  if (phase.value !== 'idle' || !list?.length) return
  rows.value = [...list]
  days.value = options.days || []
  dayOf = options.dayOf || null
  if (!options.carry) form.value = { disposition: 'benign', note: '', ack: false }
  else form.value = { ...form.value, ack: false }
  errors.value = { ack: false, note: false }
  serverSelf.value = null
  failedOnce.value = false
  rejectedText.value = ''
  showList.value = false
  remainingRows.value = []
  formOpen.value = true
}

function cancel() {
  if (phase.value !== 'idle') return
  formOpen.value = false
}

const errorBody = (error) => error?.response?.data || {}

async function submit() {
  const note = form.value.note.trim()
  errors.value = { ack: selfCount.value > 0 && !form.value.ack, note: !note }
  if (errors.value.ack || errors.value.note || !batchRows.value.length) return
  const disposition = form.value.disposition
  const sending = batchRows.value
  const rest = rows.value.slice(sending.length)
  const ack = selfCount.value
  failedOnce.value = false
  rejectedText.value = ''
  formOpen.value = false
  const { outcome, error } = await runBulk({
    kind: 'alert-bulk',
    params: { disposition, note },
    entries: sending.map((row) => ({
      id: row.id,
      label: props.labelFor(row),
      typeKey: alertTypeKey(row),
      typeName: alertTypeName(row),
      self: isSelfTriggered(row, props.currentUserId),
      day: dayOf ? dayOf(row) : '',
    })),
    isDefiniteFailure: isDefiniteBulkFailure,
    send: async (entries, batchId) => {
      const res = await batchReviewAlerts({
        alert_ids: entries.map((entry) => entry.id),
        disposition,
        note,
        batch_id: batchId,
        self_triggered_ack: ack,
      }, { skipErrorToast: true })
      const body = Array.isArray(res?.items) ? res : res?.data || {}
      if (Number.isInteger(body.limit) && body.limit > 0) limit.value = body.limit
      const patches = {}
      for (const item of body.items || []) {
        const patch = itemPatch(item, disposition)
        if (patch) patches[item.id] = patch
      }
      return patches
    },
  })
  if (outcome === BULK_OUTCOME.DONE || outcome === BULK_OUTCOME.UNCONFIRMED) {
    remainingRows.value = rest
    return
  }
  // 整批沒有寫入：回到填寫畫面，選取與已填的內容都保留
  formOpen.value = true
  if (outcome === BULK_OUTCOME.FAILED) {
    failedOnce.value = true
    return
  }
  const data = errorBody(error)
  if (data.code === CODE_SELF_ACK) {
    const n = Number(data.self_triggered ?? data.meta?.self_triggered)
    serverSelf.value = Number.isInteger(n) && n >= 0 ? n : null
    form.value.ack = false
    errors.value.ack = true
    return
  }
  if (data.code === CODE_TOO_LARGE) {
    const n = Number(data.limit ?? data.meta?.limit)
    if (Number.isInteger(n) && n > 0) limit.value = n
  }
  rejectedText.value = resolveApiError(data, error?.response?.status)
}

function done() {
  finish()
  remainingRows.value = []
  emit('finished')
}

function goNext() {
  finish()
  emit('next')
}

// 同一次處置分次送出：沿用處置與理由（可改），確認重新勾
function continueRemaining() {
  const rest = remainingRows.value
  finish()
  open(rest, { days: days.value, dayOf, carry: true })
}

onMounted(() => {
  recover()
})

defineExpose({ open, phase })
</script>

<style scoped>
.bulk {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

.bulk-lead,
.bulk-summary {
  margin: 0;
  font-weight: 600;
  line-height: 1.6;
}

.bulk-table {
  width: 100%;
  border-collapse: collapse;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.bulk-table th,
.bulk-table td {
  padding: 6px var(--ot-space-sm);
  text-align: left;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.bulk-table th {
  font-weight: 400;
  color: var(--ot-text-secondary);
  background: var(--ot-bg-elevated);
}

.bulk-table__num {
  width: 88px;
  text-align: right !important;
}

.bulk-table__sev {
  width: 64px;
}

.bulk-sev--high {
  color: var(--ot-danger);
}

.bulk-sev--medium {
  color: var(--ot-warning);
}

.bulk-muted {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.bulk-list {
  max-height: 24vh;
  margin: 0;
  padding: 0;
  overflow-y: auto;
  list-style: none;
  line-height: 1.7;
  color: var(--ot-text-secondary);
}

.bulk-box {
  margin: 0;
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  line-height: 1.6;
}

.bulk-box--warning {
  display: flex;
  gap: var(--ot-space-sm);
  border-color: var(--ot-warning);
  background-color: color-mix(in srgb, var(--ot-warning) 10%, transparent);
}

.bulk-box__icon {
  flex-shrink: 0;
  margin-top: 3px;
  color: var(--ot-warning);
}

.bulk-box--self {
  border-color: var(--ot-info);
  background-color: color-mix(in srgb, var(--ot-info) 10%, transparent);
}

.bulk-box--error {
  border-color: var(--ot-danger);
  background-color: color-mix(in srgb, var(--ot-danger) 8%, transparent);
}

.bulk-box--info {
  border-color: var(--ot-info);
}

.bulk-box__title {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  font-weight: 600;
}

.bulk-box__body {
  margin: var(--ot-space-xs) 0;
  color: var(--ot-text-secondary);
}

.bulk-error {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.5;
  color: var(--ot-danger);
}

.bulk-form :deep(.el-form-item) {
  margin-bottom: var(--ot-space-sm);
}

.batch-note {
  width: 100%;
}

.batch-note--error :deep(.el-textarea__inner) {
  box-shadow: 0 0 0 1px var(--ot-danger) inset;
}

.bulk-hint {
  margin: 0;
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.bulk-result {
  max-height: 46vh;
  margin: 0;
  padding: 0;
  overflow-y: auto;
  list-style: none;
}

.bulk-result__row {
  display: flex;
  justify-content: space-between;
  gap: var(--ot-space-md);
  padding: 6px 0;
  border-bottom: 1px solid var(--ot-border-subtle);
}

.bulk-result__main {
  font-weight: 600;
  overflow-wrap: anywhere;
}

.bulk-result__ok {
  flex-shrink: 0;
  color: var(--ot-success);
}

.bulk-result__warn {
  flex-shrink: 0;
  max-width: 50%;
  text-align: right;
  color: var(--ot-warning);
}
</style>
