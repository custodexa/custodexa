<template>
  <!-- 告警批次審閱：先填表（處置＋共用理由），送出後同一個對話框切到逐筆進度，
       再切到結果。填表與結果是先後兩個狀態，不並排 -->
  <el-dialog
    :model-value="visible"
    data-test="alerts-batch-dialog"
    :title="title"
    width="560px"
    :close-on-click-modal="false"
    :close-on-press-escape="phase === 'idle'"
    :show-close="phase === 'idle'"
    @update:model-value="(value) => { if (!value) formOpen = false }"
  >
    <div class="batch-dialog-body">
      <template v-if="phase === 'idle'">
        <ul class="batch-targets">
          <li
            v-for="row in alerts"
            :key="row.id"
          >
            {{ labelFor(row) }}
          </li>
        </ul>
        <el-form
          label-position="top"
          @submit.prevent
        >
          <el-form-item
            :label="$t('alerts.dispositionLabel')"
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
              class="batch-note"
              data-test="batch-note"
            >
              <el-input
                v-model="form.note"
                type="textarea"
                :rows="3"
                :maxlength="NOTE_MAX"
                show-word-limit
                :placeholder="$t('alerts.batch.notePlaceholder')"
              />
            </div>
          </el-form-item>
        </el-form>
        <p class="batch-hint">
          {{ $t('alerts.batch.partialHint') }}
        </p>
        <p class="batch-hint">
          {{ $t('alerts.batch.selfHint') }}
        </p>
      </template>
      <BatchProgressList
        v-else
        :phase="phase"
        :items="items"
        :progress-text="$t('alerts.batch.progress', { i: current, n: total })"
        :summary-text="$t('alerts.batch.summary', summary)"
        :checking-text="$t('alerts.batch.checking')"
        :describe="describe"
      />
      <p
        v-if="phase === 'result' && summary.unconfirmed"
        class="batch-hint"
      >
        {{ $t('alerts.batch.unconfirmedHint') }}
      </p>
    </div>
    <template #footer>
      <template v-if="phase === 'idle'">
        <el-button @click="formOpen = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          data-test="batch-submit"
          :disabled="!canSubmit"
          @click="submit"
        >
          {{ $t('alerts.batch.submit', { n: alerts.length }) }}
        </el-button>
      </template>
      <template v-else-if="phase === 'result'">
        <el-button
          v-if="summary.unconfirmed"
          data-test="batch-recheck"
          @click="recheck"
        >
          {{ $t('alerts.batch.recheck') }}
        </el-button>
        <el-button
          type="primary"
          data-test="batch-done"
          @click="done"
        >
          {{ $t('alerts.batch.done') }}
        </el-button>
      </template>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { t } from '@/i18n'
import { reviewAlert, searchAlerts } from '@/api/alerts'
import { useBatchReview, BATCH_STATE } from '@/composables/useBatchReview'
import BatchProgressList from './BatchProgressList.vue'

const NOTE_MAX = 500

const props = defineProps({
  // 已勾選的告警（呼叫端已篩過：未審閱、非本人觸發）
  alerts: { type: Array, required: true },
  currentUserId: { type: Number, default: null },
  // 列上的「規則名稱 · 時間」：沿用表格對非規則類告警的散文
  labelFor: { type: Function, required: true },
})
const emit = defineEmits(['finished'])

const formOpen = ref(false)
const form = ref({ disposition: 'benign', note: '' })
const userId = computed(() => props.currentUserId)

// 收尾查詢：向伺服端取回這幾筆的現況，逐筆比對是否就是這一批寫下的結果
const reconcile = async (entry) => {
  const ids = entry.items.filter((item) => item.state === BATCH_STATE.UNCONFIRMED).map((item) => item.id)
  const res = await searchAlerts({ ids: ids.join(','), page: 1, page_size: ids.length }, { skipErrorToast: true })
  const rows = res?.data || []
  const updates = {}
  for (const id of ids) {
    const row = rows.find((candidate) => candidate.id === id)
    if (!row) continue // 查不到：維持待確認
    if (!row.reviewed_at) {
      updates[id] = { state: BATCH_STATE.NOT_SENT }
      continue
    }
    const mine = row.reviewed_by === entry.userId
      && row.note === entry.params.note
      && row.disposition === entry.params.disposition
    updates[id] = mine
      ? { state: BATCH_STATE.SUCCESS }
      : { state: BATCH_STATE.REJECTED, reason: t('alerts.batch.alreadyReviewed') }
  }
  return updates
}

const { phase, batch, items, current, total, summary, run, recover, recheck, finish } =
  useBatchReview({ surface: 'alerts', userId, reconcile })

const visible = computed(() => formOpen.value || phase.value !== 'idle')
const title = computed(() => {
  if (phase.value === 'idle') return t('alerts.batch.dialogTitle', { n: props.alerts.length })
  return t('alerts.batch.resultTitle')
})
const canSubmit = computed(() => {
  const note = form.value.note.trim()
  return props.alerts.length > 0 && note.length > 0 && note.length <= NOTE_MAX
})

const successText = (disposition) => disposition === 'escalated'
  ? t('alerts.batch.markedEscalated')
  : t('alerts.batch.markedBenign')

const describe = (item) => {
  switch (item.state) {
    case BATCH_STATE.SUCCESS:
      return successText(batch.value?.params?.disposition)
    case BATCH_STATE.REJECTED:
      return t('alerts.batch.rejectedWith', { reason: item.reason || '' })
    case BATCH_STATE.NOT_SENT:
      return t('alerts.batch.state.notSent')
    case BATCH_STATE.UNCONFIRMED:
      return t('alerts.batch.state.unconfirmed')
    case BATCH_STATE.INFLIGHT:
      return t('alerts.batch.state.inflight')
    default:
      return t('alerts.batch.state.queued')
  }
}

function open() {
  if (phase.value !== 'idle' || !props.alerts.length) return
  form.value = { disposition: 'benign', note: '' }
  formOpen.value = true
}

async function submit() {
  if (!canSubmit.value) return
  const params = { disposition: form.value.disposition, note: form.value.note.trim() }
  formOpen.value = false
  await run({
    kind: 'alert',
    params,
    entries: props.alerts.map((row) => ({ id: row.id, label: props.labelFor(row) })),
    send: (entry, batchId) => reviewAlert(
      entry.id,
      { disposition: params.disposition, note: params.note, batch_id: batchId },
      { skipErrorToast: true },
    ),
  })
}

function done() {
  finish()
  emit('finished')
}

onMounted(() => {
  recover()
})

defineExpose({ open })
</script>

<style scoped>
.batch-targets {
  max-height: 30vh;
  margin: 0 0 var(--ot-space-md);
  padding: 0;
  overflow-y: auto;
  list-style: none;
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
  color: var(--ot-text-secondary);
}

.batch-note {
  width: 100%;
}

.batch-hint {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}
</style>
