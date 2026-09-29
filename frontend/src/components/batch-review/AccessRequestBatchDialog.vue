<template>
  <!-- 審核中心待審的批次核准／拒絕：確認畫面 → 逐張進度 → 結果，先後三個狀態 -->
  <el-dialog
    :model-value="visible"
    data-test="pending-batch-dialog"
    :title="title"
    width="600px"
    :close-on-click-modal="false"
    :close-on-press-escape="phase === 'idle'"
    :show-close="phase === 'idle'"
    @update:model-value="(value) => { if (!value) mode = '' }"
  >
    <div class="batch-dialog-body">
      <template v-if="phase === 'idle' && mode === 'approve'">
        <!-- 批次核准只能照申請內容：逐張逐項列出資產、帳號與時長 -->
        <div
          class="batch-sheets"
          data-test="batch-approve-list"
        >
          <section
            v-for="req in requests"
            :key="req.id"
            class="batch-sheet"
          >
            <p class="batch-sheet__title">
              {{ requestLabel(req) }}
            </p>
            <ul class="batch-sheet__items">
              <li
                v-for="line in approveLines(req)"
                :key="line.key"
              >
                {{ line.text }}
              </li>
            </ul>
          </section>
        </div>
        <p class="batch-hint batch-hint--strong">
          {{ $t('approvals.batch.approveHint') }}
        </p>
        <p class="batch-hint">
          {{ $t('approvals.batch.partialHint') }}
        </p>
      </template>
      <template v-else-if="phase === 'idle' && mode === 'reject'">
        <ul class="batch-targets">
          <li
            v-for="req in requests"
            :key="req.id"
          >
            {{ rejectLabel(req) }}
          </li>
        </ul>
        <el-form
          label-position="top"
          @submit.prevent
        >
          <el-form-item
            :label="$t('approvals.batch.rejectNoteLabel')"
            required
          >
            <div
              class="batch-note"
              data-test="batch-note"
            >
              <el-input
                v-model="note"
                type="textarea"
                :rows="3"
                :maxlength="NOTE_MAX"
                show-word-limit
                :placeholder="$t('approvals.rejectPlaceholder')"
              />
            </div>
          </el-form-item>
        </el-form>
        <p class="batch-hint">
          {{ $t('approvals.batch.rejectPartialHint') }}
        </p>
      </template>
      <BatchProgressList
        v-else-if="phase !== 'idle'"
        :phase="phase"
        :items="items"
        :progress-text="$t('approvals.batch.progressSheets', { i: current, n: total })"
        :summary-text="summaryText"
        :checking-text="$t('approvals.batch.checking')"
        :describe="describe"
      />
      <p
        v-if="phase === 'result' && summary.unconfirmed"
        class="batch-hint"
      >
        {{ $t('approvals.batch.unconfirmedHint') }}
      </p>
    </div>
    <template #footer>
      <template v-if="phase === 'idle'">
        <el-button @click="mode = ''">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          :type="mode === 'reject' ? 'danger' : 'primary'"
          data-test="batch-submit"
          :disabled="!canSubmit"
          @click="submit"
        >
          {{ mode === 'reject'
            ? $t('approvals.batch.rejectSubmit', { n: requests.length })
            : $t('approvals.batch.approveSubmit', { n: requests.length }) }}
        </el-button>
      </template>
      <template v-else-if="phase === 'result'">
        <el-button
          v-if="summary.unconfirmed"
          data-test="batch-recheck"
          @click="recheck"
        >
          {{ $t('approvals.batch.recheck') }}
        </el-button>
        <el-button
          type="primary"
          data-test="batch-done"
          @click="done"
        >
          {{ $t('approvals.batch.done') }}
        </el-button>
      </template>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import {
  approveAccessRequest,
  rejectAccessRequest,
  getPendingAccessRequests,
  getAccessRequestHistory,
} from '@/api/accessRequests'
import { useBatchReview, BATCH_STATE } from '@/composables/useBatchReview'
import BatchProgressList from './BatchProgressList.vue'
import {
  approveOutcome,
  batchRejectReason,
  formatMinutes,
  hasMyVotes,
  decidedByMe,
  requesterName,
} from './accessRequestBatch'

const NOTE_MAX = 1000
// 收尾比對只看歷史第一頁：再往前的單不會是剛才這一批
const HISTORY_PAGE_SIZE = 100

const props = defineProps({
  // 已勾選的待審申請（已依 id 去重）
  requests: { type: Array, required: true },
  currentUserId: { type: Number, default: null },
})
const emit = defineEmits(['finished'])

const mode = ref('') // '' | approve | reject
const note = ref('')
const userId = computed(() => props.currentUserId)

const pendingItemIds = (req) => (req.items || [])
  .filter((item) => item.status === 'pending')
  .map((item) => item.id)

const accountsText = (accounts) => {
  const list = Array.isArray(accounts) ? accounts : []
  return list.length && !list.includes('@ALL')
    ? list.join(t('common.listSeparator'))
    : t('multiRequest.allAccounts')
}

const durationText = (req) => {
  const minutes = formatMinutes(req.requested_duration_minutes)
  return req.requested_date_start
    ? `${minutes} · ${t('approvals.fromTime', { time: formatDateTime(req.requested_date_start) })}`
    : minutes
}

const requestLabel = (req) => t('approvals.batch.requestLine', { id: req.id, user: requesterName(req) })

// 核准確認的逐項明細：只列這次會送出的 pending 項目；舊式無項目單以單頭資產代表
const approveLines = (req) => {
  if (req.items?.length) {
    return req.items
      .filter((item) => item.status === 'pending')
      .map((item) => ({
        key: item.id,
        text: t('approvals.batch.itemLine', {
          asset: item.asset_name || item.asset?.name || t('common.assetRef', { id: item.asset_id }),
          accounts: accountsText(item.requested_accounts || item.accounts),
          duration: durationText(req),
        }),
      }))
  }
  return [{
    key: 'request',
    text: t('approvals.batch.itemLine', {
      asset: req.asset?.name || t('common.assetRef', { id: req.asset_id }),
      accounts: accountsText(req.accounts),
      duration: durationText(req),
    }),
  }]
}

// 只列這次會處理的待決項目的資產（已決定的項目不受這一批影響）
const assetNames = (req) => {
  const pending = (req.items || []).filter((item) => item.status === 'pending')
  const names = pending.length
    ? pending.map((item) => item.asset_name || item.asset?.name || t('common.assetRef', { id: item.asset_id }))
    : [req.asset?.name || t('common.assetRef', { id: req.asset_id })]
  return names.join(t('common.listSeparator'))
}

const rejectLabel = (req) => `${requestLabel(req)} · ${assetNames(req)}`

// 收尾查詢：仍在待審 → 看自己的票在不在；已離開待審 → 到歷史第一頁找決定者
const reconcile = async (entry) => {
  const me = entry.userId
  const unconfirmed = entry.items.filter((item) => item.state === BATCH_STATE.UNCONFIRMED)
  const pendingRes = await getPendingAccessRequests({ skipErrorToast: true })
  const pendingList = pendingRes?.data || []
  let history = null
  const updates = {}
  for (const item of unconfirmed) {
    const row = pendingList.find((candidate) => candidate.id === item.id)
    if (row) {
      const voted = entry.kind === 'approve' && hasMyVotes(row, item.meta?.itemIds || [], me)
      updates[item.id] = voted
        ? { state: BATCH_STATE.SUCCESS, outcome: { kind: 'voted' }, waiting: true }
        : { state: BATCH_STATE.NOT_SENT }
      continue
    }
    if (history === null) {
      try {
        const res = await getAccessRequestHistory({ page: 1, page_size: HISTORY_PAGE_SIZE }, { skipErrorToast: true })
        history = res?.data || []
      } catch {
        history = []
      }
    }
    const decided = history.find((candidate) => candidate.id === item.id)
    if (!decided) {
      updates[item.id] = { state: BATCH_STATE.UNCONFIRMED, hint: 'history' }
      continue
    }
    updates[item.id] = decidedByMe(decided, entry.kind, me)
      ? { state: BATCH_STATE.SUCCESS, outcome: { kind: entry.kind === 'reject' ? 'rejected' : 'approved' } }
      : { state: BATCH_STATE.REJECTED, reason: t('approvals.batch.handledByOther') }
  }
  return updates
}

const { phase, batch, items, current, total, summary, run, recover, recheck, finish } =
  useBatchReview({ surface: 'approvals-pending', userId, reconcile })

const visible = computed(() => mode.value !== '' || phase.value !== 'idle')
const title = computed(() => {
  if (phase.value === 'idle') {
    return mode.value === 'reject'
      ? t('approvals.batch.rejectTitle', { n: props.requests.length })
      : t('approvals.batch.approveTitle', { n: props.requests.length })
  }
  return batch.value?.kind === 'reject'
    ? t('approvals.batch.rejectResultTitle')
    : t('approvals.batch.approveResultTitle')
})
const canSubmit = computed(() => {
  if (!props.requests.length) return false
  if (mode.value !== 'reject') return true
  const text = note.value.trim()
  return text.length > 0 && text.length <= NOTE_MAX
})

const summaryText = computed(() => {
  const waiting = items.value.filter((item) => item.state === BATCH_STATE.SUCCESS && item.waiting).length
  return waiting
    ? t('approvals.batch.summarySheetsWaiting', { ...summary.value, waiting })
    : t('approvals.batch.summarySheets', summary.value)
})

const describeOutcome = (outcome) => {
  switch (outcome?.kind) {
    case 'rejected':
      return t('approvals.batch.rejectedDone')
    case 'voted':
      return outcome.required
        ? t('approvals.batch.votedWaiting', { received: outcome.received, required: outcome.required })
        : t('approvals.batch.votedWaitingPlain')
    case 'partly':
      return t('approvals.batch.partlyApproved', { approved: outcome.approved, pending: outcome.pending })
    default:
      return t('approvals.batch.approved')
  }
}

const describe = (item) => {
  switch (item.state) {
    case BATCH_STATE.SUCCESS:
      return describeOutcome(item.outcome)
    case BATCH_STATE.REJECTED:
      return t('approvals.batch.rejectedWith', { reason: batchRejectReason(item) })
    case BATCH_STATE.NOT_SENT:
      return t('approvals.batch.state.notSent')
    case BATCH_STATE.UNCONFIRMED:
      return item.hint === 'history'
        ? t('approvals.batch.unconfirmedCheckHistory')
        : t('approvals.batch.state.unconfirmed')
    case BATCH_STATE.INFLIGHT:
      return t('approvals.batch.state.inflight')
    default:
      return t('approvals.batch.state.queued')
  }
}

function open(nextMode) {
  if (phase.value !== 'idle' || !props.requests.length) return
  note.value = ''
  mode.value = nextMode === 'reject' ? 'reject' : 'approve'
}

async function submit() {
  if (!canSubmit.value) return
  const kind = mode.value
  const sharedNote = note.value.trim()
  const entries = props.requests.map((req) => ({
    id: req.id,
    label: rejectLabel(req),
    meta: { itemIds: pendingItemIds(req), hasItems: !!req.items?.length },
  }))
  mode.value = ''
  await run({
    kind,
    params: kind === 'reject' ? { note: sharedNote } : {},
    entries,
    send: async (entry, batchId) => {
      if (kind === 'reject') {
        await rejectAccessRequest(entry.id, sharedNote, { batchId, skipErrorToast: true })
        return { outcome: { kind: 'rejected' } }
      }
      const body = entry.meta.hasItems
        ? { items: entry.meta.itemIds.map((itemId) => ({ item_id: itemId })), batch_id: batchId }
        : { batch_id: batchId }
      const res = await approveAccessRequest(entry.id, body, { skipErrorToast: true })
      return approveOutcome(res, entry.meta)
    },
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
.batch-sheets {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  max-height: 40vh;
  margin-bottom: var(--ot-space-md);
  overflow-y: auto;
}

.batch-sheet {
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.batch-sheet__title {
  margin: 0 0 var(--ot-space-xs);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.batch-sheet__items,
.batch-targets {
  margin: 0;
  padding: 0;
  list-style: none;
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
  color: var(--ot-text-secondary);
}

.batch-targets {
  max-height: 30vh;
  margin-bottom: var(--ot-space-md);
  overflow-y: auto;
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

.batch-hint--strong {
  color: var(--ot-text-primary);
}
</style>
