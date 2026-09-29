<template>
  <!-- 待補審（破窗事後補審）的批次「確認無誤」：只提供 confirmed，
       判定違規必須逐筆處理（既有單筆補審對話框） -->
  <el-dialog
    :model-value="visible"
    data-test="reviews-batch-dialog"
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
            v-for="row in reviews"
            :key="row.id"
          >
            {{ reviewLabel(row) }}
          </li>
        </ul>
        <p class="batch-hint batch-hint--strong">
          {{ $t('approvals.batch.reviewHint') }}
        </p>
        <el-form
          label-position="top"
          @submit.prevent
        >
          <el-form-item
            :label="$t('approvals.batch.reviewNoteLabel')"
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
                :placeholder="$t('approvals.reviewNotePlaceholder')"
              />
            </div>
          </el-form-item>
        </el-form>
        <p class="batch-hint">
          {{ $t('approvals.batch.reviewPartialHint') }}
        </p>
      </template>
      <BatchProgressList
        v-else
        :phase="phase"
        :items="items"
        :progress-text="$t('approvals.batch.progressItems', { i: current, n: total })"
        :summary-text="$t('approvals.batch.summaryItems', summary)"
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
        <el-button @click="formOpen = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          data-test="batch-submit"
          :disabled="!canSubmit"
          @click="submit"
        >
          {{ $t('approvals.batch.reviewSubmit', { n: reviews.length }) }}
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
import { reviewBreakGlass, getPendingReviews, getAccessRequestHistory } from '@/api/accessRequests'
import { useBatchReview, BATCH_STATE } from '@/composables/useBatchReview'
import BatchProgressList from './BatchProgressList.vue'
import { batchRejectReason, requesterName } from './accessRequestBatch'

const NOTE_MAX = 1000
const HISTORY_PAGE_SIZE = 100

const props = defineProps({
  reviews: { type: Array, required: true },
  currentUserId: { type: Number, default: null },
})
const emit = defineEmits(['finished'])

const formOpen = ref(false)
const note = ref('')
const userId = computed(() => props.currentUserId)

const reviewLabel = (row) => t('approvals.batch.reviewLine', {
  user: requesterName(row),
  asset: row.asset?.name || t('common.assetRef', { id: row.asset_id }),
  time: formatDateTime(row.created_at),
})

// 收尾查詢：仍在待補審＝沒生效；已離開則看歷史能否確認補審者是我，確認不了就維持待確認
const reconcile = async (entry) => {
  const me = entry.userId
  const unconfirmed = entry.items.filter((item) => item.state === BATCH_STATE.UNCONFIRMED)
  const pendingRes = await getPendingReviews({ skipErrorToast: true })
  const stillPending = new Set((pendingRes?.data || []).map((row) => row.id))
  let history = null
  const updates = {}
  for (const item of unconfirmed) {
    if (stillPending.has(item.id)) {
      updates[item.id] = { state: BATCH_STATE.NOT_SENT }
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
    const row = history.find((candidate) => candidate.id === item.id)
    if (row && me != null && row.reviewed_by === me && row.review_disposition === 'confirmed') {
      updates[item.id] = { state: BATCH_STATE.SUCCESS }
    }
  }
  return updates
}

const { phase, items, current, total, summary, run, recover, recheck, finish } =
  useBatchReview({ surface: 'approvals-reviews', userId, reconcile })

const visible = computed(() => formOpen.value || phase.value !== 'idle')
const title = computed(() => phase.value === 'idle'
  ? t('approvals.batch.reviewTitle', { n: props.reviews.length })
  : t('approvals.batch.reviewResultTitle'))
const canSubmit = computed(() => {
  const text = note.value.trim()
  return props.reviews.length > 0 && text.length > 0 && text.length <= NOTE_MAX
})

const describe = (item) => {
  switch (item.state) {
    case BATCH_STATE.SUCCESS:
      return t('approvals.batch.reviewConfirmed')
    case BATCH_STATE.REJECTED:
      return t('approvals.batch.rejectedWith', { reason: batchRejectReason(item) })
    case BATCH_STATE.NOT_SENT:
      return t('approvals.batch.state.notSent')
    case BATCH_STATE.UNCONFIRMED:
      return t('approvals.batch.state.unconfirmed')
    case BATCH_STATE.INFLIGHT:
      return t('approvals.batch.state.inflight')
    default:
      return t('approvals.batch.state.queued')
  }
}

function open() {
  if (phase.value !== 'idle' || !props.reviews.length) return
  note.value = ''
  formOpen.value = true
}

async function submit() {
  if (!canSubmit.value) return
  const sharedNote = note.value.trim()
  formOpen.value = false
  await run({
    kind: 'review',
    params: { disposition: 'confirmed', note: sharedNote },
    entries: props.reviews.map((row) => ({ id: row.id, label: reviewLabel(row) })),
    send: (entry, batchId) =>
      reviewBreakGlass(entry.id, 'confirmed', sharedNote, { batchId, skipErrorToast: true }),
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
  margin: var(--ot-space-xs) 0 var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}

.batch-hint--strong {
  color: var(--ot-text-primary);
}
</style>
