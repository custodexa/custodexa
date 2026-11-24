<template>
  <!-- 審核中心待審的核准／拒絕確認框。批次：確認 → 逐張進度 → 結果。
       單張（single）：同一套送出方式，只放一張；成功或已不在待審時關閉並交給頁面以提示呈現，
       框內只留需要審核人處理的失敗（範圍、本人、連線權限）與沒有回應 -->
  <el-dialog
    :model-value="visible"
    :data-test="single ? 'single-decision-dialog' : 'pending-batch-dialog'"
    :title="title"
    :width="single ? '560px' : '600px'"
    :close-on-click-modal="false"
    :close-on-press-escape="phase === 'idle' || singleResult"
    :show-close="phase === 'idle' || singleResult"
    :before-close="beforeClose"
    @update:model-value="(value) => { if (!value) closeDialog() }"
    @opened="focusPrimary"
  >
    <div class="batch-dialog-body">
      <!-- 單張：確認內容與框內結果共用同一段申請摘要 -->
      <template v-if="single && singleRequest && (phase === 'idle' || singleResult)">
        <p
          class="single-summary"
          data-test="single-summary"
        >
          {{ $t('approvals.single.summary', {
            user: requesterName(singleRequest),
            n: singleLines.length,
            time: formatShortDateTime(singleRequest.created_at),
          }) }}
        </p>
        <p
          v-if="singleRequest.reason"
          class="batch-hint"
        >
          {{ $t('approvals.reasonLine', { reason: singleRequest.reason }) }}
        </p>
        <ul
          class="single-items"
          data-test="single-items"
        >
          <li
            v-for="line in singleLines"
            :key="line.key"
          >
            <strong>{{ line.asset }}</strong> <span>{{ line.detail }}</span>
          </li>
        </ul>
        <p
          v-if="phase === 'idle' && notDelivered"
          class="single-result single-result--warn"
          role="status"
          data-test="single-not-delivered"
        >
          {{ $t('approvals.single.notDelivered') }}
        </p>
        <template v-if="phase === 'idle' && mode === 'approve'">
          <div
            v-if="thresholdText"
            class="single-threshold"
            data-test="single-threshold"
          >
            <el-icon><Users /></el-icon>
            <span>{{ thresholdText }}</span>
          </div>
          <p
            v-else
            class="single-effect"
            data-test="single-effect"
          >
            {{ singleEffect }}
          </p>
        </template>
        <template v-else-if="phase === 'idle' && mode === 'reject'">
          <el-form
            label-position="top"
            @submit.prevent
          >
            <el-form-item
              :label="$t('approvals.rejectReasonLabel')"
              required
              :class="{ 'is-error': noteError }"
            >
              <div
                class="batch-note"
                data-test="batch-note"
              >
                <el-input
                  ref="noteInputRef"
                  v-model="note"
                  type="textarea"
                  :rows="3"
                  :maxlength="NOTE_MAX"
                  :placeholder="$t('approvals.rejectPlaceholder')"
                  @input="noteError = false"
                />
                <p
                  v-if="noteError"
                  class="single-field-error"
                  role="alert"
                  data-test="single-reason-error"
                >
                  {{ $t('approvals.single.reasonRequired') }}
                </p>
              </div>
            </el-form-item>
          </el-form>
          <p
            v-if="votedIncluded"
            class="single-effect"
            data-test="single-reject-includes-voted"
          >
            {{ $t('approvals.single.rejectIncludesVoted', { k: votedIncluded }) }}
          </p>
          <p class="single-effect">
            {{ singleLines.length > 1
              ? $t('approvals.single.rejectEffectMany', { n: singleLines.length })
              : $t('approvals.single.rejectEffect') }}
          </p>
        </template>
        <div
          v-else-if="singleResult"
          :class="['single-result', singleItem?.state === BATCH_STATE.UNCONFIRMED ? 'single-result--warn' : 'single-result--error']"
          role="alert"
          data-test="single-result"
        >
          <el-icon>
            <AlertTriangle v-if="singleItem?.state === BATCH_STATE.UNCONFIRMED" />
            <XCircle v-else />
          </el-icon>
          <span>{{ singleResultText }}</span>
        </div>
      </template>

      <template v-else-if="!single && phase === 'idle' && mode === 'approve'">
        <!-- 批次核准只能照申請內容：逐張逐項列出資產、帳號與時長；開啟時已不在待審的標「會略過」 -->
        <div
          class="batch-sheets"
          data-test="batch-approve-list"
        >
          <section
            v-for="req in rows"
            :key="req.id"
            :class="['batch-sheet', { 'batch-sheet--skip': skipIds.has(req.id) }]"
            data-test="batch-sheet"
            :data-id="req.id"
          >
            <p class="batch-sheet__title">
              {{ requestLabel(req) }}
              <el-tag
                v-if="skipIds.has(req.id)"
                size="small"
                type="info"
                data-test="batch-will-skip"
              >
                {{ $t('approvals.batch.willSkip') }}
              </el-tag>
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
      <template v-else-if="!single && phase === 'idle' && mode === 'reject'">
        <ul class="batch-targets">
          <li
            v-for="req in rows"
            :key="req.id"
            data-test="batch-sheet"
            :data-id="req.id"
          >
            {{ rejectLabel(req) }}
            <el-tag
              v-if="skipIds.has(req.id)"
              size="small"
              type="info"
              data-test="batch-will-skip"
            >
              {{ $t('approvals.batch.willSkip') }}
            </el-tag>
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
      <template v-else-if="!single && phase !== 'idle'">
        <BatchProgressList
          :phase="phase"
          :items="items"
          :progress-text="$t('approvals.batch.progressSheets', { i: current, n: total })"
          :summary-text="summaryText"
          :checking-text="$t('approvals.batch.checking')"
          :describe="describe"
        >
          <template #extra="{ item }">
            <a
              v-if="phase === 'result' && showRequestLink(item)"
              class="batch-link"
              :href="requestHref(item.id)"
              data-test="batch-open-request"
              @click="markInternalNav(item.id)"
            >{{ $t('itemReview.openRequest') }}</a>
          </template>
        </BatchProgressList>
        <p
          v-if="phase === 'result' && summary.unconfirmed"
          class="batch-hint"
        >
          {{ $t('approvals.batch.unconfirmedHint') }}
        </p>
      </template>
      <p
        v-else-if="single && phase !== 'idle' && !singleResult"
        class="batch-hint"
      >
        {{ phase === 'reconciling' ? $t('approvals.batch.checking') : $t('approvals.batch.state.inflight') }}
      </p>
    </div>
    <template #footer>
      <div
        v-if="single"
        class="single-footer"
      >
        <el-button
          v-if="phase === 'idle' && adjustLinkText"
          link
          type="primary"
          data-test="single-adjust"
          @click="toAdjust"
        >
          {{ adjustLinkText }}
        </el-button>
        <span class="single-footer__spacer" />
        <template v-if="phase === 'idle'">
          <el-button @click="closeDialog">
            {{ $t('common.cancel') }}
          </el-button>
          <el-button
            ref="submitRef"
            :type="mode === 'reject' ? 'danger' : 'primary'"
            data-test="batch-submit"
            @click="submit"
          >
            {{ mode === 'reject' ? $t('approvals.reject') : $t('approvals.approve') }}
          </el-button>
        </template>
        <template v-else-if="singleResult">
          <el-button
            data-test="single-close"
            @click="closeDialog"
          >
            {{ $t('common.close') }}
          </el-button>
          <el-button
            v-if="singleItem?.state === BATCH_STATE.UNCONFIRMED"
            type="primary"
            data-test="batch-recheck"
            @click="recheckSingle"
          >
            {{ $t('approvals.batch.recheck') }}
          </el-button>
          <el-button
            v-else-if="singleItem?.code === 'RULE_ACCESS_REQUEST_CONNECT_REQUIRED' && batch?.kind === 'approve'"
            type="danger"
            plain
            data-test="single-reject-instead"
            @click="rejectInstead"
          >
            {{ $t('approvals.single.rejectInstead') }}
          </el-button>
        </template>
        <el-button
          v-else
          type="primary"
          loading
          disabled
        >
          {{ batch?.kind === 'reject' ? $t('approvals.reject') : $t('approvals.single.approving') }}
        </el-button>
      </div>
      <template v-else-if="phase === 'idle'">
        <el-button @click="closeDialog">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          :type="mode === 'reject' ? 'danger' : 'primary'"
          data-test="batch-submit"
          :disabled="!canSubmit"
          @click="submit"
        >
          {{ mode === 'reject'
            ? $t('approvals.batch.rejectSubmit', { n: sendCount })
            : $t('approvals.batch.approveSubmit', { n: sendCount }) }}
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
import { ref, computed, onMounted, onBeforeUnmount, nextTick } from 'vue'
import { Users, AlertTriangle, XCircle } from 'lucide-vue-next'
import { t } from '@/i18n'
import { formatDateTime, formatShortDateTime } from '@/utils/format'
import {
  approveAccessRequest,
  rejectAccessRequest,
  getPendingAccessRequests,
  getAccessRequestHistory,
} from '@/api/accessRequests'
import { useBatchReview, BATCH_STATE, clearBatchProgress } from '@/composables/useBatchReview'
import BatchProgressList from './BatchProgressList.vue'
import {
  approveOutcome,
  formatMinutes,
  hasMyVotes,
  historyVerdict,
  requesterName,
} from './accessRequestBatch'
import {
  itemAssetName,
  accountsText,
  itemAccounts,
  requestHref,
  itemsAwaiting,
  pendingItems,
  itemVotedByMe,
  thresholdFor,
  markInternalNav,
} from '@/components/access-request/approvalsView'

const NOTE_MAX = 1000
// 收尾比對只看歷史第一頁：再往前的單不會是剛才這一批
const HISTORY_PAGE_SIZE = 100
const CONFLICT = 'CONFLICT_ACCESS_REQUEST_STATE'
const ALREADY_APPROVED = 'CONFLICT_ACCESS_REQUEST_ALREADY_APPROVED'

const props = defineProps({
  // 批次：已勾選的待審申請（已依 id 去重）；單張：只有這一張
  requests: { type: Array, required: true },
  currentUserId: { type: Number, default: null },
  // 單張模式：列上或展開區的整張核准、拒絕
  single: { type: Boolean, default: false },
})
const emit = defineEmits(['finished', 'adjust'])

const mode = ref('') // '' | approve | reject
const note = ref('')
const noteError = ref(false)
const submitRef = ref(null)
const noteInputRef = ref(null)
// 重新查詢後確認上一次沒有送達、回到確認畫面時的說明
const notDelivered = ref(false)
// 批次送出後回 409、但重讀時仍在待審的單：寫成狀態有變動，不寫已不在待審
const stillPendingIds = ref(new Set())
const userId = computed(() => props.currentUserId)

// 開啟批次確認時重讀的結果：id → 最新的列；已不在待審的 id 另記為略過
const fresh = ref(new Map())
const skipIds = ref(new Set())
const rows = computed(() => props.requests.map((req) => fresh.value.get(req.id) || req))
const sendCount = computed(() => rows.value.filter((req) => !skipIds.value.has(req.id)).length)

// 核准只送等候這位審核人決定的項（待審且還沒投票）；已投過核准票的項送出會被後端以重複投票整筆拒絕
const awaitingItems = (req) => itemsAwaiting(req, userId.value)
const approveItemIds = (req) => awaitingItems(req).map((item) => item.id)

const durationText = (req) => {
  const minutes = formatMinutes(req.requested_duration_minutes)
  return req.requested_date_start
    ? `${minutes} · ${t('approvals.fromTime', { time: formatDateTime(req.requested_date_start) })}`
    : minutes
}

const requestLabel = (req) => t('approvals.batch.requestLine', { id: req.id, user: requesterName(req) })

const legacyName = (req) => req.asset?.name || t('common.assetRef', { id: req.asset_id })

// 核准確認的逐項明細：只列這次會送出的 pending 項目；舊式無項目單以單頭資產代表
const approveLines = (req) => {
  if (req.items?.length) {
    return awaitingItems(req)
      .map((item) => ({
        key: item.id,
        text: t('approvals.batch.itemLine', {
          asset: itemAssetName(item),
          accounts: accountsText(itemAccounts(item)),
          duration: durationText(req),
        }),
      }))
  }
  return [{
    key: 'request',
    text: t('approvals.batch.itemLine', {
      asset: legacyName(req),
      accounts: accountsText(req.accounts),
      duration: durationText(req),
    }),
  }]
}

// 只列這次會處理的待決項目的資產（已決定的項目不受這一批影響）
const assetNamesText = (req) => {
  const pending = (req.items || []).filter((item) => item.status === 'pending')
  const names = pending.length ? pending.map(itemAssetName) : [legacyName(req)]
  return names.join(t('common.listSeparator'))
}

const rejectLabel = (req) => `${requestLabel(req)} · ${assetNamesText(req)}`

// —— 單張 ——
const singleRequest = computed(() => (props.single ? props.requests[0] || null : null))
const singleLines = computed(() => {
  const req = singleRequest.value
  if (!req) return []
  const start = req.requested_date_start
    ? t('approvals.fromTime', { time: formatDateTime(req.requested_date_start) })
    : t('approvals.single.startNow')
  const duration = formatMinutes(req.requested_duration_minutes)
  if (!req.items?.length) {
    return [{ key: 'request', asset: legacyName(req), detail: t('approvals.single.itemDetail', { accounts: accountsText(req.accounts), duration, start }) }]
  }
  // 核准列出這次會送出的項；拒絕走整張拒絕，後端會拒絕所有待審項（含已投過核准票的項），照實列出
  const list = mode.value === 'reject'
    ? (req.items || []).filter((item) => item.status === 'pending')
    : awaitingItems(req)
  return list.map((item) => ({
    key: item.id,
    asset: itemAssetName(item),
    detail: t('approvals.single.itemDetail', { accounts: accountsText(itemAccounts(item)), duration, start }),
  }))
})
const singleDuration = computed(() => formatMinutes(singleRequest.value?.requested_duration_minutes))
const singleEffect = computed(() => {
  const req = singleRequest.value
  if (!req) return ''
  const user = requesterName(req)
  return singleLines.value.length > 1
    ? t('approvals.single.effectMany', { n: singleLines.value.length, user, duration: singleDuration.value })
    : t('approvals.single.effectOne', { user, duration: singleDuration.value })
})
// 拒絕會一併拒絕的、這位審核人已投過核准票的項數
const votedIncluded = computed(() => {
  const req = singleRequest.value
  if (!req?.items?.length || mode.value !== 'reject') return 0
  return req.items.filter((item) => itemVotedByMe(item, userId.value)).length
})
// 門檻說明只用回應已有的資料：需要幾位、其他已核准的人（不含自己）、這次核准後還要幾位
const thresholdText = computed(() => {
  const req = singleRequest.value
  if (!req) return ''
  const info = thresholdFor(req, userId.value)
  if (!info) return ''
  const { required, left } = info
  const user = requesterName(req)
  const names = info.names.join(t('common.listSeparator'))
  if (!info.names.length) return t('approvals.single.thresholdFirst', { required, left, user })
  if (left === 0) return t('approvals.single.thresholdLast', { required, names, user, duration: singleDuration.value })
  return t('approvals.single.thresholdMid', { required, names, left })
})
const adjustLinkText = computed(() => {
  const req = singleRequest.value
  if (!req?.items?.length) return ''
  const many = singleLines.value.length > 1
  if (mode.value === 'reject') return many ? t('approvals.single.rejectLinkMany') : ''
  return many ? t('approvals.single.adjustLinkMany') : t('approvals.single.adjustLink')
})

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
    // 只以這一次送出的項目判定；不是由我做出的決定：只說這張已不在待審，不寫是誰處理
    const verdict = historyVerdict(decided, entry.kind, item.meta?.itemIds || [], me)
    if (verdict === 'unknown') {
      updates[item.id] = { state: BATCH_STATE.UNCONFIRMED, hint: 'history' }
      continue
    }
    updates[item.id] = verdict === 'mine'
      ? { state: BATCH_STATE.SUCCESS, outcome: { kind: entry.kind === 'reject' ? 'rejected' : 'approved' } }
      : { state: BATCH_STATE.REJECTED, status: 409, code: CONFLICT, reason: '' }
  }
  return updates
}

const { phase, batch, items, current, total, summary, run, recover, recheck, finish } =
  useBatchReview({ surface: props.single ? 'approvals-single' : 'approvals-pending', userId, reconcile })

const singleItem = computed(() => (props.single ? items.value[0] || null : null))
const singleResult = computed(() => props.single && phase.value === 'result' && !!singleItem.value)

const visible = computed(() => mode.value !== '' || phase.value !== 'idle')
const title = computed(() => {
  if (props.single) {
    const id = singleRequest.value?.id ?? ''
    const kind = phase.value === 'idle' ? mode.value : batch.value?.kind
    return kind === 'reject' ? t('approvals.single.rejectTitle', { id }) : t('approvals.single.approveTitle', { id })
  }
  if (phase.value === 'idle') {
    return mode.value === 'reject'
      ? t('approvals.batch.rejectTitle', { n: sendCount.value })
      : t('approvals.batch.approveTitle', { n: sendCount.value })
  }
  return batch.value?.kind === 'reject'
    ? t('approvals.batch.rejectResultTitle')
    : t('approvals.batch.approveResultTitle')
})
const canSubmit = computed(() => {
  if (!sendCount.value) return false
  if (mode.value !== 'reject') return true
  const text = note.value.trim()
  return text.length > 0 && text.length <= NOTE_MAX
})

// 409 分兩種：自己已投過票（重複投票）與申請狀態已變；只有狀態已變才可能「已不在待審」
const isConflict = (item) => item.state === BATCH_STATE.REJECTED && item.status === 409
const isAlreadyVoted = (item) => isConflict(item) && item.code === ALREADY_APPROVED
const isGone = (item) => isConflict(item) && !isAlreadyVoted(item)

// 伺服器沒有接受時的原因：一般人看得懂的句子，不寫「被拒」，不透露是誰處理
const notAppliedReason = (item, kind) => {
  if (isAlreadyVoted(item)) return t('approvals.batch.alreadyVoted')
  if (isGone(item)) return stillPendingIds.value.has(item.id) ? t('approvals.batch.changed') : t('approvals.batch.gone')
  switch (item.code) {
    case 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER':
      return kind === 'reject' ? t('approvals.batch.reasonScopeReject') : t('approvals.batch.reasonScope')
    case 'RULE_ACCESS_REQUEST_SELF_APPROVAL':
      return t('approvals.batch.selfApproval')
    case 'RULE_ACCESS_REQUEST_CONNECT_REQUIRED':
      return t('approvals.batch.reasonConnect')
    default:
      return item.reason || ''
  }
}

const singleResultText = computed(() => {
  const item = singleItem.value
  if (!item) return ''
  const kind = batch.value?.kind
  if (item.state === BATCH_STATE.UNCONFIRMED) {
    return kind === 'reject' ? t('approvals.single.noResponseReject') : t('approvals.single.noResponse')
  }
  switch (item.code) {
    case 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER':
      return kind === 'reject' ? t('approvals.single.notEligibleReject') : t('approvals.single.notEligible')
    case 'RULE_ACCESS_REQUEST_CONNECT_REQUIRED':
      return t('itemReview.connectRequired')
    default:
      return notAppliedReason(item, kind)
  }
})

const summaryText = computed(() => {
  const list = items.value
  const count = (fn) => list.filter(fn).length
  const success = (item) => item.state === BATCH_STATE.SUCCESS
  const parts = []
  if (batch.value?.kind === 'reject') {
    parts.push(['sumRejected', count(success)])
  } else {
    parts.push(['sumApproved', count((item) => success(item) && !item.waiting)])
    parts.push(['sumVoted', count((item) => success(item) && item.waiting)])
  }
  parts.push(['sumNotApplied', summary.value.rejected])
  parts.push(['sumSkipped', summary.value.skipped])
  parts.push(['sumNotSent', summary.value.notSent])
  parts.push(['sumUnconfirmed', summary.value.unconfirmed])
  return parts
    .filter(([, n]) => n > 0)
    .map(([key, n]) => t(`approvals.batch.${key}`, { n }))
    .join(' · ')
})

const describeOutcome = (item) => {
  const outcome = item.outcome
  const user = item.meta?.user || ''
  switch (outcome?.kind) {
    case 'rejected':
      return t('approvals.batch.rejectedDone', { user })
    case 'voted':
      return outcome.required
        ? t('approvals.batch.votedWaiting', {
          received: outcome.received,
          required: outcome.required,
          left: Math.max(0, outcome.required - outcome.received),
        })
        : t('approvals.batch.votedWaitingPlain')
    case 'partly':
      return t('approvals.batch.partlyApproved', { approved: outcome.approved, pending: outcome.pending })
    default:
      return t('approvals.batch.approved', { user })
  }
}

const describe = (item) => {
  switch (item.state) {
    case BATCH_STATE.SUCCESS:
      return describeOutcome(item)
    case BATCH_STATE.REJECTED:
      return t('approvals.batch.notApplied', { reason: notAppliedReason(item, batch.value?.kind) })
    case BATCH_STATE.SKIPPED:
      return t('approvals.batch.skipped')
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

const showRequestLink = (item) => [BATCH_STATE.REJECTED, BATCH_STATE.SKIPPED].includes(item.state)
  || (item.state === BATCH_STATE.UNCONFIRMED && item.hint === 'history')

// 開啟批次確認時重讀所選的單：已不在待審的標「會略過」、不送出；讀不到就照原清單
async function refreshSelection() {
  fresh.value = new Map()
  skipIds.value = new Set()
  try {
    const res = await getPendingAccessRequests({ skipErrorToast: true })
    const list = res?.data || []
    const byId = new Map(list.map((row) => [row.id, row]))
    const skip = new Set()
    const next = new Map()
    for (const req of props.requests) {
      const row = byId.get(req.id)
      if (row) next.set(req.id, row)
      else skip.add(req.id)
    }
    fresh.value = next
    skipIds.value = skip
  } catch {
    // 重讀失敗：維持原清單，送出時由後端逐張判定
  }
}

async function open(nextMode) {
  if (phase.value !== 'idle' || !props.requests.length) return
  note.value = ''
  noteError.value = false
  notDelivered.value = false
  stillPendingIds.value = new Set()
  mode.value = nextMode === 'reject' ? 'reject' : 'approve'
  if (props.single) {
    fresh.value = new Map()
    skipIds.value = new Set()
    redirectFocus = true
    await nextTick()
    focusPrimary()
    return
  }
  await refreshSelection()
}

// 鍵盤路徑：開啟後焦點落在主要按鈕（拒絕時落在理由欄），Enter 即送出。
// 元件庫在對話框開啟後會把焦點移到對話框容器本身：開啟後第一次落到容器時改放到主要按鈕
let redirectFocus = false
function focusPrimary() {
  if (!props.single || phase.value !== 'idle' || !mode.value) return
  if (mode.value === 'reject') noteInputRef.value?.focus?.()
  else submitRef.value?.$el?.focus?.()
}
function onDocumentFocusin(event) {
  if (!redirectFocus) return
  const target = event.target
  const dialog = target?.closest?.('[data-test="single-decision-dialog"]')
  if (!dialog) return
  if (target === dialog || target.classList?.contains('el-dialog')) {
    redirectFocus = false
    focusPrimary()
  }
}

// 焦點留在對話框本身（不在按鈕、輸入框或連結上）時按 Enter 也送出核准；按鈕上的 Enter 由按鈕自己處理
const SKIP_ENTER = new Set(['BUTTON', 'TEXTAREA', 'INPUT', 'A', 'SELECT'])
function onDocumentKeydown(event) {
  if (event.key !== 'Enter' || event.defaultPrevented || event.isComposing) return
  if (!props.single || phase.value !== 'idle' || mode.value !== 'approve') return
  const target = event.target
  if (!target?.closest?.('[data-test="single-decision-dialog"]')) return
  if (SKIP_ENTER.has(target.tagName)) return
  event.preventDefault()
  void submit()
}

const entryFor = (req, kind) => ({
  id: req.id,
  label: rejectLabel(req),
  meta: {
    // 這一次送出涵蓋的項目：核准只送等我決定的項；整張拒絕涵蓋送出當下所有待審項。查回時只以這些項目判定
    itemIds: kind === 'approve' ? approveItemIds(req) : pendingItems(req).map((pending) => pending.id),
    hasItems: !!req.items?.length,
    user: requesterName(req),
  },
  skip: skipIds.value.has(req.id),
})

async function submit() {
  const kind = mode.value
  if (props.single && kind === 'reject' && !note.value.trim()) {
    // 理由空白不送出，標示理由欄
    noteError.value = true
    noteInputRef.value?.focus?.()
    return
  }
  if (!props.single && !canSubmit.value) return
  if (props.single && !singleRequest.value) return
  if (props.single && kind === 'approve' && singleRequest.value.items?.length && !approveItemIds(singleRequest.value).length) return
  notDelivered.value = false
  const sharedNote = note.value.trim()
  const entries = rows.value.map((req) => entryFor(req, kind))
  if (!props.single) mode.value = ''
  await run({
    kind,
    params: kind === 'reject' ? { note: sharedNote } : {},
    entries,
    send: async (entry, batchId) => {
      // 單張不是批次，不帶批次關聯碼；決定內容與批次對單張的送出相同
      const extra = props.single ? {} : { batch_id: batchId }
      const opts = props.single ? { skipErrorToast: true } : { batchId, skipErrorToast: true }
      if (kind === 'reject') {
        await rejectAccessRequest(entry.id, sharedNote, opts)
        return { outcome: { kind: 'rejected' } }
      }
      const body = entry.meta.hasItems
        ? { items: entry.meta.itemIds.map((itemId) => ({ item_id: itemId })), ...extra }
        : { ...extra }
      const res = await approveAccessRequest(entry.id, body, { skipErrorToast: true })
      return approveOutcome(res, entry.meta)
    },
  })
  if (props.single) settleSingle(kind)
  else await markStillPending()
}

// 批次結果有 409 時重讀一次待審：仍在待審的單不寫「已不在待審」
async function markStillPending() {
  const conflicted = items.value.filter((item) => isGone(item))
  if (!conflicted.length) return
  try {
    const res = await getPendingAccessRequests({ skipErrorToast: true })
    const ids = new Set((res?.data || []).map((row) => row.id))
    stillPendingIds.value = new Set(conflicted.filter((item) => ids.has(item.id)).map((item) => item.id))
  } catch {
    // 讀不到時照原說法
  }
}

// 單張送出後：成功或 409 → 關框交給頁面（頁面重讀後依實況說明）；查回仍未送出 → 回到確認並說明；
// 其餘留在框內說明。closing＝審核人正在關閉框：沒有送達與無法確認也關框，交給頁面重讀並留下說明
function settleSingle(kind, { closing = false } = {}) {
  const item = singleItem.value
  if (!item || phase.value !== 'result') return
  const request = singleRequest.value
  const base = { kind, id: item.id, request }
  const close = (info) => {
    finish()
    mode.value = ''
    emit('finished', { ...base, ...info })
  }
  if (item.state === BATCH_STATE.SUCCESS || isConflict(item)) {
    close({
      gone: isGone(item),
      alreadyVoted: isAlreadyVoted(item),
      code: item.code || '',
      outcome: item.outcome || null,
      waiting: !!item.waiting,
    })
    return
  }
  if (item.state === BATCH_STATE.NOT_SENT) {
    if (closing) {
      close({ notDelivered: true })
      return
    }
    finish()
    mode.value = kind
    notDelivered.value = true
    return
  }
  if (closing) close({ unconfirmed: item.state === BATCH_STATE.UNCONFIRMED, failed: item.state !== BATCH_STATE.UNCONFIRMED })
}

async function recheckSingle() {
  const kind = batch.value?.kind
  await recheck()
  settleSingle(kind)
}

// 「可能已生效」的框不論怎麼關閉都先重新查詢一次，再交給頁面重讀清單並留下說明
let closingUnconfirmed = false
async function closeUnconfirmed() {
  if (closingUnconfirmed) return
  closingUnconfirmed = true
  const kind = batch.value?.kind
  try {
    await recheck()
  } catch {
    // 查詢失敗：維持無法確認
  }
  try {
    settleSingle(kind, { closing: true })
  } finally {
    closingUnconfirmed = false
  }
}

function rejectInstead() {
  finish()
  note.value = ''
  noteError.value = false
  mode.value = 'reject'
}

function toAdjust() {
  const id = singleRequest.value?.id
  closeDialog()
  if (id != null) emit('adjust', id)
}

// 右上角關閉與 Esc：先交給這裡判斷，「可能已生效」的框要先重新查詢再關
function beforeClose(done) {
  closeDialog()
  if (!(props.single && singleItem.value?.state === BATCH_STATE.UNCONFIRMED)) done()
}

function closeDialog() {
  if (props.single && phase.value === 'result') {
    if (singleItem.value?.state === BATCH_STATE.UNCONFIRMED) {
      void closeUnconfirmed()
      return
    }
    finish()
  }
  if (phase.value === 'idle') mode.value = ''
}

function done() {
  finish()
  emit('finished', { batch: true })
}

onMounted(() => {
  // 單張的結果不跨頁保存：重新整理後清單本身就是事實
  if (props.single) {
    clearBatchProgress('approvals-single')
    document.addEventListener('keydown', onDocumentKeydown)
    document.addEventListener('focusin', onDocumentFocusin)
  } else recover()
})
onBeforeUnmount(() => {
  document.removeEventListener('keydown', onDocumentKeydown)
  document.removeEventListener('focusin', onDocumentFocusin)
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

.batch-sheet--skip {
  border-style: dashed;
  color: var(--ot-text-secondary);
}

.batch-sheet__title {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
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

.batch-link {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-primary);
}

.single-summary {
  margin: 0 0 var(--ot-space-xs);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.single-items {
  margin: var(--ot-space-md) 0;
  padding: var(--ot-space-sm) var(--ot-space-md);
  list-style: none;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-elevated);
  font-size: var(--ot-font-size-sm);
  line-height: 1.8;
  color: var(--ot-text-secondary);
}

.single-items strong {
  color: var(--ot-text-primary);
}

.single-effect {
  margin: 0;
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-sm);
}

.single-threshold,
.single-result {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}

.single-threshold {
  border: 1px solid color-mix(in srgb, var(--ot-primary) 45%, transparent);
  background: color-mix(in srgb, var(--ot-primary) 10%, transparent);
  color: var(--ot-text-primary);
}

.single-result--error {
  border: 1px solid color-mix(in srgb, var(--ot-danger) 55%, transparent);
  background: color-mix(in srgb, var(--ot-danger) 10%, transparent);
  color: var(--ot-text-primary);
}

.single-result--warn {
  border: 1px solid color-mix(in srgb, var(--ot-warning) 55%, transparent);
  background: color-mix(in srgb, var(--ot-warning) 10%, transparent);
  color: var(--ot-text-primary);
}

.single-threshold .el-icon,
.single-result .el-icon {
  flex: none;
  margin-top: 3px;
}

.single-field-error {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-danger);
  font-size: var(--ot-font-size-xs);
  line-height: 1.5;
}

.single-footer {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.single-footer__spacer {
  flex: 1;
}
</style>
