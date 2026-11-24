<template>
  <section
    class="item-review"
    data-test="item-review"
    :data-mode="adjusting ? 'adjust' : 'read'"
  >
    <!-- 預設唯讀：先看清楚誰申請什麼，決定入口只有底部這一組拒絕、核准 -->
    <template v-if="!adjusting">
      <header
        class="item-review__header"
        data-test="review-header"
      >
        <span
          v-if="direct"
          class="item-review__direct"
          data-test="direct-label"
        >
          <el-icon><Bell /></el-icon>{{ t('itemReview.direct') }}
        </span>
        <strong class="item-review__summary">{{ t('approvals.detail.summary', { user: requesterName, n: itemCount, duration: durationText }) }}</strong>
        <span class="item-review__meta">
          {{ t('approvals.requestedAt', { time: formatDateTime(request.created_at) }) }} · <span data-test="review-representation">{{ representationLine }}</span>
        </span>
      </header>
      <div
        v-if="request.reason"
        class="item-review__reason"
      >
        <p class="item-review__label">
          {{ t('approvals.detail.reason') }}
        </p>
        <p
          class="item-review__reason-text"
          data-test="review-reason"
        >
          {{ request.reason }}
        </p>
      </div>
      <div class="item-review__table-wrap">
        <table
          class="item-review__table"
          data-test="detail-table"
        >
          <thead>
            <tr>
              <th>{{ t('approvals.detail.colAsset') }}</th>
              <th>{{ t('approvals.detail.colAccounts') }}</th>
              <th>{{ t('approvals.detail.colDuration') }}</th>
              <th>{{ anyResult ? t('approvals.detail.colStartOrResult') : t('approvals.detail.colStart') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="item in request.items || []"
              :key="item.id"
              data-test="detail-item"
              :data-id="item.id"
            >
              <td><strong>{{ itemAssetName(item) }}</strong></td>
              <td>{{ accountsText(itemAccounts(item)) }}</td>
              <td>{{ durationText }}</td>
              <td>
                <span
                  v-if="outcomes[item.id]"
                  :class="`item-review__res item-review__res--${outcomes[item.id].tone}`"
                  data-test="decision-result"
                >{{ outcomes[item.id].text }}</span>
                <span
                  v-else-if="itemVotedByMe(item, actorId)"
                  class="item-review__res item-review__res--info"
                  data-test="decision-result"
                >{{ votedText(item) }}</span>
                <el-tag
                  v-else-if="item.status !== 'pending'"
                  :type="decidedTagType(item.status)"
                  size="small"
                  data-test="item-decided-state"
                >
                  {{ t(`multiRequest.state.${item.status}`) }}
                </el-tag>
                <span v-else>{{ startText }}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <footer
        class="item-review__bar"
        data-test="review-bar"
      >
        <el-button
          v-if="pendingAll.length"
          link
          type="primary"
          data-test="enter-adjust"
          @click="emit('adjust')"
        >
          <el-icon><Pencil /></el-icon>{{ itemCount > 1 ? t('approvals.detail.adjustLink') : t('approvals.detail.adjustLinkOne') }}
        </el-button>
        <a
          :href="openRequestHref"
          class="item-review__link"
          data-test="open-request-link"
          @click="markInternalNav(request.id)"
        >{{ t('itemReview.openRequest') }}</a>
        <span class="item-review__spacer" />
        <!-- 核准只送等候這位審核人決定的台；拒絕走整張拒絕，會拒絕所有還在待審的台（含已投過核准票的台） -->
        <span
          v-if="awaiting.length && votedMine.length"
          class="item-review__hint item-review__hint--line"
          data-test="scope-split"
        >{{ t('approvals.detail.scopeSplit', { n: awaiting.length, m: pendingAll.length }) }}</span>
        <span
          v-else-if="awaiting.length && awaiting.length < itemCount"
          class="item-review__hint item-review__hint--line"
          data-test="remaining-only"
        >{{ t('approvals.detail.remainingOnly', { n: awaiting.length }) }}</span>
        <span
          v-if="pendingAll.length && !awaiting.length"
          class="item-review__hint item-review__hint--line"
          data-test="nothing-left"
        >{{ t('itemReview.nothingLeft') }}<template v-if="votedMine.length">{{ t('common.listSeparator') === '、' ? '；' : '; ' }}{{ t('approvals.detail.rejectAllPending', { m: pendingAll.length }) }}</template></span>
        <el-button
          v-if="pendingAll.length"
          type="danger"
          plain
          data-test="detail-reject"
          @click="emit('reject')"
        >
          {{ t('approvals.reject') }}
        </el-button>
        <el-button
          v-if="awaiting.length"
          type="primary"
          data-test="detail-approve"
          @click="emit('approve')"
        >
          {{ t('approvals.approve') }}
        </el-button>
      </footer>
    </template>

    <!-- 逐項調整：明確進入的模式，可以不送出而退出；退出時已選的決定不保留 -->
    <template v-else>
      <header
        class="item-review__mode"
        data-test="adjust-header"
      >
        <el-icon><Pencil /></el-icon>
        <strong>{{ t('itemReview.modeTitle', { id: request.id }) }}</strong>
        <span class="item-review__meta">{{ t('itemReview.modeHint') }}</span>
        <span class="item-review__spacer" />
        <el-button
          link
          type="primary"
          data-test="cancel-adjust-top"
          @click="cancelAdjust"
        >
          {{ t('itemReview.cancelAdjust') }}
        </el-button>
      </header>
      <article
        v-for="item in request.items || []"
        :key="item.id"
        :class="['item-review__row', { 'item-review__row--error': !!errors[item.id] }]"
        data-test="decision-item"
        :data-id="item.id"
      >
        <div class="item-review__row-head">
          <strong>{{ itemAssetName(item) }}</strong>
          <span class="item-review__meta">{{ accountsText(itemAccounts(item)) }} · {{ durationText }}</span>
          <el-tag
            v-if="item.status !== 'pending'"
            :type="decidedTagType(item.status)"
            size="small"
            data-test="item-decided-state"
          >
            {{ t(`multiRequest.state.${item.status}`) }}
          </el-tag>
          <template v-else-if="collapsed(item)">
            <span
              class="item-review__chip"
              data-test="decision-chip"
            >{{ chipText(item) }}</span>
            <span
              v-if="errors[item.id]"
              class="item-review__error item-review__chip-error"
              data-test="chip-error"
            >{{ errors[item.id].short }}</span>
            <span class="item-review__spacer" />
            <el-button
              link
              type="primary"
              data-test="change-item"
              @click="editing = item.id"
            >
              {{ t('itemReview.change') }}
            </el-button>
          </template>
        </div>
        <div
          v-if="item.status === 'pending' && !collapsed(item)"
          :id="`item-body-${item.id}`"
          class="item-review__body"
          data-test="item-body"
        >
          <el-radio-group
            v-model="forms[item.id].action"
            :disabled="busy || forms[item.id].blocked"
            data-test="item-actions"
          >
            <el-radio
              value="approve"
              :disabled="voted(item)"
            >
              {{ t('itemReview.action.approve') }}
            </el-radio>
            <el-radio value="reject">
              {{ t('itemReview.action.reject') }}
            </el-radio>
          </el-radio-group>
          <p
            v-if="voted(item)"
            class="item-review__hint"
          >
            {{ t('itemReview.err.voted') }}
          </p>
          <el-form
            v-if="forms[item.id].action === 'approve'"
            label-position="top"
            class="item-review__fields"
            @submit.prevent
          >
            <div class="item-review__field-row">
              <el-form-item
                :label="t('itemReview.durationLabel', { max: ceiling(item) })"
                :class="{ 'is-error': !!fieldError(item, 'duration') }"
              >
                <el-input-number
                  :id="`item-${item.id}-duration`"
                  v-model="forms[item.id].duration"
                  :min="1"
                  :max="ceiling(item)"
                  :precision="0"
                  :disabled="busy"
                />
                <p
                  v-if="fieldError(item, 'duration')"
                  class="item-review__field-error"
                  data-test="field-error"
                >
                  {{ fieldError(item, 'duration') }}
                </p>
              </el-form-item>
              <el-form-item
                :label="t('approvals.startTimeLabel')"
                :class="{ 'is-error': !!fieldError(item, 'start') }"
              >
                <el-date-picker
                  :id="`item-${item.id}-start`"
                  v-model="forms[item.id].start"
                  type="datetime"
                  :disabled-date="date => disabledDate(date, item)"
                  :disabled="busy"
                  :placeholder="request.requested_date_start ? formatDateTime(request.requested_date_start) : t('approvals.immediateEffect')"
                />
                <p
                  v-if="fieldError(item, 'start')"
                  class="item-review__field-error"
                  data-test="field-error"
                >
                  {{ fieldError(item, 'start') }}
                </p>
              </el-form-item>
            </div>
            <el-form-item
              :label="t('itemReview.accountsLabel')"
              :class="{ 'is-error': !!fieldError(item, 'accounts') }"
            >
              <div class="item-review__accounts">
                <el-select
                  :id="`item-${item.id}-accounts`"
                  v-model="forms[item.id].accounts"
                  multiple
                  :disabled="busy || forms[item.id].loading || !!forms[item.id].loadError"
                  @change="scopeChanged(item)"
                >
                  <el-option
                    v-if="forms[item.id].allAllowed"
                    value="@ALL"
                    :label="t('multiRequest.allAccounts')"
                    :disabled="forms[item.id].accounts.some(a => a !== '@ALL')"
                  />
                  <el-option
                    v-for="name in forms[item.id].options"
                    :key="name"
                    :value="name"
                    :label="name"
                    :disabled="forms[item.id].accounts.includes('@ALL')"
                  />
                </el-select>
                <el-button
                  v-if="forms[item.id].allAllowed"
                  :disabled="busy"
                  @click="narrowAll(item)"
                >
                  {{ t('itemReview.narrow') }}
                </el-button>
              </div>
              <p
                v-if="forms[item.id].loadError"
                role="alert"
                class="item-review__error"
              >
                {{ forms[item.id].loadError }}
              </p>
              <p
                v-if="fieldError(item, 'accounts')"
                class="item-review__field-error"
                data-test="field-error"
              >
                {{ fieldError(item, 'accounts') }}
              </p>
            </el-form-item>
            <el-form-item :label="t('itemReview.noteApprove')">
              <el-input
                v-model="forms[item.id].note"
                type="textarea"
                :rows="2"
                maxlength="1000"
                :placeholder="t('approvals.notePlaceholder')"
                :disabled="busy"
              />
            </el-form-item>
          </el-form>
          <el-form
            v-else-if="forms[item.id].action === 'reject'"
            label-position="top"
            class="item-review__fields"
            @submit.prevent
          >
            <el-form-item
              :label="t('itemReview.noteReject')"
              required
              :class="{ 'is-error': !!fieldError(item, 'note') }"
            >
              <el-input
                :id="`item-${item.id}-note`"
                v-model="forms[item.id].note"
                type="textarea"
                :rows="2"
                maxlength="1000"
                :placeholder="t('itemReview.noteRejectPh')"
                :disabled="busy"
                data-test="reject-note"
                @input="clearError(item)"
              />
              <p
                v-if="fieldError(item, 'note')"
                class="item-review__field-error"
                data-test="field-error"
              >
                {{ fieldError(item, 'note') }}
              </p>
            </el-form-item>
          </el-form>
        </div>
        <p
          v-if="outcomes[item.id]"
          :class="`item-review__res item-review__res--${outcomes[item.id].tone}`"
          role="status"
          data-test="decision-result"
        >
          {{ outcomes[item.id].text }}
        </p>
      </article>
      <footer
        class="item-review__bar"
        data-test="review-bar"
      >
        <a
          :href="openRequestHref"
          class="item-review__link"
          data-test="open-request-link"
          @click="markInternalNav(request.id)"
        >{{ t('itemReview.openRequest') }}</a>
        <span class="item-review__spacer" />
        <span
          :class="['item-review__status', { 'item-review__error': errorCount || needOneAlert }]"
          :role="errorCount || needOneAlert ? 'alert' : 'status'"
          data-test="adjust-status"
        >{{ statusText }}</span>
        <el-button
          data-test="cancel-adjust"
          @click="cancelAdjust"
        >
          {{ t('itemReview.cancelAdjust') }}
        </el-button>
        <!-- 還沒選時是外框按鈕但仍可聚焦，按下說明要先選；不以 disabled 退出 Tab 順序 -->
        <el-button
          :type="selected.length ? 'primary' : 'default'"
          :loading="busy"
          data-test="submit-decisions"
          @click="submit"
        >
          {{ selected.length ? t('itemReview.submit', { n: selected.length }) : t('itemReview.submitPlain') }}
        </el-button>
      </footer>
    </template>
  </section>
</template>
<script setup>
import { ref, computed, watch, nextTick, onBeforeUnmount } from 'vue'
import { Bell, Pencil } from 'lucide-vue-next'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { resolveApiError } from '@/api/error'
import { approveAccessRequest, rejectAccessRequestItem } from '@/api/accessRequests'
import { listAssetAccounts } from '@/api/assetAccounts'
import {
  itemAssetName,
  accountsText,
  itemAccounts,
  itemVotedByMe,
  itemsAwaiting,
  pendingItems,
  requestHref,
  formatMinutes,
  markInternalNav,
} from './approvalsView'

const props = defineProps({
  request: { type: Object, required: true },
  actorId: { type: Number, default: null },
  // 逐項調整模式由頁面持有：列上確認框的「改用逐項調整」也要能直接進入
  adjusting: { type: Boolean, default: false },
  // 從通知連結直達的這一張
  direct: { type: Boolean, default: false },
  // 這一次送出後各項的結果（頁面重讀清單後仍保留）：{ [itemId]: { text, tone } }
  outcomes: { type: Object, default: () => ({}) },
})
const emit = defineEmits(['approve', 'reject', 'adjust', 'cancel-adjust', 'decided'])

const openRequestHref = computed(() => requestHref(props.request.id))
const requesterName = computed(() => props.request.requester?.username || t('itemReview.unknownPerson'))
const onBehalfOf = computed(() => props.request.on_behalf_of_username || '')
// 執行者與申請人是兩個位置：executor 與 requester 同一個 id 時，那不是「委派」，
// 只是同一個主體自己開自己做。委派關係只在兩者不同時成立
const delegatedExecutor = computed(() => {
  const executor = props.request.executor
  if (!executor) return null
  const requesterId = props.request.requester_id ?? props.request.requester?.id
  return executor.id && requesterId && executor.id !== requesterId ? executor : null
})
// 申請人自己是不是 agent：只看申請人那一側。executor 是 agent 不代表申請人是
// ——人類指派 agent 去做，申請人仍然是人，那張單不是「自主執行」
const requesterIsAgent = computed(() => {
  const kind = props.request.requester?.kind
    || (!delegatedExecutor.value ? props.request.executor?.kind : '')
  return kind === 'agent'
})
// 負責人不等於代表對象：agent 自己開的單沒有人在背後指示，把 owner 寫成「代表」
// 會讓審核者以為這是那個人要求的。owner 只作為責任歸屬附記，與任務頁同口徑；
// 委派單的 executor.owner 不是申請人的負責人，不在這條線上借用
const ownerName = computed(() => props.request.requester?.owner_username
  || (!delegatedExecutor.value ? props.request.executor?.owner_username : '')
  || '')
// 身分關係一句話說完，四種形態各有各的說法：
// 1. 單上明載代表對象 → 代表：某人
// 2. 人類申請、agent 執行 → 由該 agent 執行，代表申請人（這不是自主執行）
// 3. agent 自己開單且無代表對象 → 自主執行（有負責人就附上）
// 4. 人類申請且沒有另指執行者 → 本人操作
const representationLine = computed(() => {
  if (onBehalfOf.value) return t('itemReview.onBehalfOf', { name: onBehalfOf.value })
  if (delegatedExecutor.value) {
    return t('itemReview.executedByFor', { agent: delegatedExecutor.value.username || t('agentPrincipals.unavailable'), requester: requesterName.value })
  }
  if (requesterIsAgent.value) {
    return ownerName.value ? t('itemReview.autonomousWithOwner', { name: ownerName.value }) : t('itemReview.autonomous')
  }
  return t('itemReview.selfOperated')
})

const itemCount = computed(() => (props.request.items || []).length)
const durationText = computed(() => formatMinutes(props.request.requested_duration_minutes))
const startText = computed(() => (props.request.requested_date_start
  ? formatDateTime(props.request.requested_date_start)
  : t('approvals.detail.startNow')))
const pendingAll = computed(() => pendingItems(props.request))
const awaiting = computed(() => itemsAwaiting(props.request, props.actorId))
const votedMine = computed(() => pendingAll.value.filter((item) => itemVotedByMe(item, props.actorId)))
const anyResult = computed(() => (props.request.items || []).some((item) =>
  item.status !== 'pending' || props.outcomes[item.id] || itemVotedByMe(item, props.actorId)))

const decidedTagType = (status) => (status === 'approved' ? 'success' : ['rejected', 'revoked'].includes(status) ? 'danger' : 'info')
const votedText = (item) => {
  const required = item.approvals_required || 1
  const received = item.approvals_received || (item.approvals || []).length
  return t('itemReview.res.voted', { received, required, left: Math.max(0, required - received), user: requesterName.value })
}

// —— 逐項調整 ——
const forms = ref({})
const busy = ref(false)
const errors = ref({})
const needOneAlert = ref(false)
// 正在編輯的那一台：其餘已選好決定的台收合成一行徽章
const editing = ref(null)
let disposed = false

const scope = (item) => item.decision_bounds?.accounts ?? item.accounts ?? []
const ceiling = (item) => item.decision_bounds?.max_duration ?? props.request.requested_duration_minutes
const isAll = (item) => !scope(item).length || scope(item).includes('@ALL')
const voted = (item) => itemVotedByMe(item, props.actorId)
const blankForm = (item) => ({
  action: '',
  duration: ceiling(item),
  start: null,
  accounts: isAll(item) ? ['@ALL'] : [...scope(item)],
  allAllowed: isAll(item),
  options: isAll(item) ? [] : [...scope(item)],
  note: '',
  loading: false,
  loadError: '',
  blocked: false,
})
function resetForms() {
  const next = {}
  for (const item of props.request.items || []) next[item.id] = blankForm(item)
  forms.value = next
  errors.value = {}
  needOneAlert.value = false
  editing.value = null
}
resetForms()
// 進入或退出調整模式都從空白開始：取消、換頁籤、重新整理都不保留已選的決定
watch(() => props.adjusting, () => resetForms())
watch(() => props.request.items, (list) => {
  for (const item of list || []) {
    if (!forms.value[item.id]) forms.value[item.id] = blankForm(item)
  }
})

// 選了（或改了）某一台的決定，就把那一台當作正在編輯的台：其餘已選的台收合成徽章
watch(() => (props.request.items || []).map((item) => forms.value[item.id]?.action || ''), (now, before) => {
  const list = props.request.items || []
  now.forEach((action, index) => {
    if (action && action !== (before || [])[index]) {
      editing.value = list[index].id
      needOneAlert.value = false
      clearError(list[index])
    }
  })
})
const collapsed = (item) => !!forms.value[item.id]?.action && editing.value !== item.id
const selected = computed(() => (props.request.items || []).filter((item) =>
  item.status === 'pending' && forms.value[item.id]?.action && !forms.value[item.id]?.blocked))
const errorCount = computed(() => Object.keys(errors.value).length)
const statusText = computed(() => {
  if (errorCount.value) return t('itemReview.fixCount', { n: errorCount.value })
  if (selected.value.length) return t('itemReview.chosenCount', { n: selected.value.length })
  return t('itemReview.needOne')
})

function chipText(item) {
  const f = forms.value[item.id]
  if (f.action === 'reject') return t('itemReview.chipReject')
  const parts = [f.duration < ceiling(item)
    ? t('itemReview.chipApprove', { duration: formatMinutes(f.duration) })
    : t('itemReview.chipApprovePlain')]
  if (!f.accounts.includes('@ALL') && f.accounts.length && (isAll(item) || f.accounts.length < scope(item).length)) {
    parts.push(t('itemReview.chipLimit', { accounts: f.accounts.join(t('common.listSeparator')) }))
  }
  return parts.join(' · ')
}
const fieldError = (item, field) => (errors.value[item.id]?.field === field ? errors.value[item.id].text : '')
function clearError(item) {
  if (!errors.value[item.id]) return
  const next = { ...errors.value }
  delete next[item.id]
  errors.value = next
}
function cancelAdjust() {
  resetForms()
  emit('cancel-adjust')
}

const minimum = (item) => Math.max(Date.now(), Date.parse(item?.decision_bounds?.earliest_start || props.request.requested_date_start || '') || 0)
function disabledDate(date, item) { return new Date(date).setHours(23, 59, 59, 999) < minimum(item) }
function scopeChanged(item) { const f = forms.value[item.id]; if (f.accounts.length && !f.accounts.includes('@ALL')) f.allAllowed = false; clearError(item) }
async function narrowAll(item) {
  const f = forms.value[item.id]
  f.loading = true; f.loadError = ''
  try { const response = await listAssetAccounts(item.asset_id, { skipErrorToast: true }); if (!disposed) { f.options = (response.data || []).map(a => a.username); f.accounts = []; f.allAllowed = false } }
  catch (e) { if (!disposed) f.loadError = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (!disposed) f.loading = false }
}

// 逐台逐欄檢查：錯誤指到該台該欄，有任何錯誤時一項都不送
function validate(item) {
  const f = forms.value[item.id]
  const max = ceiling(item)
  if (f.action === 'reject') {
    return f.note.trim() ? null : { field: 'note', text: t('itemReview.err.reasonReject'), short: t('itemReview.err.reasonRejectShort') }
  }
  if (voted(item)) return { field: 'action', text: t('itemReview.err.voted'), short: t('itemReview.err.voted') }
  if (!Number.isInteger(f.duration) || f.duration < 1 || f.duration > max) {
    return { field: 'duration', text: t('itemReview.err.durationMax', { max }), short: t('itemReview.err.durationMaxShort', { max }) }
  }
  const badAccounts = f.loading || f.loadError || !f.accounts.length
    || f.accounts.some(a => (a === '@ALL' ? !f.allAllowed : !f.options.includes(a)))
  if (badAccounts) return { field: 'accounts', text: t('itemReview.err.accounts'), short: t('itemReview.err.accountsShort') }
  if (f.start && (!Number.isFinite(new Date(f.start).getTime()) || new Date(f.start).getTime() < minimum(item))) {
    return { field: 'start', text: t('itemReview.err.startPast'), short: t('itemReview.err.startPastShort') }
  }
  return null
}

const actionLabel = (action) => t(`itemReview.action.${action}`)

async function submit() {
  if (busy.value) return
  if (!selected.value.length) {
    needOneAlert.value = true
    return
  }
  needOneAlert.value = false
  const found = {}
  for (const item of selected.value) {
    const err = validate(item)
    if (err) found[item.id] = err
  }
  errors.value = found
  const firstId = Object.keys(found)[0]
  if (firstId) {
    // 第一個出錯的台展開、焦點移到該欄
    editing.value = Number(firstId)
    await nextTick()
    document.getElementById(`item-${firstId}-${found[firstId].field}`)?.focus?.()
    return
  }
  busy.value = true
  const results = []
  for (const item of [...selected.value]) {
    if (disposed) break
    const f = forms.value[item.id]
    const action = f.action
    try {
      let response
      if (action === 'reject') {
        response = await rejectAccessRequestItem(props.request.id, item.id, f.note.trim(), { skipErrorToast: true })
      } else {
        const data = { item_id: item.id, note: f.note.trim(), duration_minutes: f.duration, accounts: [...f.accounts] }
        if (f.start) data.date_start = new Date(f.start).toISOString()
        response = await approveAccessRequest(props.request.id, data, { skipErrorToast: true })
      }
      const updated = response?.items?.find((i) => i.id === item.id)
      let kind = action === 'reject' ? 'rejected' : 'approved'
      if (action === 'approve' && updated?.status === 'pending') kind = 'voted'
      results.push({
        itemId: item.id,
        kind,
        action,
        asset: itemAssetName(item),
        duration: f.duration,
        shortened: action === 'approve' && f.duration < ceiling(item),
        received: updated?.approvals_received,
        required: updated?.approvals_required,
      })
    } catch (e) {
      const status = e?.response?.status
      const code = e?.response?.data?.code
      if (status === 409 && code !== 'CONFLICT_ACCESS_REQUEST_ALREADY_APPROVED') {
        results.push({ itemId: item.id, kind: 'gone', action, asset: itemAssetName(item) })
      } else if (status >= 400 && status < 500) {
        // 申請人（或執行者）已不持有常設連線權：核准被擋、仍可拒絕，說明以審核人的角度寫；
        // 重複投票（409 已核准過）不是「已不在待審」，照實說這一台你已核准過
        const text = code === 'RULE_ACCESS_REQUEST_CONNECT_REQUIRED'
          ? t('itemReview.connectRequired')
          : code === 'CONFLICT_ACCESS_REQUEST_ALREADY_APPROVED'
            ? t('itemReview.err.alreadyVoted')
            : resolveApiError(e?.response?.data, status)
        if (code === 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER') f.blocked = true
        results.push({ itemId: item.id, kind: 'failed', action, asset: itemAssetName(item), text })
      } else {
        results.push({ itemId: item.id, kind: 'unknown', action, asset: itemAssetName(item) })
      }
    }
  }
  if (disposed) return
  busy.value = false
  // 已送出的台不再保留選擇；失敗而仍可再決定的台保留，讓審核人改了再送
  for (const r of results) {
    if (r.kind !== 'failed' || forms.value[r.itemId]?.blocked) {
      forms.value[r.itemId] = { ...blankForm((props.request.items || []).find((i) => i.id === r.itemId) || {}), blocked: forms.value[r.itemId]?.blocked }
    }
  }
  editing.value = null
  emit('decided', { requestId: props.request.id, results, actionLabel })
}
onBeforeUnmount(() => { disposed = true })
defineExpose({ forms, errors, editing, submit, narrowAll, scopeChanged })
</script>
<style scoped>
.item-review { display: flex; flex-direction: column; gap: var(--ot-space-md); padding: var(--ot-space-md) var(--ot-space-lg); }
.item-review__header { display: flex; flex-wrap: wrap; align-items: baseline; gap: var(--ot-space-xs) var(--ot-space-md); }
.item-review__summary { font-size: var(--ot-font-size-md); color: var(--ot-text-primary); }
.item-review__meta { font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
.item-review__direct { display: inline-flex; align-items: center; gap: var(--ot-space-xs); padding: 0 var(--ot-space-sm); border: 1px solid color-mix(in srgb, var(--ot-info) 55%, transparent); border-radius: var(--ot-radius-sm); background: color-mix(in srgb, var(--ot-info) 12%, transparent); color: var(--ot-info); font-size: var(--ot-font-size-xs); line-height: 22px; }
.item-review__label { margin: 0 0 var(--ot-space-xs); font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
.item-review__reason-text { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; color: var(--ot-text-primary); }
.item-review__table-wrap { overflow-x: auto; border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); }
.item-review__table { width: 100%; border-collapse: collapse; font-size: var(--ot-font-size-sm); }
.item-review__table th { padding: var(--ot-space-sm) var(--ot-space-md); text-align: left; font-weight: 400; color: var(--ot-text-secondary); background: var(--ot-bg-elevated); }
.item-review__table td { padding: var(--ot-space-sm) var(--ot-space-md); border-top: 1px solid var(--ot-border-subtle); color: var(--ot-text-primary); vertical-align: top; }
.item-review__bar { display: flex; flex-wrap: wrap; align-items: center; gap: var(--ot-space-sm) var(--ot-space-md); padding-top: var(--ot-space-sm); border-top: 1px solid var(--ot-border-subtle); }
.item-review__bar .el-button + .el-button { margin-left: 0; }
.item-review__bar .el-icon { margin-right: var(--ot-space-xs); }
.item-review__link { font-size: var(--ot-font-size-sm); color: var(--ot-primary); text-decoration: none; }
.item-review__link:hover { text-decoration: underline; }
.item-review__spacer { flex: 1; }
.item-review__hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
/* 核准與拒絕各自涵蓋幾台的說明獨占一行、放在按鈕上方，不把按鈕擠到下一行 */
.item-review__hint--line { flex-basis: 100%; order: -1; text-align: right; }
.item-review__status { font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
.item-review__mode { display: flex; flex-wrap: wrap; align-items: center; gap: var(--ot-space-sm); }
.item-review__row { padding: var(--ot-space-sm) var(--ot-space-md); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); }
.item-review__row--error { border-color: var(--ot-danger); }
.item-review__row-head { display: flex; flex-wrap: wrap; align-items: center; gap: var(--ot-space-xs) var(--ot-space-md); }
.item-review__chip { padding: 0 var(--ot-space-sm); border: 1px solid color-mix(in srgb, var(--ot-primary) 55%, transparent); border-radius: 999px; color: var(--ot-primary); font-size: var(--ot-font-size-xs); line-height: 22px; }
.item-review__chip-error { font-size: var(--ot-font-size-sm); }
.item-review__body { margin-top: var(--ot-space-sm); }
.item-review__fields { margin-top: var(--ot-space-sm); }
.item-review__field-row { display: flex; flex-wrap: wrap; gap: 0 var(--ot-space-lg); }
.item-review__accounts { display: flex; gap: var(--ot-space-sm); width: 100%; }
.item-review__accounts .el-select { flex: 1; }
.item-review__res { font-size: var(--ot-font-size-sm); }
.item-review__res--ok { color: var(--ot-success); }
.item-review__res--info { color: var(--ot-info); }
.item-review__res--warn { color: var(--ot-warning); }
.item-review__res--error, .item-review__error { color: var(--ot-danger); }
p.item-review__res { margin: var(--ot-space-xs) 0 0; }
.item-review__field-error { width: 100%; margin: var(--ot-space-xs) 0 0; color: var(--ot-danger); font-size: var(--ot-font-size-xs); line-height: 1.5; }
</style>
