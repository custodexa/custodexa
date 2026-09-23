<template>
  <section
    class="item-review"
    data-test="item-review"
  >
    <!-- 單頭：審核者在按下決定前要先知道「誰申請、替誰做」，原本得回列表對照 -->
    <header
      class="item-review__header"
      data-test="review-header"
    >
      <p>{{ t('itemReview.requesterLine', { name: requesterName }) }}</p>
      <p data-test="review-representation">
        {{ representationLine }}
      </p>
    </header>
    <p class="item-review__hint">
      {{ t('itemReview.scopeUnknown') }}
    </p>
    <article
      v-for="item in request.items"
      :key="item.id"
      class="item-review__row"
      data-test="decision-item"
    >
      <h3>{{ assetLabels[item.asset_id]?.name || t('itemReview.assetNameUnreadable', { id: item.asset_id }) }}</h3>
      <!-- 內部識別碼收進展開層：首層要能一眼看到的是資產與帳號範圍，
           識別碼只在對帳時才需要 -->
      <details class="item-review__ids">
        <summary>{{ t('itemReview.identifiers') }}</summary>
        <p class="item-review__hint">
          {{ t('common.assetRef', { id: item.asset_id }) }} · {{ t('multiRequest.itemId', { id: item.id }) }}
        </p>
      </details>
      <p>{{ (item.accounts || []).length && !(item.accounts || []).includes('@ALL') ? item.accounts.join(t('common.listSeparator')) : t('multiRequest.allAccounts') }} · {{ t('common.minutesN', { n: request.requested_duration_minutes }) }}</p>
      <el-tag
        v-if="item.status !== 'pending'"
        :type="decidedTagType(item.status)"
        data-test="item-decided-state"
      >
        {{ t(`multiRequest.state.${item.status}`) }}
      </el-tag>
      <template v-else>
        <!-- 一次只展開一項：整張單把每一項的選項、時長、帳號、理由全部攤開時，
             第二項的決策控制與送出結果都落在可見範圍之外，要捲才看得到。
             收合後每項只剩一行標題，展開的那一項與黏底的送出列同時在畫面上 -->
        <el-button
          class="item-review__toggle"
          :aria-expanded="String(expanded === item.id)"
          :aria-controls="`item-body-${item.id}`"
          data-test="toggle-item"
          @click="toggleItem(item.id)"
        >
          {{ expanded === item.id ? t('common.collapse') : t('common.expand') }}
        </el-button>
        <!-- 決策控制自己捲：整項攤開時，選項＋時長＋時間＋帳號＋理由的高度超過
             一個畫面，radio 在最上、送出結果在最下，兩端不會同時看得見。
             把這段的高度封在視窗高度之內，決策列與黏底送出列就留在同一可見範圍 -->
        <div
          v-show="expanded === item.id"
          :id="`item-body-${item.id}`"
          class="item-review__body"
          data-test="item-body"
        >
          <el-radio-group
            v-model="forms[item.id].action"
            :disabled="busy || !!results[item.id]?.ok || forms[item.id].blocked"
          >
            <el-radio
              value="approve"
              :disabled="voted(item)"
            >
              {{ t('approvals.approve') }}
            </el-radio>
            <el-radio value="reject">
              {{ t('approvals.reject') }}
            </el-radio>
            <el-radio value="remove">
              {{ t('itemReview.remove') }}
            </el-radio>
          </el-radio-group>
          <div
            v-if="forms[item.id].action === 'approve'"
            class="item-review__fields"
          >
            <el-form label-position="top">
              <el-form-item :label="t('multiRequest.minutes')">
                <el-input-number
                  v-model="forms[item.id].duration"
                  :min="1"
                  :max="ceiling(item)"
                  :precision="0"
                  :disabled="busy || !!results[item.id]?.ok || forms[item.id].blocked"
                />
              </el-form-item>
              <el-form-item :label="t('approvals.startTimeLabel')">
                <el-date-picker
                  v-model="forms[item.id].start"
                  type="datetime"
                  :disabled-date="date => disabledDate(date, item)"
                  :disabled="busy || !!results[item.id]?.ok || forms[item.id].blocked"
                  :placeholder="request.requested_date_start ? formatDateTime(request.requested_date_start) : t('approvals.immediateEffect')"
                />
              </el-form-item>
              <el-form-item :label="t('multiRequest.accounts')">
                <el-select
                  v-model="forms[item.id].accounts"
                  multiple
                  :disabled="busy || !!results[item.id]?.ok || forms[item.id].blocked || forms[item.id].loading || !!forms[item.id].loadError"
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
                  :disabled="busy || !!results[item.id]?.ok || forms[item.id].blocked"
                  @click="narrowAll(item)"
                >
                  {{ t('itemReview.narrow') }}
                </el-button>
                <p
                  v-if="forms[item.id].loadError"
                  role="alert"
                >
                  {{ forms[item.id].loadError }}
                </p>
              </el-form-item>
            </el-form>
          </div>
          <p data-test="remove-explanation">
            {{ t('itemReview.removeHelp') }}
          </p>
          <el-input
            v-model="forms[item.id].note"
            type="textarea"
            :aria-label="t('approvals.note')"
            :placeholder="t('itemReview.note')"
            maxlength="1000"
            :disabled="busy || !!results[item.id]?.ok || forms[item.id].blocked"
          />
        </div>
      </template>
      <p
        v-if="results[item.id]"
        :id="`item-result-${item.id}`"
        :class="results[item.id].ok ? 'item-review__ok' : 'item-review__error'"
        role="status"
        data-test="decision-result"
      >
        {{ results[item.id].text }}
      </p>
      <!-- 送出後這一列不會消失：決策結果與理由留在原位，並給直達申請單的出口 -->
      <p
        v-if="results[item.id]?.ok && results[item.id].note"
        class="item-review__hint"
        data-test="decision-note"
      >
        {{ t('itemReview.decisionNote', { note: results[item.id].note }) }}
      </p>
    </article>
    <section
      v-if="selected.length"
      class="item-review__summary"
      data-test="decision-summary"
    >
      <h3>{{ t('itemReview.summary') }}</h3>
      <p
        v-for="item in selected"
        :key="item.id"
      >
        {{ assetLabels[item.asset_id]?.name || t('common.assetRef', { id: item.asset_id }) }} — {{ t(`itemReview.action.${forms[item.id].action}`) }}<template v-if="forms[item.id].action === 'approve'">
          · {{ t('common.minutesN', { n: forms[item.id].duration }) }} · {{ forms[item.id].accounts.includes('@ALL') ? t('multiRequest.allAccounts') : forms[item.id].accounts.join(t('common.listSeparator')) }} · {{ forms[item.id].start || request.requested_date_start ? formatDateTime(forms[item.id].start || request.requested_date_start) : t('approvals.immediateEffect') }}
        </template><template v-if="forms[item.id].note">
          · {{ forms[item.id].note }}
        </template>
      </p>
    </section>
    <p
      v-if="validation"
      role="alert"
    >
      {{ validation }}
    </p>
    <!-- 送出列黏在底部：項目一多就得捲回底部找按鈕，決定與送出中間隔了一整頁 -->
    <div
      class="item-review__bar"
      data-test="review-bar"
    >
      <!-- 出口依角色決定：任務視角要 audit:view，沒有那個權限的審核者點下去
           只會被路由丟回儀表板。純審核者留在審核中心，開在歷史頁的同一張單上 -->
      <a
        v-if="anyDecided"
        :href="openRequestHref"
        data-test="open-request-link"
      >{{ t('itemReview.openRequest') }}</a>
      <!-- 伺服器拒絕後，黏底列要講得出還缺什麼，不能只留一個可按的送出鈕 -->
      <span
        v-if="rejectedCount"
        class="item-review__error"
        data-test="review-bar-rejected"
      >{{ t('itemReview.itemsRejected', { n: rejectedCount }) }}</span>
      <span>{{ t('itemReview.selectedCount', { n: selected.length }) }}</span>
      <el-button
        type="primary"
        :disabled="busy || !selected.length"
        :loading="busy"
        data-test="submit-decisions"
        @click="submit"
      >
        {{ t('itemReview.submit') }}
      </el-button>
    </div>
  </section>
</template>
<script setup>
import { ref, computed, watch, nextTick, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { resolveApiError } from '@/api/error'
import { approveAccessRequest, rejectAccessRequestItem } from '@/api/accessRequests'
import { listAssetAccounts } from '@/api/assetAccounts'
import { useAssetLabels } from '@/composables/useAssetLabels'
import { useRoles } from '@/composables/useRoles'
const props = defineProps({ request: { type: Object, required: true }, actorId: { type: Number, default: null } })
const emit = defineEmits(['decided'])
// audit:view 才進得了任務視角；其餘審核者導回審核中心歷史頁的這張單
const { isPrivileged } = useRoles()
const openRequestHref = computed(() => isPrivileged.value
  ? `/audit/agent-tasks/${props.request.id}`
  : `/approvals?request=${props.request.id}`)
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
const assetLabels = useAssetLabels(() => (props.request.items || []).map(item => ({ id: item.asset_id, name: item.asset?.name || (props.request.asset_id === item.asset_id ? props.request.asset?.name : '') })))
const forms = ref({}), results = ref({}), busy = ref(false), validation = ref('')
// 展開中的項目（一次一項）。預設落在第一個還沒決定的項上，
// 讀者一進來就看得到要做的那一項，不必先點一次
const expanded = ref(null)
let disposed = false
const decidedTagType = status => status === 'approved' ? 'success' : ['rejected', 'revoked'].includes(status) ? 'danger' : 'info'
const scope = item => item.decision_bounds?.accounts ?? item.accounts ?? []
const ceiling = item => item.decision_bounds?.max_duration ?? props.request.requested_duration_minutes
const isAll = item => !scope(item).length || scope(item).includes('@ALL')
const voted = item => (item.approvals || []).some(v => v.approver_id === props.actorId)
watch(() => props.request, request => {
  for (const item of request.items || []) {
    if (!forms.value[item.id]) forms.value[item.id] = { action: '', duration: ceiling(item), start: null, accounts: isAll(item) ? ['@ALL'] : [...scope(item)], allAllowed: isAll(item), options: isAll(item) ? [] : [...scope(item)], note: '', loading: false, loadError: '', blocked: false }
  }
}, { immediate: true })
const pendingItems = computed(() => (props.request.items || []).filter(item => item.status === 'pending' && !results.value[item.id]?.ok))
// 展開／送出後把該項帶進可見範圍：控制與結果就地顯示才算「不用捲」
function reveal(id) { nextTick(() => { document.getElementById(id)?.scrollIntoView({ block: 'nearest' }) }) }
function toggleItem(id) {
  expanded.value = expanded.value === id ? null : id
  if (expanded.value === id) reveal(`item-body-${id}`)
}
// 決定完一項就把下一個待決的項接上來，讀者不必回頭找下一項在哪
watch([pendingItems, results], () => {
  if (expanded.value && pendingItems.value.some(item => item.id === expanded.value)) return
  expanded.value = pendingItems.value[0]?.id ?? null
}, { immediate: true, deep: true })
const anyDecided = computed(() => Object.values(results.value).some(result => result?.ok))
const rejectedCount = computed(() => Object.values(results.value).filter(result => result && !result.ok).length)
const selected = computed(() => (props.request.items || []).filter(i => i.status === 'pending' && forms.value[i.id]?.action && !results.value[i.id]?.ok && !forms.value[i.id]?.blocked))
const minimum = item => Math.max(Date.now(), Date.parse(item?.decision_bounds?.earliest_start || props.request.requested_date_start || '') || 0)
function disabledDate(date, item) { return new Date(date).setHours(23, 59, 59, 999) < minimum(item) }
function scopeChanged(item) { const f = forms.value[item.id]; if (f.accounts.length && !f.accounts.includes('@ALL')) f.allAllowed = false }
async function narrowAll(item) {
  const f = forms.value[item.id]
  f.loading = true; f.loadError = ''
  try { const response = await listAssetAccounts(item.asset_id, { skipErrorToast: true }); if (!disposed) { f.options = (response.data || []).map(a => a.username); f.accounts = []; f.allAllowed = false } }
  catch (e) { if (!disposed) f.loadError = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (!disposed) f.loading = false }
}
async function submit() {
  if (busy.value || !selected.value.length) return
  validation.value = ''
  for (const item of selected.value) {
    const f = forms.value[item.id]
    const badApprove = f.action === 'approve' && (voted(item) || !Number.isInteger(f.duration) || f.duration < 1 || f.duration > ceiling(item) || f.loading || f.loadError || !f.accounts.length || f.accounts.some(a => a === '@ALL' ? !f.allAllowed : !f.options.includes(a)) || (f.start && (!Number.isFinite(new Date(f.start).getTime()) || new Date(f.start).getTime() < minimum(item))))
    if (badApprove || (f.action !== 'approve' && !f.note.trim())) { validation.value = t('itemReview.invalid'); return }
  }
  busy.value = true
  let changed = false
  const batch = [...selected.value]
  for (const item of batch) {
    if (disposed) break
    const f = forms.value[item.id]
    try {
      let response
      if (f.action === 'reject') response = await rejectAccessRequestItem(props.request.id, item.id, f.note.trim())
      else {
        const data = { item_id: item.id, note: f.note.trim() }
        if (f.action === 'remove') data.remove = true
        else { data.duration_minutes = f.duration; data.accounts = [...f.accounts]; if (f.start) data.date_start = new Date(f.start).toISOString() }
        response = await approveAccessRequest(props.request.id, data)
      }
      if (!disposed) {
        const updated = response?.items?.find(i => i.id === item.id)
        results.value[item.id] = { ok: true, text: updated?.status === 'pending' ? t('itemReview.voteRecorded') : t('itemReview.saved'), note: f.note.trim() }
        reveal(`item-result-${item.id}`)
        // 後端回傳的才是事實：把該項狀態寫回列上，否則畫面仍停在舊的 radio，
        // 而側欄／頁籤的待審數又已經變了，同一頁出現兩個互相矛盾的答案
        if (updated?.status) item.status = updated.status
        else if (f.action !== 'approve') item.status = 'rejected'
        changed = true
      }
    } catch (e) {
      if (!disposed) {
        results.value[item.id] = { ok: false, text: resolveApiError(e?.response?.data, e?.response?.status) }
        if (e?.response?.data?.code === 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER') f.blocked = true
      }
    }
  }
  if (!disposed) {
    busy.value = false
    if (changed) emit('decided', props.request.id)
  }
}
onBeforeUnmount(() => { disposed = true })
</script>
<style scoped>
.item-review { padding: var(--ot-space-md); }
.item-review__row, .item-review__summary { padding: var(--ot-space-md); margin-bottom: var(--ot-space-md); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); }
.item-review__summary { background: var(--ot-bg-elevated); }
h3 { font-size: var(--ot-font-size-lg); font-weight: 600; }
.item-review__hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
.item-review__toggle { margin-bottom: var(--ot-space-sm); }
/* 48vh：加上單頭、項目標題與黏底送出列，整組仍落在一個 900px 高的視窗內 */
.item-review__body { max-height: 48vh; overflow-y: auto; }
.item-review__ids summary { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); cursor: pointer; }
.item-review__ids p { margin: var(--ot-space-xs) 0 0; }
.item-review__header { margin-bottom: var(--ot-space-sm); }
.item-review__header p { margin: 0; font-size: var(--ot-font-size-sm); color: var(--ot-text-primary); }
.item-review__bar { position: sticky; bottom: 0; display: flex; align-items: center; justify-content: flex-end; gap: var(--ot-space-md); padding: var(--ot-space-sm) var(--ot-space-md); background: var(--ot-bg-elevated); border-top: 1px solid var(--ot-border-subtle); }
.item-review__bar span { font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
.item-review__ok { color: var(--ot-success); }
.item-review__error { color: var(--ot-danger); }
</style>
