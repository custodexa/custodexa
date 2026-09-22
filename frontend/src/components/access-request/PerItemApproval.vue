<template>
  <section
    class="item-review"
    data-test="item-review"
  >
    <p class="item-review__hint">
      {{ t('itemReview.scopeUnknown') }}
    </p>
    <article
      v-for="item in request.items"
      :key="item.id"
      class="item-review__row"
      data-test="decision-item"
    >
      <h3>{{ assetLabels[item.asset_id]?.name || t('common.assetRef', { id: item.asset_id }) }}</h3>
      <p class="item-review__hint">
        {{ t('common.assetRef', { id: item.asset_id }) }} · {{ t('multiRequest.itemId', { id: item.id }) }}
      </p>
      <p>{{ (item.accounts || []).length && !(item.accounts || []).includes('@ALL') ? item.accounts.join(t('common.listSeparator')) : t('multiRequest.allAccounts') }} · {{ t('common.minutesN', { n: request.requested_duration_minutes }) }}</p>
      <p v-if="item.status !== 'pending'">
        {{ t(`multiRequest.state.${item.status}`) }}
      </p>
      <template v-else>
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
      </template>
      <p
        v-if="results[item.id]"
        :class="results[item.id].ok ? 'item-review__ok' : 'item-review__error'"
        role="status"
        data-test="decision-result"
      >
        {{ results[item.id].text }}
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
        {{ t('multiRequest.itemId', { id: item.id }) }} — {{ t(`itemReview.action.${forms[item.id].action}`) }}<template v-if="forms[item.id].action === 'approve'">
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
    <el-button
      type="primary"
      :disabled="busy || !selected.length"
      :loading="busy"
      data-test="submit-decisions"
      @click="submit"
    >
      {{ t('itemReview.submit') }}
    </el-button>
  </section>
</template>
<script setup>
import { ref, computed, watch, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { resolveApiError } from '@/api/error'
import { approveAccessRequest, rejectAccessRequestItem } from '@/api/accessRequests'
import { listAssetAccounts } from '@/api/assetAccounts'
import { useAssetLabels } from '@/composables/useAssetLabels'
const props = defineProps({ request: { type: Object, required: true }, actorId: { type: Number, default: null } })
const assetLabels = useAssetLabels(() => (props.request.items || []).map(item => ({ id: item.asset_id, name: item.asset?.name || (props.request.asset_id === item.asset_id ? props.request.asset?.name : '') })))
const forms = ref({}), results = ref({}), busy = ref(false), validation = ref('')
let disposed = false
const scope = item => item.decision_bounds?.accounts ?? item.accounts ?? []
const ceiling = item => item.decision_bounds?.max_duration ?? props.request.requested_duration_minutes
const isAll = item => !scope(item).length || scope(item).includes('@ALL')
const voted = item => (item.approvals || []).some(v => v.approver_id === props.actorId)
watch(() => props.request, request => {
  for (const item of request.items || []) {
    if (!forms.value[item.id]) forms.value[item.id] = { action: '', duration: ceiling(item), start: null, accounts: isAll(item) ? ['@ALL'] : [...scope(item)], allAllowed: isAll(item), options: isAll(item) ? [] : [...scope(item)], note: '', loading: false, loadError: '', blocked: false }
  }
}, { immediate: true })
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
        results.value[item.id] = { ok: true, text: updated?.status === 'pending' ? t('itemReview.voteRecorded') : t('itemReview.saved') }
      }
    } catch (e) {
      if (!disposed) {
        results.value[item.id] = { ok: false, text: resolveApiError(e?.response?.data, e?.response?.status) }
        if (e?.response?.data?.code === 'RULE_ACCESS_REQUEST_NOT_ELIGIBLE_APPROVER') f.blocked = true
      }
    }
  }
  if (!disposed) busy.value = false
}
onBeforeUnmount(() => { disposed = true })
</script>
<style scoped>
.item-review { padding: var(--ot-space-md); }
.item-review__row, .item-review__summary { padding: var(--ot-space-md); margin-bottom: var(--ot-space-md); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); }
.item-review__summary { background: var(--ot-bg-elevated); }
h3 { font-size: var(--ot-font-size-lg); }
.item-review__hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
.item-review__ok { color: var(--ot-success); }
.item-review__error { color: var(--ot-danger); }
</style>
