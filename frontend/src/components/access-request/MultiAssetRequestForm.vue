<template>
  <el-form
    class="multi-request"
    label-position="top"
    data-test="multi-request"
    @submit.prevent="submit"
  >
    <h2>{{ t('multiRequest.title') }}</h2>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
      data-test="request-error"
    />
    <el-form-item :label="t('multiRequest.executor')">
      <el-select
        v-model="executorId"
        :disabled="busy"
        @change="changeExecutor"
      >
        <el-option
          :label="t('multiRequest.self')"
          :value="0"
        />
        <el-option
          v-for="agent in agents"
          :key="agent.id"
          :label="agent.username"
          :value="agent.id"
          :disabled="!agent.active"
        />
      </el-select>
      <PrincipalBadge
        v-if="executor"
        :kind="executor.kind"
        :owner-id="executor.owner_user_id"
        :owner-name="executor.owner_username"
      />
      <p
        v-if="executor"
        data-test="executor-relationship"
      >
        {{ t('multiRequest.relationship') }}
      </p>
      <p
        v-if="agentError"
        role="status"
      >
        {{ agentError }}
      </p>
    </el-form-item>
    <el-form-item
      :label="t('common.requestReason')"
      required
    >
      <el-input
        v-model="reason"
        type="textarea"
        maxlength="1000"
        :disabled="busy"
      />
      <p data-test="reason-hint">
        {{ t('multiRequest.reasonHint') }}
      </p>
    </el-form-item>
    <el-form-item
      :label="t('multiRequest.minutes')"
      required
    >
      <el-input-number
        v-model="duration"
        :min="1"
        :precision="0"
        :disabled="busy"
      />
    </el-form-item>
    <article
      v-for="(item, index) in items"
      :key="item.key"
      class="request-item"
      data-test="request-item"
    >
      <h3>{{ t('multiRequest.item', { n: index + 1 }) }}</h3>
      <p
        v-if="item.error"
        role="alert"
        data-test="item-error"
      >
        {{ item.error }}
      </p>
      <el-form-item
        :label="t('common.asset')"
        required
      >
        <el-select
          v-model="item.assetId"
          filterable
          remote
          :remote-method="searchAssets"
          :loading="searching"
          :disabled="busy"
          @change="loadAccounts(item)"
        >
          <el-option
            v-for="asset in assets"
            :key="asset.id"
            :value="asset.id"
            :label="`${asset.name} (#${asset.id})`"
          />
        </el-select>
      </el-form-item>
      <el-form-item
        :label="t('multiRequest.accounts')"
        required
      >
        <el-select
          v-model="item.accounts"
          multiple
          :disabled="busy || !item.assetId || item.loading || !!item.loadError"
          :loading="item.loading"
        >
          <el-option
            v-if="!executorId"
            :label="t('multiRequest.allAccounts')"
            value="@ALL"
            :disabled="item.accounts.some(a => a !== '@ALL')"
          />
          <el-option
            v-for="account in item.options"
            :key="account.username"
            :value="account.username"
            :label="account.username"
            :disabled="item.accounts.includes('@ALL')"
          />
        </el-select>
      </el-form-item>
      <p v-if="executorId">
        {{ t('multiRequest.agentAccounts') }}
      </p>
      <p
        v-if="item.loading"
        role="status"
      >
        {{ t('multiRequest.accountsLoading') }}
      </p>
      <div v-else-if="item.loadError">
        <p role="alert">
          {{ item.loadError }}
        </p><el-button
          :disabled="busy"
          @click="loadAccounts(item)"
        >
          {{ t('common.refresh') }}
        </el-button>
      </div>
      <p v-else-if="item.assetId && !item.options.length">
        {{ t('multiRequest.accountsEmpty') }}
      </p>
      <el-button
        type="danger"
        plain
        :disabled="busy || items.length === 1"
        data-test="remove-item"
        @click="removeItem(item)"
      >
        {{ t('multiRequest.remove') }}
      </el-button>
    </article>
    <p
      v-if="assetError"
      role="alert"
    >
      {{ assetError }}
    </p>
    <p
      v-if="missingAccounts"
      role="status"
      data-test="missing-accounts"
    >
      {{ t('multiRequest.missingAccounts', { n: missingAccounts }) }}
    </p>
    <div class="request-actions">
      <el-button
        :disabled="busy || items.length >= 20"
        data-test="add-item"
        @click="addItem"
      >
        {{ t('multiRequest.add') }}
      </el-button>
      <el-button
        :disabled="busy"
        @click="emit('cancel')"
      >
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="!valid"
        :loading="busy"
        data-test="submit-request"
        @click="submit"
      >
        {{ t('multiRequest.submit') }}
      </el-button>
    </div>
  </el-form>
</template>
<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { getAssetList } from '@/api/assets'
import { listAssetAccounts } from '@/api/assetAccounts'
import { getMyAgents } from '@/api/agents'
import { createAccessRequest } from '@/api/accessRequests'
import { resolveApiError } from '@/api/error'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
const emit = defineEmits(['created', 'cancel'])
const items = ref([]), agents = ref([]), assets = ref([])
const executorId = ref(0), reason = ref(''), duration = ref(60)
const busy = ref(false), searching = ref(false), error = ref(''), assetError = ref(''), agentError = ref('')
let key = 0, searchVersion = 0, disposed = false
const executor = computed(() => agents.value.find(a => a.id === executorId.value))
const message = e => resolveApiError(e?.response?.data, e?.response?.status)
const missingAccounts = computed(() => items.value.filter(item => !item.accounts.length || (executorId.value && item.accounts.includes('@ALL'))).length)
const valid = computed(() => !busy.value && !!reason.value.trim() && Number.isInteger(duration.value) && duration.value > 0 && items.value.length > 0 && new Set(items.value.map(i => i.assetId)).size === items.value.length && items.value.every(i => i.assetId && !i.loading && !i.loadError && i.options.length && i.accounts.length && (!executorId.value || !i.accounts.includes('@ALL'))))
function addItem() { if (items.value.length < 20) items.value.push({ key: ++key, assetId: null, accounts: [], options: [], loading: false, loadError: '', error: '', version: 0 }) }
function removeItem(item) { if (items.value.length > 1) items.value = items.value.filter(i => i !== item) }
function changeExecutor() { items.value.forEach(i => { i.accounts = i.accounts.filter(a => a !== '@ALL') }) }
async function searchAssets(search = '') {
  const version = ++searchVersion
  searching.value = true; assetError.value = ''
  try { const result = await getAssetList({ search: search || undefined, page: 1, page_size: 50, active: true }); if (!disposed && version === searchVersion) {
      const found = result.data || []
      const selectedIds = new Set(items.value.map(i => i.assetId))
      assets.value = [...assets.value.filter(a => selectedIds.has(a.id) && !found.some(v => v.id === a.id)), ...found]
    } }
  catch (e) { if (!disposed && version === searchVersion) assetError.value = message(e) }
  finally { if (!disposed && version === searchVersion) searching.value = false }
}
async function loadAccounts(item) {
  const version = ++item.version
  item.accounts = []; item.options = []; item.loadError = ''; item.loading = true
  try { const result = await listAssetAccounts(item.assetId, { skipErrorToast: true }); if (!disposed && version === item.version) item.options = result.data || [] }
  catch (e) { if (!disposed && version === item.version) item.loadError = t('multiRequest.accountsFailed') + ' ' + message(e) }
  finally { if (!disposed && version === item.version) item.loading = false }
}
async function submit() {
  if (!valid.value) return
  busy.value = true; error.value = ''; items.value.forEach(item => { item.error = '' })
  const payload = { items: items.value.map(i => ({ asset_id: i.assetId, accounts: [...i.accounts] })), reason: reason.value.trim(), duration_minutes: duration.value }
  if (executorId.value) payload.executor_user_id = executorId.value
  try { const result = await createAccessRequest(payload, { skipErrorToast: true }); if (!disposed) emit('created', result) }
  catch (e) { if (!disposed) {
    error.value = message(e)
    const data = e?.response?.data, index = data?.details?.item_index
    if (data?.code === 'VALIDATION_ACCOUNT_NOT_ON_ASSET' && Number.isInteger(index) && items.value[index]?.assetId === data.details.asset_id) items.value[index].error = message(e)
  } }
  finally { if (!disposed) busy.value = false }
}
addItem()
onMounted(async () => {
  searchAssets()
  try { const result = await getMyAgents(); if (!disposed) agents.value = result.data || [] }
  catch (e) { if (!disposed) agentError.value = message(e) }
})
onBeforeUnmount(() => { disposed = true; searchVersion++ })
</script>
<style scoped>
.multi-request { padding: var(--ot-space-lg); border: 1px solid var(--ot-border); border-radius: var(--ot-radius-lg); background: var(--ot-bg-surface); }
h2 { font-size: var(--ot-font-size-xl); }
h3 { font-size: var(--ot-font-size-lg); }
.request-item { margin: var(--ot-space-md) 0; padding: var(--ot-space-md); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); }
p { font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
.request-actions { display: flex; flex-wrap: wrap; gap: var(--ot-space-sm); }
</style>
