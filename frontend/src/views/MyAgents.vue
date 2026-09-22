<template>
  <div class="my-agents">
    <PageHeader
      :title="t('agentPrincipals.myTitle')"
      :description="t('agentPrincipals.myDescription')"
    >
      <template #actions>
        <el-button
          :loading="loading"
          @click="load"
        >
          {{ t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>
    <p class="my-agents__hint">
      {{ t('agentPrincipals.ownerFixed') }}
    </p>
    <el-alert
      v-if="!policy"
      :title="t('agentPrincipals.policyUnknown')"
      type="info"
      :closable="false"
      show-icon
      data-test="policy-unavailable"
    />
    <p
      v-else-if="!policy.enabled"
      data-test="policy-disabled"
    >
      {{ t('agentPrincipals.emptyDisabled') }}
    </p>
    <section v-else>
      <p>{{ t('agentPrincipals.quota', { current: policy.current, max: policy.max_per_owner }) }}</p>
      <el-button
        v-if="!creating"
        :disabled="loading || policy.current >= policy.max_per_owner"
        data-test="create-my-agent"
        @click="creating = true; drawer = false"
      >
        {{ t('agentPrincipals.create') }}
      </el-button>
      <el-form
        v-else
        label-position="top"
        data-test="create-my-agent-form"
        @submit.prevent="create"
      >
        <el-form-item :label="t('common.username')">
          <el-input
            v-model="username"
            :disabled="saving"
            maxlength="50"
          />
        </el-form-item>
        <el-form-item :label="t('agentPrincipals.purpose')">
          <el-input
            v-model="purpose"
            :disabled="saving"
            type="textarea"
            maxlength="2000"
          />
        </el-form-item>
        <p
          v-if="createError"
          role="alert"
        >
          {{ createError }}
        </p>
        <el-button
          :disabled="saving"
          @click="creating = false"
        >
          {{ t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="saving"
          data-test="save-my-agent"
          @click="create"
        >
          {{ t('agentPrincipals.create') }}
        </el-button>
      </el-form>
    </section>
    <el-alert
      v-if="error"
      :title="t('agentPrincipals.loadFailed')"
      :description="error"
      type="error"
      :closable="false"
      show-icon
    />
    <section
      v-loading="loading"
      class="my-agents__list"
      :aria-busy="loading"
    >
      <p
        v-if="!loading && !error && !agents.length && policy?.enabled !== false"
        data-test="my-agents-empty"
      >
        {{ t('agentPrincipals.empty') }}
      </p>
      <article
        v-for="agent in agents"
        :key="agent.id"
        class="my-agents__row"
        data-test="my-agent-row"
      >
        <div>
          <h2>{{ agent.username }}</h2><PrincipalBadge
            :kind="agent.kind"
            :owner-id="agent.owner_user_id"
            :owner-name="t('agentPrincipals.you')"
          />
        </div>
        <div>
          <el-tag :type="agent.breaker_pending_at ? 'warning' : agent.active ? 'success' : 'info'">
            {{ agent.breaker_pending_at ? t('agentBreaker.pending') : t(agent.active ? 'common.enabled' : 'common.disabled') }}
          </el-tag>
        </div>
        <div class="my-agents__actions">
          <el-button @click="openKeys(agent)">
            {{ t('agentPrincipals.keys') }}
          </el-button><a
            v-if="agent.breaker_pending_at"
            :href="`/agent-breakers?user_id=${agent.id}`"
          >{{ t('agentBreaker.resolve') }}</a>
        </div>
      </article>
    </section>
    <TokenDrawer
      v-model="drawer"
      :principal="selected"
      :owner-name="t('agentPrincipals.you')"
      @changed="load"
    />
  </div>
</template>
<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { getMyAgents, createMyAgent } from '@/api/agents'
import { resolveApiError } from '@/api/error'
import PageHeader from '@/components/PageHeader.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
import TokenDrawer from '@/components/agent/TokenDrawer.vue'
const agents = ref([])
const loading = ref(false)
const error = ref('')
const selected = ref({})
const drawer = ref(false)
const policy = ref(null), creating = ref(false), saving = ref(false), username = ref(''), purpose = ref(''), createError = ref('')
let epoch = 0
async function load() {
  const version = ++epoch
  loading.value = true
  error.value = ''
  try {
    const result = await getMyAgents()
    if (version !== epoch) return
    agents.value = result.data || []
    policy.value = result.self_create || null
    if (drawer.value) {
      const updated = agents.value.find(agent => agent.id === selected.value.id)
      if (updated) selected.value = updated
      else drawer.value = false
    }
  } catch (cause) {
    if (version === epoch) {
      agents.value = []; policy.value = null
      const data = cause?.response?.data
      if (cause?.response?.status === 403 && data?.code === 'RULE_AGENT_SELF_CREATE_DISABLED' && data.self_create?.enabled === false) { policy.value = data.self_create; creating.value = false }
      else error.value = resolveApiError(data, cause?.response?.status)
    }
  } finally { if (version === epoch) loading.value = false }
}
async function create() {
  if (!policy.value?.enabled || saving.value || policy.value.current >= policy.value.max_per_owner) return
  createError.value = ''
  if (username.value.trim().length < 3 || username.value.trim().length > 50 || !purpose.value.trim()) { createError.value = t('agentPrincipals.selfRequired'); return }
  saving.value = true
  const version = epoch
  try { await createMyAgent({ username: username.value.trim(), purpose: purpose.value.trim() }); if (version === epoch) { creating.value = false; username.value = ''; purpose.value = ''; await load() } }
  catch (e) { if (version === epoch) createError.value = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { saving.value = false }
}
function openKeys(agent) { creating.value = false; selected.value = agent; drawer.value = true }
onMounted(load)
onBeforeUnmount(() => { epoch++ })
</script>
<style scoped>
.my-agents { color: var(--ot-text-primary); }
.my-agents__hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); margin: var(--ot-space-md) 0; }
.my-agents__list { margin-top: var(--ot-space-lg); padding: var(--ot-space-md); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); background: var(--ot-bg-surface); }
.my-agents__row { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; align-items: center; gap: var(--ot-space-md); padding: var(--ot-space-md); border-bottom: 1px solid var(--ot-border-subtle); }
h2 { font-size: var(--ot-font-size-lg); margin: 0 0 var(--ot-space-sm); }
.my-agents__actions { display: flex; align-items: center; gap: var(--ot-space-sm); flex-wrap: wrap; }
a { color: var(--ot-primary); }
@media (max-width: 45rem) { .my-agents__row { grid-template-columns: 1fr; } }
</style>
