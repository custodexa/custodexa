<template>
  <div class="my-agents">
    <PageHeader
      :title="t('agentPrincipals.myTitle')"
      :description="t('agentPrincipals.myDescription')"
    >
      <template #actions>
        <HelpTip :content="`${t('agentPrincipals.plainLanguage')}\n${t('agentPrincipals.ownerFixed')}`" />
        <el-button
          :loading="loading"
          @click="load"
        >
          {{ t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>
    <el-alert
      v-if="!policy"
      :title="t('agentPrincipals.policyUnknown')"
      type="info"
      :closable="false"
      show-icon
      data-test="policy-unavailable"
    />
    <el-alert
      v-else-if="!policy.enabled"
      :title="t('agentPrincipals.emptyDisabled')"
      type="info"
      :closable="false"
      show-icon
      data-test="policy-disabled"
    />
    <section v-if="policy?.enabled">
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
      <EmptyState
        v-if="!loading && !error && !agents.length"
        :title="t('agentPrincipals.empty')"
        :hint="policy?.enabled ? t('agentPrincipals.emptyEnabled') : undefined"
        :icon="Bot"
        data-test="my-agents-empty"
      />
      <article
        v-for="agent in agents"
        :key="agent.id"
        class="my-agents__row"
        data-test="my-agent-row"
      >
        <div>
          <h2>{{ agent.username }}</h2><template v-if="keySummaries[agent.id]">
            <StatBlock
              data-test="my-agent-keys"
              :items="[
                { value: keySummaries[agent.id].usable, label: t('agentPrincipals.statUsable'), dataTest: 'my-agent-usable-stat' },
                { value: keySummaries[agent.id].suspended, label: t('agentPrincipals.statSuspended'), dataTest: 'my-agent-suspended-stat' },
              ]"
            />
            <p
              v-if="keySummaries[agent.id].next"
              class="my-agents__keys"
              data-test="my-agent-next-expiry"
            >
              {{ t('agentPrincipals.summaryNextExpiry', { name: keySummaries[agent.id].next.name, time: formatDateTime(keySummaries[agent.id].next.expires_at) }) }}
            </p>
          </template><PrincipalBadge
            :kind="agent.kind"
            :owner-id="agent.owner_user_id"
            :owner-name="ownerLabel(agent)"
          />
        </div>
        <div>
          <el-tag :type="agent.breaker_pending_at ? 'warning' : agent.active ? 'success' : 'info'">
            {{ agent.breaker_pending_at ? t('agentBreaker.pending') : t(agent.active ? 'common.enabled' : 'common.disabled') }}
          </el-tag>
        </div>
        <div class="my-agents__actions">
          <!-- 「發新的」獨立成一顆：發一把鑰匙原本要先開抽屜、再捲過整份清單
               才找得到表單。這顆直接把游標帶到發證表單的名稱欄 -->
          <el-button
            type="primary"
            data-test="issue-key"
            @click="openKeys(agent, true)"
          >
            {{ t('agentPrincipals.issue') }}
          </el-button><el-button
            data-test="manage-keys"
            @click="openKeys(agent)"
          >
            {{ t('agentPrincipals.manageKeys') }}
          </el-button><a
            :href="`/agent-breakers?user_id=${agent.id}`"
            data-test="breaker-entry"
          >{{ agent.breaker_pending_at ? t('agentBreaker.resolve') : t('agentBreaker.title') }}</a>
        </div>
      </article>
    </section>
    <TokenDrawer
      v-model="drawer"
      :principal="selected"
      :owner-name="ownerLabel(selected)"
      :focus-issue="drawerFocusIssue"
      @changed="load"
    />
  </div>
</template>
<script setup>
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { getMyAgents, createMyAgent, getAgentTokens } from '@/api/agents'
import { formatDateTime } from '@/utils/format'
import { resolveApiError } from '@/api/error'
import { Bot } from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import HelpTip from '@/components/HelpTip.vue'
import EmptyState from '@/components/EmptyState.vue'
import StatBlock from '@/components/StatBlock.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
import TokenDrawer from '@/components/agent/TokenDrawer.vue'
const agents = ref([])
const loading = ref(false)
const error = ref('')
const selected = ref({})
const drawer = ref(false)
const drawerFocusIssue = ref(false)
// 首屏就要答得出「哪把快到期」：原本得逐一開抽屜、捲到底逐張卡片比日期。
// 摘要讀取失敗時整列不呈現（寧可沒有，不要顯示一個看起來精確的錯數字）。
const keySummaries = ref({})
const policy = ref(null), creating = ref(false), saving = ref(false), username = ref(''), purpose = ref(''), createError = ref('')
const me = (() => { try { return JSON.parse(localStorage.getItem('user') || '{}') } catch { return {} } })()
// 負責人在別處一律顯示帳號名；此頁多帶一個「（您）」，不改成另一種寫法
function ownerLabel(agent) {
  const name = agent?.owner_username || me.username || ''
  return name ? t('agentPrincipals.youSuffix', { name }) : t('agentPrincipals.you')
}
// 自助建立與名下清單是兩件事：政策關閉只收掉建立入口，清單照列
function readPolicy(payload) {
  const selfCreate = payload?.self_create || {}
  const enabled = payload?.self_create_enabled ?? selfCreate.enabled
  return enabled === undefined ? null : { ...selfCreate, enabled }
}
let epoch = 0
async function load() {
  const version = ++epoch
  loading.value = true
  error.value = ''
  try {
    const result = await getMyAgents()
    if (version !== epoch) return
    agents.value = result.data || []
    policy.value = readPolicy(result)
    if (drawer.value) {
      const updated = agents.value.find(agent => agent.id === selected.value.id)
      if (updated) selected.value = updated
      else drawer.value = false
    }
    loadKeySummaries(version)
  } catch (cause) {
    if (version === epoch) {
      agents.value = []; policy.value = null
      const data = cause?.response?.data
      if (cause?.response?.status === 403 && data?.code === 'RULE_AGENT_SELF_CREATE_DISABLED' && readPolicy(data)?.enabled === false) { policy.value = readPolicy(data); creating.value = false }
      else error.value = resolveApiError(data, cause?.response?.status)
    }
  } finally { if (version === epoch) loading.value = false }
}
function summarise(list) {
  const now = Date.now()
  const usable = list.filter(token => !token.revoked_at && !token.suspended_at && Date.parse(token.expires_at) > now)
  const next = usable.slice().sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at))[0] || null
  return { usable: usable.length, next, suspended: list.filter(token => token.suspended_at && !token.revoked_at).length }
}
async function loadKeySummaries(version) {
  const snapshot = agents.value.slice()
  keySummaries.value = {}
  await Promise.all(snapshot.map(async agent => {
    try {
      const result = await getAgentTokens(agent.id)
      if (version === epoch) keySummaries.value = { ...keySummaries.value, [agent.id]: summarise(result.data || []) }
    } catch { /* 讀不到就不顯示摘要；抽屜內仍可讀完整清單與錯誤原因 */ }
  }))
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
function openKeys(agent, focusIssue = false) { creating.value = false; selected.value = agent; drawerFocusIssue.value = focusIssue; drawer.value = true }
onMounted(load)
onBeforeUnmount(() => { epoch++ })
</script>
<style scoped>
.my-agents { color: var(--ot-text-primary); }
.my-agents__keys { color: var(--ot-text-primary); font-size: var(--ot-font-size-md); margin: 0 0 var(--ot-space-sm); }
.my-agents__list { margin-top: var(--ot-space-lg); padding: var(--ot-space-md); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-lg); background: var(--ot-bg-surface); }
/* 中欄原為 minmax(0,1fr)：只有一個狀態標時，標籤被推到列中段，左右各一大片空白 */
.my-agents__row { display: grid; grid-template-columns: minmax(0, 1fr) auto auto; align-items: center; gap: var(--ot-space-md); padding: var(--ot-space-md); border-bottom: 1px solid var(--ot-border-subtle); }
h2 { font-size: var(--ot-font-size-lg); font-weight: 600; margin: 0 0 var(--ot-space-sm); }
.my-agents__actions { display: flex; align-items: center; gap: var(--ot-space-sm); flex-wrap: wrap; }
a { color: var(--ot-primary); }
@media (max-width: 45rem) { .my-agents__row { grid-template-columns: 1fr; } }
</style>
