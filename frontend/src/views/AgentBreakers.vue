<template>
  <div>
    <PageHeader :title="t('agentBreaker.title')">
      <template #actions>
        <el-button
          :loading="loading"
          @click="load"
        >
          {{ t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>
    <div v-if="!targetId">
      <el-input-number
        v-model="selectedId"
        :min="1"
        :precision="0"
        :aria-label="t('agentTasks.subject')"
      />
      <el-button @click="openSelected">
        {{ t('common.search') }}
      </el-button>
      <article
        v-for="user in choices"
        :key="user.id"
        data-test="breaker-principal"
      >
        <el-button @click="choose(user.id)">
          {{ user.username }} · #{{ user.id }}
        </el-button><span>{{ t(user.breaker_pending_at ? 'agentBreaker.pending' : 'agentBreaker.noPending') }}</span>
      </article>
      <el-pagination
        v-if="choiceTotal > 20"
        :current-page="choicePage"
        :page-size="20"
        :total="choiceTotal"
        layout="prev, pager, next"
        @current-change="changeChoices"
      />
    </div>
    <el-alert
      v-if="error"
      :title="error"
      type="error"
      :closable="false"
    />
    <p
      v-if="released"
      role="status"
    >
      {{ t('agentBreaker.released') }}
    </p>
    <p v-if="!targetId">
      {{ t('agentBreaker.selectFromEntry') }}
    </p>
    <section v-if="principal && !loading">
      <h2>{{ principal.username }} · #{{ principal.id }}</h2>
      <PrincipalBadge
        :kind="principal.kind"
        :owner-id="principal.owner_user_id"
        :owner-name="principal.owner_username"
      />
      <p>{{ t(principal.breaker_pending_at ? 'agentBreaker.pending' : 'agentBreaker.noPending') }}</p>
      <AgentBreakerEvents
        :user-id="principal.id"
        :read-tokens="canManage"
        @state="setPending"
      />
      <BreakerReleaseForm
        v-if="principal.breaker_pending_at"
        :key="principal.id"
        :principal="principal"
        :actor="actor"
        @released="onReleased"
      />
    </section>
  </div>
</template>
<script setup>
import { ref, computed, watch, onBeforeUnmount } from 'vue'
import { useRoute } from 'vue-router'
import { t } from '@/i18n'
import { getCurrentUser } from '@/api/auth'
import { getUserDetail } from '@/api/user'
import { getMyAgents, getAgentBreakerEvents, getAgentTokens, listAgentPrincipals } from '@/api/agents'
import { roleNames } from '@/composables/useRoles'
import { resolveApiError } from '@/api/error'
import PageHeader from '@/components/PageHeader.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
import BreakerReleaseForm from '@/components/agent/BreakerReleaseForm.vue'
import AgentBreakerEvents from '@/components/agent/AgentBreakerEvents.vue'
const route = useRoute()
const principal = ref(null), actor = ref({}), loading = ref(false), error = ref(''), released = ref(false)
const selectedId = ref(null), chosenId = ref(null), choices = ref([]), choicePage = ref(1), choiceTotal = ref(0)
const canManage = computed(() => roleNames(actor.value.roles).includes('admin') || principal.value?.owner_user_id === actor.value.id)
const targetId = computed(() => chosenId.value || (/^\d+$/.test(String(route.query.user_id || '')) && Number.isSafeInteger(Number(route.query.user_id)) && Number(route.query.user_id) > 0 ? Number(route.query.user_id) : null))
let epoch = 0
async function load() {
  const version = ++epoch
  released.value = false; principal.value = null; actor.value = {}; error.value = ''; loading.value = false
    loading.value = true
  const id = targetId.value
  try {
    const response = await getCurrentUser(); if (version !== epoch) return
    actor.value = response.data || response
    const roles = roleNames(actor.value.roles)
    if (!id) {
      if (roles.includes('admin')) { const result = await listAgentPrincipals({ kind: 'agent', page: choicePage.value, page_size: 20 }); if (version === epoch) { choices.value = result.data || []; choiceTotal.value = result.total || 0 } }
      else if (!roles.includes('auditor')) { const result = await getMyAgents(); if (version === epoch) { choices.value = result.data || []; choiceTotal.value = 0 } }
      return
    }
    let user
    if (roles.includes('admin')) user = (await getUserDetail(id)).data
    else if (roles.includes('auditor')) {
      const result = await getAgentBreakerEvents(id, { limit: 20, offset: 0 })
      user = { id, kind: 'agent', breaker_pending_at: result.breaker_pending_at }
      // A non-admin may read these tokens only as owner. Read access remains
      // valid when self-creation is disabled, unlike the /my/agents policy gate.
      try { await getAgentTokens(id); user.owner_user_id = actor.value.id }
      catch (e) { if (e?.response?.status !== 403) throw e }
    }
    else {
      try { user = (await getMyAgents()).data?.find(a => a.id === id) }
      catch (e) { if (e?.response?.data?.code !== 'RULE_AGENT_SELF_CREATE_DISABLED') throw e
        // This endpoint allows ordinary humans only when they own this subject.
        const result = await getAgentBreakerEvents(id, { limit: 20, offset: 0 }); user = { id, kind: 'agent', owner_user_id: actor.value.id, breaker_pending_at: result.breaker_pending_at }
      }
    }
    if (version !== epoch) return
    if (user?.owner_user_id && !user.owner_username) {
      if (user.owner_user_id === actor.value.id) user = { ...user, owner_username: actor.value.username }
      else if (roles.includes('admin')) {
        // User detail does not project owner_username yet. Use the existing admin-only read.
        try {
          const owner = (await getUserDetail(user.owner_user_id)).data
          if (owner?.id === user.owner_user_id) user = { ...user, owner_username: owner.username }
        } catch { /* Name is optional; keep the identifier and the original management permissions. */ }
      }
    }
    if (version !== epoch) return
    if (user?.kind === 'agent') principal.value = user
    else error.value = t('agentBreaker.unavailable')
  } catch (e) { if (version === epoch) error.value = resolveApiError(e?.response?.data, e?.response?.status) }
  finally { if (version === epoch) loading.value = false }
}
function choose(id) { chosenId.value = id }
function openSelected() { if (Number.isSafeInteger(selectedId.value) && selectedId.value > 0) choose(selectedId.value) }
function changeChoices(page) { choicePage.value = page; load() }
function setPending(value) { if (principal.value && value !== undefined && !released.value) principal.value.breaker_pending_at = value }
function onReleased() { released.value = true; principal.value = { ...principal.value, breaker_pending_at: null } }
watch(targetId, load, { immediate: true })
onBeforeUnmount(() => { epoch++ })
</script>
<style scoped>
p { color: var(--ot-text-secondary); margin: var(--ot-space-md) 0; }
h2 { font-size: var(--ot-font-size-lg); }
</style>
