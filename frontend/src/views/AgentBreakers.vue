<template>
  <div>
    <PageHeader
      :title="t('agentBreaker.title')"
      :description="t('agentBreaker.pageHelp')"
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
          {{ user.username || t('agentPrincipals.subjectRef', { id: user.id }) }}
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
      show-icon
    >
      <el-button
        :loading="loading"
        data-test="breaker-error-retry"
        @click="load"
      >
        {{ t('common.retry') }}
      </el-button>
      <a href="/alerts">{{ t('agentBreaker.entryValue') }}</a>
    </el-alert>
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
      <header class="breaker-head">
        <h2>{{ principal.username || t('agentPrincipals.subjectRef', { id: principal.id }) }}</h2>
        <a
          :href="keysHref"
          data-test="principal-keys-link"
        >{{ t('agentPrincipals.openKeys') }}</a>
        <el-tag :type="principal.breaker_pending_at ? 'warning' : 'success'">
          {{ t(principal.breaker_pending_at ? 'agentBreaker.pending' : 'agentBreaker.noPending') }}
        </el-tag>
        <!-- 身分徽章與負責人原本各自換行，主體那一列散成三行 -->
        <PrincipalBadge
          :kind="principal.kind"
          :owner-id="principal.owner_user_id"
          :owner-name="principal.owner_username"
        />
      </header>
      <!-- 首屏就要答完五題：為什麼被停、停了以後怎樣、怎麼解除、
           解除後做什麼（含直達入口）、從告警頁怎麼回到這裡 -->
      <dl
        class="breaker-brief"
        data-test="breaker-brief"
      >
        <!-- 「為什麼被停」是對已發生事實的陳述：沒有待處置時不能照樣宣稱 -->
        <template v-if="principal.breaker_pending_at">
          <dt>{{ t('agentBreaker.whyLabel') }}</dt><dd>{{ t('agentBreaker.whyValue') }}</dd>
        </template>
        <!-- 「停了以後怎樣」講停用期間；「解除之後」講解除後還要做什麼。
             兩格原本都掛 releaseTokens，同一句說兩次而停用期間沒人交代 -->
        <dt>{{ t('agentBreaker.effectLabel') }}</dt><dd>
          <span class="breaker-sentence">{{ t('agentBreaker.effectTokens') }}</span>
          <span class="breaker-sentence">{{ t('agentBreaker.releaseSessions') }}</span>
        </dd>
        <dt>{{ t('agentBreaker.nextLabel') }}</dt><dd>
          <span class="breaker-sentence">{{ t('agentBreaker.releaseTokens') }}</span>
          <a
            :href="reissueHref"
            data-test="reissue-link"
          >{{ t('agentBreaker.reissue') }}</a>
        </dd>
        <dt>{{ t('agentBreaker.entryLabel') }}</dt><dd>
          <a href="/alerts">{{ t('agentBreaker.entryValue') }}</a>
        </dd>
      </dl>
      <!-- 無待處置時原本連一句話都沒有，讀者無從判斷是「沒有」還是「沒載到」 -->
      <p
        v-if="!principal.breaker_pending_at"
        data-test="breaker-no-pending-hint"
      >
        {{ t('agentBreaker.noPendingHint') }}
      </p>
      <!-- 處置表單在事件序列之前：這頁是來處置的，
           「怎麼解除」被整段事件擠到首屏之外等於答不到 -->
      <BreakerReleaseForm
        v-if="principal.breaker_pending_at"
        :key="principal.id"
        :principal="principal"
        :actor="actor"
        @released="onReleased"
      />
      <AgentBreakerEvents
        :user-id="principal.id"
        :read-tokens="canManage"
        @state="setPending"
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
// 解除之後要重新發一把鑰匙：管理者在使用者管理的鑰匙抽屜、負責人在「我的 agent」
// 直達該 agent 的鑰匙抽屜：admin 走使用者管理的 open 查詢，負責人走自己的清單
const keysHref = computed(() => roleNames(actor.value.roles).includes('admin') ? `/users?open=${principal.value?.id || ''}` : '/my-agents')
const reissueHref = computed(() => roleNames(actor.value.roles).includes('admin') ? '/users' : '/my-agents')
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
a { color: var(--ot-primary); }
.breaker-brief { display: grid; grid-template-columns: 9em minmax(0, 1fr); gap: var(--ot-space-sm) var(--ot-space-md); margin: var(--ot-space-md) 0; }
.breaker-brief dt { color: var(--ot-text-secondary); }
.breaker-brief dd { margin: 0; color: var(--ot-text-primary); }
/* 兩句相接時要有詞距：英日文沒有空格會黏成一個字 */
.breaker-sentence { margin-inline-end: var(--ot-space-xs); }
h2 { font-size: var(--ot-font-size-lg); margin: 0; }
.breaker-head { display: flex; align-items: center; gap: var(--ot-space-sm); flex-wrap: wrap; margin: var(--ot-space-md) 0; }
</style>
