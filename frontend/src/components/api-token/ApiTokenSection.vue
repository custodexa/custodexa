<template>
  <section
    v-loading="loading"
    class="api-token-section"
    data-test="api-token-section"
  >
    <div class="ats-head">
      <h3 class="ats-title">
        {{ $t('apiTokens.title') }}
      </h3>
      <el-button
        v-if="showCreate"
        v-preview-write:create
        type="primary"
        :disabled="createDisabled"
        data-test="api-token-create"
        @click="createOpen = true"
      >
        <Plus
          :size="14"
          aria-hidden="true"
        />
        <span class="ats-btn-text">{{ $t('apiTokens.create') }}</span>
      </el-button>
    </div>
    <p class="ats-desc">
      {{ noPermissionOnly ? $t('apiTokens.noPerm.intro') : $t('apiTokens.desc') }}
    </p>

    <template v-if="loadFailed">
      <div
        class="ats-box"
        data-test="api-token-load-failed"
      >
        <el-alert
          type="error"
          :closable="false"
          show-icon
          center
          :title="$t('apiTokens.loadFailed.title')"
          :description="$t('apiTokens.loadFailed.body')"
        />
        <el-button
          data-test="api-token-reload"
          @click="load"
        >
          <RefreshCw
            :size="14"
            aria-hidden="true"
          />
          <span class="ats-btn-text">{{ $t('common.refresh') }}</span>
        </el-button>
      </div>
      <p class="ats-edit-hint">
        {{ $t('apiTokens.editHint') }}
      </p>
    </template>

    <el-alert
      v-else-if="noPermissionOnly"
      type="info"
      :closable="false"
      show-icon
      :title="$t('apiTokens.noPerm.title')"
      :description="$t('apiTokens.noPerm.body', { role: currentRolesText })"
      data-test="api-token-no-permission"
    />

    <template v-else-if="loaded">
      <el-alert
        v-if="rolesRevoked"
        type="warning"
        :closable="false"
        show-icon
        :title="$t('apiTokens.rolesRevoked.title')"
        :description="$t('apiTokens.rolesRevoked.body', rolesRevoked)"
        data-test="api-token-roles-revoked"
      />
      <el-alert
        v-else-if="!eligible"
        type="info"
        :closable="false"
        show-icon
        :title="$t('apiTokens.noPerm.title')"
        :description="$t('apiTokens.noPerm.body', { role: currentRolesText })"
        data-test="api-token-no-permission"
      />
      <el-alert
        v-if="restoredVisible"
        type="warning"
        :closable="false"
        show-icon
        :title="$t('apiTokens.restored.title')"
        :description="restore.restored_at ? $t('apiTokens.restored.body', { time: formatDateTime(restore.restored_at) }) : $t('apiTokens.restored.bodyNoTime')"
        data-test="api-token-restored"
      />
      <el-alert
        v-else-if="allInactive"
        type="warning"
        :closable="false"
        show-icon
        :title="$t('apiTokens.allInactive.title')"
        :description="$t('apiTokens.allInactive.body')"
        data-test="api-token-all-inactive"
      />

      <ApiTokenList
        v-if="tokens.length"
        :tokens="tokens"
        mode="self"
        :just-created-id="justCreatedId"
        show-edit-hint
        @revoke="openRevoke"
      />
      <div
        v-else
        class="ats-box ats-empty"
        data-test="api-token-empty"
      >
        <EmptyState
          :title="$t('apiTokens.empty.title')"
          :hint="$t('apiTokens.empty.desc')"
          :icon="KeyRound"
        />
      </div>
    </template>

    <p
      v-if="hasAgents"
      class="ats-agent-hint"
      data-test="api-token-agent-hint"
    >
      <Bot
        :size="14"
        aria-hidden="true"
      />
      <span>{{ $t('apiTokens.agentOwner.hint') }}</span>
      <a
        href="/my-agents"
        data-test="api-token-agent-link"
        @click.prevent="goMyAgents"
      >{{ $t('apiTokens.agentOwner.link') }}</a>
    </p>

    <ApiTokenCreateDialog
      v-model="createOpen"
      :eligibility="eligibility"
      :username="username"
      @created="onCreated"
      @ineligible="load"
      @stale-roles="load"
    />
    <ApiTokenRevokeDialog
      v-model="revokeOpen"
      mode="self"
      :token="revokeTarget"
      :submit="submitRevoke"
      @done="onRevoked"
      @failed="load"
    />
  </section>
</template>

<script setup>
import { computed, inject, onMounted, ref, watch } from 'vue'
import { routerKey } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Bot, KeyRound, Plus, RefreshCw } from 'lucide-vue-next'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { apiErrorSummary } from '@/api/redact'
import { getMyApiTokens, revokeMyApiToken } from '@/api/apiTokens'
import { getMyAgents } from '@/api/agents'
import { canEnter, entryRuleFor } from '@/router/entryRules'
import { loadCapabilities } from '@/composables/useCapabilities'
import { roleLabel } from '@/constants/roles'
import { grantedRoleLabel, isInactive, rolesText } from '@/constants/apiTokens'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import EmptyState from '@/components/EmptyState.vue'
import ApiTokenList from './ApiTokenList.vue'
import ApiTokenCreateDialog from './ApiTokenCreateDialog.vue'
import ApiTokenRevokeDialog from './ApiTokenRevokeDialog.vue'

/**
 * 個人資料頁的 API token 區塊：本人的清單、建立與撤銷。
 * 是否能建立、可授權的角色、每把的狀態都取自 GET /my/api-tokens。
 */
const props = defineProps({
  // 目前登入者（GET /auth/me 的結果）：用來顯示帳號名稱與沒有管理權限時的角色
  account: { type: Object, default: () => ({}) },
})

const loading = ref(false)
const loaded = ref(false)
const loadFailed = ref(false)
const tokens = ref([])
const eligibility = ref({})
const restore = ref({})
const justCreatedId = ref(null)
const createdName = ref('')
const createOpen = ref(false)
const revokeOpen = ref(false)
const revokeTarget = ref(null)
const hasAgents = ref(false)
let loadSeq = 0

const router = inject(routerKey, null)
const goMyAgents = () => {
  if (router) void router.push('/my-agents')
  else window.location.assign('/my-agents')
}

const username = computed(() => props.account?.username || '')
const eligible = computed(() => eligibility.value?.can_create === true)

// 沒有建立資格、也沒有任何 token：卡片只剩說明，不顯示清單與建立鈕
const noPermissionOnly = computed(() => loaded.value && !loadFailed.value && !eligible.value && tokens.value.length === 0)
const showCreate = computed(() => !noPermissionOnly.value)
const createDisabled = computed(() => loading.value || loadFailed.value || !loaded.value || !eligible.value)

const currentRolesText = computed(() => {
  const fromServer = rolesText(eligibility.value?.non_grantable_roles || [])
  if (fromServer) return fromServer
  return (props.account?.roles || []).map(roleLabel).join(t('common.listSeparator'))
})

// 管理角色被收回而暫停的 token：說明哪些角色不在了、有幾把受影響
const rolesRevoked = computed(() => {
  if (eligible.value) return null
  const suspended = tokens.value.filter((tk) => tk.status === 'suspended_roles_revoked')
  if (!suspended.length) return null
  const names = []
  for (const tk of suspended) {
    for (const role of tk.granted_roles || []) {
      const label = grantedRoleLabel(role)
      if (role.effective === false && !names.includes(label)) names.push(label)
    }
  }
  return { roles: names.join(t('common.listSeparator')), n: suspended.length }
})

// 還原後、本人還沒建立新的 token 之前才顯示
const restoredVisible = computed(() => {
  const count = restore.value?.invalidated_count || 0
  if (count <= 0) return false
  const at = Date.parse(restore.value?.restored_at)
  if (!Number.isFinite(at)) return !tokens.value.some((tk) => tk.status !== 'invalidated_by_restore')
  return !tokens.value.some((tk) => Date.parse(tk.created_at) > at)
})

const allInactive = computed(() => eligible.value && tokens.value.length > 0 && tokens.value.every(isInactive))

const load = async () => {
  const seq = ++loadSeq
  loading.value = true
  loadFailed.value = false
  try {
    const res = await getMyApiTokens()
    if (seq !== loadSeq) return
    tokens.value = Array.isArray(res?.data) ? res.data : []
    eligibility.value = res?.eligibility || {}
    restore.value = res?.restore || {}
    loaded.value = true
  } catch (error) {
    if (seq !== loadSeq) return
    loadFailed.value = true
    console.error(...apiErrorSummary('api_token_list_failed', error))
  } finally {
    if (seq === loadSeq) loading.value = false
  }
}

// AI agent 的負責人：卡片底部說明 agent 用自己的鑰匙。讀不到時不顯示，不影響本區塊。
// 直接開網址或重新整理時，本區塊可能比權限先掛上：先等權限載入完再判斷，
// 否則會把「還不知道」當成「沒有權限」而永遠不查
const loadAgents = async () => {
  await loadCapabilities()
  if (!canEnter(entryRuleFor('/my-agents'))) return
  try {
    const res = await getMyAgents()
    hasAgents.value = Array.isArray(res?.data) && res.data.length > 0
  } catch {
    hasAgents.value = false
  }
}

const onCreated = (view) => {
  justCreatedId.value = view?.id ?? null
  createdName.value = view?.name || ''
  void load()
}

// 明文關閉後才提示「已建立」，與卡片上新的一列同時出現
watch(createOpen, (open) => {
  if (!open && createdName.value) {
    ElMessage.success(t('apiTokens.msg.created', { name: createdName.value }))
    createdName.value = ''
  }
})

const openRevoke = (token) => {
  revokeTarget.value = token
  revokeOpen.value = true
}
const submitRevoke = (note) => revokeMyApiToken(revokeTarget.value.id, note)
const onRevoked = () => {
  ElMessage.success(t('apiTokens.msg.revoked', { name: revokeTarget.value?.name || '' }))
  void load()
}

onMounted(() => {
  void load()
  void loadAgents()
})

defineExpose({ load })
</script>

<style scoped>
.api-token-section {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
  padding: var(--ot-space-lg);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}
.ats-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: var(--ot-space-md);
}
.ats-title {
  margin: 0;
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}
.ats-btn-text {
  margin-left: 4px;
}
.ats-desc {
  margin: calc(-1 * var(--ot-space-xs)) 0 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}
.ats-box {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--ot-space-md);
  padding: var(--ot-space-lg);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.ats-box :deep(.el-alert) {
  max-width: 520px;
}
.ats-edit-hint {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.ats-agent-hint {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  flex-wrap: wrap;
  margin: 0;
  padding-top: var(--ot-space-md);
  border-top: 1px solid var(--ot-border-subtle);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.ats-agent-hint a {
  color: var(--ot-primary);
}
</style>
