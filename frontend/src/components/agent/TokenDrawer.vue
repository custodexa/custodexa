<template>
  <el-drawer
    :model-value="modelValue"
    :title="t('agentPrincipals.keysFor', { name: principal.username || '' })"
    size="min(100%, 34rem)"
    destroy-on-close
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div
      class="token-panel"
      data-test="token-panel"
    >
      <p class="token-panel__hint">
        {{ t('agentPrincipals.keyHelp') }}
      </p>
      <PrincipalBadge
        :kind="principal.kind"
        :owner-id="principal.owner_user_id"
        :owner-name="ownerName"
      />
      <section
        v-if="principal.breaker_pending_at || breakerBlocked"
        class="token-panel__notice"
        data-test="breaker-summary"
      >
        <strong>{{ t('agentBreaker.pending') }}</strong>
        <p>{{ t('agentBreaker.issueBlocked') }}</p>
        <a :href="`/agent-breakers?user_id=${principal.id}`">{{ t('agentBreaker.resolve') }}</a>
      </section>
      <el-alert
        v-if="error"
        :title="error"
        type="error"
        :closable="false"
        show-icon
      />
      <section
        v-if="plaintext"
        class="token-panel__notice"
        data-test="token-reveal"
      >
        <strong>{{ t('agentPrincipals.revealTitle') }}</strong>
        <p>{{ t('agentPrincipals.revealOnce') }}</p>
        <code class="token-panel__secret">{{ plaintext }}</code>
        <el-button
          data-test="copy-token"
          @click="copyToken"
        >
          {{ t('common.copy') }}
        </el-button>
        <span
          v-if="copied"
          role="status"
        >{{ t('agentPrincipals.copied') }}</span>
      </section>
      <section
        v-loading="loading"
        :aria-busy="loading"
      >
        <h3>{{ t('agentPrincipals.issuedKeys') }}</h3>
        <p v-if="!loading && !listFailed && !tokens.length">
          {{ t('agentPrincipals.noKeys') }}
        </p>
        <el-button
          v-if="listFailed"
          @click="loadTokens"
        >
          {{ t('common.refresh') }}
        </el-button>
        <article
          v-for="token in tokens"
          :key="token.id"
          class="token-panel__key"
          data-test="token-row"
        >
          <div class="token-panel__row">
            <strong>{{ token.name }}</strong><el-tag :type="status(token) === 'valid' ? 'success' : 'info'">
              {{ t(`agentPrincipals.tokenStatus.${status(token)}`) }}
            </el-tag>
          </div>
          <dl>
            <dt>{{ t('agentPrincipals.createdBy') }}</dt><dd>#{{ token.created_by }}</dd>
            <dt>{{ t('common.createdAt') }}</dt><dd>{{ formatDateTime(token.created_at) }}</dd>
            <dt>{{ t('agentPrincipals.expiresAt') }}</dt><dd>{{ formatDateTime(token.expires_at) }}</dd>
            <dt>{{ t('agentPrincipals.lastUsedAt') }}</dt><dd>{{ token.last_used_at ? formatDateTime(token.last_used_at) : t('agentPrincipals.neverUsed') }}</dd>
          </dl>
          <el-button
            v-if="!token.revoked_at && revokeId !== token.id"
            :disabled="busy"
            type="danger"
            plain
            data-test="revoke-start"
            @click="revokeId = token.id; revokeNote = ''"
          >
            {{ t('agentPrincipals.revoke') }}
          </el-button>
          <div
            v-if="revokeId === token.id"
            class="token-panel__notice"
            data-test="revoke-confirm"
          >
            <p>{{ t('agentPrincipals.revokeConsequence') }}</p>
            <label :for="`revoke-note-${token.id}`">{{ t('agentPrincipals.revokeNote') }}</label>
            <el-input
              :id="`revoke-note-${token.id}`"
              v-model="revokeNote"
              maxlength="2000"
            />
            <div class="token-panel__actions">
              <el-button
                :disabled="busy"
                @click="revokeId = null"
              >
                {{ t('common.cancel') }}
              </el-button><el-button
                type="danger"
                :loading="busy"
                data-test="revoke-confirm-submit"
                @click="revoke(token)"
              >
                {{ t('agentPrincipals.revoke') }}
              </el-button>
            </div>
          </div>
        </article>
      </section>
      <section>
        <h3>{{ t('agentPrincipals.issue') }}</h3>
        <el-form
          label-position="top"
          @submit.prevent="issue"
        >
          <el-form-item
            :label="t('agentPrincipals.keyName')"
            required
          >
            <el-input
              v-model="name"
              maxlength="100"
              :disabled="busy || cannotIssue"
              data-test="token-name"
            />
          </el-form-item>
          <el-form-item
            :label="t('agentPrincipals.expiresAt')"
            required
          >
            <el-date-picker
              v-model="expiresAt"
              type="datetime"
              :disabled="busy || cannotIssue"
              :aria-label="t('agentPrincipals.expiresAt')"
            />
          </el-form-item>
          <p class="token-panel__hint">
            {{ t('agentPrincipals.expiryHelp') }}
          </p>
          <p v-if="principal.active === false">
            {{ t('agentPrincipals.inactiveHelp') }}
          </p>
          <el-button
            type="primary"
            :disabled="cannotIssue || loading || listFailed"
            :loading="busy"
            data-test="issue-token"
            @click="issue"
          >
            {{ t('agentPrincipals.issue') }}
          </el-button>
        </el-form>
      </section>
    </div>
    <template #footer>
      <el-button @click="emit('update:modelValue', false)">
        {{ t('common.close') }}
      </el-button>
    </template>
  </el-drawer>
</template>
<script setup>
import { ref, computed, watch, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { resolveApiError } from '@/api/error'
import { getAgentTokens, createAgentToken, revokeAgentToken } from '@/api/agents'
import PrincipalBadge from './PrincipalBadge.vue'
const props = defineProps({ modelValue: Boolean, principal: { type: Object, default: () => ({}) }, ownerName: { type: String, default: '' } })
const emit = defineEmits(['update:modelValue', 'open', 'changed'])
const tokens = ref([])
const plaintext = ref('')
const copied = ref(false)
const loading = ref(false)
const busy = ref(false)
const listFailed = ref(false)
const error = ref('')
const name = ref('')
const expiresAt = ref(null)
const revokeId = ref(null)
const revokeNote = ref('')
const breakerBlocked = ref(false)
const now = ref(Date.now())
let epoch = 0
let refreshTimer
const cannotIssue = computed(() => Boolean(props.principal.breaker_pending_at) || breakerBlocked.value || props.principal.active === false)
const current = version => version === epoch && props.modelValue
function status(token) {
  if (token.revoked_at) return 'revoked'
  if (token.suspended_at) return 'suspended'
  return Date.parse(token.expires_at) <= now.value ? 'expired' : 'valid'
}
function showError(cause) {
  error.value = resolveApiError(cause?.response?.data, cause?.response?.status)
  if (cause?.response?.data?.code === 'RULE_AGENT_BREAKER_PENDING') breakerBlocked.value = true
}
async function loadTokens() {
  const version = epoch
  loading.value = true
  error.value = ''
  listFailed.value = false
  try {
    const result = await getAgentTokens(props.principal.id)
    if (current(version)) tokens.value = result.data || []
  } catch (cause) {
    if (current(version)) { listFailed.value = true; showError(cause) }
  } finally { if (current(version)) loading.value = false }
}
async function issue() {
  if (busy.value || cannotIssue.value || loading.value || listFailed.value) return
  error.value = ''
  if (!name.value.trim() || !expiresAt.value || !Number.isFinite(new Date(expiresAt.value).getTime()) || new Date(expiresAt.value).getTime() <= Date.now()) {
    error.value = t('agentPrincipals.issueRequired')
    return
  }
  const version = epoch
  busy.value = true
  plaintext.value = ''
  copied.value = false
  try {
    const result = await createAgentToken(props.principal.id, { name: name.value.trim(), expires_at: new Date(expiresAt.value).toISOString() })
    if (!current(version)) return
    plaintext.value = result.token || ''
    name.value = ''
    expiresAt.value = null
    emit('changed')
    await loadTokens()
  } catch (cause) { if (current(version)) showError(cause) }
  finally { if (current(version)) busy.value = false }
}
async function revoke(token) {
  if (busy.value) return
  const version = epoch
  busy.value = true
  error.value = ''
  try {
    await revokeAgentToken(props.principal.id, token.id, revokeNote.value)
    if (!current(version)) return
    plaintext.value = ''
    revokeId.value = null
    emit('changed')
    await loadTokens()
  } catch (cause) { if (current(version)) showError(cause) }
  finally { if (current(version)) busy.value = false }
}
async function copyToken() {
  const version = epoch
  try { await navigator.clipboard.writeText(plaintext.value); if (current(version)) copied.value = true }
  catch { if (current(version)) error.value = t('agentPrincipals.copyFailed') }
}
watch(() => [props.modelValue, props.principal.id], ([open]) => {
  epoch++
  plaintext.value = ''
  copied.value = false
  tokens.value = []
  error.value = ''
  name.value = ''
  expiresAt.value = null
  revokeId.value = null
  revokeNote.value = ''
  breakerBlocked.value = false
  busy.value = false
  loading.value = false
  clearInterval(refreshTimer)
  if (open && props.principal.id) {
    emit('open')
    now.value = Date.now()
    refreshTimer = setInterval(() => { now.value = Date.now() }, 60000)
    loadTokens()
  }
}, { immediate: true })
onBeforeUnmount(() => { epoch++; plaintext.value = ''; clearInterval(refreshTimer) })
</script>
<style scoped>
.token-panel { display: flex; flex-direction: column; gap: var(--ot-space-lg); color: var(--ot-text-primary); }
.token-panel h3 { font-size: var(--ot-font-size-lg); margin: 0 0 var(--ot-space-md); }
.token-panel p { margin: var(--ot-space-sm) 0; }
.token-panel__hint, dt { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
.token-panel__notice { padding: var(--ot-space-md); border: 1px solid var(--ot-warning); border-radius: var(--ot-radius-md); background: var(--ot-bg-elevated); }
.token-panel__secret { display: block; overflow-wrap: anywhere; font-family: var(--ot-font-mono); padding: var(--ot-space-sm); background: var(--ot-bg-surface); margin-bottom: var(--ot-space-sm); }
.token-panel__key { padding: var(--ot-space-md) 0; border-bottom: 1px solid var(--ot-border-subtle); }
.token-panel__row, .token-panel__actions { display: flex; gap: var(--ot-space-sm); justify-content: space-between; flex-wrap: wrap; }
.token-panel__actions { margin-top: var(--ot-space-md); justify-content: flex-end; }
dl { display: grid; grid-template-columns: auto 1fr; gap: var(--ot-space-xs) var(--ot-space-sm); font-size: var(--ot-font-size-sm); }
dd { margin: 0; overflow-wrap: anywhere; }
a { color: var(--ot-primary); }
</style>
