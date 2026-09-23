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
      <!-- 首屏摘要：「哪把還能用」「哪把快到期」原本要捲到底逐張卡片比對，
           答案放在這裡就不必捲。兩個把數是這面板的統計，不是說明句——
           數字獨立成統計塊，標籤才降到灰字階 -->
      <template v-if="!loading && !listFailed && tokens.length">
        <StatBlock
          data-test="token-summary"
          :items="[
            { value: usableTokens.length, label: t('agentPrincipals.statUsable'), dataTest: 'token-usable-stat' },
            { value: suspendedCount, label: t('agentPrincipals.statSuspended'), dataTest: 'token-suspended-stat' },
          ]"
        />
        <p
          v-if="nextExpiring"
          class="token-panel__summary"
          data-test="token-next-expiry"
        >
          {{ t('agentPrincipals.summaryNextExpiry', { name: nextExpiring.name, time: formatDateTime(nextExpiring.expires_at) }) }}
        </p>
      </template>
      <section
        v-if="principal.breaker_pending_at || breakerBlocked"
        class="token-panel__notice"
        data-test="breaker-summary"
      >
        <strong>{{ t('agentBreaker.pending') }}</strong>
        <p>{{ t('agentBreaker.issueBlocked') }}</p>
        <a :href="`/agent-breakers?user_id=${principal.id}`">{{ t('agentBreaker.resolve') }}</a>
      </section>
      <!-- 「怎麼解除」原本只在有待處置時才有入口：沒有待處置時，讀者在這個抽屜
           找不到任何通往處置頁的路，得改走告警頁繞路。入口恆在，狀態由該頁交代 -->
      <p
        v-else
        class="token-panel__summary"
      >
        <a
          :href="`/agent-breakers?user_id=${principal.id}`"
          data-test="breaker-entry"
        >{{ t('agentBreaker.title') }}</a>
      </p>
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
        <el-button
          data-test="token-saved"
          @click="plaintext = ''; copied = false"
        >
          {{ t('agentPrincipals.savedAck') }}
        </el-button>
        <span
          v-if="copied"
          role="status"
        >{{ t('agentPrincipals.copied') }}</span>
      </section>
      <!-- 發證區排在已發鑰匙清單之前：放在最後時，名下有七張鑰匙卡的主體
           要捲過整份清單才看得到表單，「發一把新的」在走查裡被記成需要捲動 -->
      <section data-test="issue-section">
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
              ref="nameInput"
              v-model="name"
              maxlength="100"
              :disabled="busy || cannotIssue"
              data-test="token-name"
            />
          </el-form-item>
          <el-form-item required>
            <template #label>
              {{ t('agentPrincipals.expiresAt') }} <HelpTip :content="t('agentPrincipals.expiryHelp')" />
            </template>
            <el-date-picker
              v-model="expiresAt"
              type="datetime"
              :disabled="busy || cannotIssue"
              :aria-label="t('agentPrincipals.expiresAt')"
            />
          </el-form-item>
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
      <section
        v-loading="loading"
        :aria-busy="loading"
      >
        <h3>{{ t('agentPrincipals.issuedKeys') }}</h3>
        <EmptyState
          v-if="!loading && !listFailed && !tokens.length"
          :title="t('agentPrincipals.noKeys')"
          :icon="KeyRound"
        />
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
            <strong>{{ token.name }}</strong><el-tag
              :type="statusTagType(token)"
              :class="statusTagClass(token)"
            >
              {{ t(`agentPrincipals.tokenStatus.${status(token)}`) }}
            </el-tag>
          </div>
          <dl>
            <dt>{{ t('agentPrincipals.createdBy') }}</dt><dd>{{ token.created_by_username || t('agentPrincipals.unavailable') }}</dd>
            <template v-if="token.suspended_at">
              <dt>{{ t('agentPrincipals.suspendedLabel') }}</dt><dd data-test="token-suspended">
                {{ t('agentPrincipals.suspendedValue', { reason: suspendedReason(token), time: formatDateTime(token.suspended_at) }) }}
              </dd>
            </template>
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
    </div>
    <template #footer>
      <el-button @click="emit('update:modelValue', false)">
        {{ t('common.close') }}
      </el-button>
    </template>
  </el-drawer>
</template>
<script setup>
import { ref, computed, watch, nextTick, onBeforeUnmount } from 'vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { resolveApiError } from '@/api/error'
import { getAgentTokens, createAgentToken, revokeAgentToken } from '@/api/agents'
import { agentTokenState, agentTokenTagType, agentTokenTagClass } from '@/utils/agentTokenStatus'
import { KeyRound } from 'lucide-vue-next'
import EmptyState from '@/components/EmptyState.vue'
import StatBlock from '@/components/StatBlock.vue'
import HelpTip from '@/components/HelpTip.vue'
import PrincipalBadge from './PrincipalBadge.vue'
// focusIssue：由「發新的」這類直達入口開啟時，游標直接落在發證表單的名稱欄，
// 開抽屜與開始填表算同一步
const props = defineProps({ modelValue: Boolean, principal: { type: Object, default: () => ({}) }, ownerName: { type: String, default: '' }, focusIssue: Boolean })
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
const nameInput = ref(null)
const cannotIssue = computed(() => Boolean(props.principal.breaker_pending_at) || breakerBlocked.value || props.principal.active === false)
const current = version => version === epoch && props.modelValue
// 狀態與彩標的映射共用 utils/agentTokenStatus，熔斷頁用的是同一份
const status = token => agentTokenState(token, now.value)
const breakerPending = computed(() => Boolean(props.principal.breaker_pending_at) || breakerBlocked.value)
const statusTagType = token => agentTokenTagType(status(token), breakerPending.value)
const statusTagClass = token => agentTokenTagClass(status(token), breakerPending.value)
const usableTokens = computed(() => tokens.value.filter(token => status(token) === 'valid'))
const suspendedCount = computed(() => tokens.value.filter(token => status(token) === 'suspended').length)
const nextExpiring = computed(() => usableTokens.value.slice().sort((a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at))[0] || null)
const SUSPEND_REASONS = ['agent_breaker_tripped']
function suspendedReason(token) {
  return SUSPEND_REASONS.includes(token.suspended_reason) ? t(`agentPrincipals.suspendedReasons.${token.suspended_reason}`) : t('agentPrincipals.suspendedReasons.unknown')
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
    // 不動 plaintext：剛發出的那把還沒被保存，收回另一把不該連帶把它抹掉
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
// **watch 源必須是純量**：寫成 `() => [modelValue, principal.id]` 時每次求值都是
// 新陣列，Vue 以參考比較判定「變了」，於是父層任何一次清單刷新（selected 換成
// 新物件）都會重跑這支 reset，把剛發出的一次性明文清掉——使用者永遠來不及複製。
// 併成字串鍵後，只有開關或主體真的換了才重置。
watch(() => `${props.modelValue}|${props.principal.id ?? ''}`, () => {
  const open = props.modelValue
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
    if (props.focusIssue) nextTick(() => { nameInput.value?.focus?.() })
  }
}, { immediate: true })
onBeforeUnmount(() => { epoch++; plaintext.value = ''; clearInterval(refreshTimer) })
</script>
<style scoped>
/* 抽屜自身標題原為 16px/400，比其內部區塊標題（16px/600）還弱，層次倒置 */
:deep(.el-drawer__title) { font-size: var(--ot-font-size-lg); font-weight: 700; color: var(--ot-text-primary); }
.token-panel { display: flex; flex-direction: column; gap: var(--ot-space-lg); color: var(--ot-text-primary); }
.token-panel h3 { font-size: var(--ot-font-size-lg); font-weight: 600; margin: 0 0 var(--ot-space-md); }
.token-panel p { margin: var(--ot-space-sm) 0; }
.token-panel__hint, dt { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); }
.token-panel__summary { margin: 0; color: var(--ot-text-primary); font-size: var(--ot-font-size-sm); }
.token-panel__notice { padding: var(--ot-space-md); border: 1px solid var(--ot-warning); border-radius: var(--ot-radius-md); background: var(--ot-bg-elevated); }
.token-panel__secret { display: block; overflow-wrap: anywhere; font-family: var(--ot-font-mono); padding: var(--ot-space-sm); background: var(--ot-bg-surface); margin-bottom: var(--ot-space-sm); }
.token-panel__key { padding: var(--ot-space-md) 0; border-bottom: 1px solid var(--ot-border-subtle); }
.token-panel__row, .token-panel__actions { display: flex; gap: var(--ot-space-sm); justify-content: space-between; flex-wrap: wrap; }
.token-panel__actions { margin-top: var(--ot-space-md); justify-content: flex-end; }
dl { display: grid; grid-template-columns: auto 1fr; gap: var(--ot-space-xs) var(--ot-space-sm); font-size: var(--ot-font-size-sm); }
dd { margin: 0; overflow-wrap: anywhere; }
a { color: var(--ot-primary); }
</style>
