<template>
  <div
    class="api-token-reveal"
    data-test="api-token-reveal"
  >
    <el-alert
      type="warning"
      :closable="false"
      show-icon
      :title="$t('apiTokens.reveal.onceTitle')"
      :description="$t('apiTokens.reveal.onceBody')"
    />

    <div class="atr-secret-row">
      <code
        ref="secretEl"
        class="atr-secret"
        :aria-label="$t('apiTokens.reveal.tokenLabel')"
        data-test="reveal-secret"
      >{{ plaintext }}</code>
      <el-button
        class="atr-copy"
        data-test="copy-secret"
        @click="copySecret"
      >
        <Copy
          :size="14"
          aria-hidden="true"
        />
        <span class="atr-copy__text">{{ $t('common.copy') }}</span>
      </el-button>
    </div>
    <p
      v-if="secretCopy === 'ok'"
      class="atr-status is-ok"
      role="status"
      data-test="secret-copied"
    >
      <Check
        :size="14"
        aria-hidden="true"
      />
      {{ $t('apiTokens.reveal.copied') }}
    </p>
    <p
      v-else-if="secretCopy === 'failed'"
      class="atr-status is-failed"
      role="alert"
      data-test="secret-copy-failed"
    >
      <CircleX
        :size="14"
        aria-hidden="true"
      />
      {{ $t('apiTokens.reveal.copyFailed') }}
    </p>

    <section
      class="atr-test"
      data-test="reveal-test"
    >
      <h4>{{ $t('apiTokens.reveal.testTitle') }}</h4>
      <p class="atr-hint">
        {{ $t('apiTokens.reveal.testBody') }}
      </p>
      <div class="atr-command-row">
        <pre
          ref="commandEl"
          class="atr-command"
          :aria-label="$t('apiTokens.reveal.commandLabel')"
          data-test="reveal-command"
        >{{ displayCommand }}</pre>
        <el-button
          class="atr-copy"
          data-test="copy-command"
          @click="copyCommand"
        >
          <Copy
            :size="14"
            aria-hidden="true"
          />
          <span class="atr-copy__text">{{ $t('common.copy') }}</span>
        </el-button>
      </div>
      <p
        v-if="commandCopy === 'ok'"
        class="atr-status is-ok"
        role="status"
        data-test="command-copied"
      >
        <Check
          :size="14"
          aria-hidden="true"
        />
        {{ $t('apiTokens.reveal.copied') }}
      </p>
      <p
        v-else-if="commandCopy === 'failed'"
        class="atr-status is-failed"
        role="alert"
        data-test="command-copy-failed"
      >
        <CircleX
          :size="14"
          aria-hidden="true"
        />
        {{ $t('apiTokens.reveal.commandCopyFailed') }}
      </p>
    </section>

    <dl
      class="atr-details"
      data-test="reveal-details"
    >
      <dt>{{ $t('apiTokens.form.name') }}</dt>
      <dd data-test="reveal-name">
        {{ created.name }}
      </dd>
      <dt>{{ $t('apiTokens.col.grantedRoles') }}</dt>
      <dd data-test="reveal-roles">
        {{ rolesWithScopeText(created.granted_roles) }}
      </dd>
      <dt>{{ $t('apiTokens.col.expiresAt') }}</dt>
      <dd data-test="reveal-expiry">
        <template v-if="created.expires_at">
          {{ formatDateTime(created.expires_at) }}
        </template>
        <template v-else>
          <div>{{ $t('apiTokens.neverExpires') }}</div>
          <div class="atr-hint">
            {{ $t('apiTokens.reveal.neverExpires') }}
          </div>
        </template>
      </dd>
      <dt>{{ $t('apiTokens.reveal.represents') }}</dt>
      <dd data-test="reveal-represents">
        {{ $t('apiTokens.reveal.self', { user: username }) }}
      </dd>
    </dl>
  </div>
</template>

<script setup>
import { computed, nextTick, ref } from 'vue'
import { Check, CircleX, Copy } from 'lucide-vue-next'
import { formatDateTime } from '@/utils/format'
import { rolesWithScopeText } from '@/constants/apiTokens'
import { API_TOKEN_VERIFY_PATH } from '@/api/apiTokens'

/**
 * 建立完成後的一次性明文顯示。明文只經由屬性從建立對話框的區域狀態傳入，
 * 本元件不保存、不寫入任何儲存，也不輸出到主控台；對話框關閉即隨之消失。
 */
const props = defineProps({
  // 建立回應（TokenView 加上一次性的 token 欄）
  created: { type: Object, required: true },
  username: { type: String, default: '' },
})

const secretEl = ref(null)
const commandEl = ref(null)
const secretCopy = ref('')
const commandCopy = ref('')

const plaintext = computed(() => props.created?.token || '')
// 畫面上只露出前段，複製時給完整指令
const PREVIEW_LENGTH = 22
const maskedToken = computed(() =>
  plaintext.value.length > PREVIEW_LENGTH ? `${plaintext.value.slice(0, PREVIEW_LENGTH)}…` : plaintext.value
)
const origin = () => (typeof window !== 'undefined' && window.location ? window.location.origin : '')
const buildCommand = (token) =>
  `curl -s \\\n  -H "Authorization: Bearer ${token}" \\\n  ${origin()}${API_TOKEN_VERIFY_PATH}`
// 自動複製失敗時改顯示完整指令並選取：只露前段的指令照著手動抄會拿到不能用的指令
const displayCommand = computed(() =>
  buildCommand(commandCopy.value === 'failed' ? plaintext.value : maskedToken.value)
)

const writeClipboard = async (text) => {
  if (!navigator?.clipboard?.writeText) throw new Error('clipboard unavailable')
  await navigator.clipboard.writeText(text)
}

// 複製失敗時把明文（或完整指令）選取起來，讓使用者直接按複製鍵手動保存
const selectContents = (el) => {
  if (!el || typeof window === 'undefined' || !window.getSelection) return
  const range = document.createRange()
  range.selectNodeContents(el)
  const sel = window.getSelection()
  sel.removeAllRanges()
  sel.addRange(range)
}

const selectSecret = () => selectContents(secretEl.value)

const copySecret = async () => {
  try {
    await writeClipboard(plaintext.value)
    secretCopy.value = 'ok'
  } catch {
    secretCopy.value = 'failed'
    selectSecret()
  }
}

const copyCommand = async () => {
  try {
    await writeClipboard(buildCommand(plaintext.value))
    commandCopy.value = 'ok'
  } catch {
    commandCopy.value = 'failed'
    await nextTick()
    selectContents(commandEl.value)
  }
}
</script>

<style scoped>
.api-token-reveal {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}
.atr-secret-row,
.atr-command-row {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-sm);
}
.atr-secret {
  flex: 1;
  min-width: 0;
  padding: var(--ot-space-sm) 12px;
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
  background: var(--ot-bg-page);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  overflow-wrap: anywhere;
  user-select: all;
}
.atr-copy__text {
  margin-left: 4px;
}
.atr-status {
  display: flex;
  align-items: center;
  gap: 4px;
  margin: calc(-1 * var(--ot-space-sm)) 0 0;
  font-size: var(--ot-font-size-sm);
}
.atr-status.is-ok {
  color: var(--ot-success);
}
.atr-status.is-failed {
  color: var(--ot-danger);
}
.atr-test {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.atr-test h4 {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}
.atr-test .atr-status {
  margin-top: 0;
}
.atr-hint {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
.atr-command {
  flex: 1;
  min-width: 0;
  margin: 0;
  padding: var(--ot-space-sm) 12px;
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-primary);
  background: var(--ot-bg-page);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.atr-details {
  display: grid;
  grid-template-columns: max-content 1fr;
  margin: 0;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-sm);
}
.atr-details dt,
.atr-details dd {
  margin: 0;
  padding: var(--ot-space-sm) 12px;
  border-bottom: 1px solid var(--ot-border-subtle);
}
.atr-details dt:last-of-type,
.atr-details dd:last-of-type {
  border-bottom: none;
}
.atr-details dt {
  color: var(--ot-text-secondary);
}
.atr-details dd {
  color: var(--ot-text-primary);
  overflow-wrap: anywhere;
}
</style>
