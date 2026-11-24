<template>
  <el-dialog
    :model-value="modelValue"
    :title="channel ? $t('alerts.testDialogTitle', { name: channel.name }) : ''"
    width="520px"
    :close-on-click-modal="false"
    data-test="channel-test-dialog"
    @update:model-value="(v) => emit('update:modelValue', v)"
    @closed="reset"
  >
    <template v-if="channel">
      <!-- 送出前：說明與（只有 webhook 有的）內容格式選擇 -->
      <template v-if="!result">
        <template v-if="isWebhook">
          <p
            class="test-intro"
            data-test="channel-test-intro"
          >
            {{ $t('alerts.testWebhookIntro', { name: channel.name }) }}
          </p>
          <div class="test-shape-label">
            {{ $t('alerts.testShapeLabel') }}
          </div>
          <el-radio-group
            v-model="shape"
            class="test-shapes"
            data-test="channel-test-shapes"
          >
            <el-radio
              v-for="s in TEST_SHAPES"
              :key="s"
              :value="s"
              border
              class="test-shape"
              :data-test="`channel-test-shape-${s}`"
            >
              <span class="test-shape__title">{{ $t(`alerts.testShape.${s}.title`) }}</span>
              <span class="test-shape__desc">{{ $t(`alerts.testShape.${s}.desc`) }}</span>
            </el-radio>
          </el-radio-group>
        </template>
        <!-- Slack 應用程式：送到頻道或傳給我自己（預設送到頻道）。沒有任何位址或收件人欄位：
             「傳給我自己」只送給按下按鈕的人自己 -->
        <template v-else-if="isSlackApp">
          <div class="test-shape-label">
            {{ $t('alerts.test.kind') }}
          </div>
          <el-radio-group
            v-model="kind"
            class="test-shapes"
            data-test="channel-test-kinds"
          >
            <el-radio
              value="channel"
              border
              class="test-shape"
              data-test="channel-test-kind-channel"
            >
              <span class="test-shape__title">{{ $t('alerts.test.toChannel') }}</span>
              <span class="test-shape__desc">{{ toChannelDesc }}</span>
            </el-radio>
            <el-radio
              value="self"
              border
              class="test-shape"
              :disabled="!selfAllowed"
              data-test="channel-test-kind-self"
            >
              <span class="test-shape__title">{{ $t('alerts.test.toSelf') }}</span>
              <span
                class="test-shape__desc"
                :data-test="selfAllowed ? 'channel-test-self-desc' : 'channel-test-self-not-allowed'"
              >{{ selfAllowed ? $t('alerts.test.toSelfDesc') : $t('alerts.test.toSelfNotAllowed') }}</span>
            </el-radio>
          </el-radio-group>
          <p class="test-intro test-once">
            {{ $t('alerts.testOnceHint') }}
          </p>
        </template>
        <template v-else>
          <p
            class="test-intro"
            data-test="channel-test-intro"
          >
            {{ slackIntro }}
          </p>
          <p class="test-intro">
            {{ $t('alerts.testOnceHint') }}
          </p>
        </template>
      </template>

      <!-- 送出後：結果留在對話框，依錯誤給句子與下一步 -->
      <el-alert
        v-else
        :type="result.ok ? 'success' : 'error'"
        :closable="false"
        show-icon
        :title="result.title"
        data-test="channel-test-result"
      >
        <div v-if="result.next">
          {{ result.next }}
        </div>
      </el-alert>
    </template>

    <template #footer>
      <template v-if="!result">
        <el-button @click="emit('update:modelValue', false)">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          v-preview-write
          type="primary"
          :loading="sending"
          data-test="channel-test-send"
          @click="send"
        >
          {{ $t('alerts.testSendButton') }}
        </el-button>
      </template>
      <template v-else>
        <el-button
          data-test="channel-test-close"
          @click="emit('update:modelValue', false)"
        >
          {{ $t('common.close') }}
        </el-button>
        <el-button
          v-if="result.action === 'edit'"
          type="primary"
          data-test="channel-test-edit"
          @click="emit('edit', channel)"
        >
          {{ $t('alerts.testEditChannel') }}
        </el-button>
        <el-button
          v-else-if="result.action === 'retry'"
          type="primary"
          data-test="channel-test-retry"
          @click="result = null"
        >
          {{ $t('alerts.testRetry') }}
        </el-button>
      </template>
    </template>
  </el-dialog>
</template>

<script setup>
// 測試發送對話框：三種型別都先開對話框；只有 webhook 選內容格式（三種本文格式不同）。
// 送出的本文只有 shape（Slack 兩型不帶本文）；目的地一律是通道已存的設定。
import { ref, computed } from 'vue'
import { testChannel } from '@/api/alerts'
import { resolveApiError } from '@/api/error'
import { t } from '@/i18n'
import { channelLanguageLabel } from '@/constants/notification-channels'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import { reasonText } from './channelDelivery'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  /** 要測試的通道列（列表回應的一列） */
  channel: { type: Object, default: null },
})
const emit = defineEmits(['update:modelValue', 'edit'])

const TEST_SHAPES = ['command_alert', 'system_security_alert', 'system_event']

const shape = ref(TEST_SHAPES[0])
// Slack 應用程式的測試種類：送到頻道（channel）或傳給我自己（self）
const kind = ref('channel')
const sending = ref(false)
const result = ref(null)

const isWebhook = computed(() => (props.channel?.type || 'webhook') === 'webhook')
const isSlackApp = computed(() => props.channel?.type === 'slack_app')
// 「傳給我自己」只在已保存的網址屬對個人派送允許清單時提供（伺服端計算的旗標）
const selfAllowed = computed(() => props.channel?.direct_message_url_allowed === true)
const toChannelDesc = computed(() => {
  const c = props.channel || {}
  return t('alerts.test.toChannelDesc', { target: c.target || '', lang: channelLanguageLabel(c.language || 'zh-TW') })
})

const slackIntro = computed(() => {
  const c = props.channel
  const params = { name: c.name, target: c.target || '', lang: channelLanguageLabel(c.language || 'zh-TW') }
  return isSlackApp.value ? t('alerts.testSlackIntro', params) : t('alerts.testSlackWebhookIntro', params)
})

const reset = () => {
  shape.value = TEST_SHAPES[0]
  kind.value = 'channel'
  result.value = null
  sending.value = false
}

// 平台錯誤碼 → 句子與下一步（Slack 應用程式）
const PLATFORM_ERRORS = {
  channel_not_found: ['channelNotFound', 'edit'],
  not_in_channel: ['notInChannel', 'retry'],
  no_permission: ['notInChannel', 'retry'],
  invalid_auth: ['badToken', 'edit'],
  token_revoked: ['badToken', 'edit'],
  token_expired: ['badToken', 'edit'],
  account_inactive: ['badToken', 'edit'],
  not_authed: ['badToken', 'edit'],
  missing_scope: ['missingScope', 'edit'],
  ratelimited: ['rateLimited', 'retry'],
  rate_limited: ['rateLimited', 'retry'],
}

const errKey = (key, action, params) => ({
  ok: false,
  title: t(`alerts.testErr.${key}.title`, params),
  next: t(`alerts.testErr.${key}.next`, params),
  action,
})

const platformResult = (code) => {
  const hit = PLATFORM_ERRORS[code]
  if (hit) return errKey(hit[0], hit[1])
  return { ok: false, title: t('alerts.testErr.other', { code }), next: '', action: 'retry' }
}

// 收端以 HTTP 狀態回報失敗（對端有回應）
const statusResult = (status) => {
  const type = props.channel?.type || 'webhook'
  if (status === 429) return errKey('rateLimited', 'retry')
  if (status === 404) return errKey(type === 'webhook' ? 'http404Webhook' : 'http404Slack', 'edit')
  if (status >= 300 && status < 400) {
    return { ok: false, title: reasonText(type === 'slack_app' ? 'redirect_not_followed' : 'http_other', `HTTP ${status}`), next: '', action: 'edit' }
  }
  if (status === 401 || status === 403) {
    return { ok: false, title: reasonText('http_401', `HTTP ${status}`), next: t('alerts.testErr.httpAuthNext'), action: 'edit' }
  }
  if (status >= 500) return { ok: false, title: reasonText('http_5xx', `HTTP ${status}`), next: t('alerts.testErr.retryLaterNext'), action: 'retry' }
  return { ok: false, title: reasonText('http_other', `HTTP ${status}`), next: '', action: 'edit' }
}

// 對端有回應但被轉址規則擋下（轉址次數過多、轉址目的地不符傳輸政策、不跟隨轉址）：
// 以投遞紀錄同一組原因代碼給句子，不說成連不上
const reasonResult = (code, status) => ({
  ok: false,
  title: reasonText(code, status ? `HTTP ${status}` : ''),
  next: '',
  action: 'edit',
})

const okResult = (status) => {
  if (isWebhook.value) return { ok: true, title: t('alerts.testOkWebhook', { status }), next: '', action: null }
  return { ok: true, title: t('alerts.testOkSlack'), next: t('alerts.testOkSlackNext'), action: null }
}

// 「傳給我自己」的結果：成功顯示 Slack 上的顯示名稱；三種對應失敗各有句子；
// 平台錯誤碼缺以電子郵件查詢的權限時換成專屬句，其餘沿用測試發送的平台錯誤句
const SELF_RESULTS = {
  no_email: 'selfNoEmailNext',
  email_ambiguous: 'selfAmbiguousNext',
  recipient_not_found: 'selfNotFoundNext',
}
const selfResult = (res) => {
  const r = res?.result
  if (res?.success && r === 'delivered') {
    return {
      ok: true,
      title: t('alerts.test.toSelfResult.delivered'),
      next: t('alerts.test.selfOkBody', { display_name: res.display_name || '-' }),
      action: null,
    }
  }
  if (SELF_RESULTS[r]) {
    return { ok: false, title: t(`alerts.test.toSelfResult.${r}`), next: t(`alerts.test.${SELF_RESULTS[r]}`), action: null }
  }
  const platform = res?.platform_error
  if (platform === 'missing_scope') {
    return { ok: false, title: t('alerts.test.selfScopeTitle'), next: t('alerts.test.selfScopeNext'), action: 'edit' }
  }
  if (platform && PLATFORM_ERRORS[platform]) return platformResult(platform)
  if (platform) return { ok: false, title: t('alerts.testErr.other', { code: platform }), next: t('alerts.test.platformErrorNext'), action: 'retry' }
  return statusResult(Number(res?.status_code) || 0)
}

const sendToSelf = async () => {
  try {
    // 本文只有 to_self：收件人一律是請求者自己、目的地一律是已保存的設定
    result.value = selfResult(await testChannel(props.channel.id, { to_self: true }))
  } catch (error) {
    const resp = error?.response
    const code = resp?.data?.code
    if (code === 'VALIDATION_CHANNEL_DM_URL_NOT_ALLOWED') {
      result.value = { ok: false, title: t('alerts.test.toSelfNotAllowed'), next: '', action: null }
    } else if (code === 'INTERNAL_CHANNEL_TEST_CONN_FAILED' || code === 'INTERNAL_CHANNEL_TEST_TIMEOUT' || !resp) {
      result.value = errKey('unreachable', 'edit')
    } else {
      result.value = { ok: false, title: resolveApiError(resp?.data, resp?.status, t('alerts.testFailedGeneric')), next: '', action: 'retry' }
    }
  }
}

const send = async () => {
  if (!props.channel || sending.value) return
  sending.value = true
  if (isSlackApp.value && kind.value === 'self') {
    try {
      await sendToSelf()
    } finally {
      sending.value = false
    }
    return
  }
  try {
    // Slack 兩型的測試內容只有一種，不帶本文
    const res = isWebhook.value
      ? await testChannel(props.channel.id, { shape: shape.value })
      : await testChannel(props.channel.id)
    const platform = res?.platform_error
    if (res?.success) result.value = okResult(res.status_code)
    else if (platform) result.value = platformResult(platform)
    else if (res?.reason_code) result.value = reasonResult(res.reason_code, res.status_code)
    else result.value = statusResult(Number(res?.status_code) || 0)
  } catch (error) {
    const resp = error?.response
    const code = resp?.data?.code
    const platform = resp?.data?.platform_error || resp?.data?.params?.platform_error
    if (platform) {
      result.value = platformResult(platform)
    } else if (code === 'INTERNAL_CHANNEL_TEST_CONN_FAILED' || code === 'INTERNAL_CHANNEL_TEST_TIMEOUT' || !resp) {
      result.value = errKey(isWebhook.value ? 'unreachableWebhook' : 'unreachable', 'edit')
    } else {
      result.value = { ok: false, title: resolveApiError(resp?.data, resp?.status, t('alerts.testFailedGeneric')), next: '', action: 'retry' }
    }
  } finally {
    sending.value = false
  }
}

defineExpose({ send, shape, kind, result })
</script>

<style scoped>
.test-intro {
  margin: 0 0 var(--ot-space-sm);
  line-height: 1.6;
  color: var(--el-text-color-regular);
}

.test-once {
  margin-top: var(--ot-space-sm);
}

.test-shape-label {
  margin: var(--ot-space-sm) 0;
  font-weight: 600;
}

.test-shapes {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: var(--ot-space-sm);
}

/* 每個選項是一張帶框的卡片：第一行名稱、第二行說明 */
.test-shape {
  display: flex;
  align-items: flex-start;
  height: auto;
  margin-right: 0;
  padding: 10px 12px;
  white-space: normal;
}

.test-shape :deep(.el-radio__label) {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.test-shape__title {
  font-weight: 600;
}

.test-shape__desc {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
  line-height: 1.5;
}
</style>
