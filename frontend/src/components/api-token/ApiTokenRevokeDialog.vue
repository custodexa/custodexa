<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('common.confirmRevoke')"
    width="min(560px, calc(100vw - 32px))"
    :close-on-click-modal="false"
    append-to-body
    data-test="api-token-revoke-dialog"
    @update:model-value="onToggle"
  >
    <div class="atv-body">
      <el-alert
        v-if="failed"
        type="error"
        :closable="false"
        show-icon
        :title="failedReason || $t('apiTokens.revoke.failedTitle')"
        :description="failedReason
          ? (all ? $t('apiTokens.revokeAll.failedRefreshed') : $t('apiTokens.revoke.failedRefreshed'))
          : (all ? $t('apiTokens.revokeAll.failedKept') : $t('apiTokens.revoke.failedKept'))"
        data-test="revoke-failed"
      />
      <p
        class="atv-question"
        data-test="revoke-question"
      >
        {{ question }}
      </p>
      <el-alert
        :type="consequence.type"
        :closable="false"
        show-icon
        :title="consequence.title"
        :description="consequence.body"
        :data-test="`revoke-consequence-${consequence.kind}`"
      />
      <div class="atv-field">
        <label
          :for="noteId"
          class="atv-label"
        >{{ mode === 'admin' ? $t('apiTokens.revoke.reasonOther', { user: ownerName }) : $t('apiTokens.revoke.reason') }}</label>
        <el-input
          :id="noteId"
          v-model="note"
          type="textarea"
          :rows="3"
          maxlength="2000"
          :placeholder="placeholder"
          :disabled="busy"
          data-test="revoke-note"
        />
      </div>
    </div>
    <template #footer>
      <el-button
        :disabled="busy"
        data-test="revoke-cancel"
        @click="emit('update:modelValue', false)"
      >
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        v-preview-write
        type="danger"
        :loading="busy"
        data-test="revoke-submit"
        @click="confirm"
      >
        {{ all ? $t('apiTokens.revokeAll.button') : $t('apiTokens.revoke.submit') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, ref, useId, watch } from 'vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import { isInactive } from '@/constants/apiTokens'
import { resolveApiError } from '@/api/error'

/**
 * 撤銷確認：單把（本人或管理者）與撤銷全部。後果句依「用過／沒用過」切換，
 * 失敗時對話框不關，頂端說明「沒有被撤銷，仍可使用」，原因欄保留。
 * 實際送出交給父層傳入的 submit(note)，以便本人與管理者各用各的端點。
 */
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  mode: { type: String, default: 'self' },
  token: { type: Object, default: null },
  // 撤銷全部：對象為這份清單中尚未失效的
  all: { type: Boolean, default: false },
  tokens: { type: Array, default: () => [] },
  ownerName: { type: String, default: '' },
  submit: { type: Function, required: true },
})
// failed：請求被伺服器以明確理由拒絕（權限、對象已不存在、狀態已變），
// 清單可能已過時，交由上層重新載入
const emit = defineEmits(['update:modelValue', 'done', 'failed'])

const noteId = useId()
const note = ref('')
const busy = ref(false)
const failed = ref(false)
// 有明確拒絕理由時的訊息；空字串＝伺服器錯誤或連線失敗，沿用「沒有被撤銷，仍可使用」
const failedReason = ref('')

watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      note.value = ''
      busy.value = false
      failed.value = false
      failedReason.value = ''
    }
  },
  { immediate: true }
)

const targets = computed(() => props.tokens.filter((tk) => !isInactive(tk)))
const sep = () => t('common.listSeparator')

const question = computed(() => {
  if (props.all) return t('apiTokens.revokeAll.confirm', { user: props.ownerName, n: targets.value.length })
  const name = props.token?.name || ''
  return props.mode === 'admin'
    ? t('apiTokens.revoke.confirmOther', { user: props.ownerName, name })
    : t('apiTokens.revoke.confirm', { name })
})

const consequence = computed(() => {
  if (props.all) {
    const names = targets.value.map((tk) => tk.name).join(sep())
    const never = targets.value.filter((tk) => !tk.expires_at).map((tk) => tk.name)
    const namesText = never.length
      ? `${names}${t('apiTokens.revokeAll.neverNote', { names: never.join(sep()) })}`
      : names
    return {
      kind: 'all',
      type: 'error',
      title: t('apiTokens.revokeAll.title', { user: props.ownerName }),
      body: t('apiTokens.revokeAll.body', { names: namesText, user: props.ownerName }),
    }
  }
  const tk = props.token || {}
  const admin = props.mode === 'admin'
  if (tk.last_used_at) {
    const time = formatDateTime(tk.last_used_at)
    const ip = tk.last_used_ip
    let body
    if (admin) {
      body = ip
        ? t('apiTokens.revoke.usedBodyOther', { time, ip, user: props.ownerName })
        : t('apiTokens.revoke.usedBodyOtherNoIp', { time, user: props.ownerName })
    } else {
      body = ip ? t('apiTokens.revoke.usedBody', { time, ip }) : t('apiTokens.revoke.usedBodyNoIp', { time })
    }
    return {
      kind: 'used',
      type: 'error',
      title: admin ? t('apiTokens.revoke.usedTitleOther', { user: props.ownerName }) : t('apiTokens.revoke.usedTitle'),
      body,
    }
  }
  return {
    kind: 'unused',
    type: 'warning',
    title: t('apiTokens.revoke.unusedTitle'),
    body: t('apiTokens.revoke.unusedBody'),
  }
})

const placeholder = computed(() => {
  if (props.all) return t('apiTokens.revokeAll.reasonPlaceholder')
  return props.mode === 'admin' ? t('apiTokens.revoke.reasonPlaceholderOther') : t('apiTokens.revoke.reasonPlaceholder')
})

const onToggle = (value) => {
  if (!value && busy.value) return
  emit('update:modelValue', value)
}

const confirm = async () => {
  if (busy.value) return
  busy.value = true
  failed.value = false
  try {
    const result = await props.submit(note.value.trim())
    emit('done', result)
    emit('update:modelValue', false)
  } catch (err) {
    failed.value = true
    const status = err?.response?.status
    // 4xx（逾時與限流除外）代表伺服器已判定、不是暫時故障：說出理由並重新整理清單，
    // 不能再說「伺服器錯誤，請稍後重試」誤導對方重按
    if (status >= 400 && status < 500 && status !== 408 && status !== 429) {
      failedReason.value = resolveApiError(err.response.data, status)
      emit('failed', err)
    } else {
      failedReason.value = ''
    }
  } finally {
    busy.value = false
  }
}

defineExpose({ confirm })
</script>

<style scoped>
.atv-body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}
.atv-question {
  margin: 0;
  color: var(--ot-text-primary);
}
.atv-field {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}
.atv-label {
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  color: var(--ot-text-primary);
}
</style>
