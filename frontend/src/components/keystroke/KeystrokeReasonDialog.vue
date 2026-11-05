<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('keystrokeView.dialog.title')"
    width="620px"
    :close-on-click-modal="false"
    :close-on-press-escape="!submitting"
    :show-close="!submitting"
    append-to-body
    data-test="keystroke-reason-dialog"
    @update:model-value="onVisibleChange"
    @opened="focusReason"
  >
    <el-alert
      type="warning"
      :closable="false"
      show-icon
      class="intro"
    >
      <div>{{ $t('keystrokeView.dialog.introLead') }}</div>
      <div>{{ $t('keystrokeView.dialog.introLog') }}</div>
    </el-alert>

    <div class="reason-field">
      <label
        class="reason-label"
        for="keystroke-reason-input"
      ><span
        class="reason-required"
        aria-hidden="true"
      >*</span>{{ $t('keystrokeView.dialog.reasonLabel') }}</label>
      <el-input
        id="keystroke-reason-input"
        ref="inputRef"
        v-model="reason"
        type="textarea"
        :rows="4"
        :placeholder="$t('keystrokeView.dialog.reasonPlaceholder')"
        :disabled="submitting"
        :class="{ 'is-invalid': validationError }"
        data-test="keystroke-reason-input"
        @keydown.ctrl.enter.prevent="submit"
        @keydown.meta.enter.prevent="submit"
      />
      <div class="reason-foot">
        <span
          v-if="validationError"
          class="reason-error"
          data-test="keystroke-reason-error"
        >{{ validationError }}</span>
        <span
          v-else
          class="reason-hint"
        >{{ $t('keystrokeView.dialog.keyHint') }}</span>
        <span
          class="reason-count"
          :class="{ over: length > REASON_MAX }"
        >{{ $t('keystrokeView.dialog.reasonCount', { n: length.toLocaleString('en-US') }) }}</span>
      </div>
      <div
        class="reason-note"
        data-test="keystroke-reason-note"
      >
        {{ $t('keystrokeView.dialog.reasonNote') }}
      </div>
    </div>

    <el-alert
      v-if="failure"
      type="error"
      :closable="false"
      show-icon
      class="failure"
      data-test="keystroke-reason-failure"
    >
      <template #title>
        {{ $t(`keystrokeView.error.${failure.kind}.title`) }}
      </template>
      <div>{{ $t(`keystrokeView.error.${failure.kind}.body`) }}</div>
    </el-alert>

    <template #footer>
      <el-button
        :disabled="submitting"
        data-test="keystroke-reason-cancel"
        @click="close"
      >
        {{ failure && !failure.retryable ? $t('keystrokeView.dialog.close') : $t('keystrokeView.dialog.cancel') }}
      </el-button>
      <el-button
        v-if="!failure || failure.retryable"
        type="primary"
        :loading="submitting"
        data-test="keystroke-reason-submit"
        @click="submit"
      >
        {{ failure ? $t('keystrokeView.dialog.retry') : $t('keystrokeView.dialog.submit') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
// 查看理由對話框：填理由、送出第一頁並就地呈現錯誤（錯誤不走全域 toast）。
// 成功時把理由與第一頁內容交給呼叫端（success 事件）；內容只在記憶體，不進任何儲存或 console。
import { computed, nextTick, ref, watch } from 'vue'
import { t } from '@/i18n'
import { viewKeystrokes } from '@/api/keystrokes'
import { REASON_MAX, classifyKeystrokeError, reasonLength } from '@/utils/keystrokeView'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  sessionId: { type: [String, Number], required: true },
})
const emit = defineEmits(['update:modelValue', 'success', 'rights-lost', 'not-viewable'])

const reason = ref('')
const submitting = ref(false)
const failure = ref(null)
const touched = ref(false)
const inputRef = ref(null)

const length = computed(() => reasonLength(reason.value))
const validationError = computed(() => {
  if (!touched.value) return ''
  if (length.value === 0) return t('keystrokeView.dialog.errEmpty')
  if (length.value > REASON_MAX) return t('keystrokeView.dialog.errTooLong', { n: length.value - REASON_MAX })
  return ''
})

watch(() => props.modelValue, (open) => {
  if (open) {
    failure.value = null
    touched.value = false
    submitting.value = false
  } else {
    // 關閉即清空理由欄，不留在元件狀態
    reason.value = ''
  }
})

const focusReason = () => nextTick(() => inputRef.value?.focus?.())
const close = () => {
  if (submitting.value) return
  if (failure.value?.kind === 'noPermission') emit('rights-lost')
  if (failure.value?.kind === 'notViewable') emit('not-viewable')
  emit('update:modelValue', false)
}
const onVisibleChange = (v) => {
  if (!v) close()
}

const submit = async () => {
  if (submitting.value) return
  touched.value = true
  if (length.value === 0 || length.value > REASON_MAX) {
    // 錯誤寫在欄位正下方，焦點回到欄位讓使用者直接修
    focusReason()
    return
  }
  failure.value = null
  submitting.value = true
  const text = reason.value.trim()
  try {
    const res = await viewKeystrokes(props.sessionId, { reason: text })
    emit('success', { reason: text, data: res?.data ?? {}, loggedAt: new Date() })
    emit('update:modelValue', false)
  } catch (err) {
    failure.value = classifyKeystrokeError(err)
  } finally {
    submitting.value = false
  }
}

defineExpose({ submit })
</script>

<style scoped>
.intro { margin-bottom: 14px; line-height: 1.6; }
.reason-field { display: flex; flex-direction: column; gap: 6px; }
.reason-label { font-size: 14px; font-weight: 600; color: var(--ot-text-primary); }
.reason-foot { display: flex; justify-content: space-between; gap: 12px; font-size: 12.5px; }
.reason-required { color: var(--ot-danger, #e5604f); margin-right: 4px; }
.reason-hint { color: var(--ot-text-secondary); }
.reason-note { font-size: 12.5px; color: var(--ot-text-secondary); line-height: 1.6; }
.is-invalid :deep(.el-textarea__inner) { box-shadow: 0 0 0 1px var(--ot-danger, #e5604f) inset; }
.reason-error { color: var(--ot-danger, #e5604f); }
.reason-count { color: var(--ot-text-secondary); margin-left: auto; }
.reason-count.over { color: var(--ot-danger, #e5604f); }
.failure { margin-top: 12px; }
</style>
