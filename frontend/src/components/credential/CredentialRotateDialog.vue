<template>
  <el-dialog
    :model-value="modelValue"
    :title="t('credentials.rotateDialog.title')"
    width="560px"
    :close-on-click-modal="false"
    @update:model-value="close"
  >
    <div class="rotate-body">
      <p
        class="summary"
        data-test="rotate-summary"
      >
        {{ t('credentials.rotateDialog.summary', { count: bindingCount }) }}
      </p>

      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="t('credentials.rotateDialog.modeLabel')">
          <el-radio-group
            v-model="form.mode"
            class="mode-group"
            data-test="rotate-mode"
          >
            <div
              class="mode-card"
              :class="{ selected: form.mode === 'group' }"
            >
              <el-radio value="group">
                {{ t('enum.credentialRotationMode.group') }}
              </el-radio>
              <span class="mode-hint">
                {{ t('credentials.rotateDialog.groupHint',
                     { count: bindingCount, name: credentialName }) }}
              </span>
            </div>
            <div
              class="mode-card"
              :class="{ selected: form.mode === 'split' }"
            >
              <el-radio value="split">
                {{ t('enum.credentialRotationMode.split') }}
              </el-radio>
              <span class="mode-hint">{{ t('credentials.rotateDialog.splitHint') }}</span>
              <el-alert
                v-if="form.mode === 'split'"
                type="error"
                :closable="false"
                show-icon
                data-test="split-warning"
                :title="t('credentials.rotateDialog.splitWarning', { name: credentialName })"
              />
            </div>
          </el-radio-group>
        </el-form-item>

        <el-form-item :label="t('credentials.rotateDialog.length')">
          <div class="length-row">
            <el-input-number
              v-model="form.password_length"
              :min="PASSWORD_LENGTH_MIN"
              :max="PASSWORD_LENGTH_MAX"
              data-test="rotate-length"
            />
            <span class="hint">{{ t('credentials.rotateDialog.lengthHint') }}</span>
          </div>
        </el-form-item>

        <el-form-item :label="t('credentials.rotateDialog.chars')">
          <div class="char-row">
            <el-checkbox
              v-model="form.include_symbol"
              data-test="rotate-include-symbol"
            >
              {{ t('credentials.rotateDialog.includeSymbol') }}
            </el-checkbox>
            <el-checkbox
              v-model="form.exclude_ambiguous"
              data-test="rotate-exclude-ambiguous"
            >
              {{ t('credentials.rotateDialog.excludeAmbiguous') }}
            </el-checkbox>
          </div>
        </el-form-item>
      </el-form>
    </div>

    <template #footer>
      <el-button
        data-test="rotate-cancel"
        @click="close(false)"
      >
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        data-test="rotate-submit"
        @click="submit"
      >
        {{ t('credentials.rotateDialog.submit') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 共用憑證的改密對話框（設計稿 07）。
 *
 * 兩個模式的差別不只是密碼怎麼生成：「每台各自隨機」在成功後會解除共用關係，
 * 那是不可復原的結構改變，故它的後果寫在選項旁而不是送出後的確認框裡——
 * 操作者要在選之前就看見。
 */
import { reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { startCredentialRotation } from '@/api/credentials'
import {
  PASSWORD_LENGTH_MIN,
  PASSWORD_LENGTH_MAX,
  PASSWORD_LENGTH_DEFAULT,
} from '@/constants/credentials'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  credentialId: { type: [Number, String], default: 0 },
  credentialName: { type: String, default: '' },
  bindingCount: { type: Number, default: 0 },
})

const emit = defineEmits(['update:modelValue', 'submitted'])

const { t } = useI18n()

const submitting = ref(false)
const form = reactive({
  mode: 'group',
  password_length: PASSWORD_LENGTH_DEFAULT,
  include_symbol: true,
  exclude_ambiguous: true,
})

// 每次開啟都回到預設：上一次選過「每台各自隨機」而沒送出時，下一次開啟不該
// 還停在那個會解除共用的選項上
watch(() => props.modelValue, (open) => {
  if (!open) return
  form.mode = 'group'
  form.password_length = PASSWORD_LENGTH_DEFAULT
  form.include_symbol = true
  form.exclude_ambiguous = true
})

function close(visible = false) {
  emit('update:modelValue', visible === true)
}

async function submit() {
  submitting.value = true
  try {
    const res = await startCredentialRotation(props.credentialId, {
      mode: form.mode,
      policy: {
        length: form.password_length,
        include_symbol: form.include_symbol,
        exclude_ambiguous: form.exclude_ambiguous,
      },
    })
    close(false)
    ElMessage.success(t('credentials.rotateDialog.accepted'))
    emit('submitted', res?.data || null)
  } catch (err) {
    console.error('[CredentialRotate] 發起改密失敗:', err)
  } finally {
    submitting.value = false
  }
}

defineExpose({ form, submit, PASSWORD_LENGTH_MIN, PASSWORD_LENGTH_MAX })
</script>

<style scoped>
.rotate-body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}

.summary {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}

.mode-group {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  width: 100%;
}

.mode-card {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-surface);
  width: 100%;
}

.mode-card.selected {
  border-color: var(--ot-primary);
  background: var(--ot-primary-dim);
}

.mode-hint {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  line-height: 1.6;
  white-space: normal;
}

.length-row,
.char-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
}

.hint {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
}
</style>
