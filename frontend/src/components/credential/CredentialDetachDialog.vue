<template>
  <el-dialog
    :model-value="modelValue"
    :title="t('credentials.detachDialog.title')"
    width="560px"
    :close-on-click-modal="false"
    @update:model-value="close"
  >
    <div class="detach-body">
      <!-- 副標寫出這個對話框到底在動哪一台的哪個帳號：標題只說得出動作 -->
      <p
        class="subject"
        data-test="detach-subject"
      >
        {{ t('credentials.detachDialog.subject', { asset: assetName, username: username }) }}
      </p>

      <div class="transition">
        <el-tag
          size="small"
          type="primary"
          data-test="detach-from"
        >
          {{ t('credentials.detachDialog.fromTag',
               { name: credentialName, count: bindingCount }) }}
        </el-tag>
        <el-icon class="arrow">
          <ArrowRight />
        </el-icon>
        <el-tag
          size="small"
          type="info"
          data-test="detach-to"
        >
          {{ t('credentials.detachDialog.toTag',
               { asset: assetName, username: username }) }}
        </el-tag>
      </div>

      <p
        class="intro"
        data-test="detach-intro"
      >
        {{ introText }}
      </p>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        @submit.prevent
      >
        <div class="group-label">
          {{ t('credentials.detachDialog.sourceLabel') }}
        </div>
        <el-radio-group
          v-model="form.source"
          class="source-group"
          data-test="detach-source"
        >
          <div
            class="source-card"
            :class="{ selected: form.source === 'random' }"
          >
            <el-radio value="random">
              {{ t('enum.credentialDetachSource.random') }}
            </el-radio>
            <div
              v-if="form.source === 'random'"
              class="policy-row"
            >
              <span class="policy-label">{{ t('credentials.rotateDialog.length') }}</span>
              <el-input-number
                v-model="form.password_length"
                :min="PASSWORD_LENGTH_MIN"
                :max="PASSWORD_LENGTH_MAX"
                size="small"
                data-test="detach-length"
              />
              <el-checkbox
                v-model="form.include_symbol"
                data-test="detach-include-symbol"
              >
                {{ t('credentials.rotateDialog.includeSymbol') }}
              </el-checkbox>
              <el-checkbox
                v-model="form.exclude_ambiguous"
                data-test="detach-exclude-ambiguous"
              >
                {{ t('credentials.rotateDialog.excludeAmbiguous') }}
              </el-checkbox>
            </div>
          </div>
          <div
            class="source-card"
            :class="{ selected: form.source === 'custom' }"
          >
            <el-radio value="custom">
              {{ t('enum.credentialDetachSource.custom') }}
            </el-radio>
            <template v-if="form.source === 'custom'">
              <el-form-item
                prop="password"
                :label="t('credentials.detachDialog.newPassword')"
              >
                <el-input
                  v-model="form.password"
                  type="password"
                  show-password
                  autocomplete="new-password"
                  :placeholder="t('credentials.detachDialog.newPasswordPlaceholder')"
                  data-test="detach-password"
                />
              </el-form-item>
              <el-form-item
                prop="private_key"
                :label="t('credentials.detachDialog.privateKey')"
              >
                <el-input
                  v-model="form.private_key"
                  type="textarea"
                  :rows="3"
                  :placeholder="t('credentials.detachDialog.privateKeyPlaceholder')"
                  data-test="detach-private-key"
                />
              </el-form-item>
              <span
                class="source-hint"
                data-test="detach-custom-hint"
              >{{ t('credentials.detachDialog.customHint') }}</span>
            </template>
          </div>
        </el-radio-group>
      </el-form>
    </div>

    <template #footer>
      <el-button
        data-test="detach-cancel"
        @click="close(false)"
      >
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        data-test="detach-submit"
        @click="submit"
      >
        {{ t('credentials.detachDialog.submit') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 單台脫離共用（設計稿 08）。
 *
 * 脫離一律伴隨改密：這台之後用的是自己的秘密，而「自己的秘密」必須先真的
 * 套到主機上並驗證通過，否則脫離只是在資料庫裡改了歸屬，主機還吃著共用那組。
 * 失敗即維持共用，故文案把驗證這一步明說。
 *
 * 這一支端點是單台脫離的**唯一**入口（憑證庫掛載列與資產編輯都打它），
 * 請求可能耗時數十秒——送出後保持 loading，不要假設它很快回。
 */
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { ArrowRight } from 'lucide-vue-next'
import { detachCredentialBinding } from '@/api/credentials'
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
  accountId: { type: [Number, String], default: 0 },
  assetName: { type: String, default: '' },
  username: { type: String, default: '' },
  // secretType 決定自訂來源時哪一欄必填（password｜ssh_key）
  secretType: { type: String, default: 'password' },
})

const emit = defineEmits(['update:modelValue', 'detached'])

const { t } = useI18n()

const formRef = ref(null)
const submitting = ref(false)
const form = reactive({
  source: 'random',
  password_length: PASSWORD_LENGTH_DEFAULT,
  include_symbol: true,
  exclude_ambiguous: true,
  password: '',
  private_key: '',
})

// 自訂來源時必須真的給出新秘密：密碼型憑證要密碼、金鑰型要私鑰。
// 空著送出等同「請把這台改成一組沒人知道的東西」，那不是任何人的本意
const requiredSecretField = computed(() =>
  (props.secretType === 'ssh_key' ? 'private_key' : 'password'))

const missingSecret = computed(() =>
  form.source === 'custom' && !form[requiredSecretField.value])

const rules = computed(() => ({
  password: [
    {
      validator: (_rule, value, callback) => {
        if (form.source !== 'custom' || requiredSecretField.value !== 'password') {
          return callback()
        }
        if (!value) return callback(new Error(t('credentials.detachDialog.passwordRequired')))
        return callback()
      },
      trigger: 'blur',
    },
  ],
  private_key: [
    {
      validator: (_rule, value, callback) => {
        if (form.source !== 'custom' || requiredSecretField.value !== 'private_key') {
          return callback()
        }
        if (!value) return callback(new Error(t('credentials.detachDialog.privateKeyRequired')))
        return callback()
      },
      trigger: 'blur',
    },
  ],
}))

// 剩一台不是「其餘一台不受影響」：原共用憑證掉到只剩單一掛載時會被轉成那台的
// 專用憑證並清掉名稱，那是操作者當場看得到的後果，不能用「不受影響」概括
const introText = computed(() => {
  const rest = Math.max(props.bindingCount - 1, 0)
  if (rest === 0) return t('credentials.detachDialog.introLast')
  if (rest === 1) return t('credentials.detachDialog.introSolo', { name: props.credentialName })
  return t('credentials.detachDialog.intro', { name: props.credentialName, rest })
})

watch(() => props.modelValue, (open) => {
  if (!open) return
  form.source = 'random'
  form.password_length = PASSWORD_LENGTH_DEFAULT
  form.include_symbol = true
  form.exclude_ambiguous = true
  form.password = ''
  form.private_key = ''
  formRef.value?.clearValidate?.()
})

function close(visible = false) {
  emit('update:modelValue', visible === true)
}

function payload() {
  const body = { source: form.source }
  if (form.source === 'random') {
    body.policy = {
      length: form.password_length,
      include_symbol: form.include_symbol,
      exclude_ambiguous: form.exclude_ambiguous,
    }
  } else {
    body.password = form.password
    body.private_key = form.private_key
  }
  return body
}

async function submit() {
  if (missingSecret.value) {
    await formRef.value?.validate?.().catch(() => {})
    return
  }
  submitting.value = true
  try {
    const res = await detachCredentialBinding(props.credentialId, props.accountId, payload())
    close(false)
    ElMessage.success(t('credentials.detachDialog.done'))
    emit('detached', res?.data || null)
  } catch (err) {
    console.error('[CredentialDetach] 脫離共用失敗:', err)
  } finally {
    submitting.value = false
  }
}

defineExpose({ form, submit, payload, missingSecret })
</script>

<style scoped>
.detach-body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}

.subject {
  margin: 0;
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.transition {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}

.arrow {
  color: var(--ot-text-secondary);
}

.group-label {
  margin-bottom: var(--ot-space-xs);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}

.intro {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}

.source-group {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  width: 100%;
}

.source-card {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-surface);
  width: 100%;
}

.source-card.selected {
  border-color: var(--ot-primary);
  background: var(--ot-primary-dim);
}

.policy-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
}

.policy-label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.source-hint {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  line-height: 1.6;
  white-space: normal;
}
</style>
