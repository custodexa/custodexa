<template>
  <el-dialog
    :model-value="modelValue"
    :title="isEdit ? t('credentials.form.editTitle') : t('credentials.form.createTitle')"
    width="560px"
    :close-on-click-modal="false"
    @update:model-value="close"
  >
    <el-form
      ref="formRef"
      :model="form"
      :rules="rules"
      label-position="top"
      @submit.prevent
    >
      <el-form-item
        prop="name"
        :label="t('credentials.form.name')"
      >
        <el-input
          v-model="form.name"
          maxlength="128"
          :disabled="isEdit && !isShared"
          :placeholder="t('credentials.form.namePlaceholder')"
          data-test="form-name"
        />
      </el-form-item>

      <el-form-item
        prop="username"
        :label="t('credentials.form.username')"
      >
        <el-input
          v-model="form.username"
          maxlength="100"
          :disabled="isEdit && isShared"
          :placeholder="t('credentials.form.usernamePlaceholder')"
          data-test="form-username"
        />
        <span
          v-if="isEdit && isShared"
          class="hint"
          data-test="form-username-immutable"
        >{{ t('credentials.form.usernameImmutable') }}</span>
      </el-form-item>

      <template v-if="!isEdit">
        <el-form-item :label="t('credentials.form.protocolFamily')">
          <el-select
            v-model="form.protocol_family"
            :empty-values="[null, undefined]"
            class="full"
            data-test="form-protocol"
          >
            <el-option
              v-for="value in CREDENTIAL_PROTOCOL_FAMILY_VALUES"
              :key="value"
              :label="t(`enum.credentialProtocolFamily.${value}`)"
              :value="value"
            />
          </el-select>
        </el-form-item>

        <el-form-item :label="t('credentials.form.secretType')">
          <el-radio-group
            v-model="form.secret_type"
            data-test="form-secret-type"
          >
            <el-radio-button
              v-for="value in CREDENTIAL_SECRET_TYPE_VALUES"
              :key="value"
              :value="value"
            >
              {{ t(`enum.credentialSecretType.${value}`) }}
            </el-radio-button>
          </el-radio-group>
        </el-form-item>

        <el-form-item
          v-if="form.secret_type === 'password'"
          prop="password"
          :label="t('credentials.form.password')"
        >
          <el-input
            v-model="form.password"
            type="password"
            show-password
            autocomplete="new-password"
            data-test="form-password"
          />
        </el-form-item>

        <el-form-item
          v-else
          prop="private_key"
          :label="t('credentials.form.privateKey')"
        >
          <el-input
            v-model="form.private_key"
            type="textarea"
            :rows="4"
            :placeholder="t('credentials.form.privateKeyPlaceholder')"
            data-test="form-private-key"
          />
        </el-form-item>

        <p class="hint">
          {{ t('credentials.form.secretHint') }}
        </p>
      </template>

      <el-form-item :label="t('credentials.form.note')">
        <el-input
          v-model="form.note"
          maxlength="255"
          data-test="form-note"
        />
      </el-form-item>
    </el-form>

    <template #footer>
      <el-button
        data-test="form-cancel"
        @click="close(false)"
      >
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        data-test="form-submit"
        @click="submit"
      >
        {{ t('common.save') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 新增共用憑證與編輯既有憑證。
 *
 * 秘密只在建立時輸入：既有憑證要換秘密走的是改密（會動遠端）或補登（不動遠端），
 * 兩者的後果差很多，都不該混在一個看起來只是改名的表單裡。
 *
 * 共用憑證的帳號名不可改：改它等於讓每一台掛載的機器換一個登入身分，
 * 而那件事只有逐台改密做得到。畫面上把欄位鎖住並就地說明，不是靜默禁用。
 */
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { createCredential, updateCredential } from '@/api/credentials'
import {
  CREDENTIAL_PROTOCOL_FAMILY_VALUES,
  CREDENTIAL_SECRET_TYPE_VALUES,
} from '@/constants/credentials'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // credential 非空＝編輯模式
  credential: { type: Object, default: null },
})

const emit = defineEmits(['update:modelValue', 'saved'])

const { t } = useI18n()

const formRef = ref(null)
const submitting = ref(false)
const form = reactive({
  name: '',
  username: '',
  protocol_family: 'ssh',
  secret_type: 'password',
  password: '',
  private_key: '',
  note: '',
})

const isEdit = computed(() => !!props.credential)
const isShared = computed(() => (isEdit.value ? props.credential.scope === 'shared' : true))

const rules = computed(() => ({
  name: [
    {
      validator: (_rule, value, callback) => {
        if (isEdit.value && !isShared.value) return callback()
        if (!value || !value.trim()) {
          return callback(new Error(t('credentials.form.nameRequired')))
        }
        return callback()
      },
      trigger: 'blur',
    },
  ],
  username: [
    { required: true, message: () => t('credentials.form.usernameRequired'), trigger: 'blur' },
  ],
  password: [
    {
      validator: (_rule, value, callback) => {
        if (isEdit.value || form.secret_type !== 'password' || value) return callback()
        return callback(new Error(t('credentials.form.secretRequired')))
      },
      trigger: 'blur',
    },
  ],
  private_key: [
    {
      validator: (_rule, value, callback) => {
        if (isEdit.value || form.secret_type !== 'ssh_key' || value) return callback()
        return callback(new Error(t('credentials.form.secretRequired')))
      },
      trigger: 'blur',
    },
  ],
}))

watch(() => props.modelValue, (open) => {
  if (!open) return
  const cred = props.credential
  form.name = cred?.scope === 'shared' ? cred.name : ''
  form.username = cred?.username || ''
  form.protocol_family = cred?.protocol_family || 'ssh'
  form.secret_type = cred?.secret_type || 'password'
  form.password = ''
  form.private_key = ''
  form.note = cred?.note || ''
  formRef.value?.clearValidate?.()
})

function close(visible = false) {
  emit('update:modelValue', visible === true)
}

function createPayload() {
  return {
    name: form.name.trim(),
    username: form.username.trim(),
    secret_type: form.secret_type,
    protocol_family: form.protocol_family,
    note: form.note,
    password: form.secret_type === 'password' ? form.password : '',
    private_key: form.secret_type === 'ssh_key' ? form.private_key : '',
  }
}

// 更新只送真的改過的欄位：三欄都是「省略＝不動」語義，把沒動過的原值一併送出
// 會在後端看起來像一次真正的改名，審計上分不出來
function updatePayload() {
  const body = { note: form.note }
  if (isShared.value) body.name = form.name.trim()
  else body.username = form.username.trim()
  return body
}

async function submit() {
  const valid = await formRef.value?.validate?.().catch(() => false)
  if (valid === false) return
  submitting.value = true
  try {
    if (isEdit.value) {
      await updateCredential(props.credential.id, updatePayload())
      ElMessage.success(t('credentials.form.updated'))
    } else {
      await createCredential(createPayload())
      ElMessage.success(t('credentials.form.created'))
    }
    close(false)
    emit('saved')
  } catch (err) {
    console.error('[CredentialForm] 儲存憑證失敗:', err)
  } finally {
    submitting.value = false
  }
}

defineExpose({ form, submit, createPayload, updatePayload, isEdit })
</script>

<style scoped>
.full {
  width: 100%;
}

.hint {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
  line-height: 1.6;
}
</style>
