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

      <!-- 管理歸屬：共用憑證才有（專用憑證恆隨資產）。節點候選與全域選項由伺服器標示 -->
      <el-form-item
        v-if="isShared"
        :label="t('credentials.ownership.label')"
        data-test="form-ownership"
      >
        <CredentialOwnershipSelect
          v-model="ownership"
          :purpose="isEdit ? 'credential_update' : 'credential_create'"
          :active="modelValue"
          :disabled="!!ownershipDenied"
          :hint="ownershipDenied ? t(`credentials.actionReason.${ownershipDenied}`) : ''"
          :explain="isEdit"
          @state="ownershipState = $event"
        />
      </el-form-item>
      <el-form-item :label="t('credentials.form.note')">
        <el-input
          v-model="form.note"
          maxlength="255"
          data-test="form-note"
        />
      </el-form-item>

      <!-- 共用憑證的登記值打錯時，使用者第一個會打開的是這個對話框：
           在這裡說清楚它改不了秘密，並指向真正的入口 -->
      <p
        v-if="isEdit && isShared"
        class="hint"
        data-test="form-secret-fix-hint"
      >
        {{ t('credentials.secretFix.editHint', { noun: secretNoun, entry: secretFixEntry }) }}
      </p>
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
        :disabled="submitBlocked"
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
import CredentialOwnershipSelect from './CredentialOwnershipSelect.vue'
import { deniedReason } from '@/utils/credentialActions'
import {
  CREDENTIAL_PROTOCOL_FAMILY_VALUES,
  CREDENTIAL_SECRET_TYPE_VALUES,
  credentialSecretKind,
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

// 歸屬：{ kind: 'global'|'node', node_id }；選擇器回報 state（可否送出、是否範圍化）
const ownership = ref({ kind: 'global', node_id: null })
const ownershipState = ref({ loading: false, ready: true, scoped: false, allowGlobal: true })

const isEdit = computed(() => !!props.credential)
const isShared = computed(() => (isEdit.value ? props.credential.scope === 'shared' : true))
const secretNoun = computed(() =>
  t(`credentials.secretFix.noun.${credentialSecretKind(props.credential)}`))
const secretFixEntry = computed(() => t('credentials.secretFix.entry', { noun: secretNoun.value }))

// 編輯時歸屬是否有改：沒改就不送、也不因候選節點載入失敗擋住改名與備註
const originalOwnership = computed(() => {
  const o = props.credential?.ownership
  return o?.kind === 'node'
    ? { kind: 'node', node_id: o.node_id ?? null }
    : { kind: 'global', node_id: null }
})
const ownershipChanged = computed(() => ownership.value.kind !== originalOwnership.value.kind
  || (ownership.value.kind === 'node' && ownership.value.node_id !== originalOwnership.value.node_id))
// 伺服器標示本主體不能改這筆的歸屬（reassign 旗標）：欄位唯讀並說明原因
const ownershipDenied = computed(() => (isEdit.value ? deniedReason(props.credential, 'reassign') : ''))
// 要送出歸屬時（新增，或編輯且有改）必須選到可選節點
const ownershipNeeded = computed(() => isShared.value && (!isEdit.value || ownershipChanged.value))
const submitBlocked = computed(() => ownershipNeeded.value && !ownershipState.value.ready)

// 範圍化主體一律明送歸屬；全域主體不選節點時維持現行「不帶歸屬」
function ownershipBody() {
  if (!isShared.value) return null
  const { kind, node_id: nodeId } = ownership.value
  if (kind === 'node') return { kind: 'node', node_id: nodeId }
  return ownershipState.value.scoped ? { kind: 'global' } : null
}

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
  ownership.value = cred ? { ...originalOwnership.value } : { kind: 'global', node_id: null }
  formRef.value?.clearValidate?.()
})

function close(visible = false) {
  emit('update:modelValue', visible === true)
}

function createPayload() {
  const body = {
    name: form.name.trim(),
    username: form.username.trim(),
    secret_type: form.secret_type,
    protocol_family: form.protocol_family,
    note: form.note,
    password: form.secret_type === 'password' ? form.password : '',
    private_key: form.secret_type === 'ssh_key' ? form.private_key : '',
  }
  const own = ownershipBody()
  if (own) body.ownership = own
  return body
}

// 更新只送真的改過的欄位：三欄都是「省略＝不動」語義，把沒動過的原值一併送出
// 會在後端看起來像一次真正的改名，審計上分不出來
function updatePayload() {
  const body = { note: form.note }
  if (isShared.value) body.name = form.name.trim()
  else body.username = form.username.trim()
  if (ownershipChanged.value && !ownershipDenied.value) {
    const own = ownershipBody()
    if (own) body.ownership = own
    else if (ownership.value.kind === 'global') body.ownership = { kind: 'global' }
  }
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
