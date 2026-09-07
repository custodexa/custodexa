<!--
  AssetAccountAddRow：帳號表內展開的「新增帳號」一列。

  取代了原先「從其他資產帳號複製」那條路：要跟別台用同一組秘密，就挑那筆共用憑證，
  而不是複製一份出來——複製出來的兩份密文事後無從得知是否還一樣。

  新增一個登入身分等於多一個可用身分，故此處先把影響面講清楚再讓人送出。
-->
<template>
  <div
    class="add-row"
    data-test="account-add-row"
  >
    <el-form
      ref="formRef"
      :model="model"
      :rules="rules"
      label-position="top"
      @submit.prevent
    >
      <div class="add-row__title">
        {{ t('assets.editDrawer.addTitle') }}
      </div>
      <AssetCredentialSection
        :model="model"
        :protocol="protocol"
        :windows-openssh="windowsOpenssh"
        :exclude-ids="excludeIds"
        :asset-name="assetName"
        show-privileged
        compact
        @update:model="Object.assign(model, $event)"
      />
      <div
        v-if="model.credential_mode === 'shared'"
        class="hint"
        data-test="account-add-hint"
      >
        {{ t('assets.editDrawer.addHint') }}
      </div>
      <!-- 影響面是警示不是註腳：多一個登入身分等於多一條可用路徑，
           故用 warning 型提示並讓標題與說明各自成行，不併成一段灰字 -->
      <el-alert
        v-if="impactLoaded"
        type="warning"
        show-icon
        :closable="false"
        class="impact-alert"
        :title="t('assetAccounts.impactTitle', { users: impactUsers, groups: impactGroups })"
        data-test="account-add-impact"
      >
        {{ t('assetAccounts.impactHint') }}
        <span v-if="impactNote">{{ impactNote }}</span>
      </el-alert>
      <div class="inline-actions">
        <el-button
          type="primary"
          size="small"
          :loading="submitting"
          data-test="account-add-submit"
          @click="submit"
        >
          {{ t('assets.editDrawer.addSubmit') }}
        </el-button>
        <el-button
          size="small"
          data-test="account-add-cancel"
          @click="cancel"
        >
          {{ t('common.cancel') }}
        </el-button>
      </div>
    </el-form>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { createAssetAccount } from '@/api/assetAccounts'
import { getEffectiveUsers } from '@/api/authorizations'
import { effectiveAccessNote } from '@/utils/keyDisplay'
import { isDatabaseProtocol } from '@/utils/protocol'
import AssetCredentialSection from '@/components/asset/AssetCredentialSection.vue'

const props = defineProps({
  assetId: { type: [Number, String], default: null },
  assetName: { type: String, default: '' },
  protocol: { type: String, default: '' },
  windowsOpenssh: { type: Boolean, default: false },
  // 已掛在這台上的憑證：同一台不會掛兩次同一筆
  excludeIds: { type: Array, default: () => [] },
})

const emit = defineEmits(['added', 'cancel'])

const { t } = useI18n()

const formRef = ref(null)
const submitting = ref(false)
const model = reactive({
  credential_mode: 'shared',
  credential_id: null,
  username: '',
  password: '',
  private_key: '',
  privileged: false,
  auth_method: 'sql',
})

const rules = computed(() => ({
  credential_id: [
    {
      validator: (_rule, value, callback) => {
        if (model.credential_mode === 'shared' && !value) {
          callback(new Error(t('assets.credentialSection.sharedRequired')))
        } else {
          callback()
        }
      },
      trigger: 'change',
    },
  ],
  username: [
    {
      validator: (_rule, value, callback) => {
        if (model.credential_mode === 'dedicated' && !value) {
          callback(new Error(t('assetAccounts.usernameRequired')))
        } else {
          callback()
        }
      },
      trigger: 'blur',
    },
  ],
}))

// 登入憑證來源二擇一：兩種來源同時帶值會被伺服端判為意圖不明
function payload() {
  const body = { privileged: model.privileged, is_default: false }
  if (model.credential_mode === 'shared') {
    body.credential_id = model.credential_id
    return body
  }
  body.username = (model.username || '').trim()
  if (model.password) body.password = model.password
  if (model.private_key) body.private_key = model.private_key
  // 僅資料庫協定帶 auth_method；其他協定沒有這個語義，不送即讓伺服端保持預設值。
  // 下拉本身也只在資料庫協定出現（AssetCredentialSection.vue），閘門兩邊都要有：
  // 只擋畫面不擋載荷時，出廠值仍會被恆送出去
  if (isDatabaseProtocol(props.protocol) && model.auth_method) {
    body.auth_method = model.auth_method
  }
  return body
}

// 收起即清掉明文：只隱藏這一列會讓輸入值續留在元件狀態內
function cancel() {
  model.password = ''
  model.private_key = ''
  emit('cancel')
}

async function submit() {
  if (formRef.value) {
    try {
      await formRef.value.validate()
    } catch {
      return
    }
  }
  submitting.value = true
  try {
    await createAssetAccount(props.assetId, payload())
    ElMessage.success(t('assetAccounts.created'))
    model.password = ''
    model.private_key = ''
    emit('added')
  } catch (err) {
    console.error('[AssetAccountAddRow] 新增帳號失敗:', err?.response?.status, err?.response?.data?.code)
  } finally {
    submitting.value = false
  }
}

// --- 影響面：帳號範圍為「全部帳號」的既有授權會立即涵蓋新帳號 ---
const impactLoaded = ref(false)
const impactUsers = ref(0)
const impactGroups = ref(0)
const impactNote = ref('')

async function loadImpact() {
  impactLoaded.value = false
  impactNote.value = ''
  if (!props.assetId) return
  try {
    const resp = await getEffectiveUsers(props.assetId)
    const users = resp.users || []
    impactNote.value = effectiveAccessNote(resp)
    impactUsers.value = users.length
    const groups = new Set()
    for (const user of users) {
      for (const path of user.paths || []) {
        if (path.via_group_id) groups.add(path.via_group_id)
      }
    }
    impactGroups.value = groups.size
    impactLoaded.value = true
  } catch (err) {
    // 影響面是提示而非閘門：查不到就不顯示，不擋新增
    console.warn('[AssetAccountAddRow] 影響面查詢失敗:', err)
  }
}

onMounted(loadImpact)

defineExpose({ model, payload, submit, cancel, formRef })
</script>

<style scoped>
.add-row {
  margin-top: var(--ot-space-sm);
  padding: var(--ot-space-md);
  border: 1px solid var(--el-border-color);
  border-radius: var(--ot-radius-md, 6px);
  background: var(--el-fill-color-light);
}

.add-row__title {
  margin-bottom: var(--ot-space-sm);
  font-weight: 500;
}

.hint {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
  line-height: 1.6;
}

.impact-alert {
  margin-top: var(--ot-space-xs);
}

.inline-actions {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-sm);
}
</style>
