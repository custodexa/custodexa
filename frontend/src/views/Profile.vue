<template>
  <div class="profile">
    <PageHeader
      :title="$t('menu.profile')"
      :description="$t('profile.headerDesc')"
    />

    <div class="profile-grid">
      <!-- 基本資料（唯讀） -->
      <div
        v-loading="infoLoading"
        class="profile-card"
      >
        <div class="card-title">
          {{ $t('profile.basicInfo') }}
        </div>
        <el-descriptions
          :column="1"
          border
        >
          <el-descriptions-item :label="$t('common.username')">
            {{ account.username || '—' }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('profile.fullNameLabel')">
            {{ account.full_name || '—' }}
          </el-descriptions-item>
          <el-descriptions-item label="Email">
            {{ account.email || '—' }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('common.role')">
            <el-space
              wrap
              :size="6"
            >
              <el-tag
                v-for="r in account.roles || []"
                :key="r"
                size="small"
              >
                {{ roleLabel(r) }}
              </el-tag>
            </el-space>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('profile.mfaLabel')">
            <el-tag
              :type="mfaEnabled ? 'success' : 'info'"
              size="small"
            >
              {{ mfaEnabled ? $t('profile.statusEnabled') : $t('profile.statusDisabled') }}
            </el-tag>
          </el-descriptions-item>
        </el-descriptions>
        <!-- 身分欄位為權威、唯讀（PAM 治理）；LDAP 帳號另註明由目錄服務管理 -->
        <div class="card-hint">
          {{ identityNote }}
        </div>
      </div>

      <!-- 自助顯示名（profile-display-name）：LDAP 帳號亦可自助（本地欄位，不參與目錄同步） -->
      <div
        v-loading="infoLoading"
        class="profile-card"
      >
        <div class="card-title">
          {{ $t('profile.displayNameCard') }}
        </div>
        <div class="card-hint">
          {{ $t('profile.displayNameCardDesc') }}
        </div>
        <el-descriptions
          :column="1"
          border
        >
          <el-descriptions-item :label="$t('profile.currentDisplayName')">
            {{ account.display_name || '—' }}
          </el-descriptions-item>
        </el-descriptions>
        <el-form
          label-position="top"
          @submit.prevent
        >
          <el-form-item :label="$t('profile.displayNameField')">
            <el-input
              v-model="displayNameInput"
              maxlength="100"
              show-word-limit
              :placeholder="$t('profile.displayNamePlaceholder')"
              @keyup.enter="handleSaveDisplayName"
            />
          </el-form-item>
        </el-form>
        <el-alert
          v-if="displayNameError"
          class="display-name-error"
          type="error"
          :title="displayNameError"
          :closable="false"
          show-icon
        />
        <div class="display-name-hint">
          {{ $t('profile.displayNameHint') }}
        </div>
        <div class="display-name-actions">
          <el-button
            type="primary"
            :loading="displayNameSaving"
            @click="handleSaveDisplayName"
          >
            {{ $t('common.save') }}
          </el-button>
          <el-button
            :disabled="displayNameSaving || (!displayNameInput && !account.local_display_name)"
            @click="handleClearDisplayName"
          >
            {{ $t('profile.clearDisplayName') }}
          </el-button>
        </div>
      </div>

      <!-- 自助改密；外部身分帳號（LDAP／OIDC）的憑證由提供者管理，不提供表單
           （ux-consistency D5「整卡換說明 alert」；idp-oidc-integration D14.6
           將判定自 is_ldap 泛化為 external_credential——只認 is_ldap 會讓
           OIDC 供應帳號看到一個按下必被後端擋的改密表單） -->
      <div class="profile-card">
        <div class="card-title">
          {{ $t('common.changePassword') }}
        </div>
        <el-alert
          v-if="isExternalCredential"
          :title="externalPasswordTitle"
          :description="externalPasswordDesc"
          type="info"
          :closable="false"
        />
        <el-form
          v-if="!isExternalCredential"
          ref="pwdFormRef"
          :model="pwdForm"
          :rules="pwdRules"
          label-position="top"
          @submit.prevent
        >
          <el-form-item
            :label="$t('profile.currentPassword')"
            prop="oldPassword"
          >
            <el-input
              v-model="pwdForm.oldPassword"
              type="password"
              show-password
              autocomplete="current-password"
            />
          </el-form-item>
          <el-form-item
            :label="$t('common.newPassword')"
            prop="newPassword"
          >
            <el-input
              v-model="pwdForm.newPassword"
              type="password"
              show-password
              autocomplete="new-password"
            />
          </el-form-item>
          <el-form-item
            :label="$t('profile.confirmNewPassword')"
            prop="confirmPassword"
          >
            <el-input
              v-model="pwdForm.confirmPassword"
              type="password"
              show-password
              autocomplete="new-password"
              @keyup.enter="handleChangePassword"
            />
          </el-form-item>
          <el-alert
            v-if="pwdError"
            class="pwd-error"
            type="error"
            :title="pwdError"
            :closable="false"
            show-icon
          />
          <el-button
            type="primary"
            :loading="pwdChanging"
            @click="handleChangePassword"
          >
            {{ $t('profile.updatePassword') }}
          </el-button>
        </el-form>
      </div>

      <!-- MFA 管理（自 MainLayout 安全設定 dialog 遷入，流程不變） -->
      <div
        v-loading="infoLoading"
        class="profile-card"
      >
        <div class="card-title">
          {{ $t('profile.mfaCardTitle') }}
        </div>
        <template v-if="mfaEnabled">
          <el-alert
            :title="$t('profile.mfaEnabledTitle')"
            :description="$t('profile.mfaEnabledDesc')"
            type="success"
            :closable="false"
          />
          <el-form
            label-position="top"
            @submit.prevent
          >
            <el-form-item :label="$t('profile.disableMfaLabel')">
              <el-input
                v-model="disablePassword"
                type="password"
                :placeholder="$t('profile.currentPassword')"
                show-password
                @keyup.enter="handleDisableMFA"
              />
            </el-form-item>
          </el-form>
          <el-button
            type="danger"
            :loading="disabling"
            :disabled="!disablePassword"
            @click="handleDisableMFA"
          >
            {{ $t('common.disableMfa') }}
          </el-button>
        </template>

        <template v-else>
          <el-alert
            :title="$t('profile.mfaDisabledTitle')"
            :description="$t('profile.mfaDisabledDesc')"
            type="info"
            :closable="false"
          />

          <el-button
            v-if="!mfaSetup"
            type="primary"
            :loading="setupLoading"
            class="mfa-generate-btn"
            @click="handleGenerateMFASetup"
          >
            {{ $t('profile.generateSecret') }}
          </el-button>

          <template v-else>
            <div class="setup-field">
              <div class="setup-label">
                {{ $t('profile.scanQr') }}
              </div>
              <MfaQrCode :value="mfaSetup.otpauth_url" />
            </div>
            <div class="setup-field">
              <div class="setup-label">
                {{ $t('profile.otpauthLabel') }}
              </div>
              <div class="setup-value">
                <code>{{ mfaSetup.otpauth_url }}</code>
                <el-button
                  size="small"
                  text
                  @click="copyToClipboard(mfaSetup.otpauth_url)"
                >
                  {{ $t('common.copy') }}
                </el-button>
              </div>
            </div>
            <div class="setup-field">
              <div class="setup-label">
                {{ $t('profile.secretManualLabel') }}
              </div>
              <div class="setup-value">
                <code>{{ mfaSetup.secret }}</code>
                <el-button
                  size="small"
                  text
                  @click="copyToClipboard(mfaSetup.secret)"
                >
                  {{ $t('common.copy') }}
                </el-button>
              </div>
            </div>
            <el-form
              label-position="top"
              @submit.prevent
            >
              <el-form-item :label="$t('profile.enableCodeLabel')">
                <el-input
                  v-model="enableCode"
                  maxlength="6"
                  inputmode="numeric"
                  :placeholder="$t('login.codePlaceholder')"
                  @input="handleEnableCodeInput"
                  @keyup.enter="handleEnableMFA"
                />
              </el-form-item>
            </el-form>
            <el-button
              type="primary"
              :loading="enabling"
              :disabled="enableCode.length !== 6"
              @click="handleEnableMFA"
            >
              {{ $t('profile.enableMFA') }}
            </el-button>
          </template>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import MfaQrCode from '@/components/MfaQrCode.vue'
import { roleLabel } from '@/constants/roles'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import {
  getCurrentUser,
  getMFASetup,
  enableMFA,
  disableMFA,
  changePassword,
  updateProfileDisplayName,
} from '@/api/auth'

const MFA_CODE_LENGTH = 6
const DISPLAY_NAME_MAX = 100

// —— 基本資料 ——
const infoLoading = ref(false)
const account = ref({})
const mfaEnabled = ref(false)

// —— 外部憑證判定（idp-oidc-integration D14.6）——
// external_credential 是權威旗標（LDAP／OIDC 一體適用）；舊後端未回該欄時
// 退回 is_ldap，使新前端搭舊後端不致把 LDAP 帳號誤判為可改密
const isExternalCredential = computed(
  () => account.value.external_credential === true || account.value.is_ldap === true
)

// 說明文案分流：LDAP 沿用既有目錄服務措辭，其餘外部身分走通用 IdP 措辭
const externalPasswordTitle = computed(() =>
  account.value.is_ldap ? t('profile.ldapTitle') : t('profile.externalPasswordTitle')
)
const externalPasswordDesc = computed(() =>
  account.value.is_ldap ? t('profile.ldapDesc') : t('profile.externalPasswordDesc')
)
const identityNote = computed(() => {
  if (account.value.is_ldap) return t('profile.ldapIdentityNote')
  if (isExternalCredential.value) return t('profile.externalIdentityNote')
  return t('profile.identityReadonlyHint')
})

// —— 自助顯示名 ——
const displayNameInput = ref('')
const displayNameError = ref('')
const displayNameSaving = ref(false)

const loadAccount = async () => {
  infoLoading.value = true
  try {
    const info = await getCurrentUser()
    account.value = info || {}
    mfaEnabled.value = Boolean(info?.totp_enabled)
    // 編輯欄回填原始 local_display_name（null 顯示空字串），顯示一律走 resolved display_name
    displayNameInput.value = info?.local_display_name || ''
  } catch (error) {
    console.error('取得帳號資訊失敗:', error)
  } finally {
    infoLoading.value = false
  }
}

// 送出前的本地驗證（與後端同規則）：長度上限、拒控制字元/換行
const displayNameLocalError = (value) => {
  if ([...value].length > DISPLAY_NAME_MAX) return t('profile.displayNameInvalid')
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(value)) return t('profile.displayNameInvalid')
  return ''
}

// 送出顯示名更新（save＝設定，clear＝清空回退）。成功後同步 account、localStorage.user
// 與側欄（自訂事件），無需重新登入即反映（profile-display-name R1/5.2）
const submitDisplayName = async (rawValue) => {
  displayNameSaving.value = true
  displayNameError.value = ''
  try {
    const info = await updateProfileDisplayName(rawValue)
    account.value = info || {}
    displayNameInput.value = info?.local_display_name || ''
    // 合併回快取（保留登入時其他欄位），並廣播給側欄即時反映
    try {
      const cached = JSON.parse(localStorage.getItem('user') || '{}')
      localStorage.setItem('user', JSON.stringify({ ...cached, ...(info || {}) }))
      window.dispatchEvent(new Event('ot-user-updated'))
    } catch (e) {
      console.error('同步使用者快取失敗:', e)
    }
    ElMessage.success(t('profile.displayNameSaved'))
  } catch (error) {
    displayNameError.value = resolveApiError(
      error.response?.data,
      error.response?.status,
      t('profile.displayNameInvalid')
    )
    console.error('更新顯示名失敗:', error)
  } finally {
    displayNameSaving.value = false
  }
}

const handleSaveDisplayName = async () => {
  const trimmed = displayNameInput.value.trim()
  const localErr = displayNameLocalError(trimmed)
  if (localErr) {
    displayNameError.value = localErr
    return
  }
  await submitDisplayName(trimmed)
}

const handleClearDisplayName = async () => {
  // 清空送空字串，後端 trim 後寫回 NULL（回退 full_name/username）
  await submitDisplayName('')
}

// —— 自助改密（沿 Login 強制改密表單：就近錯誤、成功換發新 token）——
const pwdFormRef = ref(null)
const pwdForm = ref({ oldPassword: '', newPassword: '', confirmPassword: '' })
const pwdError = ref('')
const pwdChanging = ref(false)

const pwdRules = computed(() => ({
  oldPassword: [{ required: true, message: t('login.ruleOldPasswordRequired'), trigger: 'blur' }],
  newPassword: [{ required: true, message: t('login.ruleNewPasswordRequired'), trigger: 'blur' }],
  confirmPassword: [
    { required: true, message: t('login.ruleConfirmRequired'), trigger: 'blur' },
    {
      validator: (rule, value, callback) => {
        if (value !== pwdForm.value.newPassword) {
          callback(new Error(t('login.ruleConfirmMismatch')))
        } else {
          callback()
        }
      },
      trigger: 'blur',
    },
  ],
}))

const handleChangePassword = async () => {
  if (!pwdFormRef.value) return
  await pwdFormRef.value.validate(async (valid) => {
    if (!valid) return
    pwdChanging.value = true
    pwdError.value = ''
    try {
      const response = await changePassword({
        old_password: pwdForm.value.oldPassword,
        new_password: pwdForm.value.newPassword,
      })
      // 改密撤銷舊 refresh 憑證：以回應的新 access token 續存，不中斷會話。
      // 新的 refresh 憑證由後端以 httpOnly cookie 換發，前端不經手
      if (response?.token) localStorage.setItem('token', response.token)
      if (response?.user) {
        localStorage.setItem('user', JSON.stringify(response.user))
      }
      ElMessage.success(t('profile.passwordUpdated'))
      pwdForm.value = { oldPassword: '', newPassword: '', confirmPassword: '' }
      pwdFormRef.value.resetFields()
    } catch (error) {
      // 政策違規等：就近顯示（API skipErrorToast）
      pwdError.value = resolveApiError(
        error.response?.data,
        error.response?.status,
        t('login.changePasswordFailed')
      )
      console.error('自助改密錯誤:', error)
    } finally {
      pwdChanging.value = false
    }
  })
}

// —— MFA 管理（原 MainLayout dialog 邏輯遷入）——
const mfaSetup = ref(null)
const setupLoading = ref(false)
const enableCode = ref('')
const enabling = ref(false)
const disablePassword = ref('')
const disabling = ref(false)

const handleGenerateMFASetup = async () => {
  setupLoading.value = true
  try {
    const response = await getMFASetup()
    mfaSetup.value = {
      secret: response.secret,
      otpauth_url: response.otpauth_url,
    }
  } catch (error) {
    console.error('產生 MFA 金鑰失敗:', error)
  } finally {
    setupLoading.value = false
  }
}

const handleEnableCodeInput = (value) => {
  enableCode.value = value.replace(/\D/g, '')
}

const handleEnableMFA = async () => {
  if (enableCode.value.length !== MFA_CODE_LENGTH) return
  enabling.value = true
  try {
    await enableMFA({ code: enableCode.value })
    ElMessage.success(t('profile.mfaEnabledTitle'))
    mfaEnabled.value = true
    mfaSetup.value = null
    enableCode.value = ''
  } catch (error) {
    console.error('啟用 MFA 失敗:', error)
  } finally {
    enabling.value = false
  }
}

const handleDisableMFA = async () => {
  if (!disablePassword.value) return
  disabling.value = true
  try {
    await disableMFA({ password: disablePassword.value })
    ElMessage.success(t('profile.mfaDisabledMessage'))
    mfaEnabled.value = false
    disablePassword.value = ''
  } catch (error) {
    console.error('停用 MFA 失敗:', error)
  } finally {
    disabling.value = false
  }
}

const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success(t('profile.copiedToClipboard'))
  } catch (error) {
    console.error('複製失敗:', error)
    ElMessage.error(t('common.copyFailed'))
  }
}

onMounted(() => {
  loadAccount()
})
</script>

<style scoped>
.profile-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
  gap: var(--ot-space-md);
  align-items: start;
}

.profile-card {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
  padding: var(--ot-space-lg);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.card-title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.card-hint {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  margin-top: calc(-1 * var(--ot-space-xs));
}

.display-name-hint {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.5;
}

.display-name-error {
  margin-bottom: 0;
}

.display-name-actions {
  display: flex;
  gap: var(--ot-space-sm);
}

.pwd-error {
  margin-bottom: var(--ot-space-md);
}

.mfa-generate-btn {
  align-self: flex-start;
}

.setup-field {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.setup-label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.setup-value {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm);
  background-color: var(--ot-bg-page);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.setup-value code {
  flex: 1;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-primary);
  word-break: break-all;
}
</style>
