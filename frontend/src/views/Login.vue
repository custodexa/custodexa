<template>
  <div class="login-container">
    <!-- 登入前語言切換：偏好存 ot-lang，未登入即生效 -->
    <div class="lang-switch">
      <el-dropdown @command="setLanguage">
        <span class="lang-switch-label">
          {{ LOCALE_LABELS[locale] }}
          <el-icon class="el-icon--right"><ChevronDown /></el-icon>
        </span>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item
              v-for="l in SUPPORTED_LOCALES"
              :key="l"
              :command="l"
              :disabled="l === locale"
            >
              {{ LOCALE_LABELS[l] }}
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>
    <div class="login-card">
      <div class="card-header">
        <span class="logo-mark"><img
          :src="BRAND.icon"
          :alt="BRAND.name"
        ></span>
        <h2>{{ BRAND.name }}</h2>
        <p>{{ stepSubtitle }}</p>
        <p class="brand-tagline">
          {{ BRAND.tagline }}
        </p>
      </div>

      <!-- 部署方自填的登入前告示：常設內容，排在所有 alert 之前
           （alert 是這次送出的結果，離表單近一點比較好讀）。
           不依步驟隱藏——SSO 回跳直接落在改密或第二因素的路徑一併涵蓋 -->
      <LoginBanner
        :title="bannerTitle"
        :body="bannerBody"
      />

      <!-- 明文連線下登入狀態無法保存：
           使用者被反覆踢回登入頁時，這裡回答「為什麼又要我登入」。
           排在其他 alert 之前——它是「你為什麼會在這一頁」的脈絡，
           鎖定／SSO 錯誤則是這次送出的結果，離表單近一點比較好讀。
           可關閉、不自動消失；讀後即清，重新整理不重播 -->
      <el-alert
        v-if="insecureTransportNotice"
        class="insecure-transport-alert"
        type="info"
        :title="t('login.insecureTransportTitle')"
        :closable="true"
        show-icon
        @close="insecureTransportNotice = false"
      >
        {{ t('login.insecureTransportBody') }}
      </el-alert>

      <!-- 帳號鎖定明示訊息（8.3.4）：卡片內 alert，不透露剩餘時間/次數 -->
      <el-alert
        v-if="lockedMessage"
        class="locked-alert"
        type="error"
        :title="lockedMessage"
        :closable="true"
        show-icon
        @close="lockedMessage = ''"
      />

      <!-- SSO 交棒失敗：就近顯示於卡片內並附可行動指引。
           跨分頁綁定失敗另給「重新發起」按鈕，不以泛用錯誤打發 -->
      <el-alert
        v-if="ssoError"
        class="sso-alert"
        type="error"
        :title="ssoError"
        :closable="true"
        show-icon
        @close="clearSSOError"
      >
        <div class="sso-alert-body">
          <span v-if="ssoErrorHint">{{ ssoErrorHint }}</span>
          <el-button
            v-if="ssoCanRestart"
            class="sso-restart-btn"
            type="primary"
            link
            @click="handleSSORestart"
          >
            {{ t('login.ssoRestart') }}
          </el-button>
        </div>
      </el-alert>

      <div
        v-if="ssoExchanging"
        class="sso-exchanging"
      >
        {{ t('login.ssoExchanging') }}
      </div>

      <el-form
        v-if="step === 'credentials'"
        ref="loginFormRef"
        :model="loginForm"
        :rules="rules"
        size="large"
      >
        <el-form-item prop="username">
          <el-input
            v-model="loginForm.username"
            :placeholder="t('login.usernamePlaceholder')"
            :prefix-icon="User"
          />
        </el-form-item>

        <el-form-item prop="password">
          <el-input
            v-model="loginForm.password"
            type="password"
            :placeholder="t('login.passwordPlaceholder')"
            :prefix-icon="Lock"
            show-password
            @keyup.enter="handleLogin"
          />
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            class="login-btn"
            :loading="loading"
            @click="handleLogin"
          >
            {{ t('login.loginButton') }}
          </el-button>
        </el-form-item>
      </el-form>

      <!-- 強制改密（8.3.5/2.2.2）：密碼與 MFA 已驗證，改密成功直接換發正式 token -->
      <el-form
        v-else-if="step === 'password_change'"
        ref="changeFormRef"
        :model="changeForm"
        :rules="changeRules"
        size="large"
        label-position="top"
      >
        <el-alert
          class="change-hint"
          type="info"
          :closable="false"
          show-icon
          :title="changeHintTitle"
          :description="changeHintDescription"
        />
        <el-form-item prop="oldPassword">
          <el-input
            v-model="changeForm.oldPassword"
            type="password"
            :placeholder="t('login.currentPasswordPlaceholder')"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>
        <el-form-item prop="newPassword">
          <el-input
            v-model="changeForm.newPassword"
            type="password"
            :placeholder="t('login.newPasswordPlaceholder')"
            :prefix-icon="Lock"
            show-password
          />
        </el-form-item>
        <el-form-item prop="confirmPassword">
          <el-input
            v-model="changeForm.confirmPassword"
            type="password"
            :placeholder="t('login.confirmPasswordPlaceholder')"
            :prefix-icon="Lock"
            show-password
            @keyup.enter="handleChangePassword"
          />
        </el-form-item>
        <el-alert
          v-if="changeError"
          class="change-error"
          type="error"
          :title="changeError"
          :closable="false"
          show-icon
        />
        <el-form-item>
          <el-button
            type="primary"
            class="login-btn"
            :loading="changing"
            @click="handleChangePassword"
          >
            {{ t('login.changeSubmit') }}
          </el-button>
        </el-form-item>
        <el-button
          text
          class="mfa-back-btn"
          @click="handleBackToCredentials"
        >
          {{ t('login.backToCredentials') }}
        </el-button>
      </el-form>

      <!-- MFA 強制註冊（8.4.2）：受政策強制但未綁定者，掃碼綁定後直接換發正式 token -->
      <div
        v-else-if="step === 'mfa_enrollment'"
        class="mfa-panel"
      >
        <el-alert
          class="change-hint"
          type="info"
          :closable="false"
          show-icon
          :title="t('login.enrollAlertTitle')"
          :description="t('login.enrollAlertDesc')"
        />
        <div
          v-if="enrollLoading"
          class="enroll-loading"
        >
          {{ t('login.generatingSecret') }}
        </div>
        <template v-else>
          <MfaQrCode
            v-if="enrollOtpauthUrl"
            :value="enrollOtpauthUrl"
          />
          <div class="enroll-secret">
            <span class="enroll-secret-label">{{ t('login.manualSecretLabel') }}</span>
            <code class="enroll-secret-value">{{ enrollSecret }}</code>
          </div>
          <el-input
            ref="enrollInputRef"
            v-model="enrollCode"
            class="mfa-input"
            size="large"
            maxlength="6"
            inputmode="numeric"
            autocomplete="one-time-code"
            :placeholder="t('login.codePlaceholder')"
            @input="handleEnrollInput"
            @keyup.enter="handleConfirmEnrollment"
          />
          <el-alert
            v-if="enrollError"
            class="change-error"
            type="error"
            :title="enrollError"
            :closable="false"
            show-icon
          />
          <el-button
            type="primary"
            class="login-btn mfa-verify-btn"
            size="large"
            :loading="enrolling"
            :disabled="enrollCode.length !== 6"
            @click="handleConfirmEnrollment"
          >
            {{ t('login.confirmEnrollment') }}
          </el-button>
        </template>
        <el-button
          text
          class="mfa-back-btn"
          @click="handleBackToCredentials"
        >
          {{ t('login.backToCredentials') }}
        </el-button>
      </div>

      <div
        v-else
        class="mfa-panel"
      >
        <p class="mfa-hint">
          {{ t('login.mfaHint') }}
        </p>
        <el-input
          ref="mfaInputRef"
          v-model="mfaCode"
          class="mfa-input"
          size="large"
          maxlength="6"
          inputmode="numeric"
          autocomplete="one-time-code"
          :placeholder="t('login.codePlaceholder')"
          @input="handleMfaInput"
          @keyup.enter="handleVerifyMFA"
        />
        <el-button
          type="primary"
          class="login-btn mfa-verify-btn"
          size="large"
          :loading="verifying"
          :disabled="mfaCode.length !== 6"
          @click="handleVerifyMFA"
        >
          {{ t('login.verify') }}
        </el-button>
        <el-button
          text
          class="mfa-back-btn"
          @click="handleBackToCredentials"
        >
          {{ t('login.backToCredentials') }}
        </el-button>
      </div>

      <!-- SSO 區塊：只在 credentials 分支顯示——MFA／改密分支已在
           流程中段，此時再給一個「換個方式登入」的入口只會讓人半途跳出。
           縱向滿寬按鈕：provider 數成長時自然往下排，不像橫排小 icon 會換行崩壞。
           `/auth/methods` 失敗或回空即整區不渲染（降級為只顯示本地表單） -->
      <div
        v-if="step === 'credentials' && ssoProviders.length > 0"
        class="sso-section"
      >
        <div class="sso-divider">
          <span class="sso-divider-text">{{ t('login.ssoDivider') }}</span>
        </div>
        <el-button
          v-for="provider in ssoProviders"
          :key="provider.id"
          class="sso-btn"
          size="large"
          :loading="ssoStartingId === provider.id"
          :disabled="ssoExchanging"
          @click="handleSSOLogin(provider)"
        >
          {{ t('login.ssoButton', { name: provider.name }) }}
        </el-button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, nextTick, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { User, Lock, ChevronDown } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { BRAND } from '@/brand'
import { SUPPORTED_LOCALES, LOCALE_LABELS, setLanguage } from '@/i18n'
import MfaQrCode from '@/components/MfaQrCode.vue'
import LoginBanner from '@/components/LoginBanner.vue'
import {
  login,
  verifyMFA,
  changePassword,
  mfaEnrollSetup,
  mfaEnrollConfirm,
} from '@/api/auth'
import { getAuthMethods, buildOIDCBeginURL, exchangeSSOTicket } from '@/api/oidc'
import { getLoginBanner } from '@/api/loginBanner'
import {
  consumeSSOHandoff,
  consumeBrowserSecret,
  clearBrowserSecret,
  prepareBrowserBinding,
  isSSOCryptoAvailable,
} from '@/utils/sso'
import { resolveApiError } from '@/api/error'
import {
  RELOGIN_INSECURE_TRANSPORT,
  consumeReloginContext,
} from '@/utils/reloginContext'

const MFA_CODE_LENGTH = 6

// callback 失敗 slug → 使用者可讀訊息（對外收斂，細節只落審計與伺服端日誌）。
// 三類分流：准入未通過／帳號需管理員處理／流程失敗可重試
const SSO_ERROR_SLUGS = new Set([
  'oidc_admission_denied',
  'oidc_username_conflict',
  'oidc_provider_unavailable',
  'oidc_provider_error',
  'oidc_flow_invalid',
])

const { t, te, locale } = useI18n()
const router = useRouter()
const loginFormRef = ref(null)
const loading = ref(false)

// 多步登入狀態（登入狀態機）：
// credentials → mfa（TOTP 驗證）→ mfa_enrollment（強制註冊）→ password_change（強制改密）
const step = ref('credentials')
const pendingToken = ref('')
const mfaCode = ref('')
const mfaInputRef = ref(null)
const verifying = ref(false)

// 帳號鎖定明示訊息（後端 423 回應）
const lockedMessage = ref('')

// 登入前告示（部署方自填的純文字，不隨介面語言切換）
const bannerTitle = ref('')
const bannerBody = ref('')

// 明文連線下登入狀態無法保存的說明（決策 3）：由 api/request 的刷新終敗路徑
// 留下脈絡，本頁 onMounted 讀後即清
const insecureTransportNotice = ref(false)

// MFA 強制註冊狀態
const enrollmentToken = ref('')
const enrollSecret = ref('')
const enrollOtpauthUrl = ref('')
const enrollCode = ref('')
const enrollInputRef = ref(null)
const enrollLoading = ref(false)
const enrolling = ref(false)
const enrollError = ref('')

// 強制改密狀態
const changeFormRef = ref(null)
const changeToken = ref('')
const policyHint = ref('')
const changing = ref(false)
const changeError = ref('')
const changeReason = ref('')
const changeReasonDetail = ref('')
const changeForm = ref({
  oldPassword: '',
  newPassword: '',
  confirmPassword: '',
})

// SSO（OIDC）狀態：provider 清單、發起中的 provider、交棒兌換中、失敗呈現
const ssoProviders = ref([])
const ssoStartingId = ref(0)
const ssoExchanging = ref(false)
const ssoError = ref('')
const ssoErrorHint = ref('')
// 可重新發起：跨分頁綁定遺失屬「使用者按一下就能自救」的情形，給明確出口
const ssoCanRestart = ref(false)

const stepSubtitle = computed(() => {
  if (step.value === 'mfa') return t('login.subtitleMfa')
  if (step.value === 'mfa_enrollment') return t('login.subtitleEnroll')
  if (step.value === 'password_change') return t('login.subtitleChangePassword')
  return t('brand.subtitle')
})

// 強制改密原因分流：must_change（首登/重設，含 MFA 用戶
// 第一階段偵測的降級呈現）沿用既有文案；不符政策/已過期各自明示原因。
// 未知 reason 一律降級既有文案（前後端版本錯位不炸）
const changeHintTitle = computed(() => {
  if (changeReason.value === 'policy_noncompliant') return t('login.changeReasonNoncompliant')
  if (changeReason.value === 'password_expired') return t('login.changeReasonExpired')
  return t('login.changeHintTitle')
})

// 說明列＝具體違規（reason_code 走 apiError 既有譯文，te 精確查、缺譯即略）＋政策提示
const changeHintDescription = computed(() => {
  if (changeReasonDetail.value && policyHint.value) {
    return `${changeReasonDetail.value}；${policyHint.value}`
  }
  return changeReasonDetail.value || policyHint.value
})

const loginForm = ref({
  username: '',
  password: '',
})

// rules 走 computed：切語言後未觸發的驗證訊息即時換語
const rules = computed(() => ({
  username: [
    { required: true, message: t('login.ruleUsernameRequired'), trigger: 'blur' },
  ],
  password: [
    { required: true, message: t('login.rulePasswordRequired'), trigger: 'blur' },
  ],
}))

const changeRules = computed(() => ({
  oldPassword: [
    { required: true, message: t('login.ruleOldPasswordRequired'), trigger: 'blur' },
  ],
  newPassword: [
    { required: true, message: t('login.ruleNewPasswordRequired'), trigger: 'blur' },
  ],
  confirmPassword: [
    { required: true, message: t('login.ruleConfirmRequired'), trigger: 'blur' },
    {
      validator: (_rule, value, callback) => {
        if (value !== changeForm.value.newPassword) {
          callback(new Error(t('login.ruleConfirmMismatch')))
          return
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
}))

const handleLogin = async () => {
  if (!loginFormRef.value) return

  await loginFormRef.value.validate(async (valid) => {
    if (valid) {
      loading.value = true
      lockedMessage.value = ''
      try {
        // 呼叫登入 API
        const response = await login({
          username: loginForm.value.username,
          password: loginForm.value.password,
        })

        // MFA 用戶：進入第二階段驗證碼輸入
        if (response.mfa_required) {
          pendingToken.value = response.pending_token
          mfaCode.value = ''
          step.value = 'mfa'
          await nextTick()
          mfaInputRef.value?.focus()
          return
        }

        // 受強制但未註冊 MFA：進入強制註冊流程
        if (response.mfa_enrollment_required) {
          await enterEnrollmentStep(response)
          return
        }

        if (response.password_change_required) {
          enterPasswordChangeStep(response)
          return
        }

        completeLogin(response)
      } catch (error) {
        // 帳號鎖定（423）在卡片內明示；其餘錯誤已由 axios 攔截器 toast
        if (error.response?.status === 423) {
          lockedMessage.value =
            resolveApiError(error.response?.data, error.response?.status, t('login.lockedFallback'))
        }
        console.error('登入錯誤:', error)
      } finally {
        loading.value = false
      }
    }
  })
}

// 進入 MFA 強制註冊步驟：取 enrollment token 後拉 TOTP 設定（secret 供掃碼/手輸）
const enterEnrollmentStep = async (response) => {
  enrollmentToken.value = response.enrollment_token
  enrollCode.value = ''
  enrollError.value = ''
  enrollSecret.value = ''
  enrollOtpauthUrl.value = ''
  step.value = 'mfa_enrollment'
  enrollLoading.value = true
  try {
    const setup = await mfaEnrollSetup(enrollmentToken.value)
    enrollSecret.value = setup.secret
    enrollOtpauthUrl.value = setup.otpauth_url || ''
    await nextTick()
    enrollInputRef.value?.focus()
  } catch (error) {
    enrollError.value =
      resolveApiError(error.response?.data, error.response?.status, t('login.enrollSetupFailed'))
    console.error('MFA 註冊設定錯誤:', error)
  } finally {
    enrollLoading.value = false
  }
}

const handleEnrollInput = (value) => {
  enrollCode.value = value.replace(/\D/g, '')
}

const handleConfirmEnrollment = async () => {
  if (enrollCode.value.length !== MFA_CODE_LENGTH) return

  enrolling.value = true
  enrollError.value = ''
  try {
    const response = await mfaEnrollConfirm(enrollCode.value, enrollmentToken.value)
    // 綁定後可能仍須強制改密
    if (response.password_change_required) {
      enterPasswordChangeStep(response)
      return
    }
    completeLogin(response)
  } catch (error) {
    enrollError.value =
      resolveApiError(error.response?.data, error.response?.status, t('login.enrollConfirmFailed'))
    if (error.response?.status === 401) {
      enrollError.value += t('login.linkExpiredSuffix')
    }
    enrollCode.value = ''
    enrollInputRef.value?.focus()
    console.error('MFA 綁定錯誤:', error)
  } finally {
    enrolling.value = false
  }
}

// 進入強制改密步驟（密碼與 MFA 已驗證，改密成功後端直接換發正式 token）
const enterPasswordChangeStep = (response) => {
  changeToken.value = response.change_token
  policyHint.value = response.policy_hint || ''
  changeReason.value = response.password_change_reason || ''
  const code = response.reason_code
  changeReasonDetail.value =
    code && te(`apiError.${code}`) ? t(`apiError.${code}`, response.reason_params || {}) : ''
  changeForm.value = {
    // 目前密碼即剛輸入的登入密碼，預填免重複輸入
    oldPassword: loginForm.value.password,
    newPassword: '',
    confirmPassword: '',
  }
  changeError.value = ''
  step.value = 'password_change'
}

const handleChangePassword = async () => {
  if (!changeFormRef.value) return

  await changeFormRef.value.validate(async (valid) => {
    if (!valid) return

    changing.value = true
    changeError.value = ''
    try {
      const response = await changePassword(
        {
          old_password: changeForm.value.oldPassword,
          new_password: changeForm.value.newPassword,
        },
        changeToken.value
      )
      completeLogin(response)
    } catch (error) {
      // 政策違規/token 過期等：就近顯示於表單內（skipErrorToast）
      changeError.value =
        resolveApiError(error.response?.data, error.response?.status, t('login.changePasswordFailed'))
      if (error.response?.status === 401) {
        changeError.value += t('login.linkExpiredSuffix')
      }
      console.error('強制改密錯誤:', error)
    } finally {
      changing.value = false
    }
  })
}

// 儲存 token 和使用者資訊並導向儀表板（SSO 帶 redirect_next 時導向該站內路徑；
// next 已由後端白名單化為同源相對路徑，前端不再自行解析外部 URL）
const completeLogin = (response, next) => {
  localStorage.setItem('token', response.token)
  // refresh 憑證不落 localStorage：後端以 httpOnly cookie 下發，瀏覽器自動收存，
  // script 讀不到也就帶不走
  localStorage.setItem('user', JSON.stringify(response.user))
  ElMessage.success(
    t('login.welcomeBack', {
      // 歡迎訊息走後端 resolved display_name（單一事實源：前端不重寫 fallback 鏈；
      // 後端 resolver 已含 full_name 回退）。username 僅為舊快取的保底，與側欄一致
      name: response.user.display_name || response.user.username,
    })
  )
  const target = typeof next === 'string' && next.startsWith('/') && next !== '/' ? next : '/dashboard'
  router.push(target)
}

// 僅允許輸入數字
const handleMfaInput = (value) => {
  mfaCode.value = value.replace(/\D/g, '')
}

const handleVerifyMFA = async () => {
  if (mfaCode.value.length !== MFA_CODE_LENGTH) return

  verifying.value = true
  try {
    const response = await verifyMFA({
      pending_token: pendingToken.value,
      code: mfaCode.value,
    })

    // MFA 通過但須先改密（改密 gate 排在 MFA 之後）
    if (response.password_change_required) {
      enterPasswordChangeStep(response)
      return
    }

    completeLogin(response)
  } catch (error) {
    // 鎖定（TOTP 失敗共用計數）退回帳密步驟並明示；其餘清空驗證碼重試
    if (error.response?.status === 423) {
      lockedMessage.value =
        resolveApiError(error.response?.data, error.response?.status, t('login.lockedFallback'))
      handleBackToCredentials()
      return
    }
    console.error('MFA 驗證錯誤:', error)
    mfaCode.value = ''
    mfaInputRef.value?.focus()
  } finally {
    verifying.value = false
  }
}

// 返回帳號密碼輸入畫面
const handleBackToCredentials = () => {
  step.value = 'credentials'
  pendingToken.value = ''
  mfaCode.value = ''
  changeToken.value = ''
  changeError.value = ''
  changeForm.value = { oldPassword: '', newPassword: '', confirmPassword: '' }
  enrollmentToken.value = ''
  enrollSecret.value = ''
  enrollCode.value = ''
  enrollError.value = ''
  loginForm.value.password = ''
}

// —— SSO（OIDC）——

const setSSOError = (title, hint, canRestart = false) => {
  ssoError.value = title
  ssoErrorHint.value = hint
  ssoCanRestart.value = canRestart
}

const clearSSOError = () => {
  ssoError.value = ''
  ssoErrorHint.value = ''
  ssoCanRestart.value = false
}

// 登入方法清單。**失敗即降級為只顯示本地表單**——封印期此端點為 503（預期行為），
// 此時若把錯誤呈現給使用者，只會讓「系統封印中」表現成「登入頁壞了」
const loadAuthMethods = async () => {
  try {
    const res = await getAuthMethods()
    ssoProviders.value = Array.isArray(res?.oidc) ? res.oidc : []
  } catch (error) {
    ssoProviders.value = []
    console.error('取得登入方法清單失敗（降級為本地登入）:', error?.response?.status || error?.message)
  }
}

// 登入前告示。**失敗即不顯示**——告示是顯示型內容，封印期的 503 與網路錯誤
// 都不該讓登入頁看起來壞掉，也不該擋住任何控制項；載入後不再重抓
const loadLoginBanner = async () => {
  try {
    const res = await getLoginBanner()
    if (res?.enabled) {
      bannerTitle.value = typeof res.title === 'string' ? res.title : ''
      bannerBody.value = typeof res.body === 'string' ? res.body : ''
    }
  } catch (error) {
    console.error('取得登入告示失敗（不顯示告示）:', error?.response?.status || error?.message)
  }
}

// 發起 SSO：先在本分頁備妥綁定原值，只把雜湊送出，再整頁導向後端 begin
const handleSSOLogin = async (provider) => {
  clearSSOError()
  if (!isSSOCryptoAvailable()) {
    // crypto.subtle 只存在於 secure context——純 http 部署會走到這裡。
    // 給的是「怎麼解」而非「失敗了」
    setSSOError(t('login.ssoStartFailed'), t('login.ssoInsecureContextHint'))
    return
  }
  ssoStartingId.value = provider.id
  try {
    const binding = await prepareBrowserBinding()
    window.location.assign(buildOIDCBeginURL(provider.id, binding))
  } catch (error) {
    clearBrowserSecret()
    ssoStartingId.value = 0
    setSSOError(t('login.ssoStartFailed'), t('login.ssoStartFailedHint'))
    console.error('SSO 發起失敗:', error)
  }
}

// 重新發起：provider 唯一時直接走，否則收起錯誤讓使用者自行挑選（按鈕就在下方）
const handleSSORestart = () => {
  if (ssoProviders.value.length === 1) {
    handleSSOLogin(ssoProviders.value[0])
    return
  }
  clearSSOError()
}

// callback 失敗 slug 的呈現分流（准入／帳號衝突／流程失效），未知 slug 降級通用文案
const applySSOErrorSlug = (slug) => {
  const known = SSO_ERROR_SLUGS.has(slug) ? slug : 'oidc_flow_invalid'
  const retryable = known === 'oidc_flow_invalid' || known === 'oidc_provider_error'
  setSSOError(t(`login.ssoSlug.${known}`), t(`login.ssoSlugHint.${known}`), retryable)
}

// 以一次性 ticket 兌換正式登入回應（與 /auth/login 同形，故完全走既有分支）
const exchangeSSOLogin = async (ticket) => {
  const secret = consumeBrowserSecret()
  if (!secret) {
    // sessionStorage 是 per-tab：使用者在新分頁完成 callback 就會走到這裡。
    // 這不是「登入失敗」而是「在錯的分頁完成」，訊息必須說得出下一步
    setSSOError(t('login.ssoCrossTabTitle'), t('login.ssoCrossTabHint'), true)
    return
  }
  ssoExchanging.value = true
  try {
    const res = await exchangeSSOTicket(ticket, secret)
    const payload = res?.login || {}
    const next = res?.redirect_next || ''

    if (payload.mfa_required) {
      pendingToken.value = payload.pending_token
      mfaCode.value = ''
      step.value = 'mfa'
      await nextTick()
      mfaInputRef.value?.focus()
      return
    }
    if (payload.mfa_enrollment_required) {
      await enterEnrollmentStep(payload)
      return
    }
    if (payload.password_change_required) {
      enterPasswordChangeStep(payload)
      return
    }
    completeLogin(payload, next)
  } catch (error) {
    if (error?.response?.status === 423) {
      lockedMessage.value =
        resolveApiError(error.response?.data, error.response?.status, t('login.lockedFallback'))
      return
    }
    setSSOError(
      resolveApiError(error?.response?.data, error?.response?.status, t('login.ssoExchangeFailed')),
      t('login.ssoExchangeFailedHint'),
      true
    )
    console.error('SSO 交棒兌換失敗:', error?.response?.status || error?.message)
  } finally {
    ssoExchanging.value = false
  }
}

onMounted(() => {
  // **第一件事**：讀 fragment 並立即抹除（consumeSSOHandoff 內含 replaceState）。
  // 任何在它之前的動作都可能讓帶 ticket 的網址被保存或送出
  const handoff = consumeSSOHandoff()

  // 讀後即清；放在 SSO 早退分支之前，否則交棒失敗的那一次會把脈絡吞掉
  insecureTransportNotice.value =
    consumeReloginContext() === RELOGIN_INSECURE_TRANSPORT

  // 兩個登入前讀取彼此不阻塞：任一失敗不影響另一個，也不影響登入表單
  loadAuthMethods()
  loadLoginBanner()

  if (handoff.error) {
    clearBrowserSecret()
    applySSOErrorSlug(handoff.error)
    return
  }
  if (handoff.ticket) {
    exchangeSSOLogin(handoff.ticket)
  }
})
</script>

<style scoped>
.login-container {
  position: relative;
  display: flex;
  justify-content: center;
  align-items: center;
  /* min-height 而非 height：卡片內容高於視窗時（長告示、改密步驟）
     仍能捲到頂端與登入鈕，固定高度會把超出的部分裁掉且捲不到 */
  min-height: 100vh;
  overflow-y: auto;
  background-color: var(--ot-bg-page);
  background-image: radial-gradient(
    ellipse at 50% -20%,
    rgba(59, 158, 255, 0.08),
    transparent 60%
  );
}

.lang-switch {
  position: absolute;
  top: var(--ot-space-lg);
  right: var(--ot-space-lg);
}

.lang-switch-label {
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.lang-switch-label:hover {
  color: var(--ot-primary);
}

.login-card {
  width: 380px;
  padding: var(--ot-space-xl);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  box-shadow: var(--ot-shadow-md);
}

.card-header {
  display: flex;
  flex-direction: column;
  align-items: center;
  margin-bottom: var(--ot-space-xl);
}

.logo-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  border-radius: var(--ot-radius-lg);
  background-color: var(--ot-brand-badge-bg);
  margin-bottom: var(--ot-space-md);
}

.logo-mark img {
  width: 34px;
  height: 34px;
  display: block;
}

.brand-tagline {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
  letter-spacing: 0.3px;
}

.card-header h2 {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-xl);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.card-header p {
  margin: 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.login-btn {
  width: 100%;
}

.mfa-panel {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}

.mfa-hint {
  margin: 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  text-align: center;
}

.mfa-input :deep(input) {
  text-align: center;
  font-size: var(--ot-font-size-lg);
  letter-spacing: 0.5em;
}

.mfa-back-btn {
  margin-left: 0;
  color: var(--ot-text-secondary);
}

.mfa-back-btn:hover {
  color: var(--ot-primary);
}

.insecure-transport-alert {
  margin-bottom: var(--ot-space-md);
}

.locked-alert {
  margin-bottom: var(--ot-space-md);
}

.sso-alert {
  margin-bottom: var(--ot-space-md);
}

.sso-alert-body {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--ot-space-xs);
}

.sso-restart-btn {
  padding: 0;
  height: auto;
}

.sso-exchanging {
  text-align: center;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  padding: var(--ot-space-md) 0;
}

/* SSO 區塊：縱向滿寬按鈕（provider 數成長時自然往下排） */
.sso-section {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

/* 分隔線：文字置中、兩側虛線；文案走 i18n（不硬編碼 "Or"） */
.sso-divider {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin: var(--ot-space-xs) 0 var(--ot-space-sm);
  color: var(--ot-text-disabled);
  font-size: var(--ot-font-size-xs);
}

.sso-divider::before,
.sso-divider::after {
  content: '';
  flex: 1;
  border-top: 1px dashed var(--ot-border-subtle);
}

.sso-divider-text {
  white-space: nowrap;
}

.sso-btn {
  width: 100%;
  margin-left: 0;
}

/* el-button 相鄰時預設帶左外距，縱向排列須歸零 */
.sso-btn + .sso-btn {
  margin-left: 0;
}

.change-hint {
  margin-bottom: var(--ot-space-md);
}

.change-error {
  margin-bottom: var(--ot-space-md);
}

.enroll-loading {
  text-align: center;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  padding: var(--ot-space-md) 0;
}

.enroll-secret {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm) var(--ot-space-md);
  background-color: var(--ot-bg-page);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.enroll-secret-label {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.enroll-secret-value {
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-md);
  letter-spacing: 0.15em;
  color: var(--ot-text-primary);
  word-break: break-all;
}
</style>
