<template>
  <div class="unseal-page">
    <!-- 封印期語言切換（i18n「Language switching」）：封印時本頁是唯一可達頁面，
         沒有切換入口＝看不懂預設語言的操作者被卡在一個擋住全部服務的頁面上。
         純前端（setLanguage 只寫 i18n locale 與 localStorage），故後端 503 不影響它 -->
    <div class="lang-switch">
      <el-dropdown @command="setLanguage">
        <span class="lang-switch-label">
          {{ LOCALE_LABELS[locale] }}
          <el-icon class="el-icon--right"><ArrowDown /></el-icon>
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
    <div
      class="unseal-card"
      :class="{ 'is-initialization': showInitializationForm }"
    >
      <header class="unseal-header">
        <h1 class="unseal-title">
          {{ $t('unseal.title') }}
        </h1>
        <p class="unseal-subtitle">
          {{ $t('unseal.subtitle') }}
        </p>
      </header>

      <!-- 遺失警語（i18n「遺失警語之版面優先度」）：標題正下方、任何解封表單之前。
           版位刻意不隨狀態浮動——故障／冷卻／待釋放三種警示都排在表單之上，
           把它放表單旁會在有警示時被推到半頁以下，而讀者是跳著看的。
           已解封時不顯示：該狀態下這句不可行動，恆掛只會訓練使用者忽略它 -->
      <div
        v-if="!isUnsealed"
        class="loss-callout"
      >
        <el-icon class="loss-icon">
          <WarningFilled />
        </el-icon>
        <div>
          <p class="loss-title">
            {{ $t('unseal.lossTitle') }}
          </p>
          <p class="loss-body">
            {{ $t('unseal.lossBody') }}
          </p>
        </div>
      </div>

      <!-- 狀態區：四態徽章＋generation＋手動重整（unsealing 期間自動輪詢） -->
      <div
        v-loading="statusLoading"
        class="status-row"
      >
        <el-tag
          :type="stateTagType"
          effect="dark"
          class="state-badge"
        >
          {{ stateLabel }}
        </el-tag>
        <span class="status-meta">{{ $t('unseal.generation', { n: status.generation ?? 0 }) }}</span>
        <el-button
          text
          :loading="statusLoading"
          @click="loadStatus"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </div>

      <el-alert
        v-if="statusError"
        type="warning"
        :closable="false"
        show-icon
        class="unseal-alert"
        :title="$t('unseal.statusErrorTitle')"
        :description="statusError"
      />

      <!-- 故障機器碼（sealed-faulted）：查譯 apierror 碼，前端不自行詮釋成因 -->
      <el-alert
        v-if="status.fault_code"
        type="error"
        :closable="false"
        show-icon
        class="unseal-alert"
        :title="$t('unseal.faultTitle')"
        :description="faultText"
      />
      <!-- 動作在前、理由在後（i18n「解封頁文案的操作者可讀性」規範 1、2）：
           三個處置拆成編號步驟，疲勞時掃得到；fail-close 的語義降為尾註 -->
      <el-alert
        v-if="status.journal_faulted"
        type="error"
        :closable="false"
        show-icon
        class="unseal-alert"
        :title="$t('unseal.journalFaultedTitle')"
      >
        <p class="alert-lead">
          {{ $t('unseal.journalFaultedDesc') }}
        </p>
        <ol class="alert-steps">
          <li>{{ $t('unseal.journalFaultedStep1') }}</li>
          <li>{{ $t('unseal.journalFaultedStep2') }}</li>
          <li>{{ $t('unseal.journalFaultedStep3') }}</li>
        </ol>
        <p class="alert-note">
          {{ $t('unseal.journalFaultedWhy') }}
        </p>
      </el-alert>
      <!-- 待收束：前代解封持有者尚未釋放資源，此期間任何解封嘗試都會被拒 -->
      <el-alert
        v-if="status.cleanup_pending"
        type="warning"
        :closable="false"
        show-icon
        class="unseal-alert"
        :title="$t('unseal.cleanupPendingTitle')"
        :description="cleanupText"
      />
      <!-- 冷卻倒數：限速類刻意可區分於材料類失敗，管理員必須能分辨「被限速」與「輸錯」 -->
      <el-alert
        v-if="cooldownRemainingMs > 0"
        type="warning"
        :closable="false"
        show-icon
        class="unseal-alert"
        :title="$t('unseal.cooldownTitle')"
        :description="$t('unseal.cooldownDesc', {
          remaining: cooldownRemainingText,
          until: formatDateTime(status.cooldown_until),
        })"
      />
      <!-- 逾時 × 初始化的重試指引：逾時後 bootstrap 可能已完成，
           改用新材料會使第一把材料成為無人知曉的主 KEK -->
      <el-alert
        v-if="status.timeout_retry_hint_code"
        type="warning"
        :closable="false"
        show-icon
        class="unseal-alert"
        :title="$t('unseal.timeoutHintTitle')"
        :description="timeoutHintText"
      />

      <!-- 已解封：不再提供解封表單（再送只會拿到 409） -->
      <div
        v-if="isUnsealed"
        class="unseal-done"
      >
        <el-alert
          type="success"
          :closable="false"
          show-icon
          :title="$t('unseal.unsealedTitle')"
          :description="$t('unseal.unsealedDesc')"
        />
        <el-button
          type="primary"
          class="goto-login"
          @click="goLogin"
        >
          {{ $t('unseal.goLogin') }}
        </el-button>
      </div>

      <template v-else>
        <!-- 路徑未知（狀態未帶 initialization_required）：不猜，讓管理員顯式指定。
             呈現為兩條並列選項而非散文——讀者要的是「我該按哪個」。
             「系統不替你猜測」不寫成文案：畫面本身就沒有預選，由行為承載 -->
        <el-alert
          v-if="pathUnknown"
          type="info"
          :closable="false"
          show-icon
          class="unseal-alert"
          :title="$t('unseal.pathUnknownTitle')"
        >
          <p class="alert-lead">
            {{ $t('unseal.pathUnknownDesc') }}
          </p>
          <ul class="alert-options">
            <li>{{ $t('unseal.pathUnknownFresh') }}</li>
            <li>{{ $t('unseal.pathUnknownExisting') }}</li>
          </ul>
          <el-button
            text
            class="path-toggle"
            @click="manualInitialization = !manualInitialization"
          >
            {{ manualInitialization ? $t('unseal.switchToNormal') : $t('unseal.switchToInitialization') }}
          </el-button>
        </el-alert>

        <!-- 初始化解封：與一般解封視覺明確區分（紅框、專屬標題、不可略過的警語） -->
        <section
          v-if="showInitializationForm"
          class="form-section init-section"
        >
          <h2 class="section-title init-title">
            {{ $t('unseal.initTitle') }}
          </h2>
          <el-alert
            type="error"
            :closable="false"
            show-icon
            class="unseal-alert init-warning"
            :title="$t('unseal.initWarningTitle')"
            :description="$t('unseal.initWarningDesc')"
          />

          <div class="field">
            <label
              id="unseal-init-material-label"
              class="field-label"
            >{{ $t('unseal.materialLabel') }}</label>
            <div class="field-row">
              <el-input
                v-model="material"
                aria-labelledby="unseal-init-material-label"
                class="material-input"
                spellcheck="false"
                autocomplete="off"
                :placeholder="$t('unseal.materialPlaceholder')"
              />
              <el-button @click="generateLocalMaterial">
                {{ $t('unseal.generateLocal') }}
              </el-button>
            </div>
            <p
              v-if="materialFormatMessage"
              class="field-error"
            >
              {{ materialFormatMessage }}
            </p>
            <p class="field-hint">
              {{ $t('unseal.materialFormatIntro') }}
            </p>
            <ul class="format-list">
              <li>{{ $t('unseal.materialFormatPlain') }}</li>
              <li>{{ $t('unseal.materialFormatHex') }}</li>
              <li>{{ $t('unseal.materialFormatBase64') }}</li>
            </ul>
            <GenerateCommands />
          </div>

          <div class="field">
            <label
              id="unseal-init-confirm-label"
              class="field-label"
            >{{ $t('unseal.materialConfirmLabel') }}</label>
            <el-input
              v-model="materialConfirm"
              aria-labelledby="unseal-init-confirm-label"
              class="material-input"
              spellcheck="false"
              autocomplete="off"
              :placeholder="$t('unseal.materialConfirmPlaceholder')"
            />
            <p
              v-if="confirmMismatch"
              class="field-error"
            >
              {{ $t('unseal.materialConfirmMismatch') }}
            </p>
          </div>

          <!-- 這個標題描述的是「帳號＋密碼」兩個欄位構成的一組，不是單一控制項，
               故用 role="group" 加 aria-labelledby，而非 label。兩個輸入框各自帶
               aria-label：placeholder 不是可及名稱（輸入後即消失，且部分輔助技術不讀）。 -->
          <div
            class="field"
            role="group"
            aria-labelledby="unseal-admin-label"
          >
            <span
              id="unseal-admin-label"
              class="field-label"
            >{{ $t('unseal.adminLabel') }}</span>
            <p class="field-hint">
              {{ $t('unseal.adminHint') }}
            </p>
            <el-input
              v-model="username"
              class="admin-input"
              autocomplete="off"
              :aria-label="$t('unseal.usernamePlaceholder')"
              :placeholder="$t('unseal.usernamePlaceholder')"
            />
            <el-input
              v-model="password"
              class="admin-input"
              type="password"
              show-password
              autocomplete="off"
              :aria-label="$t('unseal.passwordPlaceholder')"
              :placeholder="$t('unseal.passwordPlaceholder')"
            />
          </div>

          <el-checkbox v-model="confirmSaved">
            {{ $t('unseal.confirmSavedCheckbox') }}
          </el-checkbox>
        </section>

        <!-- 一般解封：既有部署，只需材料（能解開代表列本身即授權證明） -->
        <section
          v-else
          class="form-section normal-section"
        >
          <h2 class="section-title">
            {{ $t('unseal.normalTitle') }}
          </h2>
          <p class="section-desc">
            {{ $t('unseal.normalDesc') }}
          </p>
          <div class="field">
            <label
              id="unseal-material-label"
              class="field-label"
            >{{ $t('unseal.materialLabel') }}</label>
            <el-input
              v-model="material"
              aria-labelledby="unseal-material-label"
              class="material-input"
              spellcheck="false"
              autocomplete="off"
              :placeholder="$t('unseal.materialPlaceholder')"
            />
          </div>
        </section>

        <el-button
          type="primary"
          class="submit-btn"
          :loading="submitting"
          :disabled="submitDisabled"
          @click="submit"
        >
          {{ $t('unseal.submit') }}
        </el-button>
      </template>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { ArrowDown, WarningFilled } from '@element-plus/icons-vue'
import { getSealStatus, unseal } from '@/api/seal'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
import { generateKEKMaterial, validateKEKMaterialFormat } from '@/utils/kek'
import { publishSealStatus } from '@/utils/sealPhase'
import GenerateCommands from '@/components/KEKGenerateCommands.vue'
import { SUPPORTED_LOCALES, LOCALE_LABELS, setLanguage, t } from '@/i18n'

// 解封頁。**封印期可達且不需登入**——
// 要求 JWT 會在 admin 已開 MFA 時死鎖（TOTP secret 是信封加密欄，封印期解不開）。
// 授權由「知道 KEK」承擔；初始化解封另要求初始管理員憑證。

const router = useRouter()
// 切換選單以 locale 為當前值來源（同 Login.vue）；setLanguage 直接當 @command 處理器
const { locale } = useI18n()

const status = ref({})
const statusLoading = ref(false)
const statusError = ref('')
const submitting = ref(false)

const material = ref('')
const materialConfirm = ref('')
const confirmSaved = ref(false)
const username = ref('')
const password = ref('')
// 狀態未帶 initialization_required 時由管理員顯式指定路徑（見 pathUnknown）
const manualInitialization = ref(false)

// 倒數用的時鐘：cooldown_until 是伺服端時間，倒數只是把它換算成人看得懂的剩餘量
const now = ref(Date.now())
let clockTimer = null
let pollTimer = null

const SEAL_STATE_TAG_TYPES = {
  sealed: 'warning',
  unsealing: 'warning',
  unsealed: 'success',
  'sealed-faulted': 'danger',
}
const SEAL_STATE_TEXT_KEYS = {
  sealed: 'unseal.stateSealed',
  unsealing: 'unseal.stateUnsealing',
  unsealed: 'unseal.stateUnsealed',
  'sealed-faulted': 'unseal.stateSealedFaulted',
}

const state = computed(() => status.value.state || '')
const stateTagType = computed(() => SEAL_STATE_TAG_TYPES[state.value] || 'info')
// 未知態原樣顯示：不歸類到任何已知態（歸類等於替後端的新狀態編造語義）
const stateLabel = computed(() =>
  SEAL_STATE_TEXT_KEYS[state.value] ? t(SEAL_STATE_TEXT_KEYS[state.value]) : state.value || '—'
)
const isUnsealed = computed(() => state.value === 'unsealed')

// 初始化 vs 一般：以伺服端判定為準（依 data_keys 筆數）。欄位缺席＝未知，
// 不以 false 頂替——那會讓全新安裝看到一般解封表單而永遠解不開
const pathUnknown = computed(
  () => !isUnsealed.value && typeof status.value.initialization_required !== 'boolean'
)
const showInitializationForm = computed(() =>
  pathUnknown.value ? manualInitialization.value : status.value.initialization_required === true
)

const faultText = computed(() =>
  status.value.fault_code ? resolveApiError({ code: status.value.fault_code }) : ''
)
const timeoutHintText = computed(() =>
  status.value.timeout_retry_hint_code
    ? resolveApiError({ code: status.value.timeout_retry_hint_code })
    : ''
)
const cleanupText = computed(() =>
  t('unseal.cleanupPendingDesc', {
    generation: status.value.cleanup_generation ?? '—',
    reason: status.value.cleanup_reason || '—',
    since: status.value.cleanup_started_at
      ? formatDateTime(status.value.cleanup_started_at)
      : '—',
  })
)

const cooldownRemainingMs = computed(() => {
  if (!status.value.cooldown_until) return 0
  const until = new Date(status.value.cooldown_until).getTime()
  if (Number.isNaN(until)) return 0
  return Math.max(0, until - now.value)
})
const cooldownRemainingText = computed(() => {
  const total = Math.ceil(cooldownRemainingMs.value / 1000)
  const minutes = Math.floor(total / 60)
  const seconds = total % 60
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
})

const MATERIAL_FORMAT_TEXT_KEYS = {
  empty: 'unseal.materialErrorEmpty',
  format: 'unseal.materialErrorFormat',
  charset: 'unseal.materialErrorCharset',
}
// 格式檢查只套用於初始化解封：一般解封的既有 KEK 可能早於格式規則，
// 前端擋掉它等於讓合法管理員解不開自己的部署
const materialFormatReason = computed(() =>
  showInitializationForm.value && material.value
    ? validateKEKMaterialFormat(material.value)
    : ''
)
const materialFormatMessage = computed(() =>
  materialFormatReason.value ? t(MATERIAL_FORMAT_TEXT_KEYS[materialFormatReason.value]) : ''
)
const confirmMismatch = computed(
  () => !!materialConfirm.value && materialConfirm.value !== material.value
)

const submitDisabled = computed(() => {
  if (!material.value) return true
  if (!showInitializationForm.value) return false
  return (
    !!materialFormatReason.value ||
    materialConfirm.value !== material.value ||
    !confirmSaved.value ||
    !username.value ||
    !password.value
  )
})

const loadStatus = async () => {
  statusLoading.value = true
  try {
    status.value = await getSealStatus({ skipErrorToast: true })
    // 導覽守衛的相位來源之一：
    // 少了這一步，解封成功後點「前往登入」會被守衛以陳舊的 sealed 相位彈回本頁
    publishSealStatus(status.value)
    statusError.value = ''
  } catch (error) {
    // 狀態讀不到不是解封失敗：明說讀取失敗，不覆蓋已知狀態、也不假裝已解封
    statusError.value = resolveApiError(error.response?.data, error.response?.status)
  } finally {
    statusLoading.value = false
  }
}

const generateLocalMaterial = () => {
  try {
    const generated = generateKEKMaterial()
    material.value = generated
    materialConfirm.value = generated
  } catch (error) {
    console.error('本地生成 KEK 失敗:', error)
    ElMessage.error(t('unseal.generateFailed'))
  }
}

// 材料清除（元件狀態層，不承諾 JS 記憶體抹除）：送出後與元件卸載
const clearMaterial = () => {
  material.value = ''
  materialConfirm.value = ''
  confirmSaved.value = false
  password.value = ''
}

const submit = async () => {
  // 送出前對兩欄套同一次修剪：貼上 `openssl rand -hex 32` 的輸出會帶結尾換行，
  // 伺服端的 paste-back 比對的是**原始位元組**，兩欄修剪不一致就會誤判不符。
  // 修剪只做這一次、且兩欄一致，故不影響「逐字確認」的證明力
  const kek = material.value.trim()
  const kekConfirm = materialConfirm.value.trim()
  // 逐變體的精確鍵集：後端以 DisallowUnknownFields 解析，夾帶多餘鍵即整包被拒
  const payload = showInitializationForm.value
    ? {
        kek,
        kek_confirm: kekConfirm,
        confirm_saved: confirmSaved.value,
        username: username.value,
        password: password.value,
      }
    : { kek }
  submitting.value = true
  try {
    const result = await unseal(payload, { skipErrorToast: true })
    status.value = { ...status.value, ...result }
    publishSealStatus(status.value)
    ElMessage.success(t('unseal.submitSuccess'))
    await loadStatus()
  } catch (error) {
    // **一律走 resolveApiError**：材料類五種失敗（格式／解包／憑證／paste-back／
    // 保存確認）的回應刻意不可區分，前端 SHALL NOT 自行推測成因
    ElMessage.error(resolveApiError(error.response?.data, error.response?.status))
    await loadStatus()
  } finally {
    submitting.value = false
    clearMaterial()
  }
}

const goLogin = () => router.push('/login')

// unsealing 期間輪詢：段 2 可能跑數十秒，讓管理員看得到它仍在進行而非卡死
const syncPolling = () => {
  const shouldPoll = state.value === 'unsealing' || status.value.cleanup_pending
  if (shouldPoll && !pollTimer) {
    pollTimer = setInterval(loadStatus, 5000)
  } else if (!shouldPoll && pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

onMounted(async () => {
  await loadStatus()
  clockTimer = setInterval(() => {
    now.value = Date.now()
    syncPolling()
  }, 1000)
})

onUnmounted(() => {
  if (clockTimer) clearInterval(clockTimer)
  if (pollTimer) clearInterval(pollTimer)
  clearMaterial()
})

// 測試驅動用（happy-dom 不跑 transition／timer 行為不穩）：狀態注入與提交入口
defineExpose({ loadStatus, submit, status, material, materialConfirm, confirmSaved })
</script>

<style scoped>
.unseal-page {
  position: relative;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px 16px;
  background: var(--el-bg-color-page);
}

/* 語言切換：版位與類名沿用 Login.vue（同為未登入的整頁置中卡片） */
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

.unseal-card {
  width: 100%;
  max-width: 640px;
  padding: 28px 32px 32px;
  border-radius: 10px;
  background: var(--el-bg-color);
  border: 1px solid var(--el-border-color);
  box-shadow: var(--el-box-shadow-light);
}

/* 初始化解封與一般解封的視覺區分：此畫面的輸入會固化為部署主金鑰 */
.unseal-card.is-initialization {
  border: 2px solid var(--el-color-danger);
  box-shadow: 0 0 0 4px var(--el-color-danger-light-9);
}

.unseal-title {
  margin: 0 0 6px;
  font-size: 20px;
  font-weight: 600;
}

.unseal-subtitle {
  margin: 0 0 20px;
  color: var(--el-text-color-secondary);
  font-size: 13px;
  line-height: 1.6;
}

.status-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.status-meta {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

.unseal-alert {
  margin-bottom: 12px;
}

.form-section {
  margin: 20px 0 8px;
}

.init-section {
  padding: 16px;
  border-radius: 8px;
  background: var(--el-color-danger-light-9);
}

.section-title {
  margin: 0 0 8px;
  font-size: 16px;
  font-weight: 600;
}

.init-title {
  color: var(--el-color-danger);
}

.section-desc {
  margin: 0 0 12px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--el-text-color-secondary);
}

.field {
  margin-bottom: 16px;
}

.field-label {
  display: block;
  font-weight: 600;
  margin-bottom: 6px;
}

.field-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.material-input {
  flex: 1;
}

.material-input :deep(.el-input__inner) {
  font-family: var(--ot-font-mono, monospace);
}

.admin-input {
  margin-top: 8px;
}

.field-error {
  margin: 6px 0 0;
  font-size: 12px;
  color: var(--el-color-danger);
}

.field-hint {
  margin: 6px 0 0;
  font-size: 12px;
  line-height: 1.6;
  color: var(--el-text-color-secondary);
}

.submit-btn {
  margin-top: 12px;
  width: 100%;
}

.goto-login {
  margin-top: 12px;
}

/* 遺失警語：版面上必須壓過同頁其他說明。標題 15px/700，正文用 primary 文字色
   ——刻意不是 secondary（次要色等於把「唯一非知道不可的事」降級成註腳） */
.loss-callout {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  margin: 0 0 20px;
  padding: 14px 16px;
  border: 2px solid var(--el-color-danger);
  border-radius: 8px;
  background: var(--el-color-danger-light-9);
}

.loss-icon {
  flex-shrink: 0;
  margin-top: 2px;
  font-size: 20px;
  color: var(--el-color-danger);
}

.loss-title {
  margin: 0 0 4px;
  font-size: 15px;
  font-weight: 700;
  line-height: 1.5;
  color: var(--el-color-danger);
}

.loss-body {
  margin: 0;
  font-size: 13px;
  line-height: 1.7;
  color: var(--el-text-color-primary);
}

/* 警示區內的步驟／選項清單：疲勞時掃列表遠比讀段落容易 */
.alert-lead {
  margin: 0;
}

.alert-steps,
.alert-options {
  margin: 6px 0 0;
  padding-left: 20px;
}

.alert-steps li,
.alert-options li {
  margin-bottom: 2px;
}

.alert-note {
  margin: 8px 0 0;
}

.format-list {
  margin: 4px 0 0;
  padding-left: 20px;
  font-size: 12px;
  line-height: 1.8;
  color: var(--el-text-color-secondary);
}
</style>
