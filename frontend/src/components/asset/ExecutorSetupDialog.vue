<!--
  ExecutorSetupDialog：設定與更換堡壘機專用帳號的對話框。

  四種來源：平台產生金鑰、共用憑證、直接輸入、轉換既有帳號。所有伺服器錯誤都寫在
  觸發的欄位或按鈕旁（請求一律帶 skipErrorToast），不呼叫全域訊息。
  expectedAccountId 取區塊最近一次載入的值，伺服器靠它擋遺失更新。
  秘密欄位在關閉、成功、切換來源時清空，不寫 log。
  平台產生成功後原地換成結果，焦點移到結果開頭；關閉動畫結束時 emit closed。
-->
<template>
  <el-dialog
    :model-value="modelValue"
    :title="dialogTitle"
    width="560px"
    append-to-body
    :close-on-click-modal="false"
    :close-on-press-escape="!submitting"
    :before-close="beforeClose"
    :class="['executor-setup-dialog', { 'is-submitting': submitting }]"
    @update:model-value="onVisible"
    @closed="emit('closed')"
  >
    <div
      ref="bodyRef"
      class="dlg-body"
    >
      <!-- 結果：平台產生金鑰成功後原地替換 -->
      <template v-if="step === 'result'">
        <div
          ref="resultRef"
          class="result-head"
          tabindex="-1"
          data-test="dlg-result-head"
        >
          <el-alert
            type="success"
            :closable="false"
            show-icon
            data-test="dlg-result-ok"
            :title="t('assetExecutor.dialog.resultOk', { account: resultAccount })"
          />
        </div>
        <ExecutorPublicKeyPanel
          inline
          :asset-id="assetId"
          :account="resultAccount"
          :fingerprint="resultFingerprint"
        />
        <ExecutorNoticeBox
          tone="warning"
          data-test="dlg-result-next"
          :title="t('assetExecutor.dialog.resultNextTitle', { account: resultAccount })"
        >
          <p>{{ t('assetExecutor.dialog.resultNextBody') }}</p>
        </ExecutorNoticeBox>
        <!-- 技術細節：文字連結式展開，不做成整列收合區塊 -->
        <div class="tech-details">
          <el-button
            link
            type="primary"
            size="small"
            class="tech-toggle"
            :aria-expanded="techOpen"
            data-test="dlg-tech-toggle"
            @click="techOpen = !techOpen"
          >
            <component
              :is="techOpen ? ChevronDown : ChevronRight"
              :size="14"
              aria-hidden="true"
              class="tech-chevron"
            />
            {{ t('assetExecutor.dialog.techDetails') }}
          </el-button>
          <div
            v-if="techOpen"
            class="tech-body"
            data-test="dlg-tech-body"
          >
            <ExecutorSetupHelp expanded />
          </div>
        </div>
        <p
          class="muted"
          data-test="dlg-result-logged"
        >
          {{ t('assetExecutor.publicKey.loggedEvery') }}
        </p>
      </template>

      <!-- 轉換既有帳號：錯誤在帳號選單正下方，三件事在其後 -->
      <ExecutorConvertStep
        v-else-if="step === 'convert'"
        v-model="convertAccountId"
        :accounts="accounts"
        :err="err"
        :disabled="submitting"
        @change="clearError"
        @fix="runFix"
      />

      <!-- 來源選擇與各來源欄位 -->
      <template v-else>
        <div
          class="info-box"
          data-test="dlg-purpose"
        >
          <Info
            :size="14"
            aria-hidden="true"
            class="info-icon"
          />
          <span>{{ mode === 'replace' ? replaceDesc : t('assetExecutor.dialog.purpose') }}</span>
        </div>
        <div
          class="field-label"
          data-test="dlg-source-label"
        >
          {{ t('assetExecutor.dialog.sourceLabel') }}
        </div>
        <p
          v-if="windowsFamily"
          class="muted"
          data-test="dlg-windows-note"
        >
          {{ t('assetExecutor.dialog.windowsNote') }}
        </p>
        <ExecutorSourceCards
          :cards="cards"
          :model-value="source"
          :disabled="submitting"
          :label="t('assetExecutor.dialog.sourceLabel')"
          :recommended-text="t('assetExecutor.dialog.recommended')"
          @pick="pickSource"
        />
        <p
          v-if="noSourceAvailable"
          class="muted"
          data-test="dlg-no-permission"
        >
          {{ t('assetExecutor.dialog.noPermission') }}
        </p>

        <!-- 帳號名稱（產生、直接輸入） -->
        <template v-if="source === 'generate' || source === 'inline'">
          <el-form-item
            :label="t('assetExecutor.dialog.usernameLabel')"
            required
            :class="{ 'is-error': errAt('field-username') }"
          >
            <el-input
              v-model="username"
              :disabled="submitting"
              maxlength="64"
              data-test="dlg-username"
              @input="clearError"
            />
          </el-form-item>
          <ExecutorErrorLine
            v-if="errAt('field-username')"
            :err="err"
            @fix="runFix"
          />
          <!-- Windows 族（只有直接輸入密碼）帳號名稱下不放提示句：帳號本來就存在，輸入的是它現有的密碼 -->
          <p
            v-else-if="!windowsFamily"
            class="muted"
            data-test="dlg-username-hint"
          >
            {{ t('assetExecutor.dialog.usernameHint') }}
            <el-button
              v-if="source === 'generate'"
              link
              type="primary"
              size="small"
              :aria-expanded="prepareOpen ? 'true' : 'false'"
              data-test="dlg-prepare-link"
              @click="prepareOpen = !prepareOpen"
            >
              {{ t('assetExecutor.dialog.prepareLink') }}
            </el-button>
          </p>
          <ExecutorSetupHelp
            v-if="prepareOpen && source === 'generate'"
            expanded
          />
        </template>

        <!-- 直接輸入 -->
        <template v-if="source === 'inline'">
          <el-form-item
            v-if="!windowsFamily"
            :label="t('assetExecutor.dialog.secretTypeLabel')"
          >
            <el-radio-group
              v-model="secretType"
              :disabled="submitting"
              data-test="dlg-secret-type"
              @change="onSecretTypeChange"
            >
              <el-radio value="password">
                {{ t('assetExecutor.dialog.password') }}
              </el-radio>
              <el-radio value="ssh_key">
                {{ t('assetExecutor.dialog.privateKey') }}
              </el-radio>
            </el-radio-group>
          </el-form-item>
          <el-form-item
            :label="secretType === 'password' ? t('assetExecutor.dialog.password') : t('assetExecutor.dialog.privateKey')"
            required
          >
            <el-input
              v-if="secretType === 'password'"
              v-model="password"
              type="password"
              show-password
              autocomplete="new-password"
              :disabled="submitting"
              data-test="dlg-password"
            />
            <el-input
              v-else
              v-model="privateKey"
              type="textarea"
              :rows="5"
              :disabled="submitting"
              data-test="dlg-private-key"
            />
          </el-form-item>
          <ExecutorErrorLine
            v-if="err && err.placement === 'field-secret-type'"
            :err="err"
            @fix="runFix"
          />
        </template>

        <!-- 共用憑證 -->
        <template v-if="source === 'shared'">
          <el-form-item
            :label="t('assetExecutor.dialog.credentialLabel')"
            required
            :class="{ 'is-error': errAt('field-credential') }"
          >
            <CredentialPicker
              v-model="credentialId"
              :protocol="windowsFamily ? 'rdp' : 'ssh'"
              executor-mode
              :windows-family="windowsFamily"
              :disabled="submitting"
              @loaded="(list) => (credentialOptions = list)"
              @update:model-value="onCredentialChange"
            />
          </el-form-item>
          <ExecutorErrorLine
            v-if="errAt('field-credential')"
            :err="err"
            @fix="runFix"
          />
          <!-- 用途不一致時這組憑證不能用，不再顯示沿用帳號與台數確認 -->
          <template v-if="selectedCredential && !purposeBlocked">
            <p
              class="muted"
              data-test="dlg-credential-username"
            >
              {{ t('assetExecutor.dialog.credentialUsername', { account: selectedCredential.username }) }}
            </p>
            <ExecutorNoticeBox
              tone="warning"
              data-test="dlg-shared-confirm"
            >
              <strong
                class="shared-title"
                data-test="dlg-shared-title"
              >{{ sharedTitle }}</strong>
              <p data-test="dlg-shared-body">
                {{ sharedBody }}
              </p>
              <p
                v-if="sharedAdvice"
                class="muted"
                data-test="dlg-shared-advice"
              >
                {{ sharedAdvice }}
              </p>
              <el-checkbox
                v-model="ack"
                :disabled="submitting"
                data-test="dlg-shared-check"
              >
                {{ sharedCheckText }}
              </el-checkbox>
            </ExecutorNoticeBox>
            <!-- 台數已變：錯誤框在確認框之外、其正下方 -->
            <ExecutorErrorLine
              v-if="errAt('confirm-count')"
              :err="err"
              @fix="runFix"
            />
          </template>
        </template>
      </template>

      <ExecutorErrorLine
        v-if="err && err.placement === 'button'"
        :err="err"
        data-test="dlg-button-error"
        @fix="runFix"
      />
    </div>

    <template #footer>
      <div class="dlg-footer">
        <div class="footer-left">
          <!-- 帳號名稱已被占用時修正鈕就是「改用轉換既有帳號」，底部不再重複同一入口 -->
          <template v-if="step === 'choose' && err?.fixAction !== 'useConvert'">
            <span class="muted">{{ t('assetExecutor.dialog.convertEntry') }}</span>
            <el-button
              link
              type="primary"
              size="small"
              :disabled="!canUpdate || submitting"
              data-test="source-convert-link"
              @click="goConvert"
            >
              {{ t('assetExecutor.dialog.convertLink') }}
            </el-button>
            <span
              v-if="!canUpdate"
              class="muted"
              data-test="source-reason-convert"
            >{{ t('assetExecutor.dialog.needUpdate') }}</span>
          </template>
          <el-button
            v-else-if="step === 'convert'"
            link
            type="primary"
            size="small"
            :disabled="submitting"
            data-test="dlg-back"
            @click="backToSources"
          >
            {{ t('assetExecutor.dialog.back') }}
          </el-button>
        </div>
        <div class="footer-right">
          <el-button
            v-if="step === 'result'"
            type="primary"
            data-test="dlg-done"
            @click="finishResult"
          >
            {{ t('assetExecutor.dialog.done') }}
          </el-button>
          <template v-else>
            <el-button
              :disabled="submitting"
              data-test="dlg-cancel"
              @click="onVisible(false)"
            >
              {{ t('assetExecutor.dialog.cancel') }}
            </el-button>
            <el-button
              v-preview-write
              :type="err && err.fixAction ? 'default' : 'primary'"
              :disabled="submitDisabled"
              :loading="submitting"
              data-test="dlg-submit"
              @click="submit()"
            >
              {{ submitLabel }}
            </el-button>
          </template>
        </div>
      </div>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ChevronDown, ChevronRight, Info } from 'lucide-vue-next'
import { can } from '@/composables/useCapabilities'
import { putAssetExecutor } from '@/api/assetExecutor'
import { listAssetAccounts } from '@/api/assetAccounts'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import CredentialPicker from '@/components/credential/CredentialPicker.vue'
import ExecutorSetupHelp from '@/components/asset/ExecutorSetupHelp.vue'
import ExecutorPublicKeyPanel from '@/components/asset/ExecutorPublicKeyPanel.vue'
import ExecutorErrorLine from '@/components/asset/ExecutorErrorLine.vue'
import ExecutorSourceCards from '@/components/asset/ExecutorSourceCards.vue'
import ExecutorConvertStep from '@/components/asset/ExecutorConvertStep.vue'
import ExecutorNoticeBox from '@/components/asset/ExecutorNoticeBox.vue'
import { useExecutorDialogText } from '@/composables/useExecutorDialogText'
import { buildExecutorError } from '@/composables/executorDialogError'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  mode: { type: String, default: 'set' },
  assetId: { type: [Number, String], required: true },
  assetName: { type: String, default: '' },
  windowsFamily: { type: Boolean, default: false },
  expectedAccountId: { type: Number, default: 0 },
  current: { type: Object, default: () => ({}) },
})
const emit = defineEmits(['update:modelValue', 'done', 'applied', 'state-changed', 'rotation-blocked', 'closed'])

const { t } = useI18n()

const canCreate = computed(() => can('credential:create'))
const canBind = computed(() => can('credential:bind'))
const canUpdate = computed(() => can('credential:update'))

const step = ref('choose') // choose | convert | result
const techOpen = ref(false)
const source = ref('generate')
const username = ref('')
const secretType = ref('password')
const password = ref('')
const privateKey = ref('')
const credentialId = ref(null)
const credentialOptions = ref([])
const ack = ref(false)
const ackCount = ref(0)
const confirmedFrom = ref(0)
const accounts = ref([])
const convertAccountId = ref(null)
const submitting = ref(false)
const err = ref(null)
const resultAccount = ref('')
const resultFingerprint = ref('')
const resultRef = ref(null)
const prepareOpen = ref(false)
const bodyRef = ref(null)
const errAt = (placement) => err.value?.placement === placement

const dialogTitle = computed(() => {
  if (step.value === 'convert') return t('assetExecutor.convert.title')
  return props.mode === 'replace' ? t('assetExecutor.dialog.replaceTitle') : t('assetExecutor.dialog.setTitle')
})

function clearSecrets() {
  password.value = ''
  privateKey.value = ''
}

function reset() {
  step.value = 'choose'
  techOpen.value = false
  username.value = ''
  secretType.value = 'password'
  clearSecrets()
  credentialId.value = null
  ack.value = false
  ackCount.value = 0
  accounts.value = []
  convertAccountId.value = null
  err.value = null
  submitting.value = false
  prepareOpen.value = false
  resultAccount.value = ''
  resultFingerprint.value = ''
  pickDefaultSource()
}

// 預設來源：能用的第一個（非 Windows 優先平台產生）
function pickDefaultSource() {
  if (props.windowsFamily || !canCreate.value) {
    source.value = canCreate.value ? 'inline' : canBind.value ? 'shared' : 'inline'
  } else {
    source.value = 'generate'
  }
}

watch(() => props.modelValue, (v) => {
  if (v) reset()
  else clearSecrets()
})

// 卡片順序：非 Windows 為產生、共用、直接輸入；Windows 族沒有產生，直接輸入密碼在前
const cards = computed(() => {
  const inline = {
    key: 'inline',
    title: props.windowsFamily ? t('assetExecutor.dialog.sourceInlinePassword') : t('assetExecutor.dialog.sourceInline'),
    desc: props.windowsFamily ? t('assetExecutor.dialog.sourceInlinePasswordDesc') : t('assetExecutor.dialog.sourceInlineDesc'),
    disabled: !canCreate.value,
    reason: canCreate.value ? '' : t('assetExecutor.dialog.needCreate'),
  }
  const shared = {
    key: 'shared',
    title: t('assetExecutor.dialog.sourceShared'),
    desc: t('assetExecutor.dialog.sourceSharedDesc'),
    disabled: !canBind.value,
    reason: canBind.value ? '' : t('assetExecutor.dialog.needBind'),
  }
  if (props.windowsFamily) return [inline, shared]
  const generate = {
    key: 'generate',
    title: t('assetExecutor.dialog.sourceGenerate'),
    desc: t('assetExecutor.dialog.sourceGenerateDesc'),
    recommended: true,
    disabled: !canCreate.value,
    reason: canCreate.value ? '' : t('assetExecutor.dialog.needCreate'),
  }
  return [generate, shared, inline]
})
const noSourceAvailable = computed(() => cards.value.every((c) => c.disabled) && !canUpdate.value)

function pickSource(key) {
  if (source.value === key) return
  source.value = key
  clearSecrets()
  err.value = null
}

function clearError() {
  err.value = null
}

function onSecretTypeChange() {
  clearSecrets()
  err.value = null
}

const { replaceDesc, selectedCredential, shownCount, secretWord, sharedTitle, sharedBody, sharedAdvice, sharedCheckText } =
  useExecutorDialogText({ props, t, credentialOptions, credentialId, ackCount })

const purposeBlocked = computed(() => err.value?.fixAction === 'useGenerate')

function onCredentialChange() {
  ack.value = false
  ackCount.value = 0
  err.value = null
}

// 轉換
async function loadAccounts() {
  try {
    const res = await listAssetAccounts(props.assetId)
    accounts.value = res?.data || []
  } catch {
    accounts.value = []
  }
}
const convertAccount = computed(() => accounts.value.find((a) => a.id === convertAccountId.value) || null)
// 預設帳號與共用憑證帳號不能轉換（選單內停用並寫原因，見 ExecutorConvertStep）
const isConvertible = (acc) => !acc.is_default && !acc.shared_credential
async function goConvert(preselectName) {
  step.value = 'convert'
  err.value = null
  clearSecrets()
  source.value = 'convert'
  if (!accounts.value.length) await loadAccounts()
  convertAccountId.value = null
  if (typeof preselectName === 'string') {
    const hit = accounts.value.find((a) => a.username === preselectName && isConvertible(a))
    if (hit) convertAccountId.value = hit.id
  }
}
function backToSources() {
  step.value = 'choose'
  pickDefaultSource()
  err.value = null
}

// 送出
const submitDisabled = computed(() => {
  if (submitting.value) return true
  if (step.value === 'convert') return !convertAccountId.value
  if (source.value === 'generate') return !username.value.trim()
  if (source.value === 'inline') {
    return !username.value.trim() || (secretType.value === 'password' ? !password.value : !privateKey.value)
  }
  if (source.value === 'shared') return !credentialId.value || !ack.value
  return true
})

const submitLabel = computed(() => {
  const replace = props.mode === 'replace'
  if (submitting.value) {
    return t(source.value === 'generate' ? 'assetExecutor.dialog.submittingGenerate' : 'assetExecutor.dialog.submitting')
  }
  if (step.value === 'convert') return t('assetExecutor.dialog.submitConvert')
  if (source.value === 'generate') return t(replace ? 'assetExecutor.dialog.submitGenerateReplace' : 'assetExecutor.dialog.submitGenerate')
  return t(replace ? 'assetExecutor.dialog.submitReplace' : 'assetExecutor.dialog.submitSet')
})

function buildBody(countOverride) {
  const base = { expected_account_id: props.expectedAccountId }
  if (step.value === 'convert') return { source: 'convert', account_id: convertAccountId.value, ...base }
  if (source.value === 'generate') return { source: 'generate', username: username.value.trim(), ...base }
  if (source.value === 'inline') {
    const secret = secretType.value === 'password' || props.windowsFamily
      ? { password: password.value }
      : { private_key: privateKey.value }
    return { source: 'inline', username: username.value.trim(), ...secret, ...base }
  }
  return {
    source: 'shared',
    credential_id: credentialId.value,
    acknowledged_host_count: countOverride || shownCount.value,
    ...base,
  }
}

function buildError(code, data, status) {
  const context = step.value === 'convert' ? 'convert' : props.mode === 'replace' ? 'replace' : 'set'
  return buildExecutorError({
    code, data, status, context, t,
    windowsFamily: props.windowsFamily,
    submittedName: username.value.trim(),
    convertAccount: convertAccount.value,
    confirmedFrom: confirmedFrom.value,
    shownCount: shownCount.value,
    secretWord: secretWord.value,
  })
}

async function submit(countOverride) {
  if (submitting.value) return
  submitting.value = true
  err.value = null
  confirmedFrom.value = countOverride ? confirmedFrom.value : shownCount.value
  const kind = step.value === 'convert' ? 'convert' : 'set'
  try {
    const wasGenerate = step.value !== 'convert' && source.value === 'generate'
    const usedUsername = username.value.trim()
    const res = await putAssetExecutor(props.assetId, buildBody(countOverride))
    clearSecrets()
    if (wasGenerate) {
      resultAccount.value = usedUsername
      resultFingerprint.value = res?.fingerprint || ''
      step.value = 'result'
      // 設定已生效：背後區塊即時換成已設定，不等按「完成」
      emit('applied')
      await nextTick()
      resultRef.value?.focus?.()
    } else {
      emit('done', { kind })
    }
  } catch (e) {
    const data = e?.response?.data
    const status = e?.response?.status
    const code = data?.code
    if (code === 'RULE_EXECUTOR_STATE_CHANGED' || code === 'RULE_EXECUTOR_PROTOCOL_UNSUPPORTED') {
      emit('state-changed', { action: props.mode === 'replace' ? 'replace' : 'set' })
      return
    }
    if (code === 'RULE_CREDENTIAL_ROTATION_ACTIVE' && props.mode === 'replace' && step.value !== 'convert') {
      emit('rotation-blocked')
      return
    }
    err.value = buildError(code, data, status)
    // 台數已變：確認框數字原地改為伺服器的現行台數，勾選清空，要使用者重新確認
    if (err.value.fixAction === 'confirmCount') {
      ackCount.value = err.value.count
      ack.value = false
    }
  } finally {
    submitting.value = false
  }
  if (err.value) await focusError()
}

// 送出被擋：焦點移到錯誤框內的修正鈕，沒有修正鈕時落在錯誤框本身，不掉到頁面最上層
async function focusError() {
  await nextTick()
  const box = bodyRef.value?.querySelector('.dlg-error')
  const target = box?.querySelector('[data-test="dlg-fix"]') || box
  target?.focus?.()
}

function runFix(which) {
  const e = err.value
  if (!e) return
  if (which === 'recheck') {
    submit()
    return
  }
  switch (e.fixAction) {
    case 'useConvert': {
      const name = username.value.trim()
      goConvert(name)
      break
    }
    case 'confirmCount':
      ackCount.value = e.count
      ack.value = true
      err.value = null
      submit(e.count)
      break
    case 'useGenerate':
      pickSource(props.windowsFamily ? 'inline' : 'generate')
      username.value = ''
      break
    case 'openPlans':
      window.open('/change-secret-plans', '_blank', 'noopener')
      break
    case 'openRotation':
      window.open(`/credentials?credential=${e.credentialId}`, '_blank', 'noopener')
      break
    case 'openCredentials':
      window.open('/credentials', '_blank', 'noopener')
      break
    default:
  }
}

function finishResult() {
  emit('done', { kind: 'set' })
}

// 送出中右上 × 仍畫出但停用：點了也不關（Esc 另由 close-on-press-escape 擋）
function beforeClose(done) {
  if (submitting.value) return
  done()
}

function onVisible(v) {
  if (submitting.value) return
  if (!v && step.value === 'result') {
    finishResult()
    return
  }
  clearSecrets()
  emit('update:modelValue', v)
}

defineExpose({ step, source, err, ack, ackCount, username, accounts, convertAccountId, goConvert, submit })
</script>

<style scoped>
.dlg-body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.dlg-body :deep(.el-form-item) {
  flex-direction: column;
  align-items: stretch;
  margin-bottom: 0;
}

.dlg-body :deep(.el-form-item__label) {
  justify-content: flex-start;
}

.info-box {
  display: flex;
  align-items: flex-start;
  gap: var(--ot-space-xs);
  padding: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  background: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-md);
}

.info-icon {
  flex: none;
  margin-top: 2px;
  color: var(--ot-primary);
}

.field-label {
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
}

.result-head {
  outline: none;
}

.muted {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.shared-title {
  font-weight: 600;
}

.tech-details {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: var(--ot-space-xs);
}

.tech-chevron {
  margin-right: 2px;
}

.tech-body {
  padding-left: var(--ot-space-md);
}

.dlg-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
}

.footer-left {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px;
  text-align: left;
}
</style>

<!-- 對話框傳送到 body，送出中的 × 停用樣式不能用 scoped -->
<style>
.executor-setup-dialog.is-submitting .el-dialog__headerbtn {
  cursor: not-allowed;
  opacity: 0.5;
  pointer-events: none;
}
</style>
