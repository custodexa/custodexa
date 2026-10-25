<template>
  <el-dialog
    :model-value="modelValue"
    :title="t('credentials.secretFix.title', { noun })"
    width="560px"
    :close-on-click-modal="false"
    data-test="secret-fix-dialog"
    @update:model-value="close"
  >
    <div
      v-loading="loading"
      class="fix-body"
    >
      <div class="cred-line">
        <span
          class="cred-name"
          data-test="secret-fix-name"
        >{{ displayName }}</span>
        <el-tag
          size="small"
          type="primary"
        >
          {{ t('enum.credentialScope.shared') }}
        </el-tag>
        <span class="cred-account">
          {{ t('credentials.secretFix.account') }}
          <span class="mono">{{ detail?.username }}</span>
        </span>
      </div>

      <div
        class="info-box"
        data-test="secret-fix-info"
      >
        <el-icon class="info-icon">
          <Info />
        </el-icon>
        <div>
          <div class="info-title">
            {{ t('credentials.secretFix.infoTitle', { noun }) }}
          </div>
          <div class="info-body">
            {{ t('credentials.secretFix.infoBody', { noun }) }}
          </div>
        </div>
      </div>

      <el-alert
        type="warning"
        :closable="false"
        show-icon
        :title="t('credentials.security.setSecretWarning')"
        data-test="secret-fix-warning"
      />

      <p
        v-if="loadError"
        class="load-error"
        data-test="secret-fix-load-error"
      >
        {{ t('credentials.secretFix.loadFailed') }}
      </p>
      <div
        v-else-if="detail"
        class="apply"
        data-test="secret-fix-apply"
      >
        <div class="apply-title">
          {{ bindings.length
            ? t('credentials.secretFix.applyTo', { count: bindings.length })
            : t('credentials.secretFix.applyNone') }}
        </div>
        <div
          v-if="bindings.length"
          class="chips"
        >
          <span
            v-for="binding in bindings"
            :key="binding.account_id"
            class="chip"
            :class="{ current: isCurrent(binding) }"
            :data-test="`secret-fix-asset-${binding.asset_id}`"
          >
            {{ binding.asset_name || t('common.assetRef', { id: binding.asset_id }) }}
            <span
              v-if="isCurrent(binding)"
              class="chip-mark"
              data-test="secret-fix-this-asset"
            >{{ t('credentials.secretFix.thisAsset') }}</span>
          </span>
        </div>
      </div>

      <el-form
        label-position="top"
        class="fix-form"
        @submit.prevent
      >
        <template v-if="kind === 'ssh_key'">
          <el-form-item
            :label="t('credentials.secretFix.fieldLabel', { noun })"
            :error="errors.secret"
            data-test="secret-fix-key-item"
          >
            <el-input
              v-model="form.secret"
              type="textarea"
              :rows="5"
              :placeholder="t('credentials.secretFix.keyPlaceholder')"
              data-test="secret-fix-private-key"
              @input="errors.secret = ''"
            />
          </el-form-item>
          <p
            v-if="!errors.secret"
            class="field-hint"
          >
            {{ t('credentials.secretFix.fieldHint', { noun }) }}
          </p>
        </template>
        <template v-else>
          <el-form-item
            :label="t('credentials.secretFix.fieldLabel', { noun })"
            :error="errors.secret"
            data-test="secret-fix-password-item"
          >
            <el-input
              v-model="form.secret"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="t('credentials.secretFix.fieldPlaceholder', { noun })"
              data-test="secret-fix-password"
              @input="errors.secret = ''"
            />
          </el-form-item>
          <p
            v-if="!errors.secret"
            class="field-hint"
          >
            {{ t('credentials.secretFix.fieldHint', { noun }) }}
          </p>
          <el-form-item
            :label="t('credentials.secretFix.confirmLabel')"
            :error="errors.confirm"
            data-test="secret-fix-confirm-item"
          >
            <el-input
              v-model="form.confirm"
              type="password"
              show-password
              autocomplete="new-password"
              :placeholder="t('credentials.secretFix.confirmPlaceholder')"
              data-test="secret-fix-confirm"
              @input="errors.confirm = ''"
            />
          </el-form-item>
        </template>
      </el-form>
    </div>

    <CredentialImpactDialog
      :model-value="impactVisible"
      operation="set_secret"
      :credential-name="displayName"
      :username="detail?.username || ''"
      :assets="bindings"
      :in-scope-count="impact?.inScopeCount || 0"
      :out-of-scope-count="impact?.outOfScopeCount || 0"
      :epoch="impactEpoch"
      :loading="impactWorking"
      :noun="noun"
      @confirm="confirmImpact"
      @cancel="flow.cancel()"
    />

    <template #footer>
      <div class="footer">
        <span
          v-if="bindings.length"
          class="rotate-hint"
          data-test="secret-fix-rotate-hint"
        >
          <template v-if="rotateAvailable">
            {{ t('credentials.secretFix.rotateHint', { noun }) }}
            <el-button
              link
              type="primary"
              class="rotate-link"
              data-test="secret-fix-rotate-link"
              @click="goRotate"
            >{{ t('credentials.secretFix.rotateLink') }}</el-button>{{ t('credentials.secretFix.rotateHintAfter') }}
          </template>
          <template v-else>
            {{ t('credentials.secretFix.rotateHintDrawer', { noun }) }}
          </template>
        </span>
        <div class="footer-actions">
          <el-button
            data-test="secret-fix-cancel"
            @click="close(false)"
          >
            {{ t('common.cancel') }}
          </el-button>
          <el-button
            type="primary"
            :loading="submitting"
            :disabled="!detail || loading"
            data-test="secret-fix-submit"
            @click="submit"
          >
            {{ bindings.length
              ? t('credentials.secretFix.submit', { count: bindings.length })
              : t('common.save') }}
          </el-button>
        </div>
      </div>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 更正登記的秘密（共用憑證）。
 *
 * 與「改密」是兩件事：改密會登入每台主機換一組平台產生的新秘密；這裡只把平台登記的值
 * 改成主機上現在的值，不碰遠端，全部掛載在同一交易內改用新版本。所以對話框先講清楚
 * 「主機不會變」與「會套用到哪幾台」，再讓人輸入。
 *
 * 只更正憑證本身那一種秘密：密碼型給密碼與確認欄，金鑰型只給私鑰欄。兩欄並陳會讓人
 * 以為兩個都要填，也會讓密碼型憑證被順手改成金鑰型。
 *
 * 憑證庫詳情帶入手上的詳情（已含掛載清單）；資產抽屜只知道憑證識別，開啟時取一次詳情。
 */
import { computed, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Info } from 'lucide-vue-next'
import { getCredential, setCredentialSecret } from '@/api/credentials'
import CredentialImpactDialog from './CredentialImpactDialog.vue'
import { skipImpactConflictToast, useCredentialImpactFlow } from '@/composables/useCredentialImpactFlow'
import { resolveApiError } from '@/api/error'
import { credentialDisplayName, credentialSecretKind } from '@/constants/credentials'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  credentialId: { type: [Number, String], default: 0 },
  // 已有詳情（含 bindings）時帶入，就不再另取
  credential: { type: Object, default: null },
  // 從某台資產開啟時帶入，套用清單在那一台旁標「這台」
  currentAssetId: { type: [Number, String], default: null },
  // 能就地開改密對話框時為 true；否則改為文字說明到憑證庫操作
  rotateAvailable: { type: Boolean, default: false },
})

const emit = defineEmits(['update:modelValue', 'saved', 'rotate'])

const { t } = useI18n()

const fetched = ref(null)
const loading = ref(false)
const loadError = ref(false)
const submitting = ref(false)
const form = reactive({ secret: '', confirm: '' })
const errors = reactive({ secret: '', confirm: '' })

const detail = computed(() => props.credential || fetched.value)

// 範圍外影響確認：台數與清單取自伺服器，勾選知情後才以確認識別送出
const flow = useCredentialImpactFlow(() => detail.value?.id, 'set_secret')
const { visible: impactVisible, impact, working: impactWorking, epoch: impactEpoch } = flow
const bindings = computed(() => detail.value?.bindings || [])
const kind = computed(() => credentialSecretKind(detail.value))
const noun = computed(() => t(`credentials.secretFix.noun.${kind.value}`))
const displayName = computed(() => credentialDisplayName(detail.value))

function isCurrent(binding) {
  return props.currentAssetId != null && String(binding.asset_id) === String(props.currentAssetId)
}

function clearInput() {
  form.secret = ''
  form.confirm = ''
  errors.secret = ''
  errors.confirm = ''
}

async function loadDetail() {
  fetched.value = null
  loadError.value = false
  if (props.credential || !props.credentialId) return
  loading.value = true
  try {
    const res = await getCredential(props.credentialId)
    fetched.value = res?.data || null
    loadError.value = !fetched.value
  } catch (err) {
    console.error('[CredentialSecretFix] 載入憑證詳情失敗:', err?.response?.status, err?.response?.data?.code)
    loadError.value = true
  } finally {
    loading.value = false
  }
}

watch(() => props.modelValue, (open) => {
  clearInput()
  if (open) void loadDetail()
})

// 關閉即清掉明文：只隱藏對話框會讓輸入值續留在元件狀態內
function close(visible = false) {
  if (visible !== true) {
    clearInput()
    flow.cancel()
  }
  emit('update:modelValue', visible === true)
}

function goRotate() {
  close(false)
  emit('rotate')
}

function validate() {
  errors.secret = ''
  errors.confirm = ''
  if (!form.secret) {
    errors.secret = t('credentials.secretFix.errRequired', { noun: noun.value })
    return false
  }
  if (kind.value !== 'ssh_key' && form.secret !== form.confirm) {
    errors.confirm = t('credentials.secretFix.errMismatch', { noun: noun.value })
    return false
  }
  return true
}

function payload() {
  return kind.value === 'ssh_key'
    ? { private_key: form.secret }
    : { password: form.secret }
}

function isPrivateKeyFieldError(error) {
  const data = error?.response?.data
  return error?.response?.status === 400
    && (data?.params?.field ?? data?.field) === 'private_key'
}

function skipSubmitToast(error) {
  return isPrivateKeyFieldError(error) || skipImpactConflictToast(error)
}

async function sendSecret(extra) {
  await setCredentialSecret(detail.value.id, { ...payload(), ...extra }, {
    skipErrorToast: skipSubmitToast,
  })
  const count = bindings.value.length
  close(false)
  emit('saved', { count, noun: noun.value })
}

function onSubmitError(err) {
  // 私鑰無法解析：錯誤掛在私鑰欄下方；其餘錯誤由全域提示顯示，對話框與輸入保留
  if (isPrivateKeyFieldError(err)) {
    errors.secret = resolveApiError(err.response.data, err.response.status)
  }
  console.error('[CredentialSecretFix] 更正失敗:', err?.response?.status, err?.response?.data?.code)
}

async function submit() {
  if (!detail.value || !validate()) return
  submitting.value = true
  try {
    await flow.start(sendSecret)
  } catch (err) {
    onSubmitError(err)
  } finally {
    submitting.value = false
  }
}

async function confirmImpact() {
  try {
    await flow.confirm()
  } catch (err) {
    onSubmitError(err)
  }
}

defineExpose({ form, errors, kind, bindings, submit, payload, confirmImpact, flow })
</script>

<style scoped>
.fix-body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}

.cred-line {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}

.cred-name {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.cred-account {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.mono {
  font-family: var(--ot-font-mono);
  color: var(--ot-text-primary);
}

.info-box {
  display: flex;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-primary);
  border-radius: var(--ot-radius-md);
  background: var(--ot-primary-dim);
}

.info-icon {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--ot-primary);
}

.info-title {
  font-weight: 600;
  color: var(--ot-text-primary);
  line-height: 1.6;
}

.info-body {
  margin-top: var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}

.apply-title {
  font-weight: 600;
  color: var(--ot-text-primary);
  margin-bottom: var(--ot-space-sm);
}

.chips {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-sm);
}

.chip {
  padding: 2px 10px;
  border: 1px solid var(--ot-border);
  border-radius: 999px;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
  background: var(--ot-bg-surface);
}

.chip-mark {
  color: var(--ot-text-secondary);
}

.load-error {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--el-color-danger);
}

.fix-form :deep(.el-form-item) {
  margin-bottom: var(--ot-space-xs);
}

.fix-form :deep(.el-form-item.is-error) {
  margin-bottom: var(--ot-space-lg);
}

.field-hint {
  margin: 0 0 var(--ot-space-md);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
  line-height: 1.6;
}

.footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-md);
}

.rotate-hint {
  text-align: left;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}

.rotate-link {
  font-size: var(--ot-font-size-xs);
  vertical-align: baseline;
  padding: 0;
  height: auto;
}

.footer-actions {
  display: flex;
  flex-shrink: 0;
  margin-left: auto;
}
</style>
