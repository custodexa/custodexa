<template>
  <SourceDetailLayout
    :title="form.name"
    :type-label="$t('identitySources.typeLabel.ldap')"
    :subtitle="subtitle"
    :enabled="savedEnabled"
    :saving="saving"
    :testing="testing"
    :dirty="isDirty"
    :can-save="!loading && !loadFailed"
    :last-saved="lastSavedText"
    @save="handleSave"
    @test="handleTest"
  >
    <el-alert
      v-if="loadFailed"
      class="detail-alert"
      type="error"
      :title="$t('ldapDirectory.loadFailedGuardTitle')"
      :description="$t('ldapDirectory.loadFailedGuardDesc')"
      :closable="false"
      show-icon
    />
    <el-alert
      v-if="formError"
      class="detail-alert"
      type="error"
      :title="formError"
      :closable="false"
      show-icon
    />

    <el-form
      ref="formRef"
      v-loading="loading"
      :model="form"
      :rules="formRules"
      label-position="top"
    >
      <SourceSection
        :index="1"
        :title="$t('identitySources.section.connection')"
        :hint="$t('identitySources.ldap.connectionHint')"
      >
        <div class="field-row">
          <el-form-item
            class="field-row__item"
            :label="$t('common.name')"
            prop="name"
          >
            <el-input
              v-model="form.name"
              maxlength="100"
              :placeholder="$t('ldapDirectory.namePlaceholder')"
            />
          </el-form-item>
          <el-form-item
            class="field-row__item"
            :label="$t('ldapDirectory.url')"
            prop="url"
          >
            <el-input
              v-model="form.url"
              maxlength="255"
              :placeholder="$t('ldapDirectory.urlPlaceholder')"
            />
            <div class="field-hint">
              {{ $t('ldapDirectory.urlHint') }}
            </div>
          </el-form-item>
        </div>

        <div class="field-row">
          <el-form-item
            class="field-row__item"
            :label="$t('ldapDirectory.bindDn')"
            prop="bind_dn"
          >
            <el-input
              v-model="form.bind_dn"
              maxlength="255"
              :placeholder="$t('ldapDirectory.bindDnPlaceholder')"
            />
            <div class="field-hint">
              {{ $t('ldapDirectory.bindDnHint') }}
            </div>
          </el-form-item>
          <!-- 密碼兩態：已設定時不再以空輸入框暗示未設定 -->
          <el-form-item
            class="field-row__item"
            :label="$t('ldapDirectory.bindPassword')"
          >
            <div
              v-if="savedHasBindPassword && !resettingPassword"
              class="secret-state"
            >
              <el-tag
                size="small"
                type="success"
                effect="plain"
              >
                {{ $t('identitySources.secretSet') }}
              </el-tag>
              <el-button
                size="small"
                @click="resettingPassword = true"
              >
                {{ $t('identitySources.secretReset') }}
              </el-button>
            </div>
            <template v-else>
              <el-input
                v-model="form.bind_password"
                type="password"
                show-password
                autocomplete="new-password"
                :disabled="form.clear_bind_password"
                :placeholder="$t('ldapDirectory.bindPasswordPlaceholder')"
              />
              <el-checkbox
                v-if="savedHasBindPassword"
                v-model="form.clear_bind_password"
                class="clear-secret"
              >
                {{ $t('ldapDirectory.clearBindPassword') }}
              </el-checkbox>
              <el-button
                v-if="savedHasBindPassword"
                size="small"
                link
                @click="cancelPasswordReset"
              >
                {{ $t('common.cancel') }}
              </el-button>
            </template>
            <div
              v-if="form.clear_bind_password"
              class="field-warning"
            >
              {{ $t('ldapDirectory.clearBindPasswordHint') }}
            </div>
            <div
              v-if="urlChangedNeedsPassword"
              class="field-warning"
            >
              {{ $t('ldapDirectory.urlChangedNeedPassword') }}
            </div>
          </el-form-item>
        </div>

        <!-- 略過傳輸憑證驗證留在本段（不歸進階）：它與位址所用的協定直接相關，
             放進階會讓人連同警語一起漏看 -->
        <el-form-item :label="$t('ldapDirectory.skipTlsVerify')">
          <el-switch v-model="form.skip_tls_verify" />
          <div class="field-warning">
            {{ $t('ldapDirectory.skipTlsVerifyWarning') }}
          </div>
        </el-form-item>
      </SourceSection>

      <SourceSection
        :index="2"
        :title="$t('identitySources.section.userMapping')"
        :hint="$t('identitySources.ldap.userMappingHint')"
      >
        <div class="field-row">
          <el-form-item
            class="field-row__item"
            :label="$t('ldapDirectory.baseDn')"
            prop="base_dn"
          >
            <el-input
              v-model="form.base_dn"
              maxlength="255"
              :placeholder="$t('ldapDirectory.baseDnPlaceholder')"
            />
          </el-form-item>
          <el-form-item
            class="field-row__item"
            :label="$t('ldapDirectory.userFilter')"
            prop="user_filter"
          >
            <el-input
              v-model="form.user_filter"
              maxlength="255"
              :placeholder="$t('ldapDirectory.userFilterPlaceholder')"
            />
            <div class="field-hint">
              {{ $t('ldapDirectory.userFilterHint') }}
            </div>
          </el-form-item>
        </div>
        <div class="field-row">
          <el-form-item
            class="field-row__item"
            :label="$t('ldapDirectory.attrEmail')"
            prop="attr_email"
          >
            <el-input
              v-model="form.attr_email"
              maxlength="64"
              :placeholder="$t('ldapDirectory.attrEmailPlaceholder')"
            />
          </el-form-item>
          <el-form-item
            class="field-row__item"
            :label="$t('ldapDirectory.attrFullname')"
            prop="attr_fullname"
          >
            <el-input
              v-model="form.attr_fullname"
              maxlength="64"
              :placeholder="$t('ldapDirectory.attrFullnamePlaceholder')"
            />
          </el-form-item>
        </div>
      </SourceSection>

      <SourceSection
        :index="3"
        :title="$t('identitySources.section.groupMapping')"
        :hint="$t('identitySources.mapping.sectionHint')"
      >
        <GroupMappingSection
          type="ldap"
          :source-id="directoryId"
          :attr-set="Boolean(form.attr_group)"
        >
          <template #attr>
            <el-form-item
              class="field-narrow"
              :label="$t('identitySources.ldap.attrGroup')"
            >
              <el-input
                v-model="form.attr_group"
                maxlength="64"
                placeholder="memberOf"
              />
              <div class="field-hint">
                {{ $t('identitySources.ldap.attrGroupHint') }}
              </div>
            </el-form-item>
          </template>
        </GroupMappingSection>
      </SourceSection>

      <!-- 目錄型別不顯示准入段（無內容）；進階段收低頻且不可逆的操作 -->
      <SourceSection
        :index="4"
        :title="$t('identitySources.section.advanced')"
        :hint="$t('identitySources.ldap.advancedHint')"
      >
        <div class="danger-zone">
          <div class="danger-zone__text">
            <div class="danger-zone__title">
              {{ $t('identitySources.ldap.deleteTitle') }}
            </div>
            <div class="field-hint">
              {{ $t('identitySources.ldap.deleteHint') }}
            </div>
          </div>
          <el-button
            type="danger"
            plain
            :loading="deleting"
            :disabled="!configured"
            @click="handleDelete"
          >
            {{ $t('ldapDirectory.deleteSettings') }}
          </el-button>
        </div>
      </SourceSection>
    </el-form>

    <!-- 連線測試結果：階梯是本端點存在的理由，故以分階段清單呈現而非單一成敗 -->
    <el-card
      v-if="testError || testResult"
      class="result-card"
      aria-live="polite"
    >
      <template #header>
        <span class="result-card__title">{{ $t('ldapDirectory.testResultTitle') }}</span>
      </template>
      <el-alert
        v-if="testError"
        type="error"
        :title="testError"
        :closable="false"
        show-icon
      />
      <template v-else>
        <el-alert
          :type="testResult.success ? 'success' : 'error'"
          :title="testResult.success
            ? $t('ldapDirectory.testSuccess')
            : $t('ldapDirectory.testFailed', { stage: stageLabel(testResult.failed_stage) })"
          :closable="false"
          show-icon
        />
        <ul class="stage-list">
          <li
            v-for="stage in stageRows"
            :key="stage.stage"
            class="stage-item"
            :class="`stage-item--${stage.state}`"
          >
            <span>{{ stageLabel(stage.stage) }}</span>
            <span class="stage-item__state">
              {{ $t(`ldapDirectory.${STAGE_STATE_KEYS[stage.state]}`) }}
            </span>
          </li>
        </ul>
        <div
          v-if="testResult.diagnostic_id"
          class="result-meta"
        >
          {{ $t('ldapDirectory.diagnosticId') }}: <code>{{ testResult.diagnostic_id }}</code>
        </div>
      </template>
    </el-card>

    <template #panel>
      <PreflightPanel
        ref="panelRef"
        type="ldap"
        :source-id="directoryId"
        :testing="testing"
        @test="handleTest"
        @status="applyStatus"
      />
    </template>
  </SourceDetailLayout>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import SourceDetailLayout from './components/SourceDetailLayout.vue'
import SourceSection from './components/SourceSection.vue'
import GroupMappingSection from './components/GroupMappingSection.vue'
import PreflightPanel from './components/PreflightPanel.vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { confirmDestructive } from '@/utils/confirm'
import { apiErrorSummary } from '@/api/redact'
import { resolveApiError } from '@/api/error'
import { riskLabel } from '@/utils/transportDisplay'
import { sameLdapEndpoint } from '@/utils/ldapUrl'
import {
  getLDAPDirectory,
  updateLDAPDirectory,
  deleteLDAPDirectory,
  testLDAPDirectory,
} from '@/api/ldapDirectory'

const TEST_STAGES = ['dial', 'bind', 'search']
const STAGE_STATE_KEYS = { ok: 'stagePassed', fail: 'stageFailed', skipped: 'stageNotRun' }
// 傳輸閘的兩個既有機器碼（沿三通道共用契約，非本頁新造）
const GATE_ACK_REQUIRED = 'VALIDATION_TRANSMISSION_ACK_REQUIRED'
const GATE_STRICT_REJECT = 'VALIDATION_TRANSMISSION_STRICT_REJECT'

const router = useRouter()

// 元件層日誌只留白名單欄位：本頁請求本文帶 bind 密碼
const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const loading = ref(false)
const loadFailed = ref(false)
const saving = ref(false)
const testing = ref(false)
const deleting = ref(false)
const formError = ref('')
const formRef = ref(null)
const panelRef = ref(null)

const configured = ref(false)
const directoryId = ref(null)
const savedURL = ref('')
const savedEnabled = ref(false)
const savedHasBindPassword = ref(false)
const savedAt = ref('')
// 最近成功登入取自狀態彙總（詳情端點不帶此欄）。面板讀完即往上送，
// 標頭與燈號因此是同一次讀取的同一個時點
const lastLoginAt = ref('')
const applyStatus = (s) => {
  lastLoginAt.value = s?.last_login_at || ''
}
const resettingPassword = ref(false)

const testResult = ref(null)
const testError = ref('')

const defaultForm = () => ({
  name: '',
  url: '',
  bind_dn: '',
  bind_password: '',
  clear_bind_password: false,
  base_dn: '',
  user_filter: '(uid=%s)',
  attr_email: 'mail',
  attr_fullname: 'cn',
  attr_group: '',
  skip_tls_verify: false,
})

const form = reactive(defaultForm())

// 必填僅於「儲存並啟用」時套用（與伺服端條件式驗證一致）：
// 停用是可暫存的草稿態，對草稿強制必填等於不准存半成品
const enableIntent = ref(false)
const requiredWhenEnabling = () => ({
  required: enableIntent.value,
  message: t('ldapDirectory.requiredWhenEnabled'),
  trigger: 'blur',
})

const formRules = computed(() => ({
  url: [requiredWhenEnabling()],
  bind_dn: [requiredWhenEnabling()],
  base_dn: [requiredWhenEnabling()],
  user_filter: [requiredWhenEnabling()],
  attr_email: [requiredWhenEnabling()],
  attr_fullname: [requiredWhenEnabling()],
}))

const snapshotOf = () => JSON.stringify(form)
const savedSnapshot = ref(snapshotOf())
const isDirty = computed(() => snapshotOf() !== savedSnapshot.value)

const subtitle = computed(() =>
  lastLoginAt.value
    ? t('identitySources.lastLoginAt', { time: formatDateTime(lastLoginAt.value) })
    : t('identitySources.ldap.subtitle')
)

const lastSavedText = computed(() =>
  savedAt.value ? t('identitySources.lastSaved', { time: formatDateTime(savedAt.value) }) : ''
)

// 位址變更且未重供密碼：伺服端會以 400 拒絕，此處只是提前提示
const urlChangedNeedsPassword = computed(
  () =>
    configured.value &&
    savedHasBindPassword.value &&
    !sameLdapEndpoint(savedURL.value, form.url) &&
    !form.bind_password &&
    !form.clear_bind_password
)

const stageRows = computed(() => {
  const reported = new Map((testResult.value?.stages || []).map((s) => [s.stage, s]))
  return TEST_STAGES.map((stage) => {
    const hit = reported.get(stage)
    if (!hit) return { stage, state: 'skipped' }
    return { stage, state: hit.ok ? 'ok' : 'fail' }
  })
})

const stageLabel = (stage) =>
  TEST_STAGES.includes(stage) ? t(`ldapDirectory.stage.${stage}`) : stage || ''

const applyView = (view) => {
  const ok = view?.configured === true
  configured.value = ok
  directoryId.value = ok ? view.id || 1 : null
  savedURL.value = ok ? view.url || '' : ''
  savedEnabled.value = ok && view.enabled === true
  savedHasBindPassword.value = ok && view.has_bind_password === true
  savedAt.value = ok ? view.updated_at || '' : ''
  resettingPassword.value = false

  const next = defaultForm()
  if (ok) {
    next.name = view.name || ''
    next.url = view.url || ''
    next.bind_dn = view.bind_dn || ''
    next.base_dn = view.base_dn || ''
    next.user_filter = view.user_filter || next.user_filter
    next.attr_email = view.attr_email || next.attr_email
    next.attr_fullname = view.attr_fullname || next.attr_fullname
    next.attr_group = view.attr_group || ''
    next.skip_tls_verify = view.skip_tls_verify === true
  }
  Object.assign(form, next)
  savedSnapshot.value = snapshotOf()
}

// 勾選清除密碼時一併清掉輸入框：先打字再勾選會讓送出的本文同時帶兩者，伺服端 400
watch(
  () => form.clear_bind_password,
  (on) => {
    if (on) form.bind_password = ''
  }
)

const fetchDirectory = async () => {
  loading.value = true
  try {
    applyView(await getLDAPDirectory())
    loadFailed.value = false
  } catch (error) {
    loadFailed.value = true
    logFailure('ldap_directory_load_failed', error)
  } finally {
    loading.value = false
  }
}

const cancelPasswordReset = () => {
  resettingPassword.value = false
  form.bind_password = ''
  form.clear_bind_password = false
}

const basePayload = () => ({
  url: form.url.trim(),
  bind_dn: form.bind_dn.trim(),
  bind_password: form.bind_password,
  clear_bind_password: form.clear_bind_password,
  base_dn: form.base_dn.trim(),
  user_filter: form.user_filter.trim(),
  attr_email: form.attr_email.trim(),
  attr_fullname: form.attr_fullname.trim(),
  attr_group: form.attr_group.trim(),
  skip_tls_verify: form.skip_tls_verify,
})

/**
 * 傳輸閘 warn 檔的確認迴圈（沿三通道共用契約）。
 * strict 檔位不進本迴圈——重送無用，由呼叫端就地呈現。
 * @param {(acknowledged: boolean) => Promise} send
 * @param {string} confirmKey 風險確認文案的 i18n 鍵
 * @returns {Promise}
 */
const withTransportGate = async (send, confirmKey) => {
  let acknowledged = false
  for (;;) {
    try {
      return await send(acknowledged)
    } catch (error) {
      const resp = error?.response
      if (resp?.status === 400 && resp.data?.code === GATE_ACK_REQUIRED && !acknowledged) {
        const risks = Array.isArray(resp.data.risks) ? resp.data.risks : []
        await ElMessageBox.confirm(
          t(confirmKey, {
            risks: risks.map((r) => riskLabel(r)).join(t('common.listSeparator')),
          }),
          t('connect.risksTitle'),
          {
            confirmButtonText: t('connect.risksConfirm'),
            cancelButtonText: t('common.cancel'),
            type: 'warning',
          }
        )
        acknowledged = true
        continue
      }
      throw error
    }
  }
}

/**
 * 儲存。停用會讓目錄使用者全數登不進來，故先確認。
 * @param {boolean} nextEnabled 動作列的目標狀態
 */
const handleSave = async (nextEnabled) => {
  formError.value = ''
  enableIntent.value = nextEnabled === true
  if (formRef.value) {
    const valid = await formRef.value.validate().catch(() => false)
    if (!valid) return
  }
  if (savedEnabled.value && !nextEnabled) {
    try {
      await confirmDestructive(
        t('identitySources.ldap.disableConfirm'),
        t('oidcProviders.disableConfirmTitle'),
        {
          confirmButtonText: t('common.confirm'),
          cancelButtonText: t('common.cancel'),
        }
      )
    } catch {
      return
    }
  }

  saving.value = true
  try {
    const view = await withTransportGate(
      (acknowledged) =>
        updateLDAPDirectory(
          {
            ...basePayload(),
            name: form.name.trim(),
            enabled: nextEnabled === true,
            risk_acknowledged: acknowledged,
          },
          { skipErrorToast: true }
        ),
      'ldapDirectory.saveRiskConfirm'
    )
    applyView(view)
    loadFailed.value = false
    testResult.value = null
    testError.value = ''
    ElMessage.success(t('ldapDirectory.saved'))
    panelRef.value?.refresh?.()
  } catch (error) {
    // 非 axios 錯誤＝使用者於風險確認框按取消，不是失敗
    if (error?.response) {
      formError.value =
        error.response.data?.code === GATE_STRICT_REJECT
          ? t('ldapDirectory.saveStrictRejected')
          : resolveApiError(
            error.response.data,
            error.response.status,
            t('ldapDirectory.saveFailed')
          )
      logFailure('ldap_directory_save_failed', error)
    }
  } finally {
    saving.value = false
  }
}

const handleTest = async () => {
  formError.value = ''
  testError.value = ''
  testResult.value = null
  testing.value = true
  try {
    testResult.value = await withTransportGate(
      (acknowledged) =>
        testLDAPDirectory({ ...basePayload(), risk_acknowledged: acknowledged }, {
          skipErrorToast: true,
        }),
      'ldapDirectory.testRiskConfirm'
    )
  } catch (error) {
    const resp = error?.response
    if (!resp) return
    testError.value =
      resp.data?.code === GATE_STRICT_REJECT
        ? t('ldapDirectory.testStrictRejected')
        : resolveApiError(resp.data, resp.status, t('ldapDirectory.testFailedGeneric'))
    logFailure('ldap_directory_test_failed', error)
  } finally {
    testing.value = false
  }
}

const handleDelete = async () => {
  try {
    await confirmDestructive(t('ldapDirectory.deleteConfirm'), t('common.deleteConfirmTitle'), {
      confirmButtonText: t('common.deleteConfirmButton'),
      cancelButtonText: t('common.cancel'),
    })
  } catch {
    return
  }
  deleting.value = true
  try {
    await deleteLDAPDirectory()
    ElMessage.success(t('ldapDirectory.deleted'))
    router.push('/identity-sources')
  } catch (error) {
    // 仍有映射規則時後端回 409，由全域攔截器以譯文提示
    logFailure('ldap_directory_delete_failed', error)
  } finally {
    deleting.value = false
  }
}

onMounted(fetchDirectory)
</script>

<style scoped>
.detail-alert {
  margin-bottom: var(--ot-space-md);
}

.field-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-md);
}

.field-row__item {
  flex: 1 1 240px;
}

.field-narrow {
  max-width: 420px;
}

.field-hint {
  width: 100%;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: 4px;
}

.field-warning {
  width: 100%;
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: 4px;
}

.secret-state {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.clear-secret {
  width: 100%;
  margin-top: 4px;
}

.danger-zone {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
}

.danger-zone__text {
  flex: 1;
  min-width: 240px;
}

.danger-zone__title {
  font-weight: 600;
}

.result-card {
  margin-bottom: var(--ot-space-md);
}

.result-card__title {
  font-weight: 600;
}

.stage-list {
  list-style: none;
  margin: var(--ot-space-sm) 0 0;
  padding: 0;
}

.stage-item {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  padding: 4px 0;
}

.stage-item--ok {
  color: var(--el-color-success);
}

.stage-item--fail {
  color: var(--el-color-danger);
}

/* 未執行：次要色。不可與失敗同色——「沒跑到」不是「失敗」 */
.stage-item--skipped {
  color: var(--ot-text-secondary);
}

.stage-item__state {
  font-size: var(--ot-font-size-xs);
}

.result-meta {
  margin-top: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}
</style>
