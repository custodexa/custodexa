<template>
  <SourceDetailLayout
    :title="form.name"
    :type-label="$t('identitySources.typeLabel.oidc')"
    :subtitle="subtitle"
    :enabled="savedEnabled"
    :saving="saving"
    :testing="discovering"
    :dirty="isDirty"
    :can-save="!loading && !loadFailed"
    :last-saved="lastSavedText"
    @save="handleSave"
    @test="runDiscovery"
  >
    <el-alert
      v-if="loadFailed"
      class="detail-alert"
      type="error"
      :title="$t('identitySources.loadFailedTitle')"
      :description="$t('identitySources.loadFailedDesc')"
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
        :hint="$t('identitySources.oidc.connectionHint')"
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
              :placeholder="$t('oidcProviders.namePlaceholder')"
            />
            <div class="field-hint">
              {{ $t('identitySources.oidc.nameHint') }}
            </div>
          </el-form-item>
          <el-form-item
            class="field-row__item"
            :label="$t('oidcProviders.issuer')"
            prop="issuer"
          >
            <el-input
              v-model="form.issuer"
              :disabled="isEdit"
              :placeholder="$t('oidcProviders.issuerPlaceholder')"
              @blur="autoDiscover"
            />
            <div
              v-if="isEdit"
              class="field-hint"
            >
              {{ $t('oidcProviders.immutableTooltip') }}
            </div>
            <div
              v-if="azureMultiTenantWarning"
              class="field-warning"
            >
              {{ azureMultiTenantWarning }}
            </div>
          </el-form-item>
        </div>

        <div class="field-row">
          <el-form-item
            class="field-row__item"
            :label="$t('oidcProviders.clientId')"
            prop="client_id"
          >
            <el-input
              v-model="form.client_id"
              :disabled="isEdit"
              :placeholder="$t('oidcProviders.clientIdPlaceholder')"
            />
          </el-form-item>
          <!-- 密鑰兩態：已設定時不再以空輸入框暗示未設定 -->
          <el-form-item
            class="field-row__item"
            :label="$t('oidcProviders.clientSecret')"
          >
            <div
              v-if="hasSecret && !resettingSecret"
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
                @click="resettingSecret = true"
              >
                {{ $t('identitySources.secretReset') }}
              </el-button>
            </div>
            <template v-else>
              <el-input
                v-model="form.client_secret"
                type="password"
                show-password
                autocomplete="new-password"
                :placeholder="$t('oidcProviders.secretPlaceholder')"
              />
              <el-button
                v-if="hasSecret"
                size="small"
                link
                @click="cancelSecretReset"
              >
                {{ $t('common.cancel') }}
              </el-button>
            </template>
            <div class="field-hint">
              {{ $t('identitySources.oidc.secretHint') }}
            </div>
          </el-form-item>
        </div>

        <!-- 探索摘要：唯讀，說明本系統實際會打哪些端點 -->
        <div
          v-if="discovery"
          class="discovery"
        >
          <div
            v-for="row in discoveryRows"
            :key="row.label"
            class="discovery__row"
          >
            <span class="discovery__label">{{ row.label }}</span>
            <span class="discovery__value">{{ row.value }}</span>
          </div>
          <div
            v-if="discoveryClaims.length"
            class="discovery__row"
          >
            <span class="discovery__label">{{ $t('identitySources.oidc.claimsSupported') }}</span>
            <span class="discovery__value">
              <el-tag
                v-for="c in discoveryClaims"
                :key="c"
                class="discovery__tag"
                size="small"
                effect="plain"
                :type="c === form.groups_claim ? 'success' : 'info'"
              >
                {{ c }}
              </el-tag>
            </span>
          </div>
        </div>
        <div
          v-else-if="discoveryError"
          class="field-warning"
        >
          {{ discoveryError }}
        </div>
      </SourceSection>

      <SourceSection
        :index="2"
        :title="$t('identitySources.section.userMapping')"
        :hint="$t('identitySources.oidc.userMappingHint')"
      >
        <div class="field-row">
          <el-form-item
            class="field-row__item"
            :label="$t('identitySources.oidc.usernameClaim')"
          >
            <el-input
              v-model="form.username_claim"
              placeholder="preferred_username"
            />
            <div class="field-hint">
              {{ $t('identitySources.oidc.usernameClaimHint') }}
            </div>
          </el-form-item>
          <el-form-item
            class="field-row__item"
            :label="$t('identitySources.oidc.emailClaim')"
          >
            <el-input
              v-model="form.email_claim"
              placeholder="email"
            />
          </el-form-item>
          <el-form-item
            class="field-row__item"
            :label="$t('identitySources.oidc.displayNameClaim')"
          >
            <el-input
              v-model="form.display_name_claim"
              placeholder="name"
            />
          </el-form-item>
        </div>
        <div class="field-hint">
          {{ $t('identitySources.oidc.claimDefaultHint') }}
        </div>
      </SourceSection>

      <SourceSection
        :index="3"
        :title="$t('identitySources.section.groupMapping')"
        :hint="$t('identitySources.mapping.sectionHint')"
      >
        <GroupMappingSection
          type="oidc"
          :source-id="providerId"
          :attr-set="Boolean(form.groups_claim)"
        >
          <template #attr>
            <el-form-item
              class="field-narrow"
              :label="$t('identitySources.oidc.groupsClaim')"
            >
              <el-input
                v-model="form.groups_claim"
                placeholder="groups"
              />
              <div class="field-hint">
                {{ $t('identitySources.oidc.groupsClaimHint') }}
              </div>
              <!-- 多數提供者只在請求該授權範圍時才發出群組宣告：設了宣告名就把
                   範圍一併勾上，並說出剛才替使用者做了什麼（沉默地改設定不算提示） -->
              <div
                v-if="groupsScopeAutoAdded"
                class="field-notice"
              >
                {{ $t('identitySources.oidc.groupsScopeAutoAdded') }}
              </div>
              <div
                v-else-if="form.groups_claim && !form.scopeExtras.includes('groups')"
                class="field-warning"
              >
                {{ $t('identitySources.oidc.groupsScopeMissingHint') }}
              </div>
            </el-form-item>
          </template>
        </GroupMappingSection>
      </SourceSection>

      <SourceSection
        :index="4"
        :title="$t('identitySources.section.admission')"
        :hint="$t('identitySources.oidc.admissionHint')"
      >
        <el-form-item :label="$t('oidcProviders.admissionMode')">
          <el-radio-group v-model="form.admission_mode">
            <el-radio value="prebound_only">
              {{ $t('oidcProviders.admission.prebound_only') }}
            </el-radio>
            <el-radio value="jit_with_rules">
              {{ $t('oidcProviders.admission.jit_with_rules') }}
            </el-radio>
          </el-radio-group>
          <div class="field-hint">
            {{ $t(`oidcProviders.admissionHint.${form.admission_mode}`) }}
          </div>
          <!-- 效力限制改為折疊式：它是必須讀過一次的條款，但不該永久佔住主視線 -->
          <div
            v-if="form.admission_mode === 'prebound_only'"
            class="limitation"
          >
            <button
              type="button"
              class="limitation__toggle"
              @click="limitationOpen = !limitationOpen"
            >
              {{ $t('oidcProviders.preboundLimitationTitle') }}
              <span>{{ limitationOpen ? $t('identitySources.collapse') : $t('identitySources.expand') }}</span>
            </button>
            <div
              v-if="limitationOpen"
              class="limitation__body"
            >
              {{ $t('oidcProviders.preboundLimitationDesc') }}
            </div>
          </div>
        </el-form-item>

        <template v-if="form.admission_mode === 'jit_with_rules'">
          <div class="field-row">
            <el-form-item
              class="field-row__item"
              :label="$t('oidcProviders.ruleTid')"
            >
              <el-select
                v-model="form.rules.tid"
                class="rule-select"
                multiple
                filterable
                allow-create
                default-first-option
                :reserve-keyword="false"
                :placeholder="$t('oidcProviders.ruleListPlaceholder')"
              />
            </el-form-item>
            <el-form-item
              class="field-row__item"
              :label="$t('oidcProviders.ruleEmailDomain')"
            >
              <el-select
                v-model="form.rules.email_domain"
                class="rule-select"
                multiple
                filterable
                allow-create
                default-first-option
                :reserve-keyword="false"
                :placeholder="$t('oidcProviders.ruleListPlaceholder')"
              />
            </el-form-item>
          </div>
          <div class="field-row">
            <el-form-item
              class="field-row__item"
              :label="$t('oidcProviders.ruleHd')"
            >
              <el-select
                v-model="form.rules.hd"
                class="rule-select"
                multiple
                filterable
                allow-create
                default-first-option
                :reserve-keyword="false"
                :placeholder="$t('oidcProviders.ruleListPlaceholder')"
              />
            </el-form-item>
            <el-form-item
              class="field-row__item"
              :label="$t('oidcProviders.ruleEmailVerified')"
            >
              <el-switch v-model="form.rules.email_verified" />
              <div class="field-hint">
                {{ $t('oidcProviders.ruleEmailVerifiedHint') }}
              </div>
            </el-form-item>
          </div>
        </template>

        <el-form-item :label="$t('oidcProviders.forceShared')">
          <el-switch v-model="form.force_shared" />
          <div class="field-hint">
            {{ $t('oidcProviders.forceSharedHint') }}
          </div>
        </el-form-item>
      </SourceSection>

      <SourceSection
        :index="5"
        :title="$t('identitySources.section.advanced')"
        :hint="$t('identitySources.advancedHint')"
      >
        <el-form-item :label="$t('oidcProviders.scopes')">
          <el-checkbox-group v-model="form.scopeExtras">
            <el-checkbox value="profile">
              profile
            </el-checkbox>
            <el-checkbox value="email">
              email
            </el-checkbox>
            <el-checkbox value="groups">
              groups
            </el-checkbox>
          </el-checkbox-group>
          <div class="field-hint">
            {{ $t('oidcProviders.scopesHint') }}
          </div>
          <div class="field-hint">
            {{ $t('identitySources.oidc.groupsScopeHint') }}
          </div>
        </el-form-item>
      </SourceSection>
    </el-form>

    <template #panel>
      <PreflightPanel
        ref="panelRef"
        type="oidc"
        :source-id="providerId"
        :redirect-uri="redirectUri"
        :redirect-uri-state="redirectUriState"
        :logout-redirect-uri="logoutRedirectUri"
        :discovering="discovering"
        @rediscover="runDiscovery"
        @status="applyStatus"
      />
    </template>
  </SourceDetailLayout>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import SourceDetailLayout from './components/SourceDetailLayout.vue'
import SourceSection from './components/SourceSection.vue'
import GroupMappingSection from './components/GroupMappingSection.vue'
import PreflightPanel from './components/PreflightPanel.vue'
import { t } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { confirmDestructive } from '@/utils/confirm'
import { withRiskGate } from '@/utils/mappingRiskGate'
import { apiErrorSummary } from '@/api/redact'
import { resolveApiError } from '@/api/error'
import { createOIDCProvider, updateOIDCProvider } from '@/api/oidc'
import {
  getOIDCProviderDetail,
  previewOIDCDiscovery,
  isNotImplemented,
} from '@/api/identitySources'

// 多租戶端點：探索文件的 issuer 字面帶佔位符，嚴格比對必失敗。輸入當下就診斷
const AZURE_MULTI_TENANT = /login\.microsoftonline\.com\/(common|organizations|consumers)(\/|$)/i
const ADMISSION_MODES = ['prebound_only', 'jit_with_rules']

const route = useRoute()
const router = useRouter()

// 元件層日誌只留白名單欄位：本頁請求本文帶密鑰
const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const providerId = computed(() => {
  const id = route.params.id
  return id === undefined || id === null || id === '' ? null : id
})
const isEdit = computed(() => providerId.value !== null)

const loading = ref(false)
const loadFailed = ref(false)
const saving = ref(false)
const discovering = ref(false)
const formError = ref('')
const formRef = ref(null)
const panelRef = ref(null)

const hasSecret = ref(false)
const resettingSecret = ref(false)
const savedEnabled = ref(false)
const savedAt = ref('')
// 最近成功登入取自狀態彙總（詳情端點不帶此欄）。面板讀完即往上送，
// 標頭與燈號因此是同一次讀取的同一個時點
const lastLoginAt = ref('')
const applyStatus = (s) => {
  lastLoginAt.value = s?.last_login_at || ''
}
const redirectUri = ref('')
const redirectUriState = ref('')
const discovery = ref(null)
const discoveryError = ref('')
const limitationOpen = ref(false)

const emptyRules = () => ({ tid: [], hd: [], email_domain: [], email_verified: false })

const form = reactive({
  name: '',
  issuer: '',
  client_id: '',
  client_secret: '',
  username_claim: '',
  email_claim: '',
  display_name_claim: '',
  groups_claim: '',
  scopeExtras: ['profile', 'email'],
  admission_mode: 'prebound_only',
  force_shared: false,
  rules: emptyRules(),
})

const formRules = computed(() => ({
  name: [{ required: true, message: t('oidcProviders.nameRequired'), trigger: 'blur' }],
  issuer: [
    { required: true, message: t('oidcProviders.issuerRequired'), trigger: 'blur' },
    {
      validator: (_rule, value, callback) => {
        if (!isEdit.value && value && !/^https:\/\//i.test(value.trim())) {
          callback(new Error(t('oidcProviders.issuerMustBeHttps')))
          return
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
  client_id: [{ required: true, message: t('oidcProviders.clientIdRequired'), trigger: 'blur' }],
}))

const snapshotOf = () => JSON.stringify(form)
const savedSnapshot = ref(snapshotOf())
const isDirty = computed(() => snapshotOf() !== savedSnapshot.value)

const subtitle = computed(() =>
  lastLoginAt.value
    ? t('identitySources.lastLoginAt', { time: formatDateTime(lastLoginAt.value) })
    : t('identitySources.neverLoggedIn')
)

const lastSavedText = computed(() =>
  savedAt.value ? t('identitySources.lastSaved', { time: formatDateTime(savedAt.value) }) : ''
)

// 登出後的回呼位址即登入頁本身；由回呼網址的來源推得，不另行宣稱後端有此設定
const logoutRedirectUri = computed(() => {
  if (!redirectUri.value) return ''
  try {
    return `${new URL(redirectUri.value).origin}/login`
  } catch {
    return ''
  }
})

const azureMultiTenantWarning = computed(() =>
  AZURE_MULTI_TENANT.test(form.issuer || '') ? t('oidcProviders.azureMultiTenantWarning') : ''
)

const discoveryRows = computed(() => {
  const d = discovery.value || {}
  return [
    { label: 'authorization', value: d.authorization_endpoint },
    { label: 'token', value: d.token_endpoint },
    { label: 'jwks', value: d.jwks_uri },
    { label: 'userinfo', value: d.userinfo_endpoint },
  ].filter((row) => Boolean(row.value))
})

const discoveryClaims = computed(() => discovery.value?.claims_supported || [])

const parseRules = (raw) => {
  const rules = emptyRules()
  if (!raw) return rules
  try {
    const parsed = JSON.parse(raw)
    rules.tid = Array.isArray(parsed.tid) ? parsed.tid : []
    rules.hd = Array.isArray(parsed.hd) ? parsed.hd : []
    rules.email_domain = Array.isArray(parsed.email_domain) ? parsed.email_domain : []
    rules.email_verified = parsed.email_verified === true
  } catch {
    console.warn('oidc_admission_rules_parse_failed')
  }
  return rules
}

// 由伺服端載入的值不算「使用者剛設定了宣告名」：載入期關掉自動勾選，
// 否則一開頁就把表單弄髒，並且會替既有設定悄悄改變授權範圍
const applyingView = ref(false)
const groupsScopeAutoAdded = ref(false)

watch(
  () => form.groups_claim,
  (next, prev) => {
    if (applyingView.value) return
    if (!next || prev) return
    if (form.scopeExtras.includes('groups')) return
    form.scopeExtras = [...form.scopeExtras, 'groups']
    groupsScopeAutoAdded.value = true
  },
  { flush: 'sync' }
)

const applyView = (view) => {
  applyingView.value = true
  groupsScopeAutoAdded.value = false
  form.name = view.name || ''
  form.issuer = view.issuer || ''
  form.client_id = view.client_id || ''
  form.client_secret = ''
  form.username_claim = view.username_claim || ''
  form.email_claim = view.email_claim || ''
  form.display_name_claim = view.display_name_claim || ''
  form.groups_claim = view.groups_claim || ''
  form.scopeExtras = String(view.scopes || '')
    .split(/\s+/)
    .filter((s) => s && s !== 'openid')
  form.admission_mode = ADMISSION_MODES.includes(view.admission_mode)
    ? view.admission_mode
    : 'prebound_only'
  form.force_shared = view.issuer_kind_source === 'admin_forced'
  form.rules = parseRules(view.admission_rules)

  hasSecret.value = view.has_secret === true
  resettingSecret.value = false
  savedEnabled.value = view.enabled === true
  savedAt.value = view.updated_at || ''
  redirectUri.value = view.redirect_uri || ''
  redirectUriState.value = view.redirect_uri_state || ''
  savedSnapshot.value = snapshotOf()
  applyingView.value = false
}

const fetchProvider = async () => {
  if (!isEdit.value) {
    savedSnapshot.value = snapshotOf()
    return
  }
  loading.value = true
  try {
    applyView(await getOIDCProviderDetail(providerId.value))
    loadFailed.value = false
  } catch (error) {
    loadFailed.value = true
    logFailure('oidc_provider_detail_failed', error)
  } finally {
    loading.value = false
  }
}

const runDiscovery = async () => {
  const issuer = form.issuer.trim()
  if (!issuer) return
  discovering.value = true
  discoveryError.value = ''
  try {
    discovery.value = await previewOIDCDiscovery(issuer)
  } catch (error) {
    discovery.value = null
    discoveryError.value = isNotImplemented(error)
      ? t('identitySources.oidc.discoveryPending')
      : resolveApiError(
        error?.response?.data,
        error?.response?.status,
        t('identitySources.oidc.discoveryFailed')
      )
    logFailure('oidc_discovery_preview_failed', error)
  } finally {
    discovering.value = false
  }
}

// issuer 失焦即自動探索：管理者不必先猜端點長什麼樣再回頭核對
const autoDiscover = () => {
  if (!discovery.value && /^https:\/\//i.test(form.issuer.trim())) runDiscovery()
}

const cancelSecretReset = () => {
  resettingSecret.value = false
  form.client_secret = ''
}

const buildRulesJSON = () => {
  const payload = {}
  const trim = (list) => list.map((v) => String(v).trim()).filter(Boolean)
  if (form.rules.tid.length) payload.tid = trim(form.rules.tid)
  if (form.rules.hd.length) payload.hd = trim(form.rules.hd)
  if (form.rules.email_domain.length) payload.email_domain = trim(form.rules.email_domain)
  if (form.rules.email_verified) payload.email_verified = true
  return JSON.stringify(payload)
}

const hasAnyRule = () =>
  form.rules.tid.length > 0 ||
  form.rules.hd.length > 0 ||
  form.rules.email_domain.length > 0 ||
  form.rules.email_verified

/**
 * 儲存。停用是破壞性動作（經此來源登入的人全數進不來），故先確認。
 * @param {boolean} nextEnabled 動作列的目標狀態
 */
const handleSave = async (nextEnabled) => {
  formError.value = ''
  if (formRef.value) {
    const valid = await formRef.value.validate().catch(() => false)
    if (!valid) return
  }
  if (form.admission_mode === 'jit_with_rules' && !hasAnyRule()) {
    formError.value = t('oidcProviders.rulesRequired')
    return
  }
  if (savedEnabled.value && !nextEnabled) {
    try {
      await confirmDestructive(
        t('oidcProviders.disableConfirm', { name: form.name }),
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

  const payload = {
    name: form.name.trim(),
    scopes: ['openid', ...form.scopeExtras].join(' '),
    username_claim: form.username_claim.trim(),
    email_claim: form.email_claim.trim(),
    display_name_claim: form.display_name_claim.trim(),
    groups_claim: form.groups_claim.trim(),
    admission_mode: form.admission_mode,
    admission_rules: buildRulesJSON(),
    force_shared: form.force_shared,
    enabled: nextEnabled === true,
  }
  if (!isEdit.value) {
    payload.issuer = form.issuer.trim()
    payload.client_id = form.client_id.trim()
  }
  // 留空即沿用既有密鑰（write-only 欄位的唯一可用語義）
  if (form.client_secret.trim()) payload.client_secret = form.client_secret

  saving.value = true
  try {
    if (isEdit.value) {
      // 設了群組宣告名卻沒請求對應授權範圍時伺服端回 422 並附警告：
      // 顯示後果、確認後帶旗標重送。閘門與規則儲存共用同一套
      const done = await withRiskGate((acknowledged) =>
        updateOIDCProvider(providerId.value, { ...payload, risk_acknowledged: acknowledged })
      )
      if (!done) return
      ElMessage.success(t('oidcProviders.updated'))
      await fetchProvider()
      panelRef.value?.refresh?.()
    } else {
      const created = await withRiskGate((acknowledged) =>
        createOIDCProvider({ ...payload, risk_acknowledged: acknowledged })
      )
      if (!created) return
      ElMessage.success(t('oidcProviders.created'))
      const newId = created?.data?.id || created?.id
      if (newId) router.replace(`/identity-sources/oidc/${newId}`)
    }
  } catch (error) {
    formError.value = resolveApiError(
      error?.response?.data,
      error?.response?.status,
      t('identitySources.saveFailed')
    )
    logFailure('oidc_provider_save_failed', error)
  } finally {
    saving.value = false
  }
}

onMounted(fetchProvider)
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

.field-notice {
  width: 100%;
  color: var(--ot-success, #67c23a);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: 4px;
}

.secret-state {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.rule-select {
  width: 100%;
}

/* 探索摘要：唯讀的事實列，說明本系統實際會打哪些端點 */
.discovery {
  margin-top: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md, 6px);
}

.discovery__row {
  display: flex;
  gap: var(--ot-space-md);
  padding: 2px 0;
  font-size: var(--ot-font-size-xs);
}

.discovery__label {
  width: 130px;
  flex-shrink: 0;
  color: var(--ot-text-secondary);
}

.discovery__value {
  flex: 1;
  min-width: 0;
  color: var(--ot-text-secondary);
  font-family: var(--ot-font-mono, monospace);
  word-break: break-all;
}

.discovery__tag {
  margin: 0 4px 4px 0;
}

/* 准入效力限制：折疊式，讀過一次即可收起，不永久佔住主視線 */
.limitation {
  width: 100%;
  margin-top: var(--ot-space-xs);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md, 6px);
}

.limitation__toggle {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  width: 100%;
  padding: 6px 10px;
  border: 0;
  background: transparent;
  color: var(--ot-text-secondary);
  font: inherit;
  font-size: var(--ot-font-size-xs);
  text-align: left;
  cursor: pointer;
}

.limitation__body {
  padding: 0 10px 8px;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.7;
}
</style>
