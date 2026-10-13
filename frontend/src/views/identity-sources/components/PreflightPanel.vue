<template>
  <div class="panel">
    <div class="panel__header">
      <span class="panel__title">{{ $t('identitySources.preflight.title') }}</span>
      <span
        v-if="updatedAt"
        class="panel__updated"
        data-test="preflight-updated-at"
      >{{ $t('identitySources.preflight.updatedAt', { time: formatShortDateTime(updatedAt) }) }}</span>
      <span class="panel__spacer" />
      <el-button
        v-if="sourceId"
        size="small"
        data-test="preflight-refresh"
        @click="fetchStatus"
      >
        <RefreshCw class="panel__btn-icon" />
        {{ $t('identitySources.preflight.refresh') }}
      </el-button>
      <button
        type="button"
        class="panel__collapse"
        data-test="preflight-collapse"
        @click="collapsed = !collapsed"
      >
        <component
          :is="collapsed ? ChevronRight : ChevronDown"
          class="panel__btn-icon"
        />
        {{ $t(collapsed ? 'common.expand' : 'common.collapse') }}
      </button>
    </div>

    <template v-if="!collapsed">
      <!-- 總結句：由燈號在前端合成，回答「設定對了沒」 -->
      <div
        v-if="summary"
        class="panel__summary"
        :class="`panel__summary--${summary.state}`"
        data-test="preflight-summary"
      >
        <component
          :is="ICONS[summary.state]"
          class="panel__icon"
        />
        <div>
          <div class="panel__summary-text">
            {{ summaryText }}
          </div>
          <div
            v-if="summary.detail"
            class="panel__hint"
          >
            {{ $t(summary.detail.key) }}
          </div>
        </div>
      </div>

      <!-- 第一塊：提供者／目錄端要配合的事。OIDC 只留回呼網址，各欄取值見左側說明 -->
      <template v-if="!isDirectory">
        <div class="panel__section-head">
          {{ $t('identitySources.preflight.oidc.redirect') }}
        </div>
        <div class="panel__box">
          <code
            class="panel__mono"
            data-test="preflight-redirect"
          >{{ redirectText }}</code>
          <el-button
            v-if="redirect.uri"
            size="small"
            data-test="preflight-redirect-copy"
            @click="copy(redirect.uri)"
          >
            <Copy class="panel__btn-icon" />
            {{ $t('common.copy') }}
          </el-button>
        </div>
        <div
          class="panel__hint"
          data-test="preflight-guide-hint"
        >
          {{ $t('identitySources.preflight.oidc.guideHint') }}
        </div>
      </template>
      <template v-else>
        <div class="panel__section-head">
          {{ $t('identitySources.preflight.checklistLdap') }}
        </div>
        <div
          v-for="k in LDAP_CHECKLIST"
          :key="k"
          class="panel__item"
        >
          <div>{{ $t(`identitySources.preflight.ldap.${k}`) }}</div>
          <div class="panel__hint">
            {{ $t(`identitySources.preflight.ldap.${k}Hint`) }}
          </div>
        </div>
      </template>

      <el-divider />

      <div class="panel__section-head">
        {{ $t('identitySources.preflight.statusHead') }}
      </div>
      <div
        v-if="statusUnavailable || statusNotConfigured"
        class="panel__hint"
      >
        {{ $t(statusUnavailable ? 'identitySources.backendPending' : 'identitySources.preflight.sourceNotConfigured') }}
      </div>
      <PreflightLightRow
        v-for="l in lights"
        :key="l.key"
        :light="l"
        :discovering="discovering"
        @rediscover="$emit('rediscover')"
      />

      <template v-if="sourceId">
        <template v-if="!isDirectory">
          <el-divider />
          <PreflightLastAttempt
            :attempt="status?.last_attempt || null"
            :window-days="status?.last_attempt?.window_days || 30"
            :wait-state="waiting.state.value"
          />
        </template>
        <el-divider />
        <PreflightLoginTest
          :type="type"
          :state="status?.login_test_state || ''"
          :url="status?.login_test_url || ''"
          @copied="waiting.arm"
        />
      </template>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onBeforeUnmount } from 'vue'
import { ElMessage } from 'element-plus'
import {
  CircleCheck,
  TriangleAlert,
  CircleDashed,
  CircleMinus,
  RefreshCw,
  Copy,
  ChevronDown,
  ChevronRight,
} from 'lucide-vue-next'
import i18n, { t } from '@/i18n'
import { formatShortDateTime } from '@/utils/format'
import { apiErrorSummary } from '@/api/redact'
import { getOIDCProviders } from '@/api/oidc'
import { useLoginTestWaiting } from '@/composables/useLoginTestWaiting'
import {
  getSourceStatus,
  isNotImplemented,
  errorCode,
  CODE_LDAP_DIRECTORY_NOT_FOUND,
} from '@/api/identitySources'
import PreflightLastAttempt from './PreflightLastAttempt.vue'
import PreflightLoginTest from './PreflightLoginTest.vue'
import PreflightLightRow from './PreflightLightRow.vue'
import { computeLights, computeSummary } from './preflightLights'

const ICONS = { ok: CircleCheck, warn: TriangleAlert, gray: CircleDashed, neutral: CircleMinus }
const LDAP_CHECKLIST = ['readGroupAttr', 'baseDnCovers']
// 自動重抓的節流間隔：切回視窗即更新，但同一面板 10 秒內至多一次
const AUTO_REFRESH_MS = 10000

const props = defineProps({
  type: { type: String, required: true },
  sourceId: { type: [Number, String], default: null },
  // 回呼網址由對外基準網址算出，隨來源詳情回；未設基準網址時是可辨識的狀態而非空字串
  redirectUri: { type: String, default: '' },
  redirectUriState: { type: String, default: '' },
  // 本頁最近一次探索預覽（useDiscoveryPreview 的 panelInput）
  discovery: { type: Object, default: null },
  // 本頁最近一次目錄測試連線（useLdapTestRecord 的 panelInput）
  ldapTest: { type: Object, default: null },
  discovering: { type: Boolean, default: false },
})

// status：把這一支彙總的結果原封往上送。頁面標頭的「最近成功登入」與面板燈號
// 同源同時點，父層不另打一次請求——多打一次就會出現兩個時點混在同一畫面上
const emit = defineEmits(['rediscover', 'status'])

const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const status = ref(null)
const updatedAt = ref('')
const statusUnavailable = ref(false)
// 目錄尚未設定：路由存在且回答了「沒有這個資源」。與端點缺席分開呈現
const statusNotConfigured = ref(false)
const collapsed = ref(false)

const isDirectory = computed(() => props.type === 'ldap')

// 新增頁還沒有單筆詳情可讀：回呼網址改取提供者列表頂層的同一個值（對所有提供者相同）
const listRedirect = ref({ uri: '', state: '' })
const redirect = computed(() =>
  props.redirectUri || props.redirectUriState
    ? { uri: props.redirectUri, state: props.redirectUriState }
    : listRedirect.value
)
const loadListRedirect = async () => {
  if (isDirectory.value || props.sourceId || props.redirectUri || props.redirectUriState) return
  try {
    const res = await getOIDCProviders({ quiet: true })
    listRedirect.value = { uri: res?.redirect_uri || '', state: res?.redirect_uri_state || '' }
  } catch (error) {
    logFailure('oidc_provider_list_failed', error)
  }
}

const redirectText = computed(() => {
  if (redirect.value.uri) return redirect.value.uri
  return redirect.value.state === 'base_url_unset'
    ? t('identitySources.preflight.oidc.redirectUnset')
    : t('identitySources.backendPending')
})

const lights = computed(() =>
  computeLights({
    type: props.type,
    status: status.value,
    discovery: props.discovery,
    ldapTest: props.ldapTest,
    fmt: (v) => (v ? formatShortDateTime(v) : ''),
    hasKey: (k) => i18n.global.te(k),
  })
)

// 等待這次登入的結果時，總結句不沿用上一次嘗試推得的結論
const summary = computed(() => {
  if (!props.sourceId || !status.value) return null
  if (waiting.state.value === 'waiting') {
    return { state: 'gray', text: { key: 'identitySources.preflight.attempt.waiting', params: {} } }
  }
  return computeSummary({ type: props.type, lights: lights.value, status: status.value })
})

const summaryText = computed(() => {
  const s = summary.value?.text
  if (!s) return ''
  const params = { ...s.params }
  if (s.itemKey) params.first = t(s.itemKey)
  if (s.nameKey) params.name = t(s.nameKey)
  return t(s.key, params)
})

// 回覆帶序號：較舊的請求晚到時丟棄，不蓋掉較新的狀態
let seq = 0
const fetchStatus = async () => {
  const mine = ++seq
  if (!props.sourceId) {
    status.value = null
    updatedAt.value = ''
    statusUnavailable.value = false
    statusNotConfigured.value = false
    emit('status', null)
    return
  }
  try {
    const next = await getSourceStatus(props.type, props.sourceId)
    if (mine !== seq) return
    status.value = next
    updatedAt.value = new Date().toISOString()
    statusUnavailable.value = false
    statusNotConfigured.value = false
  } catch (error) {
    if (mine !== seq) return
    status.value = null
    statusUnavailable.value = isNotImplemented(error)
    statusNotConfigured.value = errorCode(error) === CODE_LDAP_DIRECTORY_NOT_FOUND
    if (!statusUnavailable.value && !statusNotConfigured.value) {
      logFailure('identity_source_status_failed', error)
    }
  }
  emit('status', status.value)
}

// 切回視窗自動重抓：兩個視窗並排時頁面始終可見，只有 focus 會觸發，所以兩者都聽。
// 節流期間的觸發不丟掉，期滿補抓一次（多次觸發只補一次）
let lastAuto = -Infinity
let trailing = null
const autoRefresh = () => {
  if (!props.sourceId || trailing) return
  const wait = lastAuto + AUTO_REFRESH_MS - Date.now()
  if (wait <= 0) {
    lastAuto = Date.now()
    fetchStatus()
    return
  }
  trailing = setTimeout(() => {
    trailing = null
    lastAuto = Date.now()
    fetchStatus()
  }, wait)
}
// 複製過測試連結之後切回：由等待流程接手（短暫輪詢直到看到這次登入），否則照一般節流重抓
const waiting = useLoginTestWaiting({ fetch: () => fetchStatus(), current: () => status.value })
watch(status, waiting.observe)
const onReturn = () => {
  if (!waiting.onReturn()) autoRefresh()
}
const onVisibility = () => {
  if (document.visibilityState === 'visible') onReturn()
}

const copy = async (value) => {
  try {
    await navigator.clipboard.writeText(value || '')
    ElMessage.success(t('identitySources.copied'))
  } catch {
    ElMessage.warning(t('common.copyFailed'))
  }
}

watch(() => props.sourceId, () => {
  waiting.reset()
  fetchStatus()
})
onMounted(() => {
  fetchStatus()
  loadListRedirect()
  window.addEventListener('focus', onReturn)
  document.addEventListener('visibilitychange', onVisibility)
})
onBeforeUnmount(() => {
  window.removeEventListener('focus', onReturn)
  document.removeEventListener('visibilitychange', onVisibility)
  clearTimeout(trailing)
  trailing = null
  waiting.reset()
})

defineExpose({ refresh: fetchStatus, lights, summary })
</script>

<style scoped>
/* 黏住與捲動由右欄整欄負責（SourceDetailLayout），面板本身照內容長高 */
.panel {
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
}
.panel__header { display: flex; flex-wrap: wrap; align-items: center; gap: var(--ot-space-sm); }
.panel__title { font-weight: 600; color: var(--ot-text-primary); }
.panel__updated, .panel__hint { color: var(--ot-text-secondary); font-size: var(--ot-font-size-xs); line-height: 1.6; }
.panel__spacer { flex: 1; }
.panel__btn-icon { width: 14px; height: 14px; margin-right: 4px; }
.panel__collapse {
  display: inline-flex;
  align-items: center;
  padding: 0;
  border: 0;
  background: none;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  cursor: pointer;
}
.panel__summary {
  display: flex;
  gap: var(--ot-space-sm);
  margin: var(--ot-space-md) 0;
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.panel__icon { width: 16px; height: 16px; margin-top: 3px; flex-shrink: 0; }
.panel__summary--ok { border-color: var(--ot-success); color: var(--ot-success); }
.panel__summary--warn { border-color: var(--ot-warning); color: var(--ot-warning); }
.panel__summary--gray { color: var(--ot-text-secondary); }
.panel__summary-text { font-weight: 600; color: var(--ot-text-primary); line-height: 1.6; }
.panel__section-head { margin: var(--ot-space-sm) 0 var(--ot-space-xs); font-weight: 600; color: var(--ot-text-primary); }
.panel__box {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-xs) var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.panel__mono { flex: 1; min-width: 0; font-family: var(--ot-font-mono); font-size: var(--ot-font-size-xs); word-break: break-all; }
.panel__item { margin-bottom: var(--ot-space-sm); font-size: var(--ot-font-size-sm); }
</style>
