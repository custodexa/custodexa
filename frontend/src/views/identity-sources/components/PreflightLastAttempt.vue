<template>
  <div class="attempt">
    <div class="attempt__head">
      {{ $t(`${A}title`) }}
    </div>

    <!-- 等待這次登入的結果時不顯示上一次嘗試，免得被當成這次的結果 -->
    <div
      v-if="waitState === 'timeout'"
      class="attempt__reason"
      data-test="attempt-timeout"
    >
      {{ $t(`${A}waitTimeout`) }}
    </div>
    <div
      v-if="waitState === 'waiting'"
      class="attempt__line"
      data-test="attempt-waiting"
    >
      <LoaderCircle class="attempt__icon attempt__icon--gray attempt__spin" />
      <span>{{ $t(`${A}waiting`) }}</span>
    </div>
    <template v-else-if="attempt">
      <div class="attempt__line">
        <component
          :is="icon.comp"
          class="attempt__icon"
          :class="`attempt__icon--${icon.state}`"
        />
        <span
          class="attempt__tag"
          :class="`attempt__tag--${icon.state}`"
          data-test="attempt-label"
        >{{ $t(`${A}label.${labelKey}`) }}</span>
        <span class="attempt__meta">{{ formatShortDateTime(attempt.at) }}</span>
        <span
          v-if="attempt.username"
          class="attempt__meta"
        >{{ $t(`${A}account`) }} <code class="attempt__mono">{{ attempt.username }}</code></span>
      </div>
      <div
        v-if="reasonText"
        class="attempt__reason"
        data-test="attempt-reason"
      >
        {{ reasonText }}
      </div>
      <div
        v-if="adviceText"
        class="attempt__advice"
        data-test="attempt-advice"
      >
        {{ adviceText }}
      </div>
      <template v-if="detailRows.length">
        <button
          type="button"
          class="attempt__toggle"
          data-test="attempt-details-toggle"
          @click="detailsOpen = !detailsOpen"
        >
          <component
            :is="detailsOpen ? ChevronDown : ChevronRight"
            class="attempt__chevron"
          />
          {{ $t(`${A}${detailsOpen ? 'hideDetails' : 'showDetails'}`) }}
        </button>
        <!-- 第二層只放機器碼與提供者自報的原文；一律文字插值，不渲染成標記 -->
        <dl
          v-if="detailsOpen"
          class="attempt__details"
          data-test="attempt-details"
        >
          <template
            v-for="row in detailRows"
            :key="row.key"
          >
            <dt>{{ $t(`${A}field.${row.key}`) }}</dt>
            <dd
              :class="{ 'attempt__mono': row.mono }"
              :data-test="`attempt-detail-${row.key}`"
            >
              {{ row.value }}
            </dd>
          </template>
        </dl>
      </template>
      <button
        type="button"
        class="attempt__toggle"
        data-test="attempt-missing-toggle"
        :aria-expanded="missingOpen"
        @click="missingOpen = !missingOpen"
      >
        <component
          :is="missingOpen ? ChevronDown : ChevronRight"
          class="attempt__chevron"
        />
        {{ $t(`${A}missingToggle`) }}
      </button>
    </template>
    <div
      v-else
      class="attempt__line"
      data-test="attempt-none"
    >
      <CircleDashed class="attempt__icon attempt__icon--gray" />
      <span>{{ $t(`${A}none`, { days: windowDays }) }}</span>
    </div>

    <!-- 沒有新紀錄的可能原因：不寫成單一成因——發起與回程階段取不到探索文件也不留紀錄 -->
    <div
      v-if="waitState !== 'waiting' && (!attempt || missingOpen)"
      class="attempt__missing"
      data-test="attempt-missing"
    >
      <Info class="attempt__missing-icon" />
      <div>
        <div
          v-if="attempt"
          class="attempt__missing-strong"
          data-test="attempt-compare-time"
        >
          {{ $t(`${A}compareTime`) }}
        </div>
        <div>{{ $t(`${A}missingHead`) }}</div>
        <ul class="attempt__list">
          <li
            v-for="k in MISSING"
            :key="k"
          >
            {{ $t(`${A}missing.${k}`) }}
          </li>
        </ul>
        <div>{{ $t(`${A}missingTail`) }}</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { CircleCheck, TriangleAlert, CircleDashed, ChevronDown, ChevronRight, Info, LoaderCircle } from 'lucide-vue-next'
import i18n, { t } from '@/i18n'
import { formatShortDateTime } from '@/utils/format'

const A = 'identitySources.preflight.attempt.'
const MISSING = ['providerBlocked', 'discovery', 'sameBrowser']

// 稽核事件名：後端只對無法歸類的結果回 event；其餘依原因碼即可對回寫入時的事件
const EVENT_OF = {
  success: 'oidc_login',
  pending_mfa: 'oidc_login',
  pending_mfa_enrollment: 'oidc_login',
  pending_password_change: 'oidc_login',
  source_denied: 'oidc_login',
  code_exchange_failed: 'oidc_flow_error',
  id_token_missing: 'oidc_flow_error',
  id_token_invalid: 'oidc_flow_error',
  provider_unavailable: 'oidc_flow_error',
  internal_error: 'oidc_flow_error',
  provider_error: 'oidc_provider_denied',
  username_conflict: 'oidc_username_conflict',
  account_removed: 'oidc_account_removed',
  user_inactive: 'oidc_user_inactive',
}
const ADMISSION_PREFIX = 'admission_'

const props = defineProps({
  attempt: { type: Object, default: null },
  windowDays: { type: Number, default: 30 },
  // ''／waiting（等這次登入的稽核落庫）／timeout（等過了仍沒有新紀錄）
  waitState: { type: String, default: '' },
})

const detailsOpen = ref(false)
const missingOpen = ref(false)
watch(() => props.attempt?.at, () => {
  detailsOpen.value = false
})
watch(() => props.waitState, (s) => { if (s === 'timeout') missingOpen.value = true }, { immediate: true }) // 逾時自動展開，箭頭同步

const code = computed(() => props.attempt?.reason_code || 'unknown')
const detail = computed(() => props.attempt?.reason_detail || '')
const isAdmission = computed(() => code.value.startsWith(ADMISSION_PREFIX))

const labelKey = computed(() => {
  const outcome = props.attempt?.outcome
  if (outcome === 'success') return 'success'
  if (outcome === 'pending') return 'pending'
  if (isAdmission.value) return 'admission'
  if (code.value === 'provider_error') return detail.value && detail.value !== 'other' ? 'providerDenied' : 'providerError'
  if (code.value === 'unknown') return 'unknown'
  return outcome === 'denied' ? 'denied' : 'failed'
})

const icon = computed(() => {
  if (labelKey.value === 'success' || labelKey.value === 'pending') return { comp: CircleCheck, state: 'ok' }
  if (labelKey.value === 'unknown') return { comp: CircleDashed, state: 'gray' }
  return { comp: TriangleAlert, state: 'warn' }
})

const te = (key) => i18n.global.te(key)

// 第一層：白話原因。成功時標籤已說明結果，不再重複「登入成功」
const reasonText = computed(() => {
  if (!props.attempt || code.value === 'success') return ''
  if (code.value === 'provider_error') return t(`${A}detail.provider_error.${detail.value || 'other'}`)
  if (code.value === 'admission_rules_noncompliant') {
    return t(`${A}reason.admission_rules_noncompliant`, {
      detail: t(`${A}detail.admission_rules_noncompliant.${detail.value || 'other'}`),
    })
  }
  const key = `${A}reason.${code.value}`
  return te(key) ? t(key) : t(`${A}reason.unknown`)
})

const adviceText = computed(() => {
  if (!props.attempt) return ''
  if (code.value === 'provider_error') return t(`${A}providerAdvice.${detail.value || 'other'}`)
  const key = `${A}advice.${code.value}`
  return te(key) ? t(key) : ''
})

// 第二層：事件名、規則類別、子碼、原因碼、提供者代碼與自報說明
const detailRows = computed(() => {
  const a = props.attempt
  if (!a || code.value === 'success') return []
  const rows = []
  const event = code.value === 'unknown' ? a.event : isAdmission.value ? 'oidc_admission_denied' : EVENT_OF[code.value]
  if (event) rows.push({ key: 'event', value: event, mono: true })
  if (isAdmission.value) {
    rows.push({ key: 'rule', value: code.value.slice(ADMISSION_PREFIX.length), mono: true })
    if (detail.value) rows.push({ key: 'sub', value: detail.value, mono: true })
  }
  if (code.value === 'provider_error') {
    if (a.provider_error) rows.push({ key: 'providerCode', value: a.provider_error, mono: true })
    if (a.provider_error_description) {
      rows.push({ key: 'providerDescription', value: a.provider_error_description, mono: false })
    }
  } else if (code.value !== 'unknown') {
    rows.push({ key: 'reasonCode', value: code.value, mono: true })
  }
  return rows
})
</script>

<style scoped>
.attempt__head { margin-bottom: var(--ot-space-sm); font-weight: 600; color: var(--ot-text-primary); }
.attempt__line { display: flex; flex-wrap: wrap; align-items: center; gap: var(--ot-space-xs) var(--ot-space-sm); font-size: var(--ot-font-size-sm); }
.attempt__icon { width: 16px; height: 16px; flex-shrink: 0; }
.attempt__spin { animation: attempt-spin 1.2s linear infinite; }
@keyframes attempt-spin { to { transform: rotate(360deg); } }
.attempt__icon--ok, .attempt__tag--ok { color: var(--ot-success); }
.attempt__icon--warn, .attempt__tag--warn { color: var(--ot-warning); }
.attempt__icon--gray, .attempt__tag--gray { color: var(--ot-text-secondary); }
.attempt__tag { padding: 0 6px; border: 1px solid currentColor; border-radius: var(--ot-radius-sm); font-size: var(--ot-font-size-xs); line-height: 20px; }
.attempt__meta { color: var(--ot-text-secondary); font-size: var(--ot-font-size-xs); }
.attempt__mono { font-family: var(--ot-font-mono); color: var(--ot-text-primary); word-break: break-all; }
.attempt__reason { margin-top: var(--ot-space-xs); font-size: var(--ot-font-size-sm); font-weight: 600; line-height: 1.6; }
.attempt__advice { margin-top: 2px; color: var(--ot-text-secondary); font-size: var(--ot-font-size-xs); line-height: 1.6; }
.attempt__toggle {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-top: var(--ot-space-xs);
  padding: 0;
  border: 0;
  background: none;
  color: var(--ot-primary);
  font-size: var(--ot-font-size-xs);
  cursor: pointer;
}
.attempt__chevron { width: 14px; height: 14px; }
.attempt__details {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: 6px var(--ot-space-md);
  margin: var(--ot-space-xs) 0 0;
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-xs);
}
.attempt__details dt { color: var(--ot-text-secondary); }
.attempt__details dd { margin: 0; min-width: 0; word-break: break-word; }
.attempt__missing {
  display: flex;
  gap: var(--ot-space-xs);
  margin-top: var(--ot-space-sm);
  padding: var(--ot-space-sm);
  border-radius: var(--ot-radius-md);
  background-color: var(--ot-bg-elevated);
  font-size: var(--ot-font-size-xs);
  line-height: 1.7;
}
.attempt__missing-icon { width: 14px; height: 14px; margin-top: 4px; flex-shrink: 0; color: var(--ot-info); }
.attempt__missing-strong { font-weight: 600; }
.attempt__list { margin: 2px 0; padding-left: 1.2em; }
</style>
