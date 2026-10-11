<template>
  <!-- 以運作紀錄判定的條文（PCI 10.4.1）在條文列下方的一排事實格。
       只看開關的結果會讓「開著但天天漏簽」也顯示符合，這一排把判定依據的
       近 30 天紀錄攤開：設定、簽核率、未簽、遲簽。結果與數字全部取自後端判定，
       這裡不重算 -->
  <div
    class="signoff-facts"
    :data-test="`signoff-facts-${state}`"
  >
    <div class="facts-row">
      <div class="fact-cell">
        <span class="fact-label">{{ $t('complianceMap.signoff.setting') }}</span>
        <strong data-test="signoff-setting">{{ settingText }}</strong>
      </div>

      <!-- 期間不足：開啟日與累計天數取代簽核率 -->
      <template v-if="state === 'insufficient'">
        <div
          class="fact-cell"
          data-test="signoff-enabled-since"
        >
          <span class="fact-label">{{ $t('complianceMap.signoff.enabledSince') }}</span>
          <strong>{{ enabledSinceText }}</strong>
        </div>
        <div
          class="fact-cell"
          data-test="signoff-enabled-days"
        >
          <span class="fact-label">{{ $t('complianceMap.signoff.enabledDays') }}</span>
          <strong>{{ enabledDaysText }}</strong>
        </div>
        <div class="fact-cell">
          <span class="fact-label">{{ $t('complianceMap.signoff.late') }}</span>
          <strong>{{ $t('complianceMap.signoff.lateValue', { n: record.late }) }}</strong>
        </div>
      </template>

      <!-- 取不到紀錄：不以任何預設值推算簽核率、開啟日或累計天數 -->
      <div
        v-else-if="state === 'unavailable'"
        class="fact-cell fact-cell--wide"
        data-test="signoff-unavailable-cell"
      >
        {{ $t('complianceMap.signoff.unavailableCell') }}
      </div>

      <template v-else-if="state === 'measured'">
        <div
          class="fact-cell"
          data-test="signoff-rate"
        >
          <span class="fact-label">{{ $t('complianceMap.signoff.rate') }}</span>
          <strong :class="{ 'fact-alert': record.unsigned > 0 }">{{ rateText }}</strong>
          <span class="fact-sub">{{ $t('complianceMap.signoff.period', { from: record.from, to: record.to }) }}</span>
        </div>
        <div
          class="fact-cell"
          data-test="signoff-unsigned"
        >
          <span class="fact-label">{{ $t('complianceMap.signoff.unsigned') }}</span>
          <strong :class="{ 'fact-alert': record.unsigned > 0 }">{{ $t('complianceMap.signoff.unsignedValue', { n: record.unsigned }) }}</strong>
        </div>
        <div
          class="fact-cell"
          data-test="signoff-late"
        >
          <span class="fact-label">{{ $t('complianceMap.signoff.late') }}</span>
          <strong>{{ $t('complianceMap.signoff.lateValue', { n: record.late }) }}</strong>
        </div>
      </template>
    </div>

    <p
      v-if="state === 'measured' && record.unsigned > 0"
      class="facts-note"
      data-test="signoff-unsigned-note"
    >
      {{ $t('complianceMap.signoff.unsignedNote', { n: record.unsigned, date: record.earliest_unsigned }) }}
      <router-link
        :to="signLink"
        data-test="signoff-go-sign"
      >
        {{ $t('complianceMap.signoff.goSign') }}
      </router-link>
    </p>
    <p
      v-if="state === 'insufficient'"
      class="facts-note"
      data-test="signoff-insufficient-note"
    >
      {{ $t('complianceMap.signoff.insufficientNote') }}
    </p>
    <p
      v-if="state === 'unavailable'"
      class="facts-note facts-note--action"
      data-test="signoff-unavailable-note"
    >
      <span>{{ $t('complianceMap.signoff.unavailableNote', { time: formatDateTime(builtAt) }) }}</span>
      <el-button
        size="small"
        data-test="signoff-refresh"
        @click="$emit('refresh')"
      >
        {{ $t('common.refresh') }}
      </el-button>
    </p>
    <!-- 推定日只加說明不改結果：那些日子已照樣計入應簽 -->
    <p
      v-if="record && record.inferred_days > 0"
      class="facts-note facts-note--minor"
      data-test="signoff-inferred-note"
    >
      {{ $t('complianceMap.signoffInferredDays', { n: record.inferred_days }) }}
    </p>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { formatDateTime } from '@/utils/format'

const props = defineProps({
  // 該條文對每日審閱簽核鍵的判定（comparator=signoff_record），運作紀錄在 verdict.signoff
  verdict: { type: Object, required: true },
  // 判定建構時點（取不到紀錄時說明「何時判定的」）
  builtAt: { type: String, default: '' },
})

defineEmits(['refresh'])

const { t } = useI18n()

const record = computed(() => props.verdict.signoff || null)

// 四種呈現：關閉（只有設定格）、取不到紀錄、期間不足、有紀錄（符合或偏離）。
// 「資料不足」是同一個結果碼，依理由碼分兩種說法——來源故障說成開啟未滿 7 天，
// 使用者會被引導去等待，而不知道是查詢出了問題
const state = computed(() => {
  switch (props.verdict.reason) {
    case 'daily_review_disabled':
      return 'disabled'
    case 'signoff_source_unavailable':
      return 'unavailable'
    case 'signoff_insufficient_data':
      return 'insufficient'
    default:
      return record.value ? 'measured' : 'disabled'
  }
})

const settingText = computed(() =>
  props.verdict.current === 'true'
    ? t('complianceMap.signoff.settingOn')
    : t('complianceMap.signoff.settingOff')
)

const signedDays = computed(() => (record.value ? record.value.on_time + record.value.late : 0))

const rateText = computed(() => {
  const r = record.value
  if (!r || r.sign_rate_percent === null || r.sign_rate_percent === undefined) {
    return t('complianceMap.signoff.rateNone')
  }
  return t('complianceMap.signoff.rateValue', {
    pct: r.sign_rate_percent,
    signed: signedDays.value,
    required: r.required,
  })
})

// 開啟日以業務時區的日期呈現（與每日簽核分頁同一條日界）
const enabledSinceDate = computed(() => {
  const r = record.value
  if (!r || !r.enabled_since) return ''
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: r.timezone || undefined,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(new Date(r.enabled_since))
})

const enabledSinceText = computed(() => {
  const date = enabledSinceDate.value
  if (!date) return '—'
  return record.value.enabled_since_inferred ? `${date}${t('complianceMap.signoff.inferred')}` : date
})

// 已累計＝開啟日所屬日到昨日（後端 enabled_days 的同一段，迄日即 record.to），
// 連同已簽天數（規格要求期間不足時三者都看得到）。起訖同年時省略年份，與開啟日格
// 並排不重複；起點晚於迄日（今天才開）或缺起點時不寫起訖
const enabledDaysText = computed(() => {
  const r = record.value
  const from = enabledSinceDate.value
  const days = r?.enabled_days ?? 0
  if (!r || !from || !r.to || from > r.to || !days) {
    return t('complianceMap.signoff.enabledDaysValue', { days, signed: signedDays.value })
  }
  const sameYear = from.slice(0, 4) === r.to.slice(0, 4)
  return t('complianceMap.signoff.enabledDaysRange', {
    days,
    signed: signedDays.value,
    from: sameYear ? from.slice(5) : from,
    to: sameYear ? r.to.slice(5) : r.to,
  })
})

const signLink = computed(() => ({
  path: '/audit-logs',
  query: { tab: 'reviews', date: record.value?.earliest_unsigned || '' },
}))
</script>

<style scoped>
.signoff-facts {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
}

.facts-row {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: var(--ot-space-sm);
}

.fact-cell {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--ot-space-xs) var(--ot-space-sm);
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background-color: var(--ot-bg-elevated);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

.fact-cell--wide {
  grid-column: span 3;
  color: var(--ot-text-secondary);
}

.fact-label {
  color: var(--ot-text-secondary);
}

.fact-sub {
  flex-basis: 100%;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
}

.fact-alert {
  color: var(--ot-warning);
}

.facts-note {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.facts-note a {
  margin-left: var(--ot-space-xs);
  color: var(--ot-primary);
}

.facts-note--action {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
}

.facts-note--minor {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
}
</style>
