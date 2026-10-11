<template>
  <!-- 期間統計：數字一律照統計查詢的回應呈現。期間、到期與分母的定義只在後端，
       介面自己用日期推分母的話，畫面、證據包與合規報告會對不上 -->
  <section
    class="dr-stats"
    data-test="dr-stats"
  >
    <div class="dr-stats__head">
      <div>
        <div class="dr-stats__title">
          {{ $t('dailyReview.stats.title') }}
        </div>
        <div
          v-if="stats"
          class="dr-stats__range"
          data-test="dr-stats-range"
        >
          {{ $t('dailyReview.stats.range', { from: stats.from, to: stats.to }) }}
          <span v-if="period !== 'custom'">{{ $t('dailyReview.stats.rangeNote', { n: period === '90d' ? 90 : 30 }) }}</span>
          ・{{ $t('dailyReview.stats.asOf', { time: formatInZone(stats.as_of, stats.timezone) }) }}
        </div>
      </div>
      <div class="dr-stats__period">
        <el-radio-group
          v-model="period"
          size="small"
          @change="onPeriodChange"
        >
          <el-radio-button value="30d">
            {{ $t('dailyReview.stats.period30') }}
          </el-radio-button>
          <el-radio-button value="90d">
            {{ $t('dailyReview.stats.period90') }}
          </el-radio-button>
          <el-radio-button value="custom">
            {{ $t('dailyReview.stats.custom') }}
          </el-radio-button>
        </el-radio-group>
        <el-date-picker
          v-if="period === 'custom'"
          v-model="customRange"
          type="daterange"
          size="small"
          value-format="YYYY-MM-DD"
          :start-placeholder="$t('dailyReview.stats.customStart')"
          :end-placeholder="$t('dailyReview.stats.customEnd')"
          :range-separator="$t('sessions.rangeSeparator')"
          class="dr-stats__picker"
          @change="load"
        />
      </div>
    </div>

    <div
      v-loading="loading"
      class="dr-stats__cells"
    >
      <div class="dr-stats__cell">
        <div
          class="dr-stats__value"
          data-test="dr-stats-rate"
        >
          {{ rateText }}
        </div>
        <div class="dr-stats__label">
          {{ $t('dailyReview.stats.rate', { required: stats?.required ?? '—', signed: signedDays }) }}
        </div>
      </div>
      <div class="dr-stats__cell">
        <div
          class="dr-stats__value"
          data-test="dr-stats-on-time"
        >
          {{ stats?.on_time ?? '—' }}
        </div>
        <div class="dr-stats__label">
          {{ $t('dailyReview.stats.onTime') }}
        </div>
      </div>
      <div class="dr-stats__cell">
        <div
          class="dr-stats__value dr-stats__value--warning"
          data-test="dr-stats-late"
        >
          {{ stats?.late ?? '—' }}
        </div>
        <div class="dr-stats__label">
          {{ $t('dailyReview.stats.late') }}
        </div>
      </div>
      <div class="dr-stats__cell">
        <div
          class="dr-stats__value"
          :class="{ 'dr-stats__value--danger': stats?.unsigned > 0 }"
          data-test="dr-stats-unsigned"
        >
          {{ stats?.unsigned ?? '—' }}
        </div>
        <div class="dr-stats__label">
          {{ $t('dailyReview.stats.unsigned') }}
        </div>
      </div>
    </div>

    <p class="dr-stats__basis">
      {{ $t('dailyReview.stats.basis') }}
      <span
        v-if="stats?.inferred_days > 0"
        data-test="dr-stats-inferred"
      >{{ $t('dailyReview.enabledInferred.statsNote', { n: stats.inferred_days }) }}</span>
    </p>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { getDailyReviewStats } from '@/api/dailyReviews'
import { formatInZone } from './dailyReviewFormat'

const period = ref('30d')
const customRange = ref([])
const stats = ref(null)
const loading = ref(false)

// 已簽天數＝準時＋遲簽（兩個回應欄位相加，不是另算一個分母）
const signedDays = computed(() =>
  stats.value ? (stats.value.on_time ?? 0) + (stats.value.late ?? 0) : '—'
)
// 百分比照回應值顯示（後端已無條件捨去）；分母為 0 時後端回 null
const rateText = computed(() => {
  const value = stats.value?.sign_rate_percent
  return value === null || value === undefined ? '—' : `${value}%`
})

async function load() {
  let params
  if (period.value === 'custom') {
    if (!customRange.value || customRange.value.length !== 2) return
    params = { from: customRange.value[0], to: customRange.value[1] }
  } else {
    params = { period: period.value }
  }
  loading.value = true
  try {
    const res = await getDailyReviewStats(params)
    stats.value = res?.data || null
  } catch (error) {
    // 期間不合法等錯誤由全域攔截器提示；保留上一次的數字
    console.error('載入簽核統計失敗:', error)
  } finally {
    loading.value = false
  }
}

const onPeriodChange = () => {
  if (period.value !== 'custom') load()
}

onMounted(load)

defineExpose({ load, stats })
</script>

<style scoped>
.dr-stats {
  padding: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.dr-stats__head {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--ot-space-sm) var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
}

.dr-stats__title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-stats__range {
  margin-top: var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.dr-stats__period {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-sm);
}

.dr-stats__picker {
  max-width: 280px;
}

.dr-stats__cells {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: var(--ot-space-sm);
}

.dr-stats__cell {
  padding: var(--ot-space-sm) var(--ot-space-md);
  background-color: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.dr-stats__value {
  font-size: 22px;
  font-weight: 600;
  line-height: 1.3;
  color: var(--ot-text-primary);
}

.dr-stats__value--warning {
  color: var(--ot-warning);
}

.dr-stats__value--danger {
  color: var(--ot-danger);
}

.dr-stats__label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.dr-stats__basis {
  margin: var(--ot-space-sm) 0 0;
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--ot-text-secondary);
}
</style>
