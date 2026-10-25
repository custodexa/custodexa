<template>
  <!-- 儀表板的每日審閱卡片只負責提醒與入口，不在卡片上簽核：
       告警要先處置完才能簽，那只有抽屜做得到。按鈕與日期一律開啟操作日誌頁
       每日簽核分頁的該日抽屜 -->
  <div
    class="review-card"
    :class="{ 'review-card--overdue': state === 'multi' }"
    data-test="dr-card"
  >
    <!-- 歷次簽核入口是真連結（href 同目標）：原生可 Tab 聚焦、Enter 觸發，
         修飾鍵點擊交還瀏覽器開新分頁 -->
    <div class="review-head">
      <div class="review-head-main">
        <a
          class="review-title review-link"
          :href="REVIEW_HISTORY_HREF"
          :aria-label="$t('dashboard.reviewTitleLinkLabel')"
          @click.exact.prevent="$router.push(REVIEW_HISTORY_ROUTE)"
        >
          {{ $t('dashboard.reviewTitle') }}
          <ChevronRight
            class="review-title-icon"
            :size="16"
            aria-hidden="true"
          />
        </a>
        <span
          v-if="yesterday?.date"
          class="review-date"
        >{{ yesterday.date }}<template v-if="state !== 'done'">{{ $t('dailyReview.card.yesterdayMark') }}</template></span>
      </div>
      <el-tag
        size="small"
        :type="tag.type"
        data-test="dr-card-tag"
      >
        {{ tag.text }}
      </el-tag>
    </div>

    <!-- 功能未開啟 -->
    <template v-if="state === 'disabled'">
      <p class="review-lead">
        {{ $t('dailyReview.card.disabledLead') }}
      </p>
      <p class="review-hint">
        {{ $t('dailyReview.card.disabledFrom') }}
      </p>
      <a
        v-if="canOpenPolicies"
        class="review-link"
        href="/security-policies"
        data-test="dr-card-policy-link"
        @click.exact.prevent="$router.push('/security-policies')"
      >
        {{ $t('dailyReview.card.disabledAdminLink') }}
      </a>
      <p
        v-else
        class="review-hint"
      >
        {{ $t('dailyReview.card.disabledContact') }}
      </p>
    </template>

    <template v-else>
      <!-- 多日未簽：天數、最早一天晚了幾天、日期標籤（點了直接開那一天） -->
      <div
        v-if="state === 'multi'"
        class="review-multi"
        data-test="dr-card-multi"
      >
        <span data-test="dr-card-multi-line">{{ earliestLateDays === null
          ? $t('dailyReview.card.multiLineNoLate', { n: status.pending_count })
          : $t('dailyReview.card.multiLine', { n: status.pending_count, late: earliestLateDays }) }}</span>
        <a
          v-for="date in (status.pending_dates || []).slice(0, 10)"
          :key="date"
          class="review-chip"
          :href="dayHref(date)"
          data-test="dr-card-date"
          @click.exact.prevent="$router.push(dayRoute(date))"
        >{{ monthDay(date) }}</a>
      </div>

      <div
        v-if="yesterday && yesterdayInScope"
        class="review-counts"
      >
        <div
          class="review-count"
          role="button"
          tabindex="0"
          @click="$router.push('/audit-logs')"
          @keydown.enter.space.prevent="$router.push('/audit-logs')"
        >
          <div class="review-count-value">
            {{ count('login_failures', 'login_failures_source') }}
          </div>
          <div class="review-count-label">
            {{ state === 'multi' ? $t('dailyReview.card.yesterdayLoginFailures') : $t('common.loginFailures') }}
          </div>
        </div>
        <div
          class="review-count"
          role="button"
          tabindex="0"
          @click="$router.push('/alerts')"
          @keydown.enter.space.prevent="$router.push('/alerts')"
        >
          <div
            class="review-count-value"
            :class="{ 'review-count-value--warning': unreviewed > 0 }"
          >
            {{ count('unreviewed_alerts', 'alerts_source') }}
          </div>
          <div class="review-count-label">
            {{ state === 'multi' ? $t('dailyReview.card.yesterdayUnreviewedAlerts') : $t('common.unreviewedAlerts') }}
          </div>
        </div>
        <div
          class="review-count"
          role="button"
          tabindex="0"
          @click="$router.push('/audit-logs')"
          @keydown.enter.space.prevent="$router.push('/audit-logs')"
        >
          <div class="review-count-value">
            {{ count('high_risk_ops', 'high_risk_ops_source') }}
          </div>
          <div class="review-count-label">
            {{ state === 'multi' ? $t('dailyReview.card.yesterdayHighRiskOps') : $t('common.highRiskOps') }}
          </div>
        </div>
      </div>

      <!-- 全部完成：簽核者、時刻與近 30 天簽核率 -->
      <div
        v-if="state === 'done'"
        class="review-signed"
      >
        <span
          class="review-signed-text"
          data-test="dr-card-signed"
        >
          {{ $t('dailyReview.card.signedLine', { name: yesterday.review.reviewer_name, time: formatInZone(yesterday.review.signed_at, yesterday.review.timezone) }) }}
          <template v-if="ratePercent !== null">{{ $t('dailyReview.card.rateLine', { rate: ratePercent }) }}</template>
        </span>
        <a
          class="review-link"
          :href="REVIEW_HISTORY_HREF"
          @click.exact.prevent="$router.push(REVIEW_HISTORY_ROUTE)"
        >
          {{ $t('dailyReview.card.viewRecords') }}
        </a>
      </div>

      <!-- 目前沒有待簽的日子，昨日也不在範圍（剛開啟）：不捏造簽核者 -->
      <p
        v-else-if="state === 'none'"
        class="review-hint"
        data-test="dr-card-none"
      >
        {{ $t('dailyReview.card.noneYet') }}
      </p>

      <div
        v-else
        class="review-action"
      >
        <span
          class="review-hint"
          data-test="dr-card-hint"
        >{{ actionHint }}</span>
        <el-button
          type="primary"
          data-test="dr-card-action"
          @click="$router.push(dayRoute(status.earliest_pending_date))"
        >
          {{ state === 'multi'
            ? $t('dailyReview.card.startFrom', { date: monthDay(status.earliest_pending_date) })
            : $t('dailyReview.card.reviewButton') }}
        </el-button>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { ChevronRight } from 'lucide-vue-next'
import { t } from '@/i18n'
import { getDailyReviewPending } from '@/api/dailyReviews'
import {
  countText,
  formatInZone,
  lastMinuteBefore,
  monthDay,
  timeInZone,
} from './dailyReviewFormat'

const props = defineProps({
  // GET /daily-reviews/status 的回應
  status: { type: Object, required: true },
  canOpenPolicies: { type: Boolean, default: false },
})

// 歷次簽核在操作日誌頁的「每日簽核」分頁；該頁只認白名單內的 tab 值
const REVIEW_HISTORY_ROUTE = Object.freeze({ path: '/audit-logs', query: Object.freeze({ tab: 'reviews' }) })
const REVIEW_HISTORY_HREF = '/audit-logs?tab=reviews'
const dayRoute = (date) => ({ path: '/audit-logs', query: { tab: 'reviews', date } })
const dayHref = (date) => `/audit-logs?tab=reviews&date=${encodeURIComponent(date)}`

const yesterday = computed(() => props.status.yesterday || null)
// 舊形態或缺欄位時視為在範圍內；明確 in_scope=false 才排除
const yesterdayInScope = computed(() => yesterday.value?.in_scope !== false)

// disabled｜done｜none｜multi｜single
const state = computed(() => {
  const s = props.status
  if (!s.enabled) return 'disabled'
  const pendingCount = Number(s.pending_count) || 0
  if (pendingCount === 0) return yesterday.value?.signed && yesterday.value?.review ? 'done' : 'none'
  if ((Number(s.overdue_count) || 0) > 0 || pendingCount > 1) return 'multi'
  return 'single'
})

const settling = computed(() => state.value === 'single' && yesterday.value && yesterday.value.signable === false)

const tag = computed(() => {
  switch (state.value) {
    case 'disabled':
      return { type: 'info', text: t('dailyReview.card.tagDisabled') }
    case 'done':
      return { type: 'success', text: t('dailyReview.card.tagSigned') }
    case 'none':
      return { type: 'info', text: t('dailyReview.card.tagNone') }
    case 'multi':
      return { type: 'warning', text: t('dailyReview.card.tagDays', { n: props.status.pending_count }) }
    default:
      return settling.value
        ? { type: 'info', text: t('dailyReview.card.tagSettling') }
        : { type: 'warning', text: t('dailyReview.card.tagPending') }
  }
})

const count = (key, sourceKey) => {
  const counts = yesterday.value?.counts || {}
  if (!(key in counts) && !(sourceKey in counts)) return t('dailyReview.count.none')
  return countText(counts[key], counts[sourceKey])
}
const unreviewed = computed(() => Number(yesterday.value?.counts?.unreviewed_alerts) || 0)

// 最早一天晚了幾天：直接用待簽清單第一列的 late_days（後端以該日自己的切日時區計算）。
// 不在前端用「今天 −（所屬日＋1）」推算：改過業務時區後，最早那天可能以舊時區切日，
// 兩種算法會差一天，卡片與清單就對不上。取不到時只寫天數，不寫晚幾天
const earliestLateDays = ref(null)
let lateRequest = 0
watch(
  () => [state.value, props.status.earliest_pending_date],
  async ([current, earliest]) => {
    const seq = ++lateRequest
    earliestLateDays.value = null
    if (current !== 'multi' || !earliest) return
    try {
      const res = await getDailyReviewPending({ page: 1, page_size: 1 }, { skipErrorToast: true })
      const first = res?.data?.items?.[0]
      if (seq !== lateRequest) return
      if (first?.date === earliest && Number.isFinite(first.late_days)) earliestLateDays.value = first.late_days
    } catch {
      // 提醒卡片不因這一句失敗而報錯
    }
  },
  { immediate: true },
)

const ratePercent = computed(() => {
  const value = props.status.stats_30d?.sign_rate_percent
  return value === null || value === undefined ? null : value
})

const actionHint = computed(() => {
  if (state.value === 'multi') return t('dailyReview.card.multiHint')
  const y = yesterday.value
  if (!y) return ''
  const due = t('dailyReview.card.onTimeBy', { time: timeInZone(lastMinuteBefore(y.due_at), y.timezone) })
  if (settling.value) return `${t('dailyReview.card.settling', { time: timeInZone(y.signable_at, y.timezone) })}${due}`
  if (unreviewed.value > 0) return `${t('dailyReview.card.alertsFirst', { n: unreviewed.value })}${due}`
  return due
})
</script>

<style scoped>
.review-card {
  margin-top: 16px;
  padding: 14px 16px;
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: 6px;
}

.review-card--overdue {
  border-color: var(--ot-warning);
}

.review-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px 12px;
  margin-bottom: 12px;
}

.review-head-main {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 12px;
}

/* 連結樣式：品牌主色＋底線於 hover／焦點出現，與一般文字可區分 */
.review-link {
  color: var(--ot-primary);
  font-size: 13px;
  text-decoration: none;
  border-radius: 2px;
}

.review-link:hover,
.review-link:focus-visible {
  color: var(--ot-primary-hover);
  text-decoration: underline;
  text-underline-offset: 3px;
}

.review-link:focus-visible,
.review-chip:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}

/* 標題本身維持標題字色，靠右側箭頭與 hover 底線表明可點 */
.review-title {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  font-weight: 600;
  font-size: 14px;
  color: var(--ot-text-primary);
}

.review-title-icon {
  color: var(--ot-primary);
  flex-shrink: 0;
}

.review-date {
  font-size: 13px;
  color: var(--ot-text-secondary);
}

.review-lead {
  margin: 0 0 8px;
  font-weight: 600;
  color: var(--ot-text-primary);
}

.review-multi {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 8px;
  margin-bottom: 12px;
  font-size: 13px;
  font-weight: 600;
  color: var(--ot-text-primary);
}

.review-chip {
  padding: 1px 8px;
  font-size: 12px;
  font-weight: normal;
  color: var(--ot-primary);
  text-decoration: none;
  border: 1px solid var(--ot-border);
  border-radius: var(--ot-radius-sm);
}

.review-chip:hover {
  border-color: var(--ot-primary);
}

.review-counts {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 12px;
}

.review-count {
  flex: 1;
  min-width: 120px;
  padding: 10px;
  text-align: center;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  cursor: pointer;
  transition: border-color 0.15s;
}

.review-count:hover {
  border-color: var(--ot-primary);
}

.review-count-value {
  font-size: 22px;
  font-weight: 600;
  color: var(--ot-text-primary);
  line-height: 1.3;
}

.review-count-value--warning {
  color: var(--ot-warning);
}

.review-count-label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.review-action,
.review-signed {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px 12px;
}

/* 按鈕文字帶日期，窄欄時允許換行而不溢出卡片 */
.review-action :deep(.el-button) {
  max-width: 100%;
  height: auto;
  min-height: 32px;
  white-space: normal;
}

.review-hint,
.review-signed-text {
  margin: 0;
  font-size: 13px;
  color: var(--el-text-color-regular);
}
</style>
