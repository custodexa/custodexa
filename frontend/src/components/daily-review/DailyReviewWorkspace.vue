<template>
  <!-- 每日簽核工作區：上方期間統計，中段待簽日（由最早排起），下段已簽紀錄。
       簽核在右側抽屜完成，不離開清單 -->
  <div
    class="dr-workspace"
    data-test="dr-workspace"
  >
    <div
      v-if="!canSign"
      class="dr-notice dr-notice--info"
      data-test="dr-readonly-notice"
    >
      {{ $t('dailyReview.workspace.readonlyNotice') }}
    </div>

    <!-- 功能未開啟：既有已簽紀錄照常列在下方 -->
    <div
      v-if="status && !status.enabled"
      class="dr-empty"
      data-test="dr-disabled"
    >
      <div class="dr-empty__title">
        {{ $t('dailyReview.workspace.disabledTitle') }}
      </div>
      <p>{{ $t('dailyReview.workspace.disabledBody') }}</p>
      <el-button
        v-if="canOpenPolicies"
        data-test="dr-disabled-link"
        @click="router?.push('/security-policies')"
      >
        {{ $t('dailyReview.workspace.disabledAdminLink') }}
      </el-button>
      <p v-else>
        {{ $t('dailyReview.workspace.disabledContact') }}
      </p>
    </div>

    <template v-else>
      <DailyReviewStats ref="statsRef" />

      <div
        v-if="overdueCount > 0"
        class="dr-notice dr-notice--warning"
        data-test="dr-overdue-banner"
      >
        {{ $t('dailyReview.workspace.overdueBanner', {
          count: pendingTotal,
          overdue: overdueCount,
          earliest: pending[0]?.date || status?.earliest_pending_date || '',
        }) }}
      </div>

      <h3 class="dr-section-title">
        {{ $t('dailyReview.workspace.pendingTitle', { n: pendingTotal }) }}
      </h3>
      <div
        v-if="!pendingLoading && pendingTotal === 0"
        class="dr-empty"
        data-test="dr-all-done"
      >
        <CircleCheck
          :size="22"
          class="dr-empty__ok"
          aria-hidden="true"
        />
        <div class="dr-empty__title">
          {{ $t('dailyReview.workspace.allDoneTitle') }}
        </div>
        <p v-if="status?.timezone_state?.today?.date">
          {{ $t('dailyReview.workspace.allDoneHint', { date: status.timezone_state.today.date }) }}
        </p>
      </div>
      <div
        v-else
        class="list-card"
      >
        <el-table
          v-loading="pendingLoading"
          :data="pending"
          data-test="dr-pending-table"
          style="width: 100%"
        >
          <el-table-column
            :label="$t('dailyReview.workspace.col.date')"
            min-width="170"
          >
            <template #default="{ row }">
              <div class="dr-date">
                <span data-test="dr-pending-date">{{ dateWithWeekday(row.date) }}</span>
                <span
                  v-if="!row.overdue"
                  class="dr-sub"
                >{{ $t('dailyReview.yesterdayMark') }}</span>
                <el-tag
                  v-if="isInferredBasis(row.enabled_basis)"
                  size="small"
                  type="info"
                  data-test="dr-pending-inferred"
                >
                  {{ $t('dailyReview.enabledInferred.tag') }}
                </el-tag>
              </div>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('dailyReview.workspace.col.deadline')"
            min-width="190"
          >
            <template #default="{ row }">
              <span :class="{ 'dr-warn': row.overdue }">
                {{ row.overdue
                  ? $t('dailyReview.workspace.deadlineLate', { n: row.late_days })
                  : $t('dailyReview.workspace.deadlineOnTime', { time: timeInZone(lastMinuteBefore(row.due_at), row.timezone) }) }}
              </span>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('common.loginFailures')"
            width="110"
          >
            <template #default="{ row }">
              {{ countText(row.counts?.login_failures, row.counts?.login_failures_source) }}
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('common.unreviewedAlerts')"
            width="110"
          >
            <template #default="{ row }">
              <span :class="{ 'dr-warn': row.counts?.unreviewed_alerts > 0 }">
                {{ countText(row.counts?.unreviewed_alerts, row.counts?.alerts_source) }}
              </span>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('common.highRiskOps')"
            width="110"
          >
            <template #default="{ row }">
              {{ countText(row.counts?.high_risk_ops, row.counts?.high_risk_ops_source) }}
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('dailyReview.workspace.col.action')"
            width="130"
          >
            <template #default="{ row }">
              <el-button
                v-if="canSign"
                type="primary"
                size="small"
                data-test="dr-pending-action"
                @click="openDay(row.date)"
              >
                {{ row.overdue ? $t('dailyReview.workspace.actionLate') : $t('dailyReview.workspace.actionSign') }}
              </el-button>
              <el-button
                v-else
                link
                type="primary"
                data-test="dr-pending-action"
                @click="openDay(row.date)"
              >
                {{ $t('dailyReview.workspace.actionView') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
        <div
          v-if="pendingTotal > PENDING_PAGE_SIZE"
          class="pagination"
        >
          <el-pagination
            v-model:current-page="pendingPage"
            :page-size="PENDING_PAGE_SIZE"
            :total="pendingTotal"
            layout="total, prev, pager, next"
            @current-change="loadPending"
          />
        </div>
      </div>
    </template>

    <DailyReviewSignedTable
      ref="signedRef"
      :active-timezone="activeTimezone"
      @open="openDay"
    />

    <DailyReviewDrawer
      ref="drawerRef"
      v-model="drawerOpen"
      :can-sign="canSign"
      @changed="refreshAfterChange"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { CircleCheck } from 'lucide-vue-next'
import { getDailyReviewPending, getDailyReviewStatus } from '@/api/dailyReviews'
import DailyReviewStats from './DailyReviewStats.vue'
import DailyReviewSignedTable from './DailyReviewSignedTable.vue'
import DailyReviewDrawer from './DailyReviewDrawer.vue'
import {
  DAILY_REVIEWS_CHANGED,
  countText,
  dateWithWeekday,
  isInferredBasis,
  isReviewDate,
  lastMinuteBefore,
  timeInZone,
} from './dailyReviewFormat'

const PENDING_PAGE_SIZE = 31

const props = defineProps({
  // 有簽核權限（alert:manage）；沒有時版面唯讀、動作為「查看」
  canSign: { type: Boolean, default: false },
  canOpenPolicies: { type: Boolean, default: false },
  // 網址帶入的所屬日：直接開該日抽屜
  openDate: { type: String, default: '' },
})

const router = useRouter()

const status = ref(null)
const pending = ref([])
const pendingTotal = ref(0)
const pendingPage = ref(1)
const pendingLoading = ref(false)
const statsRef = ref(null)
const signedRef = ref(null)
const drawerRef = ref(null)
const drawerOpen = ref(false)

const overdueCount = computed(() => status.value?.overdue_count ?? pending.value.filter((p) => p.overdue).length)
// 目前生效的切日時區：已簽紀錄據此判斷「當時以別的時區切日」要不要加註
const activeTimezone = computed(() => status.value?.timezone_state?.active || '')

async function loadStatus() {
  try {
    const res = await getDailyReviewStatus()
    status.value = res?.data || { enabled: false }
  } catch (error) {
    console.error('載入每日簽核狀態失敗:', error)
  }
}

async function loadPending() {
  pendingLoading.value = true
  try {
    const res = await getDailyReviewPending({ page: pendingPage.value, page_size: PENDING_PAGE_SIZE })
    pending.value = res?.data?.items || []
    pendingTotal.value = Number(res?.data?.total) || 0
  } catch (error) {
    console.error('載入待簽日失敗:', error)
  } finally {
    pendingLoading.value = false
  }
}

async function refresh() {
  await Promise.all([loadStatus(), loadPending(), signedRef.value?.load(), statsRef.value?.load()])
}

// 抽屜內簽核或處置告警後：清單、統計、已簽紀錄同步（徽章由事件重算）
async function refreshAfterChange() {
  await refresh()
}

function openDay(date) {
  drawerRef.value?.openDay(date)
}

// 別處（例如側欄）造成的變動也同步；自己派的事件已由 changed 處理，重複無害
const onExternalChange = () => {
  if (!drawerOpen.value) loadPending()
}

watch(
  () => props.openDate,
  (date) => {
    if (isReviewDate(date)) openDay(date)
  },
  { flush: 'post' }
)

onMounted(() => {
  loadStatus()
  loadPending()
  if (isReviewDate(props.openDate)) openDay(props.openDate)
  window.addEventListener(DAILY_REVIEWS_CHANGED, onExternalChange)
})

onUnmounted(() => {
  window.removeEventListener(DAILY_REVIEWS_CHANGED, onExternalChange)
})

defineExpose({ refresh, openDay, closeDrawer: () => { drawerOpen.value = false } })
</script>

<style scoped>
.dr-workspace {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.dr-section-title {
  margin: var(--ot-space-sm) 0 0;
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-notice {
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
  color: var(--ot-text-primary);
}

.dr-notice--warning {
  border-color: var(--ot-warning);
  background-color: color-mix(in srgb, var(--ot-warning) 10%, transparent);
}

.dr-notice--info {
  border-color: var(--ot-info);
  background-color: color-mix(in srgb, var(--ot-info) 10%, transparent);
}

.dr-empty {
  padding: var(--ot-space-lg) var(--ot-space-md);
  text-align: center;
  border: 1px dashed var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.dr-empty__title {
  margin: var(--ot-space-xs) 0;
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-empty__ok {
  color: var(--ot-success);
}

.dr-date {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs) var(--ot-space-sm);
}

.dr-sub {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.dr-warn {
  color: var(--ot-warning);
}

.list-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.pagination {
  margin-top: var(--ot-space-md);
  display: flex;
  justify-content: flex-end;
}
</style>
