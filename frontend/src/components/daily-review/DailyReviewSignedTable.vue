<template>
  <!-- 已簽紀錄：新到舊，所屬日與簽核時間分欄。時間窗涵蓋、來源完整性、
       切日時區與啟用依據各自加註，不合併成一個標籤 -->
  <section
    class="dr-signed"
    data-test="dr-signed"
  >
    <div class="dr-signed__head">
      <h3 class="dr-signed__title">
        {{ $t('dailyReview.workspace.signedTitle') }}
      </h3>
      <el-radio-group
        v-model="filter"
        size="small"
        data-test="dr-signed-filter"
        @change="onFilterChange"
      >
        <el-radio-button value="all">
          {{ $t('dailyReview.workspace.filterAll') }}
        </el-radio-button>
        <el-radio-button value="late">
          {{ $t('dailyReview.workspace.filterLate') }}
        </el-radio-button>
      </el-radio-group>
    </div>
    <div class="list-card">
      <el-table
        v-loading="loading"
        :data="rows"
        data-test="dr-signed-table"
        style="width: 100%"
        row-class-name="dr-signed__row"
        @row-click="(row) => $emit('open', row.review_date)"
      >
        <el-table-column
          :label="$t('dailyReview.workspace.col.date')"
          min-width="190"
        >
          <template #default="{ row }">
            <div class="dr-date">
              <span>{{ dateWithWeekday(row.review_date) }}</span>
              <el-tag
                v-if="isInferredBasis(row.enabled_basis)"
                size="small"
                type="info"
                data-test="dr-signed-inferred"
              >
                {{ $t('dailyReview.enabledInferred.tag') }}
              </el-tag>
            </div>
            <div
              v-for="note in rowNotes(row)"
              :key="note"
              class="dr-sub"
              data-test="dr-signed-note"
            >
              {{ note }}
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('dailyReview.workspace.col.signedAt')"
          min-width="190"
        >
          <template #default="{ row }">
            {{ formatInZone(row.signed_at || row.created_at, row.timezone) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('dailyReview.workspace.col.type')"
          width="130"
        >
          <template #default="{ row }">
            <el-tag
              size="small"
              :type="row.late ? 'warning' : 'success'"
              data-test="dr-signed-type"
            >
              {{ row.late
                ? $t('dailyReview.workspace.typeLate', { n: row.late_days })
                : $t('dailyReview.workspace.typeOnTime') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="reviewer_name"
          :label="$t('dailyReview.workspace.col.signer')"
          width="130"
        />
        <el-table-column
          :label="$t('dailyReview.workspace.col.counts')"
          min-width="210"
        >
          <template #default="{ row }">
            <span data-test="dr-signed-counts">{{ countsLine(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('dailyReview.workspace.col.remark')"
          min-width="200"
          show-overflow-tooltip
        >
          <template #default="{ row }">
            {{ remark(row) }}
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState :title="$t('dailyReview.workspace.emptySigned')" />
        </template>
      </el-table>
      <div class="dr-signed__foot">
        <span class="dr-sub">{{ $t('dailyReview.workspace.signedHint') }}</span>
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50]"
          :total="total"
          layout="total, sizes, prev, pager, next"
          @size-change="load"
          @current-change="load"
        />
      </div>
    </div>
  </section>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { t } from '@/i18n'
import { getDailyReviews } from '@/api/dailyReviews'
import EmptyState from '@/components/EmptyState.vue'
import {
  countText,
  dateWithWeekday,
  formatInZone,
  isInferredBasis,
  offsetLabel,
  parseSnapshot,
} from './dailyReviewFormat'

const props = defineProps({
  // 目前生效的業務時區；該列切日時區與它不同時加註「當時以 … 切日」
  activeTimezone: { type: String, default: '' },
})

defineEmits(['open'])

const rows = ref([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const filter = ref('all')
const loading = ref(false)

async function load() {
  loading.value = true
  try {
    const params = { page: page.value, page_size: pageSize.value }
    if (filter.value === 'late') params.late_only = true
    const res = await getDailyReviews(params)
    rows.value = res?.data?.items || []
    total.value = Number(res?.data?.total) || 0
  } catch (error) {
    console.error('查詢簽核紀錄失敗:', error)
  } finally {
    loading.value = false
  }
}

const onFilterChange = () => {
  page.value = 1
  load()
}

const countsLine = (row) => {
  const s = parseSnapshot(row.snapshot_json)
  if (!s) return '-'
  return t('dailyReview.workspace.countsLine', {
    login: countText(s.login_failures, s.login_failures_source),
    alerts: countText(s.alerts_total ?? s.unreviewed_alerts, s.alerts_source),
    high: countText(s.high_risk_ops, s.high_risk_ops_source),
  })
}

const remark = (row) => {
  if (row.late && row.delay_reason) return t('dailyReview.workspace.remarkDelay', { text: row.delay_reason })
  return row.note || t('dailyReview.workspace.remarkNone')
}

const rowNotes = (row) => {
  const notes = []
  if (row.timezone && props.activeTimezone && row.timezone !== props.activeTimezone) {
    notes.push(t('dailyReview.workspace.rowTzDiff', { offset: offsetLabel(row.timezone, row.window_start || row.signed_at) }))
  }
  if (row.timezone_inferred) notes.push(t('dailyReview.workspace.rowTzInferred'))
  if (row.source_status === 'purged') notes.push(t('dailyReview.workspace.rowSourcePurged'))
  else if (row.source_status === 'partial') notes.push(t('dailyReview.workspace.rowSourcePartial'))
  return notes
}

onMounted(load)

defineExpose({ load })
</script>

<style scoped>
.dr-signed__head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  margin: var(--ot-space-sm) 0;
}

.dr-signed__title {
  margin: 0;
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.dr-signed__foot {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-md);
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

.list-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

:deep(.dr-signed__row) {
  cursor: pointer;
}
</style>
