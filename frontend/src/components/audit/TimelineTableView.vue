<template>
  <div
    class="table-view"
    data-test="table-view"
  >
    <div class="table-block">
      <div class="block-title">
        {{ $t('auditorWorkbench.spans.title') }}
      </div>
      <el-table
        :data="spans"
        size="small"
        stripe
        data-test="spans-table"
      >
        <el-table-column
          :label="$t('auditorWorkbench.table.counterpart')"
          min-width="140"
        >
          <template #default="{ row }">
            {{ subject === 'asset' ? (row.user_name || `#${row.user_id}`)
              : (row.asset_name || (row.asset_id ? `#${row.asset_id}` : '-')) }}
          </template>
        </el-table-column>
        <el-table-column
          prop="account"
          :label="$t('auditorWorkbench.table.account')"
          width="120"
        />
        <el-table-column
          prop="protocol"
          :label="$t('auditorWorkbench.table.protocol')"
          width="90"
        />
        <el-table-column
          :label="$t('auditorWorkbench.table.start')"
          width="180"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.start) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('auditorWorkbench.table.end')"
          width="180"
        >
          <template #default="{ row }">
            {{ row.end ? formatDateTime(row.end) : $t('auditorWorkbench.spans.ongoing') }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('auditorWorkbench.table.recording')"
          width="140"
        >
          <template #default="{ row }">
            <!-- 無錄影檔時掛上「未設定或錄影失敗」的分辨說明（同 SessionSpanBars） -->
            <span
              :title="
                row.recording_state && row.recording_state !== 'none'
                  ? undefined
                  : $t('auditorWorkbench.recording.noneHint')
              "
            >
              {{ $t(`auditorWorkbench.recording.${row.recording_state || 'none'}`) }}
            </span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="table-block">
      <div class="block-title">
        {{ $t('auditorWorkbench.events.title') }}
      </div>
      <el-table
        :data="events"
        size="small"
        stripe
        row-key="id"
        data-test="events-table"
        :row-class-name="rowClass"
      >
        <el-table-column
          :label="$t('auditorWorkbench.table.time')"
          width="180"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.ts) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('auditorWorkbench.table.type')"
          width="110"
        >
          <template #default="{ row }">
            {{ typeLabel(row.type) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('auditorWorkbench.table.summary')"
          min-width="240"
        >
          <template #default="{ row }">
            <span>{{ summaryText(row) }}</span>
            <span
              v-if="detailText(row)"
              class="detail"
            >{{ detailText(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('auditorWorkbench.table.counterpart')"
          min-width="140"
        >
          <template #default="{ row }">
            {{ row.counterpart ? (row.counterpart.name || `#${row.counterpart.id}`) : '-' }}
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { typeLabel, summaryText, detailText } from './timelineSummary'
import { formatDateTime } from '@/utils/format'

// 純文字降級模式：同一份資料以表格呈現。時序視覺化對螢幕閱讀器與
// 複製貼上都不友善，調查結論常要貼進報告——表格是那條路徑
const props = defineProps({
  events: { type: Array, default: () => [] },
  spans: { type: Array, default: () => [] },
  subject: { type: String, default: 'user' },
  focusId: { type: String, default: '' },
})

const rowClass = ({ row }) => (row.id === props.focusId ? 'focus-row' : '')
</script>

<style scoped>
.table-block {
  margin-bottom: var(--ot-space-md);
}

.block-title {
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
  font-weight: 600;
  margin-bottom: var(--ot-space-sm);
}

.detail {
  display: block;
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  word-break: break-all;
}

:deep(.focus-row) {
  background-color: var(--ot-primary-dim);
}
</style>
