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
          :label="$t('auditorWorkbench.table.clientIp')"
          width="170"
        >
          <template #default="{ row }">
            <SourceAddressCell
              :address="row.client_ip"
              :reason="row.client_ip_reason"
              event-type="session"
              :link="addressLink(row)"
            />
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
            <!-- 經由 API token 的操作：與時間軸檢視同一句，複製進報告時不丟歸因 -->
            <span
              v-if="row.api_token_name && subject !== 'ip'"
              class="via"
              data-test="table-via"
            >{{ viaText(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column
          v-if="subject === 'ip'"
          :label="$t('auditorWorkbench.table.actor')"
          min-width="140"
        >
          <template #default="{ row }">
            {{ !row.actor
              ? $t('auditorWorkbench.events.actorUnauthenticated')
              : row.api_token_name
                ? viaText(row)
                : (row.actor.name || `#${row.actor.id}`) }}
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
        <el-table-column
          :label="$t('auditorWorkbench.table.clientIp')"
          width="170"
        >
          <template #default="{ row }">
            <SourceAddressCell
              :address="row.client_ip"
              :reason="row.client_ip_reason"
              :event-type="row.type"
              :link="addressLink(row)"
            />
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { useI18n } from 'vue-i18n'
import SourceAddressCell from './SourceAddressCell.vue'
import { buildAddressPivotLink } from './timelineQuery'
import { typeLabel, summaryText, detailText } from './timelineSummary'
import { formatDateTime } from '@/utils/format'

// 純文字降級模式：同一份資料以表格呈現。時序視覺化對螢幕閱讀器與
// 複製貼上都不友善，調查結論常要貼進報告——表格是那條路徑
const props = defineProps({
  events: { type: Array, default: () => [] },
  spans: { type: Array, default: () => [] },
  subject: { type: String, default: 'user' },
  // 人樞紐的事件不帶 actor：操作者即調查對象本人，經由 token 的註記要用到這個名字
  subjectName: { type: String, default: '' },
  focusId: { type: String, default: '' },
  // 深連結要保留的調查範圍（與時間軸檢視同一組）
  from: { type: String, default: '' },
  to: { type: String, default: '' },
  types: { type: Array, default: () => [] },
})

const { t } = useI18n()

// 操作者取名規則與時間軸檢視一致：actor → 對造為人時取對造 → 人樞紐取調查對象
const operatorName = (row) => {
  if (row.actor) return row.actor.name || `#${row.actor.id}`
  const cp = row.counterpart
  if (cp && cp.kind === 'user') return cp.name || `#${cp.id}`
  return props.subject === 'user' ? props.subjectName : ''
}
const viaText = (row) =>
  t('auditorWorkbench.events.operatorVia', { user: operatorName(row), name: row.api_token_name })

const rowClass = ({ row }) => (row.id === props.focusId ? 'focus-row' : '')

// 位址深連結行為與時間軸檢視逐字相同：人／資產樞紐下可點、位址樞紐下與
// 未知來源不加連結。兩個檢視分岔就等於同一份資料有兩套規則
const addressLink = (row) => {
  if (props.subject === 'ip' || !row?.client_ip) return null
  return buildAddressPivotLink(row.client_ip, {
    from: props.from,
    to: props.to,
    types: props.types,
  })
}
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

.via {
  display: block;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

:deep(.focus-row) {
  background-color: var(--ot-primary-dim);
}
</style>
