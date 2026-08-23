<template>
  <div class="my-requests">
    <PageHeader
      :title="$t('menu.myRequests')"
      :description="$t('myRequests.headerDesc')"
    >
      <template #actions>
        <el-button @click="fetchAll">
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 有效限時連線：核准後的可連線時窗（到期自動失效，不影響進行中連線） -->
    <div
      v-if="activeTickets.length > 0"
      class="list-panel ticket-panel"
    >
      <div class="panel-title">
        {{ $t('myRequests.activeTicketsTitle') }}
      </div>
      <el-table
        :data="activeTickets"
        style="width: 100%"
      >
        <el-table-column
          :label="$t('common.asset')"
          min-width="180"
        >
          <template #default="{ row }">
            {{ row.asset?.name || $t('common.assetRef', { id: row.asset_id }) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.connectableTime')"
          min-width="300"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.date_start) }} ～ {{ formatDateTime(row.date_expired) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.status')"
          width="120"
        >
          <template #default>
            <el-tag type="success">
              {{ $t('myRequests.connectable') }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 申請列表：在途與歷史 -->
    <div class="list-panel">
      <el-table
        v-loading="loading"
        :data="requests"
        style="width: 100%"
        stripe
      >
        <el-table-column
          :label="$t('common.asset')"
          min-width="180"
        >
          <template #default="{ row }">
            {{ row.asset?.name || $t('common.assetRef', { id: row.asset_id }) }}
            <el-tag
              v-if="row.kind === 'break_glass'"
              type="danger"
              size="small"
              effect="plain"
            >
              {{ $t('common.emergency') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.requestReason')"
          min-width="200"
          show-overflow-tooltip
          prop="reason"
        />
        <el-table-column
          :label="$t('myRequests.colDuration')"
          width="110"
        >
          <template #default="{ row }">
            {{ formatMinutes(row.requested_duration_minutes) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.requestTime')"
          width="170"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.status')"
          width="120"
        >
          <template #default="{ row }">
            <el-tooltip
              :content="statusTooltip(row)"
              :disabled="!statusTooltip(row)"
              placement="top"
            >
              <el-tag :type="displayStatusTagType(row)">
                {{ displayStatusText(row) }}
              </el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('myRequests.colResult')"
          min-width="180"
        >
          <template #default="{ row }">
            <span v-if="row.revoked_at">
              {{ $t('myRequests.revokedAt', {
                time: formatDateTime(row.revoked_at),
                note: row.revoke_note ? $t('myRequests.revokeNoteSuffix', { note: row.revoke_note }) : '',
              }) }}
            </span>
            <span v-else-if="row.status === 'approved'">
              {{ decisionSummary(row) }}
            </span>
            <span v-else-if="row.status === 'rejected'">
              {{ row.decision_note || '—' }}
            </span>
            <span v-else-if="row.status === 'pending' && (row.approvals_required || 1) > 1">
              {{ $t('myRequests.pendingQuorum', { received: row.approvals_received, required: row.approvals_required }) }}
            </span>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <!-- fixed right：欄寬總和逾 1060px，常見視窗溢寬會使撤回入口消失（Assets 同型教訓） -->
        <el-table-column
          :label="$t('common.actions')"
          width="100"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              v-if="row.status === 'pending'"
              link
              type="danger"
              size="small"
              @click="handleCancel(row)"
            >
              {{ $t('myRequests.cancel') }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            :title="$t('myRequests.emptyTitle')"
            :hint="$t('myRequests.emptyHint')"
          />
        </template>
      </el-table>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { t } from '@/i18n'
import {
  getMyAccessRequests,
  getMyActiveTickets,
  cancelAccessRequest,
} from '@/api/accessRequests'

const loading = ref(false)
const requests = ref([])
const activeTickets = ref([])

const fetchAll = async () => {
  loading.value = true
  try {
    const [reqRes, ticketRes] = await Promise.all([
      getMyAccessRequests(),
      getMyActiveTickets(),
    ])
    requests.value = reqRes.data || []
    activeTickets.value = ticketRes.data || []
  } catch (error) {
    console.error('載入我的申請失敗:', error)
  } finally {
    loading.value = false
  }
}

// 撤回：二次確認（僅 pending 可撤；競態由後端 CAS 判 409，攔截器顯示訊息）
const handleCancel = async (row) => {
  try {
    await ElMessageBox.confirm(
      t('myRequests.cancelConfirm', { name: row.asset?.name || t('common.assetRef', { id: row.asset_id }) }),
      t('myRequests.cancelTitle'),
      {
        confirmButtonText: t('myRequests.cancel'),
        cancelButtonText: t('myRequests.cancelNo'),
        type: 'warning',
      }
    )
  } catch {
    return
  }

  try {
    await cancelAccessRequest(row.id)
    ElMessage.success(t('myRequests.cancelled'))
  } catch (error) {
    console.error('撤回申請失敗:', error)
  } finally {
    fetchAll()
  }
}

// 狀態文案（白話）：pending=等候審核、approved=已核准、rejected=未核准、
// cancelled=已撤回、expired=逾時未處理
const statusText = (status) => {
  const map = {
    pending: t('myRequests.status.pending'),
    approved: t('myRequests.status.approved'),
    rejected: t('myRequests.status.rejected'),
    cancelled: t('myRequests.status.cancelled'),
    expired: t('myRequests.status.expired'),
  }
  return map[status] || status
}

const statusTagType = (status) => {
  const map = {
    pending: 'warning',
    approved: 'success',
    rejected: 'danger',
    cancelled: 'info',
    expired: 'info',
  }
  return map[status] || 'info'
}

// 已撤銷的核准單顯示「已提前撤銷」而非「已核准」
//（撤銷是附註不是狀態轉移，前端據 revoked_at 覆蓋顯示）
const displayStatusText = (row) => {
  if (row.revoked_at && row.status === 'approved') return t('myRequests.statusRevoked')
  return statusText(row.status)
}

const displayStatusTagType = (row) => {
  if (row.revoked_at && row.status === 'approved') return 'info'
  return statusTagType(row.status)
}

const statusTooltip = (row) => {
  if (row.revoked_at && row.status === 'approved') return t('myRequests.tooltipRevoked')
  if (row.status === 'pending') return t('myRequests.tooltipPending')
  if (row.status === 'expired') return t('myRequests.tooltipExpired')
  return ''
}

// 核准摘要：自動核准可辨識；顯示實際核准的時窗
const decisionSummary = (row) => {
  const who = row.auto_approved
    ? t('common.systemAutoApproved')
    : t('myRequests.approvedBy', { name: row.approver?.username || t('myRequests.approverFallback') })
  const duration = row.approved_duration_minutes
    ? formatMinutes(row.approved_duration_minutes)
    : ''
  return duration ? t('myRequests.decisionWithDuration', { who, duration }) : who
}

const formatMinutes = (minutes) => {
  if (!minutes && minutes !== 0) return '—'
  if (minutes < 60) return t('common.minutesN', { n: minutes })
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  return rest === 0
    ? t('common.hoursN', { n: hours })
    : t('common.hoursMinutes', { h: hours, m: rest })
}

onMounted(fetchAll)
</script>

<style scoped>
.my-requests {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-lg);
}

.list-panel {
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-lg);
}

.panel-title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
  margin-bottom: var(--ot-space-md);
}

.ticket-panel {
  border-color: var(--ot-primary-dim);
}
</style>
