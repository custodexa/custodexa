<template>
  <div class="my-requests">
    <PageHeader
      :title="$t('menu.myRequests')"
      :description="$t('myRequests.headerDesc')"
    >
      <template #actions>
        <el-button
          type="primary"
          @click="createVisible = true"
        >
          {{ $t('multiRequest.title') }}
        </el-button>
        <el-button @click="fetchAll">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 表單走抽屜：原本開表單會把列表整個換掉，送出前看不到自己已經有哪些單 -->
    <el-drawer
      v-model="createVisible"
      :title="$t('multiRequest.title')"
      size="60%"
      data-test="create-request-drawer"
      destroy-on-close
    >
      <MultiAssetRequestForm
        v-if="createVisible"
        @cancel="createVisible = false"
        @created="requestCreated"
      />
    </el-drawer>

    <!-- 送出後的結果面板：橫幅文字與顏色依後端回傳的實際狀態決定。
         固定寫「等候審核」會與自動核准的單互相矛盾，讀者無從判斷現在能不能連線。
         逐項結果就地列在同一面板，不必再展開列表比對 -->
    <section
      v-if="created"
      class="list-panel result-panel"
      data-test="request-created"
    >
      <el-alert
        :type="createdAlertType"
        :title="createdTitle"
        :closable="true"
        show-icon
        @close="created = null"
      />
      <RequestItems
        v-if="created.items?.length"
        :request="created"
        data-test="request-created-items"
      />
      <a href="#my-requests-list">{{ $t('myRequests.createdGoToList') }}</a>
    </section>

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
    <div
      id="my-requests-list"
      class="list-panel"
    >
      <!-- 不加 stripe：斑馬列的底色是 bg-elevated，撤回（danger 文字）落在上面
           只有 4.36:1，低於 AA；列與列之間本來就有分隔線，底色不必再差一階 -->
      <el-table
        v-loading="loading"
        v-expand-row-a11y
        :data="requests"
        style="width: 100%"
      >
        <el-table-column type="expand">
          <template #default="{ row }">
            <RequestItems :request="row" />
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('multiRequest.task')"
          min-width="110"
        >
          <template #default="{ row }">
            <a
              v-if="(row.items || []).some(i => i.status === 'approved') || row.status === 'approved'"
              :href="`/audit/agent-tasks/${row.id}`"
              data-test="request-task"
            >{{ $t('agentTasks.detailTitle', { id: row.id }) }}</a><span v-else>{{ $t('agentTasks.detailTitle', { id: row.id }) }}</span><p v-if="row.items">
              {{ $t('multiRequest.count', { n: row.items.length }) }}
            </p>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.asset')"
          min-width="140"
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
          min-width="150"
          prop="reason"
        >
          <template #default="{ row }">
            <span class="reason-cell">{{ row.reason }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('myRequests.colDuration')"
          width="90"
        >
          <template #default="{ row }">
            {{ formatMinutes(row.requested_duration_minutes) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.requestTime')"
          width="150"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.status')"
          width="100"
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
          min-width="200"
          class-name="result-cell"
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
          class-name="actions-cell"
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
import { ref, computed, onMounted } from 'vue'
import { RefreshCw } from 'lucide-vue-next'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import MultiAssetRequestForm from '@/components/access-request/MultiAssetRequestForm.vue'
import RequestItems from '@/components/access-request/RequestItems.vue'
import { expandRowA11y as vExpandRowA11y } from '@/directives/expandRowA11y'
import { formatDateTime } from '@/utils/format'
import { t } from '@/i18n'
import {
  getMyAccessRequests,
  getMyActiveTickets,
  cancelAccessRequest,
} from '@/api/accessRequests'

const createVisible = ref(false)
// 整份回傳而不只是編號：橫幅要講的是「現在是什麼狀態」，那只有回傳的 status
// 與逐項 status 說得準
const created = ref(null)
function requestCreated(result) {
  createVisible.value = false
  created.value = result?.data ?? result ?? null
  fetchAll()
}

// 主旨取申請理由（過長截斷）：編號本身不說明任何事，讀者記得的是自己寫的理由
const createdSubject = computed(() => {
  const reason = (created.value?.reason || '').trim()
  if (!reason) return t('myRequests.createdNoSubject')
  return reason.length > 30 ? `${reason.slice(0, 30)}…` : reason
})

const createdState = computed(() => {
  const request = created.value
  if (!request) return 'pending'
  const items = request.items || []
  if (items.length) {
    const approved = items.filter(item => item.status === 'approved').length
    if (approved === items.length) return 'approved'
    if (approved > 0) return 'partial'
    return 'pending'
  }
  return request.status === 'approved' ? 'approved' : 'pending'
})

const createdTitle = computed(() => t(`myRequests.created.${createdState.value}`, {
  id: created.value?.id,
  subject: createdSubject.value,
}))

// 綠色只留給「真的已經可以連線」；還要等人處理的用警示階，與列表狀態標籤同色系
const createdAlertType = computed(() => createdState.value === 'approved' ? 'success' : 'warning')
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
      t('myRequests.cancelConfirm', { name: row.items?.length > 1 ? t('multiRequest.count', { n: row.items.length }) : row.asset?.name || t('common.assetRef', { id: row.asset_id }) }),
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
  if (row.revoked_at && !row.items?.some(i => i.status === 'approved') && row.status === 'approved') return t('myRequests.statusRevoked')
  return statusText(row.status)
}

const displayStatusTagType = (row) => {
  if (row.revoked_at && !row.items?.some(i => i.status === 'approved') && row.status === 'approved') return 'info'
  return statusTagType(row.status)
}

const statusTooltip = (row) => {
  if (row.revoked_at && !row.items?.some(i => i.status === 'approved') && row.status === 'approved') return t('myRequests.tooltipRevoked')
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
a { color: var(--ot-primary); }
.my-requests {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-lg);
}

/* 版面縱向間距一律由上面的 gap 給；PageHeader 自帶的下緣會與 gap 疊成 48px，
   那不在間距階上 */
.my-requests > :deep(.page-header) {
  margin-bottom: 0;
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

/* 處理結果是「送出之後怎麼了」的唯一出口：不折行就會被右側固定的操作欄蓋掉 */
.list-panel :deep(.result-cell .cell) {
  white-space: normal;
  overflow-wrap: anywhere;
}

/* 理由整段可讀：截斷後要 hover 才看得到全文，稽核時等於把資訊藏起來 */
.reason-cell {
  display: block;
  white-space: normal;
  overflow-wrap: anywhere;
}

.ticket-panel {
  border-color: var(--ot-primary-dim);
}

/* 撤回是這一列唯一的出口：size=small 的 12px 在這張表上太小，提到次要字級階 */
.list-panel :deep(.actions-cell .el-button) {
  font-size: var(--ot-font-size-sm);
}

.result-panel {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
  align-items: flex-start;
}
</style>
