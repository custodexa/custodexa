<template>
  <div class="sessions">
    <PageHeader
      :title="$t('menu.sessions')"
      :description="$t('sessions.headerDesc')"
    >
      <template #actions>
        <el-switch
          v-model="autoRefresh"
          :active-text="$t('sessions.autoRefresh')"
          @change="handleAutoRefreshChange"
        />
        <el-button @click="handleRefresh">
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- Tab 切換：活動 Session / 歷史記錄 -->
    <el-tabs
      v-model="activeTab"
      @tab-change="handleTabChange"
    >
      <!-- 活動 Session -->
      <el-tab-pane
        :label="$t('sessions.tabActive')"
        name="active"
      >
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="activeSessions"
            style="width: 100%"
            stripe
          >
            <el-table-column
              prop="id"
              label="ID"
              width="80"
            />
            <el-table-column
              :label="$t('common.user')"
              width="120"
            >
              <template #default="{ row }">
                {{ row.user?.username || '-' }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="150"
            >
              <template #default="{ row }">
                {{ row.asset?.name || '-' }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('assets.host')"
              min-width="150"
            >
              <template #default="{ row }">
                {{ row.asset?.host || '-' }}:{{ row.asset?.port || '-' }}
              </template>
            </el-table-column>
            <!-- 連線帳號（asset-multi-account D7）：連線當下的 username 快照，
                 帳號日後改名／刪除不改寫此欄 -->
            <el-table-column
              :label="$t('sessions.accountColumn')"
              min-width="120"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                <span
                  v-if="row.account_username"
                  class="account-cell"
                >{{ row.account_username }}</span>
                <span v-else>-</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.protocol')"
              width="80"
            >
              <template #default="{ row }">
                <el-tag :type="protocolTagType(row.protocol)">
                  {{ row.protocol.toUpperCase() }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.clientIp')"
              width="140"
            >
              <template #default="{ row }">
                {{ row.client_ip || '-' }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.startTime')"
              width="170"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.start_time) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.duration')"
              width="120"
            >
              <template #default="{ row }">
                {{ formatDuration(row.start_time) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.actions')"
              width="190"
              fixed="right"
            >
              <template #default="{ row }">
                <!-- 會中錄影失敗警示（fixed right 恆可見）：不做自動斷線（L3
                     裁決）的前提是 admin 看得到才能人工處置強制斷線 -->
                <el-tooltip
                  v-if="row.recording_error"
                  :content="$t('sessions.recordingErrorTooltip', { error: auditCauseLabel(row.recording_error) })"
                  placement="top"
                >
                  <el-tag
                    type="danger"
                    size="small"
                    style="margin-right: 8px"
                  >
                    {{ $t('sessions.recordingFailed') }}
                  </el-tag>
                </el-tooltip>
                <el-button
                  v-if="isTextTerminal(row.protocol)"
                  type="primary"
                  size="small"
                  link
                  @click="handleMonitor(row)"
                >
                  <el-icon><View /></el-icon>
                  {{ $t('sessions.monitor') }}
                </el-button>
                <el-button
                  type="danger"
                  size="small"
                  link
                  @click="handleTerminate(row)"
                >
                  <el-icon><Close /></el-icon>
                  {{ $t('sessions.terminate') }}
                </el-button>
              </template>
            </el-table-column>

            <template #empty>
              <EmptyState
                :title="$t('sessions.emptyActiveTitle')"
                :hint="$t('sessions.emptyActiveHint')"
              />
            </template>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 歷史記錄 -->
      <el-tab-pane
        :label="$t('sessions.tabHistory')"
        name="history"
      >
        <!-- 過濾器 -->
        <div class="filter-bar">
          <el-form
            :inline="true"
            :model="filterForm"
          >
            <el-form-item :label="$t('common.protocol')">
              <el-select
                v-model="filterForm.protocol"
                :placeholder="$t('common.all')"
                clearable
                style="width: 120px"
                @change="handleFilter"
              >
                <!-- 由協議事實源生成（role-enum-metadata-sync）：7 協議全覆蓋 -->
                <el-option
                  v-for="(port, proto) in PROTOCOL_DEFAULT_PORTS"
                  :key="proto"
                  :label="proto.toUpperCase()"
                  :value="proto"
                />
              </el-select>
            </el-form-item>
            <el-form-item :label="$t('common.status')">
              <el-select
                v-model="filterForm.status"
                :placeholder="$t('common.all')"
                clearable
                style="width: 120px"
                @change="handleFilter"
              >
                <el-option
                  :label="$t('common.stateActive')"
                  value="active"
                />
                <el-option
                  :label="$t('common.stateEnded')"
                  value="closed"
                />
                <el-option
                  :label="$t('sessions.statusInterrupted')"
                  value="disconnected"
                />
              </el-select>
            </el-form-item>
            <el-form-item :label="$t('sessions.timeRange')">
              <el-date-picker
                v-model="dateRange"
                type="datetimerange"
                :range-separator="$t('sessions.rangeSeparator')"
                :start-placeholder="$t('sessions.startTime')"
                :end-placeholder="$t('sessions.endTime')"
                @change="handleFilter"
              />
            </el-form-item>
            <el-form-item>
              <el-button
                type="primary"
                @click="handleFilter"
              >
                <el-icon><Search /></el-icon>
                {{ $t('common.search') }}
              </el-button>
              <el-button @click="handleResetFilter">
                <el-icon><Refresh /></el-icon>
                {{ $t('common.reset') }}
              </el-button>
            </el-form-item>
          </el-form>
        </div>

        <!-- 歷史列表 -->
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="sessionList"
            style="width: 100%"
            stripe
          >
            <el-table-column
              prop="id"
              label="ID"
              width="80"
            />
            <el-table-column
              :label="$t('common.user')"
              width="120"
            >
              <template #default="{ row }">
                {{ row.user?.username || '-' }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="150"
            >
              <template #default="{ row }">
                {{ row.asset?.name || '-' }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('assets.host')"
              min-width="150"
            >
              <template #default="{ row }">
                {{ row.asset?.host || '-' }}:{{ row.asset?.port || '-' }}
              </template>
            </el-table-column>
            <!-- 連線帳號（asset-multi-account D7）：連線當下的 username 快照，
                 帳號日後改名／刪除不改寫此欄 -->
            <el-table-column
              :label="$t('sessions.accountColumn')"
              min-width="120"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                <span
                  v-if="row.account_username"
                  class="account-cell"
                >{{ row.account_username }}</span>
                <span v-else>-</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.protocol')"
              width="80"
            >
              <template #default="{ row }">
                <el-tag :type="protocolTagType(row.protocol)">
                  {{ row.protocol.toUpperCase() }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.status')"
              width="100"
            >
              <template #default="{ row }">
                <el-tag :type="getStatusTagType(row.status)">
                  {{ getStatusText(row.status) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.endReason')"
              width="110"
            >
              <template #default="{ row }">
                <el-tag
                  v-if="row.status !== 'active'"
                  :type="getEndReasonTagType(row.end_reason)"
                >
                  {{ getEndReasonText(row.end_reason) }}
                </el-tag>
                <span v-else>-</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.clientIp')"
              width="140"
            >
              <template #default="{ row }">
                {{ row.client_ip || '-' }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.startTime')"
              width="170"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.start_time) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.endTime')"
              width="170"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.end_time) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.duration')"
              width="120"
            >
              <template #default="{ row }">
                {{ formatDurationSeconds(row.duration) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.recordingColumn')"
              width="90"
            >
              <template #default="{ row }">
                <!-- 無錄影額外標示（recording-failure-handling D3）：
                     缺錄影必須可見，不得只是播放鈕沉默消失 -->
                <el-tooltip
                  v-if="row.recording_error"
                  :content="$t('sessions.recordingErrorTooltip', { error: auditCauseLabel(row.recording_error) })"
                  placement="top"
                >
                  <el-tag
                    type="danger"
                    size="small"
                  >
                    {{ $t('sessions.noRecording') }}
                  </el-tag>
                </el-tooltip>
                <el-icon
                  v-else-if="row.has_recording"
                  style="color: var(--ot-success)"
                >
                  <VideoPlay />
                </el-icon>
                <span v-else>-</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.actions')"
              width="120"
              fixed="right"
            >
              <template #default="{ row }">
                <el-button
                  v-if="row.has_recording"
                  type="primary"
                  size="small"
                  link
                  @click="handleViewRecording(row)"
                >
                  <el-icon><VideoPlay /></el-icon>
                  {{ $t('sessions.viewRecording') }}
                </el-button>
                <!-- 操作欄 fixed right 恆可見——無錄影標示在此兜底，
                     不因表格溢寬把「錄製」欄推出視窗而不可見 -->
                <el-tooltip
                  v-else-if="row.recording_error"
                  :content="$t('sessions.recordingErrorTooltip', { error: auditCauseLabel(row.recording_error) })"
                  placement="top"
                >
                  <el-tag
                    type="danger"
                    size="small"
                  >
                    {{ $t('sessions.noRecording') }}
                  </el-tag>
                </el-tooltip>
                <span v-else>-</span>
              </template>
            </el-table-column>

            <template #empty>
              <EmptyState
                :title="$t('sessions.emptyHistoryTitle')"
                :hint="$t('sessions.emptyHistoryHint')"
              />
            </template>
          </el-table>

          <!-- 分頁 -->
          <div class="pagination">
            <el-pagination
              v-model:current-page="pagination.page"
              v-model:page-size="pagination.page_size"
              :page-sizes="[10, 20, 50, 100]"
              :total="pagination.total"
              layout="total, sizes, prev, pager, next, jumper"
              @size-change="handleSizeChange"
              @current-change="handlePageChange"
            />
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Refresh,
  Search,
  Close,
  VideoPlay,
  View,
} from '@element-plus/icons-vue'
import {
  getSessionList,
  getActiveSessions,
  terminateSession,
} from '@/api/sessions'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { isTextTerminal, protocolTagType, PROTOCOL_DEFAULT_PORTS } from '@/utils/protocol'
import { getEndReasonText, getEndReasonTagType } from '@/utils/end-reason'
import { formatDateTime, formatDurationSeconds } from '@/utils/format'
import { t } from '@/i18n'
import { auditCauseLabel } from '@/constants/audit-enums'

const router = useRouter()

// Tab 狀態
const activeTab = ref('active')

// 資料狀態
const loading = ref(false)
const activeSessions = ref([])
const sessionList = ref([])
const pagination = reactive({
  page: 1,
  page_size: 20,
  total: 0,
})

// 過濾表單
const filterForm = reactive({
  protocol: '',
  status: '',
})
const dateRange = ref(null)

// 自動刷新
const autoRefresh = ref(true)
let refreshTimer = null

// 取得活動 Session
const fetchActiveSessions = async () => {
  loading.value = true
  try {
    const sessions = await getActiveSessions()
    activeSessions.value = sessions
  } catch (error) {
    console.error('取得活動 Session 失敗:', error)
  } finally {
    loading.value = false
  }
}

// 取得 Session 歷史列表
const fetchSessionList = async () => {
  loading.value = true
  try {
    const params = {
      page: pagination.page,
      page_size: pagination.page_size,
      protocol: filterForm.protocol || undefined,
      status: filterForm.status || undefined,
    }

    // 處理時間範圍
    if (dateRange.value && dateRange.value.length === 2) {
      params.start_time = dateRange.value[0].toISOString()
      params.end_time = dateRange.value[1].toISOString()
    }

    const response = await getSessionList(params)
    sessionList.value = response.data
    pagination.total = response.total
  } catch (error) {
    console.error('取得 Session 列表失敗:', error)
  } finally {
    loading.value = false
  }
}

// 處理 Tab 切換
const handleTabChange = (tabName) => {
  if (tabName === 'active') {
    fetchActiveSessions()
  } else {
    fetchSessionList()
  }
}

// 處理刷新
const handleRefresh = () => {
  if (activeTab.value === 'active') {
    fetchActiveSessions()
  } else {
    fetchSessionList()
  }
}

// 處理自動刷新
const handleAutoRefreshChange = (value) => {
  if (value) {
    startAutoRefresh()
  } else {
    stopAutoRefresh()
  }
}

// 開始自動刷新
const startAutoRefresh = () => {
  if (refreshTimer) return
  refreshTimer = setInterval(() => {
    if (activeTab.value === 'active') {
      fetchActiveSessions()
    }
  }, 5000) // 每 5 秒刷新一次
}

// 停止自動刷新
const stopAutoRefresh = () => {
  if (refreshTimer) {
    clearInterval(refreshTimer)
    refreshTimer = null
  }
}

// 處理過濾
const handleFilter = () => {
  pagination.page = 1
  fetchSessionList()
}

// 重置過濾
const handleResetFilter = () => {
  filterForm.protocol = ''
  filterForm.status = ''
  dateRange.value = null
  pagination.page = 1
  fetchSessionList()
}

// 處理分頁大小變更
const handleSizeChange = () => {
  fetchSessionList()
}

// 處理頁碼變更
const handlePageChange = () => {
  fetchSessionList()
}

// 處理強制斷線
// 開啟唯讀即時監看（僅 SSH 活動會話；後端限 admin/auditor 角色）
// 分頁模型：監看開新分頁，會話列表留在原分頁
const handleMonitor = (row) => {
  window.open(`/sessions/${row.id}/monitor`, '_blank')
}

const handleTerminate = async (row) => {
  try {
    await ElMessageBox.confirm(
      t('sessions.terminateConfirm', { name: row.user?.username }),
      t('sessions.terminateConfirmTitle'),
      {
        confirmButtonText: t('common.confirm'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await terminateSession(row.id)
    ElMessage.success(t('sessions.terminated'))
    fetchActiveSessions()
  } catch (error) {
    console.error('強制斷線失敗:', error)
  }
}

// 處理檢視錄製
const handleViewRecording = (row) => {
  router.push(`/sessions/${row.id}`)
}

// 狀態標籤類型
const getStatusTagType = (status) => {
  const typeMap = {
    active: 'success',
    closed: 'info',
    disconnected: 'danger',
  }
  return typeMap[status] || ''
}

// 狀態文字（i18n：閉集走 enum.sessionStatus、未知值原樣顯示）
const SESSION_STATUS_VALUES = ['active', 'closed', 'disconnected']
const getStatusText = (status) =>
  SESSION_STATUS_VALUES.includes(status) ? t(`enum.sessionStatus.${status}`) : status


// 格式化持續時間（從開始時間計算）
const formatDuration = (startTime) => {
  if (!startTime) return '-'
  const start = new Date(startTime)
  const now = new Date()
  const seconds = Math.floor((now - start) / 1000)
  return formatDurationSeconds(seconds)
}


// 掛載時取得資料
onMounted(() => {
  fetchActiveSessions()
  if (autoRefresh.value) {
    startAutoRefresh()
  }
})

// 卸載時停止自動刷新
onUnmounted(() => {
  stopAutoRefresh()
})
</script>

<style scoped>
.sessions {
  /* MainLayout already provides padding via --ot-space-lg */
}

.account-cell {
  font-family: var(--ot-font-mono, monospace);
}

.filter-bar {
  margin-bottom: var(--ot-space-md);
  padding: var(--ot-space-md);
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.list-panel {
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
  min-height: 400px;
}

.pagination {
  margin-top: var(--ot-space-md);
  display: flex;
  justify-content: flex-end;
}
</style>
