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
          :aria-label="$t('sessions.autoRefresh')"
          @change="handleAutoRefreshChange"
        />
        <el-button @click="handleRefresh">
          <el-icon><RefreshCw /></el-icon>
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
            <!-- 編號帶類型：單獨一格「118」讀不出是什麼的編號 -->
            <el-table-column
              prop="id"
              :label="$t('common.idColumn')"
              width="120"
            >
              <template #default="{ row }">
                {{ $t('common.sessionRef', { id: row.id }) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.actorColumn')"
              min-width="180"
            >
              <template #default="{ row }">
                <div>{{ row.user?.username || $t('agentPrincipals.unavailable') }}</div>
                <PrincipalBadge
                  :kind="row.actor_kind || ''"
                  :owner-id="row.owner_user_id"
                  :owner-name="row.owner_username"
                />
              </template>
            </el-table-column>
            <!-- 代表人：agent 是替誰做的。沒有這欄，列表答不出「替誰」 -->
            <el-table-column
              :label="$t('agentSession.onBehalf')"
              min-width="120"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                <span data-test="session-on-behalf">{{ onBehalfText(row) }}</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('multiRequest.task')"
              min-width="160"
            >
              <template #default="{ row }">
                <el-tooltip
                  v-if="row.access_request_id"
                  :content="taskReasons[row.access_request_id] || $t('agentTasks.reason')"
                  :disabled="!taskReasons[row.access_request_id]"
                  placement="top"
                >
                  <a
                    :href="`/audit/agent-tasks/${row.access_request_id}`"
                    data-test="session-task"
                  >{{ $t('agentTasks.detailTitle', { id: row.access_request_id }) }}</a>
                </el-tooltip><span v-else>—</span>
                <p
                  v-if="taskReasons[row.access_request_id]"
                  class="cell-subline"
                  data-test="session-task-subject"
                >
                  {{ taskReasons[row.access_request_id] }}
                </p>
                <p
                  v-if="row.revoked_during_session_at"
                  class="session-revocation-line"
                  data-test="session-revocation"
                >
                  {{ $t('agentSession.revoked', { time: formatDateTime(row.revoked_during_session_at) }) }}
                </p>
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
            <!-- 連線帳號：連線當下的 username 快照，
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
              width="140"
            >
              <template #default="{ row }">
                <el-tag class="ot-tag-neutral">
                  {{ protocolText(row.protocol) }}
                </el-tag>
                <!-- 同一個協議有命令列與查詢主控台兩種載體，錄影形態與
                     指令紀錄的欄位都不同：協議 chip 旁必須看得出是哪一種 -->
                <el-tag
                  v-if="row.db_console"
                  class="console-badge"
                  type="warning"
                  effect="plain"
                  data-test="console-badge"
                >
                  {{ $t('sessions.consoleBadge') }}
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
                <!-- 會中錄影失敗警示（fixed right 恆可見）：不做自動斷線
                     的前提是 admin 看得到才能人工處置強制斷線 -->
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
                  <el-icon><Eye /></el-icon>
                  {{ $t('sessions.monitor') }}
                </el-button>
                <el-button
                  type="danger"
                  size="small"
                  link
                  @click="handleTerminate(row)"
                >
                  <el-icon><X /></el-icon>
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
            <el-form-item :label="$t('agentPrincipals.kind')">
              <el-select
                v-model="filterForm.actor_kind"
                clearable
                :placeholder="$t('common.all')"
                data-test="session-kind-filter"
                style="width: 160px"
                @change="handleFilter"
              >
                <el-option
                  value="human"
                  :label="$t('agentPrincipals.human')"
                />
                <el-option
                  value="agent"
                  :label="$t('agentPrincipals.agent')"
                />
              </el-select>
            </el-form-item>
            <el-form-item :label="$t('common.protocol')">
              <el-select
                v-model="filterForm.protocol"
                :placeholder="$t('common.all')"
                clearable
                style="width: 120px"
                @change="handleFilter"
              >
                <!-- 由協議事實源生成：7 協議全覆蓋 -->
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
                <el-icon><RefreshCw /></el-icon>
                {{ $t('common.reset') }}
              </el-button>
            </el-form-item>
          </el-form>
        </div>

        <!-- 歷史列表 -->
        <div class="list-panel">
          <el-table
            v-loading="loading"
            v-expand-row-a11y
            :data="sessionList"
            class="history-table"
            data-test="history-table"
            style="width: 100%"
            stripe
          >
            <!-- 次要欄位（負責人、來源位址、結束時間、持續時間）收進展開列：
                 每列三行灰字時，首屏的次要文字會多過要讀的主文字 -->
            <el-table-column type="expand">
              <template #default="{ row }">
                <dl
                  class="session-more"
                  data-test="session-more"
                >
                  <dt>{{ $t('common.idColumn') }}</dt>
                  <dd>{{ $t('common.sessionRef', { id: row.id }) }}</dd>
                  <template v-if="row.actor_kind === 'agent'">
                    <dt>{{ $t('agentPrincipals.owner') }}</dt>
                    <dd>{{ row.owner_username || $t('agentPrincipals.unavailable') }}</dd>
                  </template>
                  <dt>{{ $t('sessions.clientIp') }}</dt>
                  <dd>{{ row.client_ip || '-' }}</dd>
                  <dt>{{ $t('sessions.endTime') }}</dt>
                  <dd>{{ formatDateTime(row.end_time) }}</dd>
                  <dt>{{ $t('sessions.duration') }}</dt>
                  <dd>{{ formatDurationSeconds(row.duration) }}</dd>
                  <template v-if="row.revoked_during_session_at">
                    <dt>{{ $t('agentSession.revokedShort') }}</dt>
                    <dd data-test="session-more-revocation">
                      {{ formatDateTime(row.revoked_during_session_at) }}
                    </dd>
                  </template>
                </dl>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('sessions.actorColumn')"
              min-width="130"
            >
              <template #default="{ row }">
                <div
                  class="ident-line"
                  :title="row.user?.username || ''"
                >
                  {{ row.user?.username || $t('agentPrincipals.unavailable') }}
                </div>
                <PrincipalBadge
                  :kind="row.actor_kind || ''"
                  :owner-id="row.owner_user_id"
                  :owner-name="row.owner_username"
                  :show-owner="false"
                />
              </template>
            </el-table-column>
            <!-- 代表人：agent 是替誰做的。沒有這欄，列表答不出「替誰」 -->
            <el-table-column
              :label="$t('agentSession.onBehalf')"
              min-width="90"
              class-name="nowrap-cell"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                <span data-test="session-on-behalf">{{ onBehalfText(row) }}</span>
              </template>
            </el-table-column>
            <!-- 任務欄帶主旨：只有「任務 91」時，讀者仍得點進去才知道那張單在做什麼 -->
            <el-table-column
              :label="$t('multiRequest.task')"
              min-width="120"
            >
              <template #default="{ row }">
                <a
                  v-if="row.access_request_id"
                  :href="`/audit/agent-tasks/${row.access_request_id}`"
                  data-test="session-task"
                >{{ $t('agentTasks.detailTitle', { id: row.access_request_id }) }}</a><span v-else>—</span>
                <p
                  v-if="taskReasons[row.access_request_id]"
                  class="cell-subline"
                  data-test="session-task-subject"
                >
                  {{ taskReasons[row.access_request_id] }}
                </p>
              </template>
            </el-table-column>
            <!-- 工具呼叫次數：原本要進詳情再捲到帳本逐列數，列表直接給總數與擋下數 -->
            <el-table-column
              :label="$t('agentLedger.callsColumn')"
              min-width="80"
            >
              <template #default="{ row }">
                <span
                  v-if="!callCounts[row.id]"
                  data-test="session-calls"
                >—</span>
                <span
                  v-else-if="callCounts[row.id].state === 'loading'"
                  data-test="session-calls"
                >{{ $t('agentTasks.summary.counting') }}</span>
                <span
                  v-else-if="callCounts[row.id].state === 'error'"
                  data-test="session-calls"
                >{{ $t('agentLedger.unknown') }}<el-button
                  link
                  size="small"
                  @click="loadCallCount(row)"
                >{{ $t('common.retry') }}</el-button></span>
                <span
                  v-else
                  data-test="session-calls"
                >{{ $t('agentLedger.callsValue', { n: callCounts[row.id].total }) }}<br>{{ $t('agentLedger.blockedValue', { n: callCounts[row.id].blocked }) }}</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="120"
            >
              <template #default="{ row }">
                {{ row.asset?.name || '-' }}
                <p class="sub-text">
                  {{ row.asset?.host || '-' }}:{{ row.asset?.port || '-' }}
                </p>
              </template>
            </el-table-column>

            <!-- 連線帳號：連線當下的 username 快照，
                 帳號日後改名／刪除不改寫此欄 -->
            <el-table-column
              :label="$t('sessions.accountColumn')"
              min-width="95"
              class-name="nowrap-cell"
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
              min-width="95"
            >
              <template #default="{ row }">
                <el-tag class="ot-tag-neutral">
                  {{ protocolText(row.protocol) }}
                </el-tag>
                <!-- 同一個協議有命令列與查詢主控台兩種載體，錄影形態與
                     指令紀錄的欄位都不同：協議 chip 旁必須看得出是哪一種 -->
                <el-tag
                  v-if="row.db_console"
                  class="console-badge"
                  type="warning"
                  effect="plain"
                  data-test="console-badge"
                >
                  {{ $t('sessions.consoleBadge') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.status')"
              min-width="100"
            >
              <template #default="{ row }">
                <el-tag :type="getStatusTagType(row.status)">
                  {{ getStatusText(row.status) }}
                </el-tag>
                <p
                  v-if="row.status !== 'active'"
                  class="sub-text"
                >
                  {{ getEndReasonText(row.end_reason) }}
                </p>
                <!-- 撤權句原本整句塞進狀態欄：en 折六行、列高 270px。欄內只留
                     彩標＋完整句子的 title，時間另落在展開列，兩處都讀得到 -->
                <!-- 結束原因已是「授權撤銷斷線」時不再掛同義彩標：同一件事說兩次 -->
                <el-tag
                  v-if="row.revoked_during_session_at && row.end_reason !== 'revoked'"
                  type="danger"
                  class="session-revocation"
                  data-test="session-revocation"
                  :title="$t('agentSession.revoked', { time: formatDateTime(row.revoked_during_session_at) })"
                >
                  {{ $t('agentSession.revokedShort') }}
                </el-tag>
              </template>
            </el-table-column>


            <el-table-column
              :label="$t('sessions.startTime')"
              min-width="110"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.start_time) }}
              </template>
            </el-table-column>


            <!-- 錄影狀態與入口併在本欄：原本另立的「錄製」欄與這裡講同一件事，
                 兩欄並存時欄寬預算被佔掉，反而讓操作文字在 en 被裁掉尾字。
                 寬度取三語最長者（en「View Recording」） -->
            <el-table-column
              :label="$t('common.actions')"
              width="140"
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
                  <el-icon><CirclePlay /></el-icon>
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
import { expandRowA11y as vExpandRowA11y } from '@/directives/expandRowA11y'
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  RefreshCw,
  Search,
  X,
  CirclePlay,
  Eye,
} from 'lucide-vue-next'
import {
  getSessionList,
  getActiveSessions,
  terminateSession,
} from '@/api/sessions'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import PrincipalBadge from '@/components/agent/PrincipalBadge.vue'
import { isTextTerminal, PROTOCOL_DEFAULT_PORTS } from '@/utils/protocol'
import { getAgentToolCalls, getAgentTask } from '@/api/agentTasks'
import { getEndReasonText } from '@/utils/end-reason'
import { formatDateTime, formatDurationSeconds } from '@/utils/format'
import { t } from '@/i18n'
import { auditCauseLabel } from '@/constants/audit-enums'

// 代表人只有 agent 會有；後端未投影名稱時退回「—」而不是裸 id
const onBehalfText = (row) => {
  if (row.on_behalf_of_username) return row.on_behalf_of_username
  if (row.on_behalf_of_user_id) return t('agentPrincipals.unavailable')
  return row.actor_kind === 'agent' ? t('agentSession.none') : '—'
}

// 協議碼在首層一律帶人話：SSH／RDP 這類縮寫本身不說明它是什麼連線
const PROTOCOL_KINDS = { ssh: 'terminal', k8s: 'terminal', rdp: 'desktop', vnc: 'desktop', mysql: 'database', postgres: 'database', redis: 'database', mssql: 'database' }
const protocolText = (protocol) => {
  const code = String(protocol || '').toUpperCase()
  const kind = PROTOCOL_KINDS[String(protocol || '').toLowerCase()]
  return kind ? t(`enum.protocolKind.${kind}`, { code }) : code
}

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
  actor_kind: '',
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

// 工具呼叫計數：只對 agent 會話讀，名下沒有紀錄就是 0；讀不到說「未知」並可重試
const callCounts = reactive({})
let countEpoch = 0
const loadCallCount = async (row) => {
  const version = countEpoch
  callCounts[row.id] = { state: 'loading', total: 0, blocked: 0 }
  try {
    const response = await getAgentToolCalls({ session_id: row.id, offset: 0, limit: 500 })
    if (version !== countEpoch) return
    const data = response.data || []
    const blocked = data.filter((call) => ['denied', 'breaker', 'rate_limited'].includes(call.decision)).length
    callCounts[row.id] = { state: 'ok', total: response.total || data.length, blocked }
  } catch {
    if (version === countEpoch) callCounts[row.id] = { state: 'error', total: 0, blocked: 0 }
  }
}
const loadCallCounts = async (rows) => {
  countEpoch += 1
  for (const key of Object.keys(callCounts)) delete callCounts[key]
  const agents = rows.filter((row) => row.actor_kind === 'agent')
  for (let i = 0; i < agents.length; i += 4) await Promise.all(agents.slice(i, i + 4).map(loadCallCount))
}

// 任務主旨：會話契約沒有這一欄，向任務端點補取，只為了讓「任務 N」有 tooltip 說出
// 那張單在做什麼；讀不到就不顯示 tooltip，不猜也不宣稱讀得到
const taskReasons = reactive({})
let reasonEpoch = 0
const loadTaskReasons = async (rows) => {
  reasonEpoch += 1
  const version = reasonEpoch
  for (const key of Object.keys(taskReasons)) delete taskReasons[key]
  const ids = [...new Set(rows.map((row) => row.access_request_id).filter(Boolean))]
  for (let i = 0; i < ids.length; i += 4) {
    await Promise.all(ids.slice(i, i + 4).map(async (id) => {
      try {
        const response = await getAgentTask(id, { limit: 1, offset: 0 })
        if (version === reasonEpoch && response?.request?.reason) taskReasons[id] = response.request.reason
      } catch { /* 讀不到就沒有 tooltip */ }
    }))
  }
}

// 取得 Session 歷史列表
const fetchSessionList = async () => {
  loading.value = true
  try {
    const params = {
      page: pagination.page,
      page_size: pagination.page_size,
      actor_kind: filterForm.actor_kind || undefined,
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
    loadCallCounts(sessionList.value)
    loadTaskReasons(sessionList.value)
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
  filterForm.actor_kind = ''
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
a { color: var(--ot-primary); }
.session-revocation { margin-top: var(--ot-space-xs); }
.session-revocation-line { color: var(--ot-text-primary); font-weight: 600; font-size: var(--ot-font-size-sm); margin: var(--ot-space-sm) 0; }

.console-badge {
  margin-left: 4px;
}

.sessions {
  /* MainLayout already provides padding via --ot-space-lg */
}

/* 元件庫的分頁標頭預設留 15px，不在間距刻度上 */
.sessions :deep(.el-tabs__header) {
  margin-bottom: var(--ot-space-md);
}

/* 展開列：標籤與值成對，值維持主文字階（要讀的是值不是標籤） */
.session-more {
  display: grid;
  grid-template-columns: 10em minmax(0, 1fr);
  gap: var(--ot-space-xs) var(--ot-space-md);
  margin: 0;
  padding: var(--ot-space-md);
}

.session-more dt {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.session-more dd {
  margin: 0;
  color: var(--ot-text-primary);
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
/* anywhere 會把 testuser 這種單詞從中間切成 testuse／r；
   break-word 只在整個單詞放不下時才斷，欄寬已經各自放寬 */
/* break-word 仍會在長識別字沒處斷時從中間切（testuser → testuse／r）。
   改回預設斷行規則（中日文照常逐字換行、西文只在詞界斷），
   放不下的識別欄改單行省略號＋tooltip（nowrap-cell） */
.history-table :deep(.cell) { white-space: normal; overflow-wrap: normal; word-break: normal; }
.history-table :deep(td.nowrap-cell .cell) { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ident-line { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
/* 任務主旨是要讀的內容而不是註腳，留在主文字色，只降字級 */
.cell-subline { color: var(--ot-text-primary); font-size: var(--ot-font-size-sm); margin: var(--ot-space-xs) 0 0; }
.history-table :deep(.el-tag) { height: auto; min-height: 24px; white-space: normal; overflow-wrap: normal; word-break: normal; line-height: 1.4; padding: var(--ot-space-xs); }
.history-table :deep(.el-button) { margin: var(--ot-space-xs); }
/* 操作文字在三語間長短差一倍（en「View Recording」最長）：EP 的按鈕預設
   nowrap，固定欄寬下尾字直接被儲存格裁掉。允許換行，裁切消失 */
.sessions :deep(.el-table .el-button) { white-space: normal; height: auto; }
.history-table .sub-text { color: var(--ot-text-secondary); font-size: var(--ot-font-size-sm); margin: var(--ot-space-xs) 0; }
</style>
