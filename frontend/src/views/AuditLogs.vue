<template>
  <div class="audit-logs-page">
    <PageHeader
      :title="$t('menu.auditLogs')"
      :description="$t('auditLogs.headerDesc')"
    >
      <template #actions>
        <el-button @click="handleRefresh">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
        <el-button
          type="primary"
          @click="openExportDialog"
        >
          <el-icon><Download /></el-icon>
          {{ $t('auditLogs.exportEvidence') }}
        </el-button>
      </template>
    </PageHeader>

    <el-tabs
      v-model="activeTab"
      @tab-change="handleTabChange"
    >
      <!-- 頁籤一：操作日誌（原有內容） -->
      <el-tab-pane
        :label="$t('menu.auditLogs')"
        name="logs"
      >
        <!-- 過濾器面板 -->
        <div class="filter-bar">
          <el-form
            :inline="true"
            :model="filters"
          >
            <el-form-item :label="$t('auditLogs.action')">
              <el-select
                v-model="filters.action"
                clearable
                :placeholder="$t('common.all')"
                style="width: 120px"
                @change="handleSearch"
              >
                <!-- 由 AUDIT_ACTIONS 事實源生成：勿手寫選項 -->
                <el-option
                  v-for="(meta, value) in AUDIT_ACTIONS"
                  :key="value"
                  :label="meta.label"
                  :value="value"
                />
              </el-select>
            </el-form-item>

            <el-form-item :label="$t('auditLogs.resource')">
              <el-select
                v-model="filters.resource"
                clearable
                :placeholder="$t('common.all')"
                style="width: 120px"
                @change="handleSearch"
              >
                <!-- 由 AUDIT_RESOURCES 事實源生成：勿手寫選項（原殭屍 value=alert 已移除） -->
                <el-option
                  v-for="(label, value) in AUDIT_RESOURCES"
                  :key="value"
                  :label="label"
                  :value="value"
                />
              </el-select>
            </el-form-item>

            <el-form-item :label="$t('common.status')">
              <el-select
                v-model="filters.status"
                clearable
                :placeholder="$t('common.all')"
                style="width: 120px"
                @change="handleSearch"
              >
                <!-- 由 AUDIT_STATUS_VALUES 閉集生成，與表格 translateStatus 同 key 源：勿手寫選項 -->
                <el-option
                  v-for="value in AUDIT_STATUS_VALUES"
                  :key="value"
                  :label="translateStatus(value)"
                  :value="value"
                />
              </el-select>
            </el-form-item>

            <el-form-item :label="$t('sessions.timeRange')">
              <el-date-picker
                v-model="timeRange"
                type="datetimerange"
                :range-separator="$t('sessions.rangeSeparator')"
                :start-placeholder="$t('sessions.startTime')"
                :end-placeholder="$t('sessions.endTime')"
                format="YYYY-MM-DD HH:mm"
                value-format="YYYY-MM-DDTHH:mm:ssZ"
                style="width: 360px"
                @change="handleSearch"
              />
            </el-form-item>

            <el-form-item>
              <el-button
                type="primary"
                @click="handleSearch"
              >
                {{ $t('common.search') }}
              </el-button>
              <el-button @click="handleReset">
                {{ $t('common.reset') }}
              </el-button>
              <!-- 完整性驗證入口（PCI 10.3.4）：後端 admin only，前端同步隱藏 -->
              <el-button
                v-if="isAdmin"
                @click="openIntegrityDialog"
              >
                {{ $t('auditLogs.integrityVerify') }}
              </el-button>
            </el-form-item>
          </el-form>
        </div>

        <!-- 資料表格 -->
        <div class="list-card">
          <el-table
            v-loading="loading"
            :data="logs"
            stripe
            style="width: 100%"
          >
            <el-table-column
              prop="created_at"
              :label="$t('common.time')"
              width="180"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.created_at) }}
              </template>
            </el-table-column>

            <el-table-column
              prop="username"
              :label="$t('common.user')"
              width="120"
            />

            <el-table-column
              prop="action"
              :label="$t('auditLogs.action')"
              width="100"
            >
              <template #default="{ row }">
                <el-tag
                  :type="getActionTagType(row.action)"
                  size="small"
                >
                  {{ translateAction(row.action) }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column
              prop="resource"
              :label="$t('auditLogs.resource')"
              width="100"
            >
              <template #default="{ row }">
                {{ translateResource(row.resource) }}
              </template>
            </el-table-column>

            <el-table-column
              prop="status"
              :label="$t('common.status')"
              width="90"
            >
              <template #default="{ row }">
                <el-tag
                  :type="getStatusTagType(row.status)"
                  size="small"
                >
                  {{ translateStatus(row.status) }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column
              prop="client_ip"
              :label="$t('auditLogs.ipAddress')"
              width="140"
            />

            <el-table-column
              prop="duration"
              :label="$t('auditLogs.durationMs')"
              width="100"
            >
              <template #default="{ row }">
                <span v-if="row.duration_ms">{{ row.duration_ms }}ms</span>
                <span v-else>-</span>
              </template>
            </el-table-column>

            <el-table-column
              prop="path"
              :label="$t('auditLogs.path')"
              min-width="200"
              show-overflow-tooltip
            />

            <el-table-column
              :label="$t('common.actions')"
              width="100"
              fixed="right"
            >
              <template #default="{ row }">
                <el-button
                  link
                  type="primary"
                  @click="showDetails(row)"
                >
                  {{ $t('auditLogs.details') }}
                </el-button>
              </template>
            </el-table-column>

            <template #empty>
              <EmptyState
                :title="$t('auditLogs.emptyLogsTitle')"
                :hint="$t('auditLogs.emptyLogsHint')"
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
              @size-change="handleSearch"
              @current-change="handleSearch"
            />
          </div>
        </div>
      </el-tab-pane>

      <!-- 頁籤二：每日簽核歷史（PCI 10.4.1） -->
      <el-tab-pane
        :label="$t('auditLogs.tabReviews')"
        name="reviews"
      >
        <div class="list-card">
          <el-table
            v-loading="reviewsLoading"
            :data="reviews"
            stripe
            style="width: 100%"
          >
            <el-table-column
              :label="$t('auditLogs.dateColumn')"
              width="120"
            >
              <template #default="{ row }">
                {{ (row.review_date || '').slice(0, 10) }}
              </template>
            </el-table-column>

            <el-table-column
              prop="reviewer_name"
              :label="$t('auditLogs.reviewerColumn')"
              width="140"
            />

            <el-table-column
              :label="$t('auditLogs.snapshotCountsColumn')"
              min-width="300"
            >
              <template #default="{ row }">
                <template v-if="snapshotCounts(row).length">
                  <span
                    v-for="item in snapshotCounts(row)"
                    :key="item.label"
                    class="snapshot-count"
                  >{{ item.label }} {{ item.value }}</span>
                </template>
                <span v-else>-</span>
              </template>
            </el-table-column>

            <el-table-column
              prop="note"
              :label="$t('auditLogs.noteColumn')"
              min-width="160"
              show-overflow-tooltip
            />

            <el-table-column
              :label="$t('auditLogs.reviewTimeColumn')"
              width="180"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.created_at) }}
              </template>
            </el-table-column>

            <template #empty>
              <EmptyState
                :title="$t('auditLogs.emptyReviewsTitle')"
                :hint="$t('auditLogs.emptyReviewsHint')"
              />
            </template>
          </el-table>

          <div class="pagination">
            <el-pagination
              v-model:current-page="reviewsPagination.page"
              v-model:page-size="reviewsPagination.page_size"
              :page-sizes="[10, 20, 50]"
              :total="reviewsPagination.total"
              layout="total, sizes, prev, pager, next, jumper"
              @size-change="fetchReviews"
              @current-change="fetchReviews"
            />
          </div>
        </div>
      </el-tab-pane>

      <!-- 頁籤三：審計機制失效事件（PCI 10.7.3） -->
      <el-tab-pane
        :label="$t('auditLogs.tabFailures')"
        name="failures"
      >
        <div class="list-card">
          <el-table
            v-loading="failuresLoading"
            :data="failures"
            stripe
            style="width: 100%"
          >
            <el-table-column
              :label="$t('auditLogs.mechanismColumn')"
              width="160"
            >
              <template #default="{ row }">
                {{ auditMechanismLabel(row.mechanism) }}
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('sessions.startTime')"
              width="180"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.started_at) }}
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('sessions.endTime')"
              width="230"
            >
              <template #default="{ row }">
                <el-tag
                  v-if="!row.ended_at"
                  type="danger"
                  size="small"
                >
                  {{ $t('auditLogs.failureOngoing') }}
                </el-tag>
                <template v-else>
                  <el-tag
                    type="success"
                    size="small"
                  >
                    {{ $t('auditLogs.failureRecovered') }}
                  </el-tag>
                  {{ formatDateTime(row.ended_at) }}
                </template>
              </template>
            </el-table-column>

            <!-- cause_code 為權威表述，散文 cause
                 欄降為未知碼／存量資料的 fallback -->
            <el-table-column
              :label="$t('auditLogs.causeColumn')"
              min-width="180"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                {{ auditCauseLabel(row.cause_code, row.cause) }}
              </template>
            </el-table-column>

            <el-table-column
              prop="details"
              :label="$t('auditLogs.details')"
              min-width="200"
              show-overflow-tooltip
            />

            <template #empty>
              <EmptyState
                :title="$t('auditLogs.emptyFailuresTitle')"
                :hint="$t('auditLogs.emptyFailuresHint')"
              />
            </template>
          </el-table>

          <div class="pagination">
            <el-pagination
              v-model:current-page="failuresPagination.page"
              v-model:page-size="failuresPagination.page_size"
              :page-sizes="[10, 20, 50]"
              :total="failuresPagination.total"
              layout="total, sizes, prev, pager, next, jumper"
              @size-change="fetchFailures"
              @current-change="fetchFailures"
            />
          </div>
        </div>
      </el-tab-pane>
    </el-tabs>

    <!-- 詳情對話框 -->
    <!-- 稽核證據匯出對話框（audit-workflows）：ZIP=日誌+指令+錄影+manifest(SHA-256) -->
    <el-dialog
      v-model="exportDialogVisible"
      :title="$t('auditLogs.exportDialogTitle')"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-alert
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
      >
        {{ $t('auditLogs.exportDialogInfo') }}
      </el-alert>
      <el-form
        label-position="top"
        :model="exportForm"
      >
        <el-form-item :label="$t('sessions.timeRange')">
          <el-date-picker
            v-model="exportTimeRange"
            type="datetimerange"
            :range-separator="$t('sessions.rangeSeparator')"
            :start-placeholder="$t('sessions.startTime')"
            :end-placeholder="$t('sessions.endTime')"
            format="YYYY-MM-DD HH:mm"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item :label="$t('auditLogs.userId')">
          <el-input-number
            v-model="exportForm.user_id"
            :min="1"
            :controls="false"
            :placeholder="$t('common.optional')"
            style="width: 160px"
          />
        </el-form-item>
        <el-form-item :label="$t('auditLogs.assetId')">
          <el-input-number
            v-model="exportForm.asset_id"
            :min="1"
            :controls="false"
            :placeholder="$t('common.optional')"
            style="width: 160px"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="exportDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="exporting"
          @click="submitExport"
        >
          {{ $t('auditLogs.exportZip') }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="detailsVisible"
      :title="$t('auditLogs.detailsTitle')"
      width="680px"
      :close-on-click-modal="false"
    >
      <el-descriptions
        v-if="selectedLog"
        :column="2"
        border
      >
        <el-descriptions-item label="ID">
          {{ selectedLog.id }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('common.time')">
          {{ formatDateTime(selectedLog.created_at) }}
        </el-descriptions-item>

        <el-descriptions-item :label="$t('auditLogs.userId')">
          {{ selectedLog.user_id }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('common.username')">
          {{ selectedLog.username }}
        </el-descriptions-item>

        <el-descriptions-item :label="$t('auditLogs.action')">
          <el-tag :type="getActionTagType(selectedLog.action)">
            {{ translateAction(selectedLog.action) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLogs.resource')">
          {{ translateResource(selectedLog.resource) }}
          <span v-if="selectedLog.resource_id"> (ID: {{ selectedLog.resource_id }})</span>
        </el-descriptions-item>

        <el-descriptions-item :label="$t('common.status')">
          <el-tag :type="getStatusTagType(selectedLog.status)">
            {{ translateStatus(selectedLog.status) }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item
          v-if="selectedLog.status_code"
          :label="$t('auditLogs.statusCode')"
        >
          {{ selectedLog.status_code }}
        </el-descriptions-item>

        <el-descriptions-item
          v-if="selectedLog.method"
          :label="$t('auditLogs.httpMethod')"
        >
          {{ selectedLog.method }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('auditLogs.clientIp')">
          {{ selectedLog.client_ip }}
        </el-descriptions-item>

        <el-descriptions-item
          :label="$t('auditLogs.requestPath')"
          :span="2"
        >
          {{ selectedLog.path }}
        </el-descriptions-item>

        <el-descriptions-item
          v-if="selectedLog.request_id"
          :label="$t('auditLogs.requestId')"
          :span="2"
        >
          <code class="inline-code">{{ selectedLog.request_id }}</code>
        </el-descriptions-item>

        <el-descriptions-item
          v-if="selectedLog.duration_ms"
          :label="$t('auditLogs.durationMs')"
        >
          {{ selectedLog.duration_ms }}ms
        </el-descriptions-item>

        <el-descriptions-item
          v-if="selectedLog.request_body"
          :label="$t('auditLogs.requestBody')"
          :span="2"
        >
          <pre class="json-content">{{ formatJSON(selectedLog.request_body) }}</pre>
        </el-descriptions-item>

        <el-descriptions-item
          v-if="selectedLog.details"
          :label="$t('auditLogs.changeDetails')"
          :span="2"
        >
          <div class="changes-content">
            <div
              v-for="(change, index) in parseChanges(selectedLog.details)"
              :key="index"
              class="change-item"
            >
              <strong>{{ change.field }}</strong>:
              <span class="old-value">{{ formatValue(change.old) }}</span>
              →
              <span class="new-value">{{ formatValue(change.new) }}</span>
            </div>
          </div>
        </el-descriptions-item>

        <el-descriptions-item
          v-if="selectedLog.error_msg"
          :label="$t('auditLogs.errorMsg')"
          :span="2"
        >
          <el-alert
            type="error"
            :closable="false"
          >
            {{ selectedLog.error_msg }}
          </el-alert>
        </el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <!-- 完整性驗證對話框（PCI 10.3.4；僅 admin） -->
    <el-dialog
      v-model="integrityDialogVisible"
      :title="$t('auditLogs.integrityTitle')"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-alert
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
      >
        {{ $t('auditLogs.integrityInfo') }}
      </el-alert>

      <el-form :inline="true">
        <el-form-item :label="$t('auditLogs.integrityRangeLabel')">
          <el-date-picker
            v-model="integrityRange"
            type="daterange"
            :range-separator="$t('sessions.rangeSeparator')"
            :start-placeholder="$t('auditLogs.startDatePlaceholder')"
            :end-placeholder="$t('auditLogs.endDatePlaceholder')"
            value-format="YYYY-MM-DD"
            style="width: 280px"
          />
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            :loading="verifying"
            @click="runIntegrityVerify"
          >
            {{ $t('auditLogs.runVerify') }}
          </el-button>
        </el-form-item>
      </el-form>

      <div
        v-if="integrityResult"
        class="integrity-result"
      >
        <div class="integrity-stats">
          <div class="integrity-stat">
            <div class="integrity-stat-value">
              {{ integrityResult.checked ?? 0 }}
            </div>
            <div class="integrity-stat-label">
              {{ $t('auditLogs.integrityChecked') }}
            </div>
          </div>
          <div class="integrity-stat">
            <div class="integrity-stat-value">
              {{ integrityResult.passed ?? 0 }}
            </div>
            <div class="integrity-stat-label">
              {{ $t('auditLogs.integrityPassed') }}
            </div>
          </div>
          <div
            class="integrity-stat"
            :class="{ 'integrity-stat-danger': integrityResult.mismatched > 0 }"
          >
            <div class="integrity-stat-value">
              {{ integrityResult.mismatched ?? 0 }}
            </div>
            <div class="integrity-stat-label">
              {{ $t('auditLogs.integrityMismatched') }}
            </div>
          </div>
          <div class="integrity-stat">
            <div class="integrity-stat-value">
              {{ integrityResult.legacy ?? 0 }}
            </div>
            <div class="integrity-stat-label">
              {{ $t('auditLogs.integrityLegacy') }}
            </div>
          </div>
        </div>

        <el-alert
          v-if="integrityResult.mismatched > 0"
          type="error"
          :closable="false"
          show-icon
        >
          {{ $t('auditLogs.integrityMismatchAlert', {
            n: integrityResult.mismatched,
            ids: (integrityResult.mismatched_ids || []).join($t('common.listSeparator')),
          }) }}
        </el-alert>
        <el-alert
          v-else
          type="success"
          :closable="false"
          show-icon
        >
          {{ $t('auditLogs.integrityAllPassed') }}
        </el-alert>

        <div
          v-if="integrityResult.legacy > 0"
          class="legacy-note"
        >
          {{ $t('auditLogs.integrityLegacyNote', { n: integrityResult.legacy }) }}
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Download, RefreshCw } from 'lucide-vue-next'
import { getAuditLogs } from '@/api/audit'
import { exportAuditEvidence } from '@/api/auditExport'
import { getDailyReviews } from '@/api/dailyReviews'
import { getAuditFailures } from '@/api/auditFailures'
import { verifyAuditIntegrity } from '@/api/auditIntegrity'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import {
  AUDIT_ACTIONS,
  AUDIT_RESOURCES,
  auditActionLabel,
  auditActionTagType,
  auditResourceLabel,
  auditMechanismLabel,
  auditCauseLabel,
} from '@/constants/audit-enums'
import { useRoles } from '@/composables/useRoles'
import { t } from '@/i18n'

const activeTab = ref('logs')

// 完整性驗證僅 admin（後端 admin only）
const { isAdmin } = useRoles()

// 響應式資料
const logs = ref([])
const loading = ref(false)
const detailsVisible = ref(false)
const selectedLog = ref(null)
const timeRange = ref([])

const filters = ref({
  action: null,
  resource: null,
  status: null,
})

const pagination = ref({
  page: 1,
  page_size: 20,
  total: 0,
})

// 查詢日誌
const fetchLogs = async () => {
  loading.value = true
  try {
    const params = {
      page: pagination.value.page,
      page_size: pagination.value.page_size,
    }

    // 添加過濾條件
    if (filters.value.action) params.action = filters.value.action
    if (filters.value.resource) params.resource = filters.value.resource
    if (filters.value.status) params.status = filters.value.status

    // 時間範圍
    if (timeRange.value && timeRange.value.length === 2) {
      params.start_time = timeRange.value[0]
      params.end_time = timeRange.value[1]
    }

    const response = await getAuditLogs(params)
    logs.value = response.data || []
    pagination.value.total = response.total || 0
  } catch (error) {
    console.error('查詢審計日誌失敗:', error)
  } finally {
    loading.value = false
  }
}

// 搜尋處理
const handleSearch = () => {
  pagination.value.page = 1
  fetchLogs()
}

// 重設過濾器
const handleReset = () => {
  filters.value = {
    action: null,
    resource: null,
    status: null,
  }
  timeRange.value = []
  handleSearch()
}

// 重新整理：依目前頁籤重載對應資料（C4）
const handleRefresh = () => {
  if (activeTab.value === 'reviews') fetchReviews()
  else if (activeTab.value === 'failures') fetchFailures()
  else fetchLogs()
}

// 顯示詳情
const showDetails = (log) => {
  selectedLog.value = log
  detailsVisible.value = true
}

// 稽核證據匯出（audit-workflows）
const exportDialogVisible = ref(false)
const exporting = ref(false)
const exportTimeRange = ref([])
const exportForm = ref({ user_id: null, asset_id: null })

const openExportDialog = () => {
  // 預填目前列表的時間範圍作為匯出範圍起點
  exportTimeRange.value = timeRange.value && timeRange.value.length === 2 ? [...timeRange.value] : []
  exportForm.value = { user_id: null, asset_id: null }
  exportDialogVisible.value = true
}

const submitExport = async () => {
  const params = {}
  if (exportTimeRange.value && exportTimeRange.value.length === 2) {
    params.start_time = exportTimeRange.value[0]
    params.end_time = exportTimeRange.value[1]
  }
  if (exportForm.value.user_id) params.user_id = exportForm.value.user_id
  if (exportForm.value.asset_id) params.asset_id = exportForm.value.asset_id

  if (Object.keys(params).length === 0) {
    ElMessage.warning(t('auditLogs.exportScopeRequired'))
    return
  }

  exporting.value = true
  try {
    const blob = await exportAuditEvidence(params)
    // 觸發瀏覽器下載 ZIP
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-evidence-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '')}.zip`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    window.URL.revokeObjectURL(url)
    ElMessage.success(t('auditLogs.exportSuccess'))
    exportDialogVisible.value = false
  } catch (error) {
    // 全域攔截器已 toast 錯誤（C10：頁內不重複）
    console.error('匯出證據包失敗:', error)
  } finally {
    exporting.value = false
  }
}


// 格式化 JSON
const formatJSON = (jsonString) => {
  if (!jsonString) return ''
  try {
    const obj = typeof jsonString === 'string' ? JSON.parse(jsonString) : jsonString
    return JSON.stringify(obj, null, 2)
  } catch {
    return jsonString
  }
}

// 解析變更詳情
const parseChanges = (detailsString) => {
  if (!detailsString) return []
  try {
    const details = typeof detailsString === 'string' ? JSON.parse(detailsString) : detailsString
    return details.changes || []
  } catch {
    return []
  }
}

// 格式化值
const formatValue = (value) => {
  if (value === null || value === undefined) return t('auditLogs.emptyValue')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

// 翻譯操作/資源：constants/audit-enums 唯一事實源
const translateAction = auditActionLabel
const translateResource = auditResourceLabel

// 翻譯狀態（i18n：閉集走 enum.auditStatus、未知值原樣顯示）；
// 篩選下拉與表格同走本閉集，勿手寫選項
const AUDIT_STATUS_VALUES = ['success', 'failure', 'denied']
const translateStatus = (status) =>
  AUDIT_STATUS_VALUES.includes(status) ? t(`enum.auditStatus.${status}`) : status

const getActionTagType = auditActionTagType

// 獲取狀態標籤類型
const getStatusTagType = (status) => {
  const map = {
    success: 'success',
    failure: 'danger',
    denied: 'warning',
  }
  return map[status] || 'info'
}

// —— 每日簽核歷史（PCI 10.4.1）——
const reviews = ref([])
const reviewsLoading = ref(false)
const reviewsPagination = ref({ page: 1, page_size: 20, total: 0 })

const fetchReviews = async () => {
  reviewsLoading.value = true
  try {
    const res = await getDailyReviews({
      page: reviewsPagination.value.page,
      page_size: reviewsPagination.value.page_size,
    })
    reviews.value = res.data?.items || []
    reviewsPagination.value.total = res.data?.total || 0
  } catch (error) {
    console.error('查詢每日簽核歷史失敗:', error)
  } finally {
    reviewsLoading.value = false
  }
}

// 解析簽核快照 JSON 為三計數（解析失敗回空陣列，顯示 -）
const snapshotCounts = (row) => {
  let snap = row.snapshot_json
  if (!snap) return []
  if (typeof snap === 'string') {
    try {
      snap = JSON.parse(snap)
    } catch {
      return []
    }
  }
  return [
    { label: t('common.loginFailures'), value: snap.login_failures ?? 0 },
    { label: t('common.unreviewedAlerts'), value: snap.unreviewed_alerts ?? 0 },
    { label: t('common.highRiskOps'), value: snap.high_risk_ops ?? 0 },
  ]
}

// —— 審計機制失效事件（PCI 10.7.3）——
const failures = ref([])
const failuresLoading = ref(false)
const failuresPagination = ref({ page: 1, page_size: 20, total: 0 })

const fetchFailures = async () => {
  failuresLoading.value = true
  try {
    const res = await getAuditFailures({
      page: failuresPagination.value.page,
      page_size: failuresPagination.value.page_size,
    })
    failures.value = res.data?.items || []
    failuresPagination.value.total = res.data?.total || 0
  } catch (error) {
    console.error('查詢失效事件失敗:', error)
  } finally {
    failuresLoading.value = false
  }
}

// —— 完整性驗證（PCI 10.3.4；僅 admin）——
const integrityDialogVisible = ref(false)
const integrityRange = ref([])
const verifying = ref(false)
const integrityResult = ref(null)

const toDateStr = (d) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`

const openIntegrityDialog = () => {
  // 預設近 7 天（含今日）
  const today = new Date()
  const weekAgo = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 6)
  integrityRange.value = [toDateStr(weekAgo), toDateStr(today)]
  integrityResult.value = null
  integrityDialogVisible.value = true
}

const runIntegrityVerify = async () => {
  if (!integrityRange.value || integrityRange.value.length !== 2) {
    ElMessage.warning(t('auditLogs.integrityRangeRequired'))
    return
  }
  verifying.value = true
  try {
    const res = await verifyAuditIntegrity({
      from: integrityRange.value[0],
      to: integrityRange.value[1],
    })
    integrityResult.value = res.data || null
  } catch (error) {
    console.error('完整性驗證失敗:', error)
  } finally {
    verifying.value = false
  }
}

// tab 切換即 refetch（C8：資料新鮮優先，對齊 Sessions 模式）
const handleTabChange = (tab) => {
  if (tab === 'reviews') fetchReviews()
  else if (tab === 'failures') fetchFailures()
  else fetchLogs()
}

// 初始化
onMounted(() => {
  fetchLogs()
})
</script>

<style scoped>
.audit-logs-page {
  /* MainLayout main-content 已有 padding，此處不重複加 */
}

.filter-bar {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
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

.snapshot-count {
  display: inline-block;
  margin-right: var(--ot-space-md);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

.integrity-result {
  margin-top: var(--ot-space-md);
}

.integrity-stats {
  display: flex;
  gap: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
}

.integrity-stat {
  flex: 1;
  text-align: center;
  padding: var(--ot-space-sm);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.integrity-stat-value {
  font-size: 22px;
  font-weight: 600;
  color: var(--ot-text-primary);
  line-height: 1.3;
}

.integrity-stat-danger .integrity-stat-value {
  color: var(--ot-danger);
}

.integrity-stat-label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.legacy-note {
  margin-top: var(--ot-space-sm);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.json-content {
  background: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  padding: var(--ot-space-sm);
  border-radius: var(--ot-radius-sm);
  font-size: var(--ot-font-size-xs);
  font-family: var(--ot-font-mono);
  color: var(--ot-text-primary);
  max-height: 300px;
  overflow-y: auto;
}

.changes-content {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}

.change-item {
  padding: var(--ot-space-sm);
  background: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-sm);
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}

/* 舊值與新值可能是多行文字（政策的文字型鍵存的是使用者自填的內容）：
   pre-wrap 讓換行照原樣顯示，否則多行值會被折成一行而看不出實際存了什麼 */
.old-value {
  color: var(--ot-danger);
  text-decoration: line-through;
  white-space: pre-wrap;
}

.new-value {
  color: var(--ot-success);
  font-weight: 500;
  white-space: pre-wrap;
}

.inline-code {
  background: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  padding: 2px 6px;
  border-radius: var(--ot-radius-sm);
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-primary);
}
</style>
