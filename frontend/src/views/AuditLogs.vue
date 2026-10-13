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
                @change="onTimeRangeChange"
              />
              <!-- 由每日簽核抽屜帶入的起訖：尾端是排他條件（隔天 00:00 那一刻屬於下一天）。
                   使用者手動改時間後回到含尾端的一般篩選，這個標示一起消失 -->
              <el-tag
                v-if="endBefore"
                class="end-before-tag"
                type="info"
                effect="plain"
                data-test="end-before-tag"
              >
                {{ $t('dailyReview.logsFilter.endExclusive') }}
              </el-tag>
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

        <!-- 由某個設定的記錄連結進來時，畫面要說得出「現在只看什麼」。
             不說的話，一份被收斂過的日誌看起來就像本來只有這幾列 -->
        <div
          v-if="filters.key"
          class="applied-filter"
        >
          <span>{{ $t('auditLogs.filterKeyNotice', { setting: settingLabel(filters.key) }) }}</span>
          <el-button
            link
            type="primary"
            @click="clearKeyFilter"
          >
            {{ $t('auditLogs.filterKeyClear') }}
          </el-button>
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

      <!-- 頁籤二：每日簽核工作區（PCI 10.4.1）。lazy：切到這個分頁才掛載與取數 -->
      <el-tab-pane
        name="reviews"
        lazy
      >
        <template #label>
          <span class="tab-label-with-badge">
            {{ $t('auditLogs.tabReviews') }}
            <span
              v-if="canSign && reviewBadge.count.value > 0"
              :class="['tab-badge', reviewBadge.overdueCount.value > 0 ? 'tab-badge--danger' : 'tab-badge--warning']"
              data-test="reviews-tab-badge"
            >{{ reviewBadge.count.value }}</span>
          </span>
        </template>
        <DailyReviewWorkspace
          ref="workspaceRef"
          :can-sign="canSign"
          :is-admin="isAdmin"
          :open-date="reviewDate"
        />
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
    <!-- 稽核證據匯出對話框（audit-workflows）：送出非同步打包，產物在下載中心取件 -->
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

        <!-- 沒有變更明細時不留空區塊，改列原因與原始 details -->
        <el-descriptions-item
          v-if="detailBlocks.changes.length"
          :label="$t('auditLogs.changeDetails')"
          :span="2"
        >
          <div class="changes-content">
            <div
              v-for="(change, index) in detailBlocks.changes"
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
          v-if="detailBlocks.showReason"
          :label="$t('auditLogs.reason')"
          :span="2"
        >
          <span data-test="log-reason">{{ reasonText(selectedLog) }}</span>
        </el-descriptions-item>
        <el-descriptions-item
          v-if="detailBlocks.raw"
          :label="$t('auditLogs.detailsRaw')"
          :span="2"
        >
          <pre
            class="json-content"
            data-test="log-details-raw"
          >{{ detailBlocks.raw }}</pre>
        </el-descriptions-item>

        <!-- 成功的操作也可能帶訊息（例如做了什麼替代處置）。把它掛在「錯誤訊息」
             底下並塗成紅色，會讓一筆成功的紀錄在稽核眼裡讀成失敗 -->
        <el-descriptions-item
          v-if="selectedLog.error_msg"
          :label="isSuccessLog(selectedLog)
            ? $t('auditLogs.noticeMsg')
            : $t('auditLogs.errorMsg')"
          :span="2"
        >
          <el-alert
            :type="isSuccessLog(selectedLog) ? 'info' : 'error'"
            :closable="false"
            data-test="log-message"
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
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Download, RefreshCw } from 'lucide-vue-next'
import { getAuditLogs } from '@/api/audit'
import { buildBundleScope, submitEvidenceBundle } from '@/components/audit/evidenceBundleSubmit'
import { getAuditFailures } from '@/api/auditFailures'
import { verifyAuditIntegrity } from '@/api/auditIntegrity'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import DailyReviewWorkspace from '@/components/daily-review/DailyReviewWorkspace.vue'
import { useDailyReviewBadge } from '@/composables/useDailyReviewBadge'
import { formatDateTime } from '@/utils/format'
import { logDetailBlocks, reasonText } from '@/components/daily-review/auditReason'
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
import { settingLabel } from '@/utils/policyClauseText'
import { t } from '@/i18n'

const route = useRoute()
const router = useRouter()
const activeTab = ref('logs')

// 完整性驗證僅 admin（後端 admin only）；簽核權限 alert:manage＝admin／auditor
const { isAdmin, isPrivileged: canSign } = useRoles()
// 分頁標籤的待簽天數：與側欄同一份數字（側欄負責輪詢）
const reviewBadge = useDailyReviewBadge()
const workspaceRef = ref(null)
// 網址帶入的所屬日（?date=），交給工作區開抽屜
const reviewDate = ref('')
// 排他尾端（?end_before=）：只由每日簽核抽屜的連結帶入
const endBefore = ref(null)

// 響應式資料
const logs = ref([])
const loading = ref(false)
const detailsVisible = ref(false)
const selectedLog = ref(null)
const detailBlocks = computed(() => logDetailBlocks(selectedLog.value))
const timeRange = ref([])

const filters = ref({
  action: null,
  resource: null,
  status: null,
  // key 只由網址帶入（畫面上沒有輸入框）：它收斂的是安全政策的變更列，
  // 供稽核人員由設定名一路追到那個設定的變更記錄
  key: null,
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
    if (filters.value.key) params.key = filters.value.key

    // 時間範圍。帶入排他尾端時送 end_before、不送 end_time：每日區間是半開區間，
    // 含尾端會把恰在下一日起點的事件也列進來
    if (timeRange.value && timeRange.value.length === 2) {
      params.start_time = timeRange.value[0]
      if (endBefore.value) params.end_before = endBefore.value
      else params.end_time = timeRange.value[1]
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
    key: null,
  }
  timeRange.value = []
  endBefore.value = null
  handleSearch()
}

// 手動改時間＝回到既有的含尾端篩選
const onTimeRangeChange = () => {
  endBefore.value = null
  handleSearch()
}

// 清除由記錄連結帶進來的篩選。
//
// **鍵與分類一起清**：只有安全政策的變更列帶得出設定鍵，兩者是同一句話的兩半。
// 只清鍵會留下一個「還在只看安全政策」但畫面上不再說明的狀態；分類選單本來就在
// 畫面上，清完之後使用者看得見它回到全部
const clearKeyFilter = () => {
  filters.value.key = null
  filters.value.resource = null
  handleSearch()
}

// 重新整理：依目前頁籤重載對應資料（C4）
const handleRefresh = () => {
  if (activeTab.value === 'reviews') workspaceRef.value?.refresh()
  else if (activeTab.value === 'failures') fetchFailures()
  else fetchLogs()
}

// 顯示詳情
const showDetails = (log) => {
  selectedLog.value = log
  detailsVisible.value = true
}

// 稽核證據匯出（audit-workflows）：證據包只走非同步 job
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
  const scope = buildBundleScope(exportTimeRange.value, exportForm.value)
  if (!scope) {
    ElMessage.warning(t('auditLogs.exportScopeRequired'))
    return
  }
  exporting.value = true
  try {
    if (await submitEvidenceBundle(scope, router)) exportDialogVisible.value = false
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

// 成功的操作：訊息欄的標籤與樣式由它決定（失敗與拒絕仍是錯誤訊息）
const isSuccessLog = (log) => log?.status === 'success'

// 獲取狀態標籤類型
const getStatusTagType = (status) => {
  const map = {
    success: 'success',
    failure: 'danger',
    denied: 'warning',
  }
  return map[status] || 'info'
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
  // 工作區首次掛載時自己取數；之後切回來才由這裡重取
  if (tab === 'reviews') workspaceRef.value?.refresh()
  else if (tab === 'failures') fetchFailures()
  else fetchLogs()
}

// 初始化。
//
// `?tab=failures` 讓別的頁面連得進失效事件頁籤（檢查點驗證頁的角色指派
// 差異即由此連入）。**只認白名單內的值**：未知的 tab 一律落回操作日誌，
// 不讓網址上的字串決定要打哪一支 API
//
// `?resource=` 與 `?key=` 同理，供設定名 → 變更記錄的連結落地即收斂：
// 分類只認既有值域內的值；鍵是設定鍵，長度以政策鍵欄位寬度為界。
const TAB_FROM_QUERY = ['logs', 'reviews', 'failures']
const POLICY_KEY_MAX_LENGTH = 64
const REVIEW_DATE_RE = /^\d{4}-\d{2}-\d{2}$/
// RFC3339：日期、T、時刻與位移（或 Z）；格式不符一律忽略
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/
const isRFC3339 = (value) =>
  typeof value === 'string' && RFC3339_RE.test(value) && Number.isFinite(Date.parse(value))

// 網址參數監聽：初次與之後每次變更都套用。側欄徽章、儀表板卡片與抽屜內的
// 「在操作日誌查看全部」都是同頁改 query，只在掛載時讀一次的話這些入口都會失效
const applyQuery = (query = {}) => {
  const tab = query.tab
  if (typeof tab === 'string' && TAB_FROM_QUERY.includes(tab)) {
    activeTab.value = tab
  }
  // 以自有鍵比對而非 `in`：`in` 連物件原型上的名字（constructor 之類）都算命中，
  // 那些不是分類值，卻會被原樣送給端點
  if (
    typeof query.resource === 'string' &&
    Object.keys(AUDIT_RESOURCES).includes(query.resource)
  ) {
    filters.value.resource = query.resource
  }
  if (
    typeof query.key === 'string' &&
    query.key !== '' &&
    query.key.length <= POLICY_KEY_MAX_LENGTH
  ) {
    filters.value.key = query.key
  }
  // 時間篩選只在操作日誌分頁有效；帶了就整組取代舊的時間篩選
  if (activeTab.value === 'logs' && isRFC3339(query.start_time)) {
    if (isRFC3339(query.end_before)) {
      timeRange.value = [query.start_time, query.end_before]
      endBefore.value = query.end_before
    } else if (isRFC3339(query.end_time)) {
      timeRange.value = [query.start_time, query.end_time]
      endBefore.value = null
    }
    pagination.value.page = 1
  }
  // 所屬日只在每日簽核分頁有效，格式不符忽略
  reviewDate.value =
    activeTab.value === 'reviews' && typeof query.date === 'string' && REVIEW_DATE_RE.test(query.date)
      ? query.date
      : ''
  handleTabChange(activeTab.value)
}

watch(() => route?.query, (query) => applyQuery(query || {}), { immediate: true })
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

.applied-filter {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
  padding: var(--ot-space-sm) var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
  background-color: var(--ot-bg-elevated);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  font-size: var(--ot-font-size-sm);
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

.end-before-tag {
  margin-left: var(--ot-space-sm);
}

.tab-label-with-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

/* 待簽天數：只有期限內的日子用警示色，有任一天逾期轉危險色 */
.tab-badge {
  min-width: 18px;
  padding: 0 6px;
  font-size: var(--ot-font-size-xs);
  line-height: 18px;
  text-align: center;
  border-radius: 9px;
  color: var(--ot-text-inverse);
}

.tab-badge--warning {
  background-color: var(--ot-warning);
}

.tab-badge--danger {
  background-color: var(--ot-danger);
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
