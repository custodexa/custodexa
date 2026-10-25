<template>
  <div class="alerts-page">
    <PageHeader
      :title="$t('alerts.title')"
      :description="$t('alerts.headerDesc')"
    >
      <template #actions>
        <el-button @click="handleRefresh">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <el-tabs
      v-model="activeTab"
      @tab-change="handleTabChange"
    >
      <!-- 頁籤一：告警記錄 -->
      <el-tab-pane
        v-if="canViewAlerts"
        :label="$t('alerts.tabAlerts')"
        name="alerts"
      >
        <div class="filter-bar">
          <el-form
            :inline="true"
            :model="filters"
            @submit.prevent
          >
            <el-form-item :label="$t('alerts.severity')">
              <el-select
                v-model="filters.severity"
                clearable
                :placeholder="$t('common.all')"
                style="width: 140px"
                @change="handleSearch"
              >
                <el-option
                  v-for="option in severityOptions"
                  :key="option.value"
                  :label="option.label"
                  :value="option.value"
                />
              </el-select>
            </el-form-item>

            <el-form-item :label="$t('alerts.kindFilter')">
              <el-select
                v-model="filters.kind"
                clearable
                :placeholder="$t('common.all')"
                style="width: 190px"
                data-test="alert-kind-filter"
                @change="handleSearch"
              >
                <el-option
                  v-for="option in kindOptions"
                  :key="option.value"
                  :label="option.label"
                  :value="option.value"
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
                @change="handleRangeChange"
              />
            </el-form-item>

            <el-form-item :label="$t('alerts.reviewStatus')">
              <el-switch
                v-model="filters.unreviewed"
                :active-text="$t('alerts.onlyUnreviewed')"
                inline-prompt
                style="--el-switch-on-color: var(--el-color-warning)"
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
            </el-form-item>
          </el-form>
        </div>

        <div class="list-card">
          <!-- 批次審閱列：勾選後出現；只收未審閱且非本人觸發的告警 -->
          <BatchSelectionBar
            v-if="canReview && alertSelection.selected.value.length"
            :count-text="$t('alerts.batch.selectedCount', { n: alertSelection.selected.value.length })"
            :clear-text="$t('alerts.batch.clear')"
            :limit-text="alertBatchLimitText"
            @clear="alertSelection.clear()"
          >
            <el-button
              type="primary"
              data-test="batch-open"
              @click="alertBatchDialogRef?.open()"
            >
              {{ $t('alerts.batch.open') }}
            </el-button>
          </BatchSelectionBar>
          <el-table
            v-loading="alertsLoading"
            :data="alerts"
            stripe
            style="width: 100%"
          >
            <el-table-column
              v-if="canReview"
              width="48"
              fixed="left"
            >
              <template #header>
                <BatchCheckbox
                  test-id="batch-select-all"
                  :checked="alertPageState.checked"
                  :indeterminate="alertPageState.indeterminate"
                  :disabled="alertPageState.disabled"
                  :label="$t('alerts.batch.selectAll')"
                  @change="alertSelection.toggleAll(alerts, isAlertBatchSelectable)"
                />
              </template>
              <template #default="{ row }">
                <!-- 不可勾的原因（本人觸發、已審閱）同時給滑鼠提示與讀屏名稱 -->
                <el-tooltip
                  :content="alertSelectBlockedReason(row)"
                  :disabled="!alertSelectBlockedReason(row)"
                  placement="right"
                >
                  <BatchCheckbox
                    test-id="batch-select-cell"
                    :data-id="row.id"
                    :checked="alertSelection.isSelected(row)"
                    :disabled="!alertSelection.canToggle(row, isAlertBatchSelectable)"
                    :label="alertSelectBlockedReason(row) || $t('alerts.batch.selectRow', { label: alertBatchLabel(row) })"
                    @change="(checked) => alertSelection.toggle(row, checked)"
                  />
                </el-tooltip>
              </template>
            </el-table-column>

            <el-table-column
              prop="triggered_at"
              :label="$t('common.time')"
              width="180"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.triggered_at) }}
              </template>
            </el-table-column>

            <el-table-column
              prop="severity"
              :label="$t('alerts.severity')"
              width="110"
            >
              <template #default="{ row }">
                <el-tag
                  :type="severityTagType(row.severity)"
                  size="small"
                >
                  {{ severityLabel(row.severity) }}
                </el-tag>
              </template>
            </el-table-column>

            <!-- 規則名為純淨值（後端不再把「（已阻斷）」串進 rule_name），
                 阻斷與否改以 blocked 欄的 tag 呈現（既有枚舉 tag 慣例） -->
            <el-table-column
              prop="rule_name"
              :label="$t('alerts.ruleName')"
              width="200"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                <!-- 降級告警沒有規則可指（rule_id 為 NULL、rule_name 存的是機器碼），
                     此欄改顯示來源類別的散文，不把機器碼原樣丟給稽核員 -->
                <span v-if="isDegradedAlert(row)">{{ $t('alerts.kindAuditDegraded') }}</span>
                <!-- 新來源位址告警同樣不掛規則：rule_name 存的是機器碼，
                     此欄改顯示來源類別的散文 -->
                <span
                  v-else-if="isNewSourceIPAlert(row)"
                  data-test="alert-new-source-ip-kind"
                >{{ $t('alerts.kindNewSourceIP') }}</span>
                <span v-else-if="isAgentBreakerAlert(row)">{{ $t('alerts.kindAgentBreaker') }}</span>
                <span
                  v-else-if="row.kind === 'sensitive_reveal'"
                  data-test="alert-sensitive-reveal-kind"
                >{{ $t('alerts.kindSensitiveReveal') }}</span>
                <span
                  v-else-if="isSystemAlert(row)"
                  data-test="alert-system-name"
                >{{ systemAlertName(row) }}</span>
                <span v-else>{{ row.rule_name }}</span>
                <el-tag
                  v-if="row.blocked"
                  class="blocked-tag"
                  type="danger"
                  size="small"
                >
                  {{ $t('alerts.blockedTag') }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column
              prop="command"
              :label="$t('commands.commandColumn')"
              min-width="240"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                <!-- 降級告警本來就沒有指令文字（那正是它要說的事）：渲染成狀態列，
                     空白格會被讀成「規則命中了一個空指令」，那是另一種捏造 -->
                <div
                  v-if="isDegradedAlert(row)"
                  class="alert-degraded"
                  data-test="alert-degraded"
                >
                  <span class="alert-degraded__title">{{ $t('commands.degrade.title') }}</span>
                  <span class="alert-degraded__reason">{{ commandAlertReasonLabel(row.reason_code) }}</span>
                </div>
                <!-- 新來源位址告警本來就沒有指令（`command` 為空字串是刻意的）：
                     這一格改說它實際在講的事——位址，加上「首次自此位址建線」。
                     位址為深連結：一鍵以該位址為樞紐進入調查工作台，時間窗為
                     觸發當日、類別為全部，稽核員不必手動複製位址再重設條件 -->
                <div
                  v-else-if="isNewSourceIPAlert(row)"
                  class="alert-new-source"
                  data-test="alert-new-source-ip"
                >
                  <router-link
                    v-if="newSourceIPLink(row)"
                    :to="newSourceIPLink(row)"
                    class="command-text alert-new-source__addr"
                    :title="$t('alerts.newSourceIPPivot')"
                    data-test="alert-new-source-ip-link"
                  >
                    {{ row.client_ip }}
                  </router-link>
                  <span
                    v-else
                    class="command-missing"
                  >{{ $t('alerts.newSourceIPNoAddress') }}</span>
                  <span class="alert-new-source__note">
                    {{ $t('alerts.newSourceIPFirstSession') }}
                  </span>
                </div>
                <span
                  v-else-if="isAgentBreakerAlert(row)"
                >{{ $t('alerts.agentBreakerDescription') }}</span>
                <span
                  v-else-if="row.kind === 'sensitive_reveal'"
                  data-test="alert-sensitive-reveal"
                >{{ $t('alerts.sensitiveRevealDescription') }}</span>
                <span
                  v-else-if="isSystemAlert(row)"
                  data-test="alert-system-description"
                >{{ systemAlertDescription(row) }}</span>
                <span
                  v-else-if="row.reason_code?.startsWith('o1:')"
                  data-test="alert-output-sensitive"
                >
                  {{ $t('alerts.outputSummary', { count: parseInt(row.reason_code.split(':')[1], 36) }) }}
                </span>
                <!-- 非降級類但也沒有文字：不宣稱成因，只把事實講清楚 -->
                <span
                  v-else-if="!row.command"
                  class="command-missing"
                  data-test="alert-no-command"
                >{{ $t('alerts.noCommandText') }}</span>
                <span
                  v-else
                  class="command-text"
                >{{ row.command }}</span>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('alerts.reviewStatus')"
              width="120"
            >
              <template #default="{ row }">
                <el-tag
                  :type="dispositionTagType(row)"
                  size="small"
                >
                  <el-icon><component :is="dispositionIcon(row)" /></el-icon>
                  {{ dispositionLabel(row) }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('common.actions')"
              width="180"
              fixed="right"
            >
              <template #default="{ row }">
                <a
                  v-if="isAgentBreakerAlert(row) && row.user_id"
                  :href="`/agent-breakers?user_id=${row.user_id}`"
                  class="agent-breaker-link"
                  data-test="breaker-entry"
                >{{ $t('agentBreaker.open') }}</a>
                <el-button
                  v-if="isSystemAlert(row)"
                  link
                  type="primary"
                  data-test="alert-system-detail"
                  @click="openSystemDetail(row)"
                >
                  {{ $t('systemAlerts.detail.title') }}
                </el-button>
                <el-button
                  v-if="row.session_id"
                  link
                  type="primary"
                  @click="goToSession(row)"
                >
                  {{ $t('commands.viewSession') }}
                </el-button>
                <el-button
                  v-if="canReview"
                  link
                  type="warning"
                  @click="openReviewDialog(row)"
                >
                  {{ row.reviewed_at ? $t('alerts.rereview') : $t('alerts.review') }}
                </el-button>
              </template>
            </el-table-column>

            <template #empty>
              <EmptyState
                :title="$t('alerts.emptyAlertsTitle')"
                :hint="$t('alerts.emptyAlertsHint')"
              />
            </template>
          </el-table>

          <div class="pagination">
            <el-pagination
              v-model:current-page="pagination.page"
              v-model:page-size="pagination.page_size"
              :page-sizes="[10, 20, 50, 100]"
              :total="pagination.total"
              layout="total, sizes, prev, pager, next, jumper"
              @size-change="handleSizeChange"
              @current-change="fetchAlerts"
            />
          </div>
        </div>
      </el-tab-pane>

      <!-- 頁籤二：規則管理（alertrule:manage） -->
      <el-tab-pane
        v-if="canManageRules"
        :label="$t('alerts.tabRules')"
        name="rules"
      >
        <div class="list-card">
          <div class="toolbar">
            <el-button
              type="primary"
              @click="openCreateDialog"
            >
              {{ $t('alerts.createRule') }}
            </el-button>
          </div>

          <el-table
            v-loading="rulesLoading"
            :data="rules"
            stripe
            style="width: 100%"
          >
            <el-table-column
              prop="name"
              :label="$t('common.name')"
              width="200"
              show-overflow-tooltip
            />

            <el-table-column
              :label="$t('alerts.subjectKind')"
              width="130"
            >
              <template #default="{ row }">
                {{ $t(`alerts.subject${({ all: 'All', human: 'Human', agent: 'Agent' })[row.subject_kind || 'all']}`) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('alerts.direction')"
              width="130"
            >
              <template #default="{ row }">
                {{ $t(row.direction === 'output' ? 'alerts.directionOutput' : 'alerts.directionInput') }}
              </template>
            </el-table-column>
            <el-table-column
              prop="pattern"
              :label="$t('alerts.patternLabel')"
              min-width="280"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                <span class="command-text">{{ row.pattern }}</span>
              </template>
            </el-table-column>

            <el-table-column
              prop="severity"
              :label="$t('alerts.severity')"
              width="110"
            >
              <template #default="{ row }">
                <el-tag
                  :type="severityTagType(row.severity)"
                  size="small"
                >
                  {{ severityLabel(row.severity) }}
                </el-tag>
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('alerts.protocolsLabel')"
              width="160"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                {{ row.protocols || $t('alerts.allProtocols') }}
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('common.enabled')"
              width="90"
            >
              <template #default="{ row }">
                <el-switch
                  :model-value="row.enabled"
                  @change="(value) => handleToggleEnabled(row, value)"
                />
              </template>
            </el-table-column>

            <el-table-column
              :label="$t('common.actions')"
              width="140"
              fixed="right"
            >
              <template #default="{ row }">
                <el-button
                  link
                  type="primary"
                  @click="openEditDialog(row)"
                >
                  {{ $t('common.edit') }}
                </el-button>
                <el-button
                  link
                  type="danger"
                  @click="handleDeleteRule(row)"
                >
                  {{ $t('common.delete') }}
                </el-button>
              </template>
            </el-table-column>

            <template #empty>
              <EmptyState
                :title="$t('alerts.emptyRulesTitle')"
                :hint="$t('alerts.emptyRulesHint')"
              />
            </template>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 頁籤三：系統告警目錄（systemalert:manage）。通知通道已移到系統設定 -->
      <el-tab-pane
        v-if="canManageSystemAlerts"
        :label="$t('alerts.tabSystemAlerts')"
        name="systemAlerts"
        lazy
      >
        <SystemAlertCatalog />
      </el-tab-pane>
    </el-tabs>

    <SystemAlertDetailDrawer
      v-model="systemDetailVisible"
      :alert-id="systemDetailId"
    />

    <!-- 告警審閱處置對話框（audit-workflows） -->
    <el-dialog
      v-model="reviewDialogVisible"
      :title="$t('alerts.reviewDialogTitle')"
      width="480px"
      :close-on-click-modal="false"
    >
      <div
        v-if="reviewingAlert"
        class="review-alert-summary"
      >
        <div
          v-if="!reviewingAlert.command"
          class="review-cmd command-missing"
        >
          {{ $t('alerts.noCommandText') }}
        </div>
        <div
          v-else
          class="review-cmd"
        >
          {{ reviewingAlert.command }}
        </div>
        <div class="review-meta">
          {{ $t('alerts.reviewRuleLine', { name: reviewingAlert.rule_name }) }} ·
          <el-tag
            :type="severityTagType(reviewingAlert.severity)"
            size="small"
          >
            {{ severityLabel(reviewingAlert.severity) }}
          </el-tag>
        </div>
      </div>
      <el-form label-position="top">
        <el-form-item
          :label="$t('alerts.dispositionLabel')"
          required
        >
          <el-radio-group v-model="reviewForm.disposition">
            <el-radio-button value="benign">
              {{ $t('alerts.dispositionBenign') }}
            </el-radio-button>
            <el-radio-button value="escalated">
              {{ $t('alerts.dispositionEscalated') }}
            </el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="$t('auditLogs.noteColumn')">
          <el-input
            v-model="reviewForm.note"
            type="textarea"
            :rows="3"
            maxlength="500"
            show-word-limit
            :placeholder="$t('alerts.reviewNotePlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="reviewDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="reviewSubmitting"
          @click="submitReview"
        >
          {{ $t('alerts.confirmReview') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 告警批次審閱：逐筆呼叫單筆審閱端點（非原子），結果逐筆列出 -->
    <AlertBatchReviewDialog
      v-if="canReview"
      ref="alertBatchDialogRef"
      :alerts="alertSelection.selected.value"
      :current-user-id="currentUserId"
      :label-for="alertBatchLabel"
      @finished="handleAlertBatchFinished"
    />


    <!-- 新增 / 編輯規則對話框 -->
    <el-dialog
      v-model="ruleDialogVisible"
      :title="editingRuleId ? $t('alerts.editRule') : $t('alerts.createRule')"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-form
        ref="ruleFormRef"
        :model="ruleForm"
        :rules="ruleFormRules"
        label-position="top"
        @submit.prevent
      >
        <el-form-item
          :label="$t('common.name')"
          prop="name"
        >
          <el-input
            v-model="ruleForm.name"
            :placeholder="$t('alerts.ruleNamePlaceholder')"
            maxlength="100"
          />
        </el-form-item>

        <el-form-item
          :label="$t('alerts.patternLabel')"
          prop="pattern"
        >
          <el-input
            v-model="ruleForm.pattern"
            :placeholder="$t('alerts.rulePatternPlaceholder')"
            class="pattern-input"
          />
        </el-form-item>

        <el-form-item
          :label="$t('alerts.severity')"
          prop="severity"
        >
          <el-select
            v-model="ruleForm.severity"
            style="width: 100%"
          >
            <el-option
              v-for="option in severityOptions"
              :key="option.value"
              :label="option.label"
              :value="option.value"
            />
          </el-select>
        </el-form-item>

        <el-form-item
          :label="$t('alerts.subjectKind')"
          prop="subject_kind"
        >
          <el-select v-model="ruleForm.subject_kind">
            <el-option
              value="all"
              :label="$t('alerts.subjectAll')"
            />
            <el-option
              value="human"
              :label="$t('alerts.subjectHuman')"
            />
            <el-option
              value="agent"
              :label="$t('alerts.subjectAgent')"
            />
          </el-select>
        </el-form-item>
        <el-form-item
          :label="$t('alerts.direction')"
          prop="direction"
        >
          <el-select
            v-model="ruleForm.direction"
            @change="ruleForm.action = ruleForm.direction === 'output' ? 'alert' : ruleForm.action"
          >
            <el-option
              value="input"
              :label="$t('alerts.directionInput')"
            />
            <el-option
              value="output"
              :label="$t('alerts.directionOutput')"
            />
          </el-select>
        </el-form-item>
        <el-alert
          v-if="ruleForm.direction === 'output'"
          :title="$t('alerts.outputScope')"
          :description="`${$t('alerts.outputNoBlock')} ${$t('alerts.outputCardContract')}`"
          type="info"
          :closable="false"
        />
        <el-form-item :label="$t('alerts.actionLabel')">
          <el-radio-group v-model="ruleForm.action">
            <el-radio-button value="alert">
              {{ $t('alerts.actionAlert') }}
            </el-radio-button>
            <el-radio-button
              value="block"
              :disabled="ruleForm.direction === 'output'"
            >
              {{ $t('alerts.actionBlock') }}
            </el-radio-button>
          </el-radio-group>
          <div
            v-if="ruleForm.action === 'block'"
            class="action-hint"
          >
            {{ $t('alerts.blockHint') }}
          </div>
        </el-form-item>

        <el-form-item :label="$t('alerts.protocolsLabel')">
          <el-select
            v-model="ruleForm.protocols"
            multiple
            clearable
            :placeholder="$t('alerts.protocolsPlaceholder')"
            style="width: 100%"
          >
            <el-option
              v-for="option in protocolOptions"
              :key="option.value"
              :label="option.label"
              :value="option.value"
            />
          </el-select>
          <div class="action-hint">
            {{ $t('alerts.protocolsHint') }}
          </div>
        </el-form-item>

        <el-form-item :label="$t('common.enabled')">
          <el-switch v-model="ruleForm.enabled" />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="ruleDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="saving"
          @click="handleSaveRule"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { CircleCheck, CircleAlert, Clock, RefreshCw } from 'lucide-vue-next'
import {
  searchAlerts,
  reviewAlert,
  getAlertRules,
  createAlertRule,
  updateAlertRule,
  deleteAlertRule,
} from '@/api/alerts'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import SystemAlertCatalog from '@/components/system-alert/SystemAlertCatalog.vue'
import SystemAlertDetailDrawer from '@/components/system-alert/SystemAlertDetailDrawer.vue'
import BatchSelectionBar from '@/components/batch-review/BatchSelectionBar.vue'
import BatchCheckbox from '@/components/batch-review/BatchCheckbox.vue'
import AlertBatchReviewDialog from '@/components/batch-review/AlertBatchReviewDialog.vue'
import { useBatchSelection } from '@/composables/useBatchReview'
import { formatDateTime } from '@/utils/format'
import { can } from '@/composables/useCapabilities'
import { useRoles } from '@/composables/useRoles'
import { t } from '@/i18n'
import {
  isDegradedAlert,
  isNewSourceIPAlert,
  isAgentBreakerAlert,
  commandAlertReasonLabel,
} from '@/constants/command-degrade'
import { buildAddressPivotLink, localDayRange } from '@/components/audit/timelineQuery'

const router = useRouter()

const SEVERITY_TAG_TYPES = {
  high: 'danger',
  medium: 'warning',
  low: 'info',
}

// 告警等級（i18n：閉集走 enum.alertLevel、未知值原樣顯示）；
// 篩選下拉與表格同 key 源，勿手寫選項
const SEVERITY_VALUES = ['high', 'medium', 'low']

const severityOptions = computed(() =>
  SEVERITY_VALUES.map((value) => ({ value, label: t(`enum.alertLevel.${value}`) }))
)
const KIND_LABELS = {
  rule: 'kindRule',
  audit_degraded: 'kindAuditDegraded',
  new_source_ip: 'kindNewSourceIP',
  agent_breaker_tripped: 'kindAgentBreaker',
  sensitive_reveal: 'kindSensitiveReveal',
  system_security: 'kindSystemSecurity',
}
const kindOptions = computed(() => Object.entries(KIND_LABELS)
  .map(([value, key]) => ({ value, label: t(`alerts.${key}`) })))

// 規則管理頁籤僅 admin 顯示；審閱處置權限 alert:manage（admin/auditor 有，user 無）——與後端一致
// 操作者能力（後端才是強制點）：審閱告警 alert:manage、規則頁籤 alertrule:manage、
// currentUserId 只用來比對「自己觸發的告警」，不是授權
const { currentUserId } = useRoles()
const canReview = computed(() => can('alert:manage'))
const canManageRules = computed(() => can('alertrule:manage'))
const canManageSystemAlerts = computed(() => can('systemalert:manage'))
// 告警記錄頁籤（指令告警列表）由 audit:view 把關；入口規則是三個頁籤能力的「任一」，
// 所以只持有其他頁籤能力的人也會進到這頁，頁內不得替他們呼叫無權的 API
const canViewAlerts = computed(() => can('audit:view'))
// 預設落在第一個看得到的頁籤
const activeTab = ref(
  canViewAlerts.value ? 'alerts'
    : canManageRules.value ? 'rules'
      : canManageSystemAlerts.value ? 'systemAlerts'
        : 'alerts',
)

// --- 系統告警（來源類別 system_security）---
const isSystemAlert = (row) => row.kind === 'system_security'
const systemAlertName = (row) => t(`systemAlerts.types.${row.reason_code}.name`)
const systemAlertDescription = (row) => t(`systemAlerts.types.${row.reason_code}.description`)
const systemDetailVisible = ref(false)
const systemDetailId = ref(null)
const openSystemDetail = (row) => {
  systemDetailId.value = row.id
  systemDetailVisible.value = true
}

// --- 告警記錄 ---
const alerts = ref([])
const alertsLoading = ref(false)
const timeRange = ref([])
const filters = ref({
  kind: '',
  severity: '',
  unreviewed: false,
})

// 儀表板帶入的時間界線：伺服端字串含微秒，原樣保存並原樣送出，不經 Date 轉換
//（Date 只到毫秒，會截掉尾端而與卡片的計數口徑對不上）。使用者自己改時間或重置即清掉。
const carriedStart = ref('')
const carriedEnd = ref('')
const applyDashboardQuery = () => {
  const q = router.currentRoute?.value?.query
  if (!q || typeof q !== 'object') return
  if (q.unreviewed === 'true') filters.value.unreviewed = true
  if (typeof q.start_time === 'string' && typeof q.end_time === 'string' && q.start_time && q.end_time) {
    carriedStart.value = q.start_time
    carriedEnd.value = q.end_time
    // 選擇器只作顯示；實際送出的是上面兩個原字串
    const a = new Date(q.start_time)
    const b = new Date(q.end_time)
    if (!Number.isNaN(a.getTime()) && !Number.isNaN(b.getTime())) timeRange.value = [a, b]
  }
}
const clearCarriedRange = () => {
  carriedStart.value = ''
  carriedEnd.value = ''
}
const handleRangeChange = () => {
  clearCarriedRange()
  handleSearch()
}

// 審閱處置對話框
const reviewDialogVisible = ref(false)
const reviewingAlert = ref(null)
const reviewSubmitting = ref(false)
const reviewForm = ref({ disposition: 'benign', note: '' })

// disposition 呈現（color-not-only：icon+文字，非僅顏色）
const dispositionLabel = (row) => {
  if (!row.reviewed_at) return t('enum.alertStatus.unreviewed')
  return row.disposition === 'escalated'
    ? t('enum.alertStatus.escalated')
    : t('enum.alertStatus.reviewed')
}
const dispositionTagType = (row) => {
  if (!row.reviewed_at) return 'warning'
  return row.disposition === 'escalated' ? 'danger' : 'success'
}
const dispositionIcon = (row) => {
  if (!row.reviewed_at) return Clock
  return row.disposition === 'escalated' ? CircleAlert : CircleCheck
}

const openReviewDialog = (row) => {
  reviewingAlert.value = row
  reviewForm.value = {
    disposition: row.disposition === 'escalated' ? 'escalated' : 'benign',
    note: row.note || '',
  }
  reviewDialogVisible.value = true
}

const submitReview = async () => {
  if (!reviewingAlert.value) return
  reviewSubmitting.value = true
  try {
    await reviewAlert(reviewingAlert.value.id, {
      disposition: reviewForm.value.disposition,
      note: reviewForm.value.note,
    })
    ElMessage.success(t('alerts.reviewed'))
    reviewDialogVisible.value = false
    fetchAlerts()
  } catch (error) {
    console.error('審閱告警失敗:', error)
  } finally {
    reviewSubmitting.value = false
  }
}
// --- 批次審閱（勾選多筆 → 共用理由 → 逐筆送出） ---
// 只收未審閱、且不是自己連線觸發的告警；目前使用者不明時一律不給勾（後端也會擋）
const alertSelection = useBatchSelection()
const alertBatchDialogRef = ref(null)
const isAlertBatchSelectable = (row) =>
  !row.reviewed_at && currentUserId.value != null && row.user_id !== currentUserId.value
const alertSelectBlockedReason = (row) => {
  if (row.reviewed_at) return t('alerts.batch.reviewedTip')
  if (currentUserId.value != null && row.user_id === currentUserId.value) return t('alerts.batch.selfTriggeredTip')
  return ''
}
const alertPageState = computed(() => alertSelection.pageState(alerts.value, isAlertBatchSelectable))
const alertBatchLimitText = computed(() =>
  alertSelection.atLimit.value || alertSelection.truncated.value
    ? t('alerts.batch.limitHint', { limit: alertSelection.limit })
    : '')
// 規則名稱欄的同一套散文：非規則類告警的 rule_name 是機器碼，不直接顯示
const alertRuleText = (row) => {
  if (isDegradedAlert(row)) return t('alerts.kindAuditDegraded')
  if (isNewSourceIPAlert(row)) return t('alerts.kindNewSourceIP')
  if (isAgentBreakerAlert(row)) return t('alerts.kindAgentBreaker')
  if (row.kind === 'sensitive_reveal') return t('alerts.kindSensitiveReveal')
  if (isSystemAlert(row)) return systemAlertName(row)
  return row.rule_name
}
const alertBatchLabel = (row) => `${alertRuleText(row)} · ${formatDateTime(row.triggered_at)}`
const handleAlertBatchFinished = () => {
  alertSelection.clear()
  fetchAlerts()
}

const pagination = ref({
  page: 1,
  page_size: 20,
  total: 0,
})

const fetchAlerts = async () => {
  if (!canViewAlerts.value) return
  alertsLoading.value = true
  // 列表換了（翻頁、篩選、重新整理）：勾選只對本頁有效，一併清掉
  alertSelection.clear()
  try {
    const params = {
      page: pagination.value.page,
      page_size: pagination.value.page_size,
    }

    if (filters.value.severity) params.severity = filters.value.severity
    if (filters.value.kind) params.kind = filters.value.kind
    if (filters.value.unreviewed) params.unreviewed = 'true'

    if (carriedStart.value && carriedEnd.value) {
      params.start_time = carriedStart.value
      params.end_time = carriedEnd.value
    } else if (timeRange.value && timeRange.value.length === 2) {
      params.start_time = timeRange.value[0]
      params.end_time = timeRange.value[1]
    }

    const response = await searchAlerts(params)
    alerts.value = response.data || []
    pagination.value.total = response.total || 0
  } catch (error) {
    console.error('查詢告警記錄失敗:', error)
  } finally {
    alertsLoading.value = false
  }
}

const handleSearch = () => {
  pagination.value.page = 1
  fetchAlerts()
}

const handleSizeChange = () => {
  pagination.value.page = 1
  fetchAlerts()
}

const handleReset = () => {
  filters.value = { kind: '', severity: '', unreviewed: false }
  timeRange.value = []
  clearCarriedRange()
  handleSearch()
}

// 重新整理：依目前頁籤重載對應資料（C4）
const handleRefresh = () => {
  if (activeTab.value === 'rules') fetchRules()
  else if (activeTab.value === 'systemAlerts') return
  else fetchAlerts()
}

const goToSession = (row) => {
  router.push(`/sessions/${row.session_id}`)
}

// 新來源位址告警的位址深連結：以該位址為樞紐、時間窗為**觸發當日的本地整日**、
// 類別全部。「當日」用本地時區——稽核員讀的是自己所在時區的那一天，
// 換成伺服器時區會讓跨時區調查的邊界對不上。
// 位址缺席（會話已刪、或建線當下取不到來源）時不給連結：
// 沒有目的地的連結是假話
const newSourceIPLink = (row) => {
  if (!row?.client_ip) return null
  const [from, to] = localDayRange(row.triggered_at)
  return buildAddressPivotLink(row.client_ip, { from, to })
}

// --- 規則管理 ---
const rules = ref([])
const rulesLoading = ref(false)

const fetchRules = async () => {
  rulesLoading.value = true
  try {
    const response = await getAlertRules()
    rules.value = Array.isArray(response) ? response : response.data || []
  } catch (error) {
    console.error('查詢告警規則失敗:', error)
  } finally {
    rulesLoading.value = false
  }
}

const ruleDialogVisible = ref(false)
const editingRuleId = ref(null)
const saving = ref(false)
const ruleFormRef = ref(null)

// 具指令審計的文字終端協議（與後端 commandAuditedProtocols 值域一致）
const protocolOptions = [
  { value: 'ssh', label: 'SSH' },
  { value: 'k8s', label: 'K8s' },
  { value: 'mysql', label: 'MySQL' },
  { value: 'postgres', label: 'PostgreSQL' },
  { value: 'redis', label: 'Redis' },
  { value: 'mssql', label: 'SQL Server' },
]

const emptyRuleForm = () => ({
  name: '',
  pattern: '',
  severity: 'high',
  action: 'alert',
  direction: 'input',
  subject_kind: 'all',
  protocols: [],
  enabled: true,
})

const ruleForm = ref(emptyRuleForm())

// 表單驗證規則（computed：切語言時錯誤訊息隨當下語言）
const ruleFormRules = computed(() => ({
  name: [{ required: true, message: t('alerts.ruleNameRequired'), trigger: 'blur' }],
  pattern: [{ required: true, message: t('alerts.rulePatternRequired'), trigger: 'blur' }],
  severity: [{ required: true, message: t('alerts.ruleSeverityRequired'), trigger: 'change' }],
}))

const openCreateDialog = () => {
  editingRuleId.value = null
  ruleForm.value = emptyRuleForm()
  ruleDialogVisible.value = true
}

const openEditDialog = (row) => {
  editingRuleId.value = row.id
  ruleForm.value = {
    name: row.name,
    pattern: row.pattern,
    severity: row.severity,
    action: row.action || 'alert',
    direction: row.direction || 'input',
    subject_kind: row.subject_kind || 'all',
    protocols: row.protocols ? row.protocols.split(',').filter(Boolean) : [],
    enabled: row.enabled,
  }
  ruleDialogVisible.value = true
}

const handleSaveRule = async () => {
  if (ruleForm.value.direction === 'output' && ruleForm.value.action === 'block') {
    ElMessage.error(t('alerts.outputNoBlock'))
    return
  }
  if (ruleFormRef.value) {
    const valid = await ruleFormRef.value.validate().catch(() => false)
    if (valid === false) return
  }

  saving.value = true
  try {
    // protocols 表單為陣列，API 為逗號分隔字串（空=全協議）
    const payload = { ...ruleForm.value, protocols: ruleForm.value.protocols.join(',') }
    if (editingRuleId.value) {
      await updateAlertRule(editingRuleId.value, payload)
      ElMessage.success(t('alerts.ruleUpdated'))
    } else {
      await createAlertRule(payload)
      ElMessage.success(t('alerts.ruleCreated'))
    }
    ruleDialogVisible.value = false
    fetchRules()
  } catch (error) {
    // 400（無效 regex 等）錯誤訊息已由 axios 攔截器直接顯示，保持對話框開啟
    console.error('儲存告警規則失敗:', error)
  } finally {
    saving.value = false
  }
}

const handleToggleEnabled = async (row, value) => {
  try {
    await updateAlertRule(row.id, {
      name: row.name,
      pattern: row.pattern,
      severity: row.severity,
      enabled: value,
      direction: row.direction || 'input',
    subject_kind: row.subject_kind || 'all',
      action: row.action || 'alert',
    })
    ElMessage.success(value ? t('alerts.ruleEnabled') : t('alerts.ruleDisabled'))
    fetchRules()
  } catch (error) {
    console.error('切換規則狀態失敗:', error)
    fetchRules()
  }
}

const handleDeleteRule = async (row) => {
  try {
    await ElMessageBox.confirm(
      t('alerts.deleteRuleConfirm', { name: row.name }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await deleteAlertRule(row.id)
    ElMessage.success(t('alerts.ruleDeleted'))
    fetchRules()
  } catch (error) {
    console.error('刪除告警規則失敗:', error)
  }
}

// --- 工具函式 ---
const severityTagType = (severity) => SEVERITY_TAG_TYPES[severity] || 'info'

const severityLabel = (severity) =>
  SEVERITY_VALUES.includes(severity) ? t(`enum.alertLevel.${severity}`) : severity



onMounted(() => {
  applyDashboardQuery()
  fetchAlerts()
  if (canManageRules.value) {
    fetchRules()
  }
})

// tab 切換即 refetch（C8：資料新鮮優先，對齊 Sessions 模式）
const handleTabChange = (tab) => {
  if (tab === 'rules') fetchRules()
  else fetchAlerts()
}
</script>

<style scoped>
.alerts-page {
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

.toolbar {
  display: flex;
  justify-content: flex-end;
  margin-bottom: var(--ot-space-md);
}

.pagination {
  margin-top: var(--ot-space-md);
  display: flex;
  justify-content: flex-end;
}

.command-text {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}

/* 沒有指令文字的告警：狀態敘述而非指令，故不用等寬字，並以警示色與一般列區隔 */
.command-missing {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-warning);
}

.alert-new-source {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.alert-new-source__addr {
  color: var(--ot-primary);
  text-decoration: none;
}

.alert-new-source__addr:hover {
  text-decoration: underline;
}

.alert-new-source__note {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.alert-degraded {
  white-space: normal;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.alert-degraded__title {
  color: var(--ot-warning);
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
}

.alert-degraded__reason {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.5;
}

.pattern-input :deep(input) {
  font-family: var(--ot-font-mono);
}

.action-hint {
  margin-top: 6px;
  font-size: var(--ot-font-size-xs);
  color: var(--el-color-warning);
  line-height: 1.5;
}

.blocked-tag {
  margin-left: 6px;
}

</style>

<style scoped>
.agent-breaker-link { color: var(--ot-primary); margin-right: var(--ot-space-sm); }
</style>
