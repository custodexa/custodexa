<template>
  <div class="alerts-page">
    <PageHeader
      :title="$t('alerts.title')"
      :description="$t('alerts.headerDesc')"
    >
      <template #actions>
        <el-button @click="handleRefresh">
          <el-icon><Refresh /></el-icon>
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
          <el-table
            v-loading="alertsLoading"
            :data="alerts"
            stripe
            style="width: 100%"
          >
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
                <el-button
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

      <!-- 頁籤二：規則管理（僅 admin） -->
      <el-tab-pane
        v-if="isAdmin"
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

      <!-- 頁籤三：通知通道（僅 admin） -->
      <el-tab-pane
        v-if="isAdmin"
        :label="$t('alerts.tabChannels')"
        name="channels"
      >
        <div class="list-card">
          <div class="toolbar">
            <el-button
              type="primary"
              @click="openChannelDialog()"
            >
              {{ $t('alerts.createChannel') }}
            </el-button>
          </div>
          <el-table
            v-loading="channelsLoading"
            :data="channels"
            style="width: 100%"
          >
            <el-table-column
              prop="name"
              :label="$t('common.name')"
              min-width="140"
            />
            <el-table-column
              :label="$t('alerts.channelType')"
              width="100"
            >
              <template #default="{ row }">
                {{ row.type === 'slack' ? 'Slack' : 'Webhook' }}
              </template>
            </el-table-column>
            <el-table-column
              prop="url"
              label="URL"
              min-width="280"
            >
              <template #default="{ row }">
                <span class="mono-text">{{ row.url }}</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('alerts.signatureColumn')"
              width="110"
            >
              <template #default="{ row }">
                <span
                  v-if="row.type === 'slack'"
                  class="field-muted"
                >{{ $t('alerts.notApplicable') }}</span>
                <el-tag
                  v-else
                  :type="row.has_secret ? 'success' : 'info'"
                  size="small"
                >
                  {{ row.has_secret ? $t('alerts.secretSet') : $t('alerts.unsigned') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('alerts.languageColumn')"
              width="110"
            >
              <template #default="{ row }">
                <span
                  v-if="row.type !== 'slack'"
                  class="field-muted"
                >{{ $t('alerts.notApplicable') }}</span>
                <template v-else>
                  {{ channelLanguageLabel(row.language) }}
                </template>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.enabled')"
              width="90"
            >
              <template #default="{ row }">
                <el-switch
                  :model-value="row.enabled"
                  @change="(val) => handleChannelToggle(row, val)"
                />
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.actions')"
              width="220"
              fixed="right"
            >
              <template #default="{ row }">
                <el-button
                  size="small"
                  link
                  type="primary"
                  @click="handleTestChannel(row)"
                >
                  {{ $t('alerts.testSend') }}
                </el-button>
                <el-button
                  size="small"
                  link
                  type="primary"
                  @click="openChannelDialog(row)"
                >
                  {{ $t('common.edit') }}
                </el-button>
                <el-button
                  size="small"
                  link
                  type="danger"
                  @click="handleDeleteChannel(row)"
                >
                  {{ $t('common.delete') }}
                </el-button>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState
                :title="$t('alerts.emptyChannelsTitle')"
                :hint="$t('alerts.emptyChannelsHint')"
              />
            </template>
          </el-table>
        </div>
      </el-tab-pane>
    </el-tabs>

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

    <!-- 新增 / 編輯通道對話框 -->
    <el-dialog
      v-model="channelDialogVisible"
      :title="editingChannelId ? $t('alerts.editChannel') : $t('alerts.createChannel')"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-form
        ref="channelFormRef"
        :model="channelForm"
        :rules="channelFormRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.name')"
          prop="name"
        >
          <el-input v-model="channelForm.name" />
        </el-form-item>
        <el-form-item
          :label="$t('alerts.channelType')"
          prop="type"
        >
          <el-select
            v-model="channelForm.type"
            style="width: 100%"
          >
            <el-option
              :label="$t('alerts.channelTypeWebhook')"
              value="webhook"
            />
            <el-option
              :label="$t('alerts.channelTypeSlack')"
              value="slack"
            />
          </el-select>
        </el-form-item>
        <el-form-item
          label="URL"
          prop="url"
          :required="!editingChannelId"
        >
          <div
            v-if="editingChannelId"
            class="secret-status"
          >
            {{ $t('alerts.currentUrlMasked') }}
            <span class="mono-text">{{ channelForm.maskedUrl }}</span>
          </div>
          <el-input
            v-model="channelForm.url"
            :placeholder="editingChannelId
              ? $t('alerts.urlKeepPlaceholder')
              : (channelForm.type === 'slack'
                ? 'https://hooks.slack.com/services/...'
                : 'https://hooks.example.com/...')"
          />
        </el-form-item>
        <el-form-item
          v-if="channelForm.type === 'slack'"
          :label="$t('alerts.signingSecret')"
        >
          <div class="field-hint">
            {{ $t('alerts.slackNoSecretHint') }}
          </div>
        </el-form-item>
        <el-form-item
          v-else
          :label="$t('alerts.signingSecret')"
        >
          <div
            v-if="editingChannelId"
            class="secret-status"
          >
            {{ $t('alerts.currentStatus') }}
            <el-tag
              :type="channelForm.hasSecret ? 'success' : 'info'"
              size="small"
            >
              {{ channelForm.hasSecret ? $t('alerts.secretSetFull') : $t('alerts.secretUnsetFull') }}
            </el-tag>
          </div>
          <el-input
            v-model="channelForm.secret"
            type="password"
            show-password
            :disabled="channelForm.clearSecret"
            :placeholder="editingChannelId
              ? (channelForm.hasSecret ? $t('alerts.secretKeepPlaceholder') : $t('alerts.secretFillPlaceholder'))
              : $t('alerts.secretNewPlaceholder')"
          />
          <el-checkbox
            v-if="editingChannelId && channelForm.hasSecret"
            v-model="channelForm.clearSecret"
            class="clear-secret-check"
          >
            {{ $t('alerts.clearSecretLabel') }}
          </el-checkbox>
          <!-- 提示帶 <code> 標記：走 i18n-t 具名插槽插值，三語各自掌控語序 -->
          <i18n-t
            keypath="alerts.secretHint"
            scope="global"
            tag="div"
            class="field-hint"
          >
            <template #cmd>
              <code>openssl rand -hex 32</code>
            </template>
          </i18n-t>
        </el-form-item>
        <el-form-item
          :label="$t('alerts.channelLanguage')"
          prop="language"
        >
          <el-select
            v-model="channelForm.language"
            style="width: 100%"
          >
            <el-option
              v-for="lang in CHANNEL_LANGUAGE_VALUES"
              :key="lang"
              :label="channelLanguageLabel(lang)"
              :value="lang"
            />
          </el-select>
          <div class="field-hint">
            {{ $t('alerts.channelLanguageHint') }}
          </div>
        </el-form-item>
        <el-form-item :label="$t('common.enabled')">
          <el-switch v-model="channelForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="channelDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="channelSaving"
          @click="handleSaveChannel"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>

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

        <el-form-item :label="$t('alerts.actionLabel')">
          <el-radio-group v-model="ruleForm.action">
            <el-radio-button value="alert">
              {{ $t('alerts.actionAlert') }}
            </el-radio-button>
            <el-radio-button value="block">
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
import { CircleCheck, Warning, Clock, Refresh } from '@element-plus/icons-vue'
import {
  searchAlerts,
  reviewAlert,
  getAlertRules,
  createAlertRule,
  updateAlertRule,
  deleteAlertRule,
  getChannels,
  createChannel,
  updateChannel,
  deleteChannel,
  testChannel,
} from '@/api/alerts'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { useRoles } from '@/composables/useRoles'
import { t } from '@/i18n'
import { riskLabel } from '@/utils/transportDisplay'
import { isDegradedAlert, commandAlertReasonLabel } from '@/constants/command-degrade'
import { resolveApiError } from '@/api/error'
import {
  CHANNEL_LANGUAGE_VALUES,
  CHANNEL_LANGUAGE_DEFAULT,
  channelLanguageLabel,
} from '@/constants/notification-channels'

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

const activeTab = ref('alerts')

// 規則管理頁籤僅 admin 顯示；審閱處置權限 alert:manage（admin/auditor 有，user 無）——與後端一致
const { isAdmin, isPrivileged: canReview } = useRoles()

// --- 告警記錄 ---
const alerts = ref([])
const alertsLoading = ref(false)
const timeRange = ref([])
const filters = ref({
  severity: '',
  unreviewed: false,
})

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
  return row.disposition === 'escalated' ? Warning : CircleCheck
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
const pagination = ref({
  page: 1,
  page_size: 20,
  total: 0,
})

const fetchAlerts = async () => {
  alertsLoading.value = true
  try {
    const params = {
      page: pagination.value.page,
      page_size: pagination.value.page_size,
    }

    if (filters.value.severity) params.severity = filters.value.severity
    if (filters.value.unreviewed) params.unreviewed = 'true'

    if (timeRange.value && timeRange.value.length === 2) {
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
  filters.value = { severity: '', unreviewed: false }
  timeRange.value = []
  handleSearch()
}

// 重新整理：依目前頁籤重載對應資料（C4）
const handleRefresh = () => {
  if (activeTab.value === 'rules') fetchRules()
  else if (activeTab.value === 'channels') fetchChannels()
  else fetchAlerts()
}

const goToSession = (row) => {
  router.push(`/sessions/${row.session_id}`)
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
    protocols: row.protocols ? row.protocols.split(',').filter(Boolean) : [],
    enabled: row.enabled,
  }
  ruleDialogVisible.value = true
}

const handleSaveRule = async () => {
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
  fetchAlerts()
  if (isAdmin.value) {
    fetchRules()
  }
})

// ---- 通知通道（頁籤三，admin） ----
const channels = ref([])
const channelsLoading = ref(false)
const channelDialogVisible = ref(false)
const channelSaving = ref(false)
const editingChannelId = ref(null)
const channelFormRef = ref(null)
const channelForm = ref({ name: '', type: 'webhook', url: '', secret: '', clearSecret: false, hasSecret: false, enabled: true, language: CHANNEL_LANGUAGE_DEFAULT })

// 編輯時 URL 留空＝沿用既有值，僅建立時必填
const channelFormRules = computed(() => ({
  name: [
    { required: true, message: t('alerts.channelNameRequired'), trigger: 'blur' },
  ],
  type: [
    { required: true, message: t('alerts.channelTypeRequired'), trigger: 'change' },
  ],
  url: [
    {
      validator: (rule, value, callback) => {
        if (!editingChannelId.value && !value) {
          callback(new Error(t('alerts.channelUrlRequired')))
        } else {
          callback()
        }
      },
      trigger: 'blur',
    },
  ],
}))

const fetchChannels = async () => {
  channelsLoading.value = true
  try {
    const response = await getChannels()
    channels.value = Array.isArray(response) ? response : response.data || []
  } catch (error) {
    console.error('取得通知通道失敗:', error)
  } finally {
    channelsLoading.value = false
  }
}

const openChannelDialog = (row = null) => {
  editingChannelId.value = row ? row.id : null
  // 編輯時 secret 與 url 皆留空＝沿用既有（後端回應的 url 已遮罩，
  // 回填會把遮罩字串存成真 URL）；maskedUrl 僅供顯示
  channelForm.value = row
    ? { name: row.name, type: row.type || 'webhook', url: '', maskedUrl: row.url, secret: '', clearSecret: false, hasSecret: !!row.has_secret, enabled: row.enabled, language: row.language || CHANNEL_LANGUAGE_DEFAULT }
    : { name: '', type: 'webhook', url: '', maskedUrl: '', secret: '', clearSecret: false, hasSecret: false, enabled: true, language: CHANNEL_LANGUAGE_DEFAULT }
  channelDialogVisible.value = true
}

// 傳輸政策 warn 檔存 http 通道：
// 後端回 400＋code=VALIDATION_TRANSMISSION_ACK_REQUIRED＋risks，前端確認後帶 risk_acknowledged 重送
const saveChannelOnce = (payload, ack) => {
  const body = { ...payload, risk_acknowledged: ack }
  const opts = { skipErrorToast: true }
  return editingChannelId.value
    ? updateChannel(editingChannelId.value, body, opts)
    : createChannel(body, opts)
}

const handleSaveChannel = async () => {
  try {
    await channelFormRef.value.validate()
  } catch {
    return // 驗證未過，紅字就近提示
  }
  channelSaving.value = true
  try {
    // clearSecret（表單）→ clear_secret（API）；secret/url 留空＝後端沿用既有值。
    // 僅送後端欄位：hasSecret/maskedUrl/clearSecret 為表單顯示狀態不外送
    const f = channelForm.value
    const payload = {
      name: f.name,
      type: f.type,
      url: f.url,
      secret: f.secret,
      enabled: f.enabled,
      clear_secret: f.clearSecret,
      // 通道語系：Create 未給＝後端預設 zh-TW、Update 省略＝保留，
      // 表單恆有值故一律送出（白名單外由後端 VALIDATION 碼擋）
      language: f.language,
    }
    let acknowledged = false
    for (;;) {
      try {
        await saveChannelOnce(payload, acknowledged)
        break
      } catch (error) {
        const resp = error?.response
        if (resp?.status === 400 && resp.data?.code === 'VALIDATION_TRANSMISSION_ACK_REQUIRED' && !acknowledged) {
          const risks = Array.isArray(resp.data.risks) ? resp.data.risks : []
          // 使用者取消＝reject → 中止儲存（對話框保持開啟）
          await ElMessageBox.confirm(
            t('alerts.channelRiskConfirm', {
              risks: risks.map((r) => riskLabel(r)).join(t('common.listSeparator')),
            }),
            t('connect.risksTitle'),
            { confirmButtonText: t('connect.risksConfirm'), cancelButtonText: t('common.cancel'), type: 'warning' }
          )
          acknowledged = true
          continue
        }
        // 其他錯誤：skipErrorToast 已關掉全域 toast，此處補回呈現
        ElMessage.error(resolveApiError(resp?.data, resp?.status, t('alerts.channelSaveFailed')))
        throw error
      }
    }
    ElMessage.success(editingChannelId.value ? t('alerts.channelUpdated') : t('alerts.channelCreated'))
    channelDialogVisible.value = false
    fetchChannels()
  } catch (error) {
    // 使用者取消同意（cancel）或錯誤已呈現；對話框保持開啟供修正
    console.error('儲存通道失敗:', error)
  } finally {
    channelSaving.value = false
  }
}

const handleChannelToggle = async (row, val) => {
  try {
    // 不送 url：row.url 是遮罩值，送出會把遮罩存成真 URL；空值＝後端沿用既有
    await updateChannel(row.id, { name: row.name, type: row.type, enabled: val })
    row.enabled = val
  } catch (error) {
    console.error('切換通道狀態失敗:', error)
    fetchChannels()
  }
}

const handleTestChannel = async (row) => {
  try {
    const result = await testChannel(row.id)
    if (result.success) {
      ElMessage.success(t('alerts.testSent', { status: result.status_code }))
    } else {
      ElMessage.error(t('alerts.testFailed', { status: result.status_code }))
    }
  } catch (error) {
    console.error('測試通知送出失敗:', error)
  }
}

const handleDeleteChannel = async (row) => {
  try {
    await ElMessageBox.confirm(
      t('alerts.deleteChannelConfirm', { name: row.name }),
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
    await deleteChannel(row.id)
    ElMessage.success(t('alerts.channelDeleted'))
    fetchChannels()
  } catch (error) {
    console.error('刪除通道失敗:', error)
  }
}

// tab 切換即 refetch（C8：資料新鮮優先，對齊 Sessions 模式）
const handleTabChange = (tab) => {
  if (tab === 'rules') fetchRules()
  else if (tab === 'channels') fetchChannels()
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
  font-size: 12px;
  color: var(--el-color-warning);
  line-height: 1.5;
}

.clear-secret-check {
  margin-top: 6px;
}

.secret-status {
  margin-bottom: 6px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.field-muted {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.field-hint {
  margin-top: 6px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  line-height: 1.5;
}

.field-hint code {
  padding: 1px 5px;
  border-radius: 3px;
  background: var(--el-fill-color-light);
  font-size: 11px;
}

.blocked-tag {
  margin-left: 6px;
}
</style>
