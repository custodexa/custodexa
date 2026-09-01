<template>
  <div class="approvals">
    <PageHeader
      :title="$t('menu.approvals')"
      :description="$t('approvals.headerDesc')"
    >
      <template #actions>
        <el-button @click="fetchCurrentTab">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 無審核資格：直接打 URL 進來時後端一律 403。此處必須明說
         「你沒有資格」，不得退化成一張空表格——那會被讀成「佇列是空的」 -->
    <div
      v-if="accessDenied"
      class="list-panel"
    >
      <EmptyState
        :icon="Lock"
        :title="$t('approvals.forbiddenTitle')"
        :hint="$t('approvals.forbiddenHint')"
      />
    </div>

    <!-- tabs 置頁面層（C8，對齊 Sessions/AuditLogs 結構），面板框在各頁籤內 -->
    <el-tabs
      v-else
      v-model="activeTab"
      @tab-change="fetchCurrentTab"
    >
      <!-- 待審 -->
      <el-tab-pane
        :label="pendingLabel"
        name="pending"
      >
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="pendingRequests"
            style="width: 100%"
            stripe
          >
            <el-table-column
              :label="$t('approvals.colRequester')"
              width="130"
            >
              <template #default="{ row }">
                {{ row.requester?.username || `#${row.requester_id}` }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="150"
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
              min-width="220"
              show-overflow-tooltip
              prop="reason"
            />
            <el-table-column
              :label="$t('approvals.colWishUse')"
              width="150"
            >
              <template #default="{ row }">
                {{ formatMinutes(row.requested_duration_minutes) }}
                <div
                  v-if="row.requested_date_start"
                  class="sub-text"
                >
                  {{ $t('approvals.fromTime', { time: formatDateTime(row.requested_date_start) }) }}
                </div>
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
              v-if="quorumEnabled"
              :label="$t('approvals.colApprovalProgress')"
              width="110"
            >
              <template #default="{ row }">
                <el-tooltip
                  :content="voterNames(row)"
                  :disabled="!(row.approvals || []).length"
                  placement="top"
                >
                  <el-tag
                    size="small"
                    :type="row.approvals_received > 0 ? 'warning' : 'info'"
                  >
                    {{ row.approvals_received }}/{{ row.approvals_required }}
                  </el-tag>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.actions')"
              width="190"
              fixed="right"
            >
              <template #default="{ row }">
                <el-button
                  link
                  type="primary"
                  size="small"
                  :disabled="hasMyVote(row)"
                  @click="openApprove(row)"
                >
                  {{ hasMyVote(row) ? $t('approvals.approvedByMe') : $t('approvals.approve') }}
                </el-button>
                <el-button
                  link
                  type="danger"
                  size="small"
                  @click="openReject(row)"
                >
                  {{ $t('approvals.reject') }}
                </el-button>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState :title="emptyTitleFor('approvals.emptyPending')" />
            </template>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 歷史 -->
      <el-tab-pane
        :label="$t('approvals.tabHistory')"
        name="history"
      >
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="historyRequests"
            style="width: 100%"
            stripe
          >
            <el-table-column
              :label="$t('approvals.colRequester')"
              width="130"
            >
              <template #default="{ row }">
                {{ row.requester?.username || `#${row.requester_id}` }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="150"
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
              :label="$t('approvals.colResult')"
              width="120"
            >
              <template #default="{ row }">
                <el-tag :type="statusTagType(row.status)">
                  {{ statusText(row.status) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colHandler')"
              width="150"
            >
              <template #default="{ row }">
                <el-tag
                  v-if="row.auto_approved"
                  type="info"
                  size="small"
                >
                  {{ $t('common.systemAutoApproved') }}
                </el-tag>
                <span v-else>
                  {{ row.approver?.username || '—' }}
                  <div
                    v-if="(row.approvals || []).length > 1"
                    class="sub-text"
                  >
                    {{ $t('approvals.approvedByCount', { n: row.approvals.length }) }}
                  </div>
                </span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colHandledTime')"
              width="170"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.decided_at) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.note')"
              min-width="160"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                {{ row.decision_note === 'system' ? '—' : row.decision_note || '—' }}
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState :title="emptyTitleFor('approvals.emptyHistory')" />
            </template>
          </el-table>
          <div class="pagination">
            <el-pagination
              v-model:current-page="historyPage"
              v-model:page-size="historyPageSize"
              :page-sizes="[10, 20, 50, 100]"
              :total="historyTotal"
              layout="total, sizes, prev, pager, next, jumper"
              @size-change="handleHistorySizeChange"
              @current-change="fetchHistory"
            />
          </div>
        </div>
      </el-tab-pane>

      <!-- 有效限時連線 -->
      <el-tab-pane
        :label="$t('approvals.tabTickets')"
        name="tickets"
      >
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="tickets"
            style="width: 100%"
            stripe
          >
            <el-table-column
              :label="$t('common.user')"
              width="150"
            >
              <template #default="{ row }">
                {{ row.user?.username || `#${row.user_id}` }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="160"
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
              :label="$t('common.connectableTime')"
              min-width="300"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.date_start) }} ～ {{ formatDateTime(row.date_expired) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colApprover')"
              width="130"
            >
              <template #default="{ row }">
                {{ row.granted_by_user?.username || `#${row.granted_by}` }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.actions')"
              width="110"
              fixed="right"
            >
              <template #default="{ row }">
                <el-button
                  type="danger"
                  size="small"
                  link
                  @click="openRevokeDialog(row)"
                >
                  {{ $t('approvals.revokeEarly') }}
                </el-button>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState :title="emptyTitleFor('approvals.emptyTickets')" />
            </template>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 待補審：破窗連線事後補審 -->
      <el-tab-pane
        :label="pendingReviewLabel"
        name="reviews"
      >
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="pendingReviews"
            style="width: 100%"
            stripe
          >
            <el-table-column
              :label="$t('common.user')"
              width="130"
            >
              <template #default="{ row }">
                {{ row.requester?.username || `#${row.requester_id}` }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.asset')"
              min-width="150"
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
              :label="$t('approvals.colEmergencyReason')"
              min-width="220"
              show-overflow-tooltip
            >
              <template #default="{ row }">
                {{ row.reason }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approvals.colConnectTime')"
              width="170"
            >
              <template #default="{ row }">
                {{ formatDateTime(row.created_at) }}
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
                  size="small"
                  @click="openReviewDialog(row)"
                >
                  {{ $t('approvals.review') }}
                </el-button>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState :title="emptyTitleFor('approvals.emptyReviews')" />
            </template>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- SQL 核准預留頁籤位（與現有核准共用同一收件匣，本版未開放） -->
      <el-tab-pane
        :label="$t('approvals.tabSql')"
        name="sql"
        disabled
      />
    </el-tabs>

    <!-- 核准對話框：時長只能縮短、開始時間只能延後（放寬會被拒絕） -->
    <el-dialog
      v-model="approveVisible"
      :title="$t('approvals.approveDialogTitle')"
      width="480px"
      :close-on-click-modal="false"
    >
      <div
        v-if="approveTarget"
        class="approve-summary"
      >
        <i18n-t
          keypath="approvals.approveSummary"
          tag="p"
          scope="global"
        >
          <template #user>
            <strong>{{ approveTarget.requester?.username }}</strong>
          </template>
          <template #asset>
            <strong>{{ approveTarget.asset?.name }}</strong>
          </template>
        </i18n-t>
        <p class="reason-text">
          {{ $t('approvals.reasonLine', { reason: approveTarget.reason }) }}
        </p>
      </div>
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('approvals.durationLabel', { max: approveTarget?.requested_duration_minutes || 0 })">
          <el-input-number
            v-model="approveForm.duration_minutes"
            :min="1"
            :max="approveTarget?.requested_duration_minutes || 1"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item :label="$t('approvals.startTimeLabel')">
          <el-date-picker
            v-model="approveForm.date_start"
            type="datetime"
            :placeholder="$t('approvals.immediateEffect')"
            style="width: 100%"
          />
        </el-form-item>
        <el-form-item :label="$t('approvals.noteOptional')">
          <el-input
            v-model="approveForm.note"
            type="textarea"
            :rows="2"
            maxlength="1000"
            :placeholder="$t('approvals.notePlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="approveVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="deciding"
          @click="submitApprove"
        >
          {{ $t('approvals.approve') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 拒絕對話框：理由必填（申請人會看到） -->
    <el-dialog
      v-model="rejectVisible"
      :title="$t('approvals.rejectDialogTitle')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('approvals.rejectReasonLabel')">
          <el-input
            v-model="rejectNote"
            type="textarea"
            :rows="3"
            maxlength="1000"
            :placeholder="$t('approvals.rejectPlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="rejectVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="danger"
          :disabled="!rejectNote.trim()"
          :loading="deciding"
          @click="submitReject"
        >
          {{ $t('approvals.reject') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 提前撤銷對話框：事由必填 -->
    <el-dialog
      v-model="revokeVisible"
      :title="$t('approvals.revokeDialogTitle')"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-alert
        v-if="revokeTarget"
        :title="$t('approvals.revokeAlertTitle', {
          user: revokeTarget.user?.username || $t('common.user'),
          asset: revokeTarget.asset?.name || $t('common.asset'),
        })"
        type="warning"
        :closable="false"
        class="dialog-hint"
      >
        <template #default>
          {{ $t('approvals.revokeAlertBody') }}
        </template>
      </el-alert>
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('approvals.revokeReasonLabel')">
          <el-input
            v-model="revokeNote"
            type="textarea"
            :rows="3"
            maxlength="1000"
            :placeholder="$t('approvals.revokePlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="revokeVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="danger"
          :disabled="!revokeNote.trim()"
          :loading="deciding"
          @click="submitRevoke"
        >
          {{ $t('common.confirmRevoke') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 補審對話框：處置＋備註 -->
    <el-dialog
      v-model="reviewVisible"
      :title="$t('approvals.reviewDialogTitle')"
      width="480px"
      :close-on-click-modal="false"
    >
      <div
        v-if="reviewTarget"
        class="approve-summary"
      >
        <i18n-t
          keypath="approvals.reviewSummary"
          tag="p"
          scope="global"
        >
          <template #user>
            <strong>{{ reviewTarget.requester?.username }}</strong>
          </template>
          <template #asset>
            <strong>{{ reviewTarget.asset?.name }}</strong>
          </template>
        </i18n-t>
        <p class="reason-text">
          {{ $t('approvals.reasonOriginLine', { reason: reviewTarget.reason }) }}
        </p>
      </div>
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('approvals.reviewConclusionLabel')">
          <el-radio-group v-model="reviewForm.disposition">
            <el-radio label="confirmed">
              {{ $t('approvals.dispositionConfirmed') }}
            </el-radio>
            <el-radio label="violation">
              {{ $t('approvals.dispositionViolation') }}
            </el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="$t('approvals.noteOptional')">
          <el-input
            v-model="reviewForm.note"
            type="textarea"
            :rows="2"
            maxlength="1000"
            :placeholder="$t('approvals.reviewNotePlaceholder')"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="reviewVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="deciding"
          @click="submitReview"
        >
          {{ $t('approvals.submitReview') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { RefreshCw, Lock } from 'lucide-vue-next'
import { ElMessage } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { useRoles } from '@/composables/useRoles'
import { t } from '@/i18n'
import {
  getPendingAccessRequests,
  getAccessRequestHistory,
  getActiveTickets,
  approveAccessRequest,
  rejectAccessRequest,
  revokeAccessRequest,
  reviewBreakGlass,
  getPendingReviews,
} from '@/api/accessRequests'

const activeTab = ref('pending')
const loading = ref(false)
const deciding = ref(false)

const pendingRequests = ref([])
const historyRequests = ref([])
const historyPage = ref(1)
const historyPageSize = ref(20)
const historyTotal = ref(0)
const tickets = ref([])
const pendingReviews = ref([])

const pendingLabel = computed(() =>
  pendingRequests.value.length > 0
    ? t('approvals.pendingTabCount', { n: pendingRequests.value.length })
    : t('approvals.pendingTab')
)

// quorum：門檻 >1 才顯示進度欄；已投票者禁重複核准
const { currentUserId } = useRoles()
const quorumEnabled = computed(() =>
  pendingRequests.value.some((r) => (r.approvals_required || 1) > 1)
)
const hasMyVote = (row) =>
  (row.approvals || []).some((v) => v.approver_id === currentUserId.value)
const voterNames = (row) =>
  t('approvals.votedList', {
    names: (row.approvals || [])
      .map((v) => v.approver?.username || `#${v.approver_id}`)
      .join(t('common.listSeparator')),
  })
const pendingReviewLabel = computed(() =>
  pendingReviews.value.length > 0
    ? t('approvals.reviewTabCount', { n: pendingReviews.value.length })
    : t('approvals.reviewTab')
)

// 載入結果狀態：**403 不得被吞成空陣列**。
// 收斂前四個頁籤的 catch 都只 console.error，於是不具審核資格者（例如僅具
// admin 者，審核端點對他一律 403）看到的是一張空表格＋「目前沒有等候
// 審核的申請」——把「你看不到」謊報成「沒有東西」。有待審單時這會讓人誤判佇列
// 已清空。'forbidden'＝無資格（連頁籤都不該給）；'failed'＝其他載入失敗
//（頁籤保留，但空態文案必須說是載入失敗而非沒有資料）
const accessDenied = ref(false)
const loadFailed = ref(false)

const handleFetchError = (error, label) => {
  console.error(label, error)
  if (error?.response?.status === 403) {
    accessDenied.value = true
  } else {
    loadFailed.value = true
  }
}

// 任一頁籤載入成功即代表資格與連線正常，清掉兩個錯誤狀態
const markFetchOk = () => {
  accessDenied.value = false
  loadFailed.value = false
}

// 空態文案：載入失敗時不得沿用「沒有資料」的說法
const emptyTitleFor = (key) =>
  loadFailed.value ? t('approvals.loadFailed') : t(key)

const fetchPending = async () => {
  loading.value = true
  try {
    const res = await getPendingAccessRequests()
    pendingRequests.value = res.data || []
    markFetchOk()
  } catch (error) {
    handleFetchError(error, '載入待審申請失敗:')
  } finally {
    loading.value = false
  }
}

const fetchHistory = async () => {
  loading.value = true
  try {
    const res = await getAccessRequestHistory({
      page: historyPage.value,
      page_size: historyPageSize.value,
    })
    historyRequests.value = res.data || []
    historyTotal.value = res.total ?? 0
    markFetchOk()
  } catch (error) {
    handleFetchError(error, '載入申請歷史失敗:')
  } finally {
    loading.value = false
  }
}

const handleHistorySizeChange = () => {
  historyPage.value = 1
  fetchHistory()
}

const fetchTickets = async () => {
  loading.value = true
  try {
    const res = await getActiveTickets()
    tickets.value = res.data || []
    markFetchOk()
  } catch (error) {
    handleFetchError(error, '載入限時連線失敗:')
  } finally {
    loading.value = false
  }
}

const fetchReviews = async () => {
  loading.value = true
  try {
    const res = await getPendingReviews()
    pendingReviews.value = res.data || []
    markFetchOk()
  } catch (error) {
    handleFetchError(error, '載入待補審失敗:')
  } finally {
    loading.value = false
  }
}

const fetchCurrentTab = () => {
  if (activeTab.value === 'pending') fetchPending()
  else if (activeTab.value === 'history') fetchHistory()
  else if (activeTab.value === 'tickets') fetchTickets()
  else if (activeTab.value === 'reviews') fetchReviews()
}

// 核准對話框
const approveVisible = ref(false)
const approveTarget = ref(null)
const approveForm = ref({ duration_minutes: 60, date_start: null, note: '' })

const openApprove = (row) => {
  approveTarget.value = row
  approveForm.value = {
    duration_minutes: row.requested_duration_minutes,
    date_start: row.requested_date_start ? new Date(row.requested_date_start) : null,
    note: '',
  }
  approveVisible.value = true
}

const submitApprove = async () => {
  if (!approveTarget.value) return
  deciding.value = true
  try {
    const payload = {
      duration_minutes: approveForm.value.duration_minutes,
      note: approveForm.value.note || undefined,
    }
    if (approveForm.value.date_start) {
      payload.date_start = new Date(approveForm.value.date_start).toISOString()
    }
    const res = await approveAccessRequest(approveTarget.value.id, payload)
    if (res?.status === 'pending') {
      ElMessage.success(
        t('approvals.approveRecorded', {
          received: res.approvals_received,
          required: res.approvals_required,
        })
      )
    } else {
      ElMessage.success(t('approvals.approveSuccess'))
    }
    approveVisible.value = false
  } catch (error) {
    // 409（已被他人處理/撤回）、400（放寬被拒）由攔截器顯示後端訊息
    console.error('核准失敗:', error)
  } finally {
    deciding.value = false
    fetchPending()
  }
}

// 拒絕對話框
const rejectVisible = ref(false)
const rejectTarget = ref(null)
const rejectNote = ref('')

const openReject = (row) => {
  rejectTarget.value = row
  rejectNote.value = ''
  rejectVisible.value = true
}

const submitReject = async () => {
  if (!rejectTarget.value || !rejectNote.value.trim()) return
  deciding.value = true
  try {
    await rejectAccessRequest(rejectTarget.value.id, rejectNote.value.trim())
    ElMessage.success(t('approvals.rejectSuccess'))
    rejectVisible.value = false
  } catch (error) {
    console.error('拒絕失敗:', error)
  } finally {
    deciding.value = false
    fetchPending()
  }
}

// 提前撤銷：撤銷限時連線，事由必填
const revokeVisible = ref(false)
const revokeTarget = ref(null)
const revokeNote = ref('')

const openRevokeDialog = (row) => {
  revokeTarget.value = row
  revokeNote.value = ''
  revokeVisible.value = true
}

const submitRevoke = async () => {
  if (!revokeTarget.value || !revokeNote.value.trim()) return
  deciding.value = true
  try {
    // 有效限時連線列的 id 是授權記錄，撤銷走申請單——後端以 authorization_id
    // 回鏈，故此處帶申請單 id（票證列附 request_id）
    await revokeAccessRequest(revokeTarget.value.request_id, revokeNote.value.trim())
    ElMessage.success(t('approvals.revokeSuccess'))
    revokeVisible.value = false
  } catch (error) {
    // 403 非資格、409 已撤/到期由攔截器顯示後端訊息
    console.error('撤銷失敗:', error)
  } finally {
    deciding.value = false
    fetchTickets()
  }
}

// 補審：破窗事後審核，處置＋備註
const reviewVisible = ref(false)
const reviewTarget = ref(null)
const reviewForm = ref({ disposition: 'confirmed', note: '' })

const openReviewDialog = (row) => {
  reviewTarget.value = row
  reviewForm.value = { disposition: 'confirmed', note: '' }
  reviewVisible.value = true
}

const submitReview = async () => {
  if (!reviewTarget.value) return
  deciding.value = true
  try {
    await reviewBreakGlass(
      reviewTarget.value.id,
      reviewForm.value.disposition,
      reviewForm.value.note || ''
    )
    ElMessage.success(t('approvals.reviewSuccess'))
    reviewVisible.value = false
  } catch (error) {
    // 403 自審/範圍外、409 已補審由攔截器顯示後端訊息
    console.error('補審失敗:', error)
  } finally {
    deciding.value = false
    fetchReviews()
  }
}

const statusText = (status) => {
  const map = {
    approved: t('approvals.status.approved'),
    rejected: t('approvals.status.rejected'),
    cancelled: t('approvals.status.cancelled'),
    expired: t('approvals.status.expired'),
  }
  return map[status] || status
}

const statusTagType = (status) => {
  const map = {
    approved: 'success',
    rejected: 'danger',
    cancelled: 'info',
    expired: 'info',
  }
  return map[status] || 'info'
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

onMounted(fetchPending)
</script>

<style scoped>
.approvals {
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

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--ot-space-md);
}

.approve-summary {
  margin-bottom: var(--ot-space-md);
  color: var(--ot-text-primary);
}

.approve-summary p {
  margin: 0 0 var(--ot-space-xs);
}

.reason-text {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.sub-text {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
</style>
