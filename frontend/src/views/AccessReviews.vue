<template>
  <div class="access-reviews">
    <PageHeader
      :title="$t('menu.accessReviews')"
      :description="$t('accessReviews.headerDesc')"
    >
      <template #actions>
        <el-button
          v-if="isAdmin"
          type="primary"
          @click="openReviewDialog"
        >
          <el-icon><Select /></el-icon>
          {{ $t('accessReviews.initReview') }}
        </el-button>
        <el-button @click="fetchReviews">
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 複審狀態卡：週期與逾期判定由伺服端回傳（前端不硬編碼） -->
    <div
      class="review-bar"
      role="status"
    >
      <div class="review-status">
        <el-icon :class="overdue ? 'review-icon is-warn' : 'review-icon is-ok'">
          <Warning v-if="overdue" />
          <CircleCheck v-else />
        </el-icon>
        <span v-if="lastReviewDaysAgo < 0">{{ $t('accessReviews.neverReviewed', { n: periodDays }) }}</span>
        <span v-else-if="overdue">{{ $t('accessReviews.overdueLine', { days: lastReviewDaysAgo, period: periodDays }) }}</span>
        <span v-else>{{ $t('accessReviews.lastReviewLine', { days: lastReviewDaysAgo, period: periodDays }) }}</span>
      </div>
    </div>

    <!-- 複審歷史清單 -->
    <div class="list-card">
      <el-alert
        v-if="loadError"
        type="error"
        :closable="false"
        show-icon
        :title="$t('accessReviews.loadFailed')"
        :description="loadError"
        class="load-error"
      />
      <el-table
        v-loading="loading"
        :data="reviewList"
        style="width: 100%"
        stripe
      >
        <el-table-column
          prop="id"
          label="ID"
          width="80"
        />
        <el-table-column
          prop="reviewer_name"
          :label="$t('accessReviews.reviewer')"
          width="140"
        />
        <el-table-column
          :label="$t('accessReviews.reviewTime')"
          width="180"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.reviewed_at) }}
          </template>
        </el-table-column>
        <el-table-column
          prop="authorization_count"
          :label="$t('accessReviews.authCount')"
          width="100"
        />
        <el-table-column
          prop="note"
          :label="$t('accessReviews.conclusion')"
          min-width="220"
          show-overflow-tooltip
        />
        <el-table-column
          :label="$t('accessReviews.daysAgoCol')"
          width="100"
        >
          <template #default="{ row }">
            {{ $t('accessReviews.daysAgo', { n: row.days_ago }) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="120"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              type="primary"
              size="small"
              link
              @click="openDetail(row)"
            >
              <el-icon><View /></el-icon>
              {{ $t('accessReviews.viewSnapshot') }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            v-if="!loadError"
            :title="$t('accessReviews.emptyTitle')"
            :hint="isAdmin ? $t('accessReviews.emptyHintAdmin') : $t('accessReviews.emptyHintUser')"
          />
          <span v-else />
        </template>
      </el-table>
    </div>

    <!-- 單筆快照檢視抽屜（型別化矩陣渲染） -->
    <el-drawer
      v-model="detailVisible"
      :title="detailTitle"
      size="60%"
    >
      <div
        v-if="detail"
        class="detail-body"
      >
        <el-descriptions
          border
          :column="2"
          class="detail-meta"
        >
          <el-descriptions-item :label="$t('accessReviews.reviewer')">
            {{ detail.reviewer_name }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('accessReviews.reviewTime')">
            {{ formatDateTime(detail.reviewed_at) }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('accessReviews.scope')">
            {{ detail.scope }}
          </el-descriptions-item>
          <el-descriptions-item :label="$t('accessReviews.authCount')">
            {{ detail.authorization_count }}
          </el-descriptions-item>
          <el-descriptions-item
            :label="$t('accessReviews.conclusion')"
            :span="2"
          >
            {{ detail.note || $t('accessReviews.notFilled') }}
          </el-descriptions-item>
        </el-descriptions>

        <el-table
          :data="detail.matrix"
          stripe
          height="480"
        >
          <el-table-column
            prop="authorization_id"
            :label="$t('accessReviews.authId')"
            width="90"
          />
          <el-table-column
            :label="$t('accessReviews.subject')"
            min-width="150"
          >
            <template #default="{ row }">
              <template v-if="row.user_group_id">
                <el-tag
                  size="small"
                  type="warning"
                >
                  {{ $t('common.group') }}
                </el-tag>
                {{ row.user_group_name }}
              </template>
              <template v-else>
                {{ row.username }}
              </template>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('accessReviews.object')"
            min-width="150"
          >
            <template #default="{ row }">
              <template v-if="row.asset_group_id">
                <el-tag
                  size="small"
                  type="info"
                >
                  {{ $t('common.node') }}
                </el-tag>
                {{ row.group_name }}
              </template>
              <template v-else>
                {{ row.asset_name }}
              </template>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('common.permission')"
            width="100"
          >
            <template #default="{ row }">
              {{ ['view', 'connect'].includes(row.permission) ? $t(`assets.permission.${row.permission}`) : row.permission }}
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('common.grantedTime')"
            width="170"
          >
            <template #default="{ row }">
              {{ formatDateTime(row.granted_at) }}
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-drawer>

    <!-- 發起簽核對話框（admin only） -->
    <el-dialog
      v-model="reviewDialogVisible"
      :title="$t('accessReviews.initReview')"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-alert
        type="info"
        :closable="false"
        show-icon
        style="margin-bottom: 16px"
      >
        {{ $t('accessReviews.initAlert', { n: matrixCount }) }}
      </el-alert>
      <el-form
        ref="reviewFormRef"
        :model="reviewForm"
        :rules="reviewFormRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('accessReviews.conclusionLabel')"
          prop="note"
        >
          <el-input
            v-model="reviewForm.note"
            type="textarea"
            :rows="4"
            maxlength="500"
            show-word-limit
            :placeholder="$t('accessReviews.notePlaceholder')"
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
          {{ $t('accessReviews.confirmSign') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, Select, View, Warning, CircleCheck } from '@element-plus/icons-vue'
import {
  getAccessReviews,
  getAccessMatrix,
  getAccessReviewDetail,
  createAccessReview,
} from '@/api/access-reviews'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { useRoles } from '@/composables/useRoles'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'

// 存取複審獨立頁（自授權頁遷出，
// 職能歸審計區；admin＋auditor 可見、簽核限 admin——auditor 隱藏發起按鈕，
// 後端另有無條件 admin 守門）
const loading = ref(false)
const loadError = ref('')
const reviewList = ref([])
const lastReviewDaysAgo = ref(-1)
const periodDays = ref(180)
const overdue = ref(false)
const { isAdmin } = useRoles()

const fetchReviews = async () => {
  loading.value = true
  loadError.value = ''
  try {
    const res = await getAccessReviews()
    reviewList.value = res.data || []
    lastReviewDaysAgo.value =
      res.last_review_days_ago === undefined ? -1 : res.last_review_days_ago
    if (res.review_period_days) periodDays.value = res.review_period_days
    overdue.value = !!res.overdue
  } catch (error) {
    console.error('查詢複審歷史失敗:', error)
    loadError.value = resolveApiError(
      error?.response?.data,
      error?.response?.status,
      t('common.serverError')
    )
  } finally {
    loading.value = false
  }
}

// 快照檢視
const detailVisible = ref(false)
const detail = ref(null)
const detailTitle = ref('')

const openDetail = async (row) => {
  detail.value = null
  detailTitle.value = t('accessReviews.snapshotTitle', { id: row.id })
  try {
    detail.value = await getAccessReviewDetail(row.id)
    detailVisible.value = true
  } catch (error) {
    // 全域攔截器已 toast 錯誤（C10：頁內不重複）
    console.error('查詢複審快照失敗:', error)
  }
}

// 發起簽核（admin only）
const reviewDialogVisible = ref(false)
const reviewSubmitting = ref(false)
const reviewFormRef = ref(null)
const reviewForm = ref({ note: '' })
const matrixCount = ref(0)

// 簽核為管理層確認語意（PCI 7.2.4）：結論必填留痕（computed：切語言即時重算訊息）
const reviewFormRules = computed(() => ({
  note: [
    { required: true, message: t('accessReviews.noteRequired'), trigger: 'blur' },
  ],
}))

const openReviewDialog = async () => {
  reviewForm.value = { note: '' }
  try {
    const res = await getAccessMatrix()
    matrixCount.value = res.total || 0
  } catch {
    matrixCount.value = 0
  }
  reviewDialogVisible.value = true
}

const submitReview = async () => {
  try {
    await reviewFormRef.value.validate()
  } catch {
    return // 驗證未過，紅字就近提示
  }
  reviewSubmitting.value = true
  try {
    await createAccessReview({ note: reviewForm.value.note })
    ElMessage.success(t('accessReviews.signed'))
    reviewDialogVisible.value = false
    fetchReviews()
  } catch (error) {
    // 全域攔截器已 toast 錯誤（C10：頁內不重複）
    console.error('提交存取複審失敗:', error)
  } finally {
    reviewSubmitting.value = false
  }
}

onMounted(() => {
  fetchReviews()
})
</script>

<style scoped>
.access-reviews {
  /* MainLayout main-content 已有 padding */
}

.review-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-md);
  flex-wrap: wrap;
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

.review-status {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  font-size: 14px;
}

.review-icon {
  font-size: 18px;
}

.review-icon.is-ok {
  color: var(--el-color-success);
}

.review-icon.is-warn {
  color: var(--el-color-warning);
}

.list-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  min-height: 400px;
}

.load-error {
  margin-bottom: var(--ot-space-md);
}

.detail-meta {
  margin-bottom: var(--ot-space-md);
}

.detail-body {
  padding: 0 var(--ot-space-sm);
}
</style>
