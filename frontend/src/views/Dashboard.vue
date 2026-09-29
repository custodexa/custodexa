<template>
  <div class="dashboard">
    <PageHeader
      :title="$t('menu.dashboard')"
      :description="$t('dashboard.headerDesc', { name: BRAND.name, subtitle: $t('brand.subtitle') })"
    >
      <template #actions>
        <el-button @click="handleRefresh">
          <el-icon><RefreshCw /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <el-row :gutter="16">
      <el-col
        v-for="card in statCards"
        :key="card.label"
        :xs="12"
        :sm="12"
        :md="6"
      >
        <!-- 可點擊性依 card.to 是否存在而定：錄影佔用卡沒有可跳轉的目標頁
             （不存在「錄影儲存」頁），隨便指一個頁會讓使用者以為那裡有儲存資訊 -->
        <div
          v-loading="loading"
          class="stat-card"
          :class="{ 'stat-card-clickable': card.to }"
          :role="card.to ? 'button' : undefined"
          :tabindex="card.to ? 0 : undefined"
          @click="card.to && $router.push(card.to)"
          @keydown.enter.space.prevent="card.to && $router.push(card.to)"
        >
          <div
            class="stat-icon"
            :style="{ color: card.color, backgroundColor: card.bg }"
          >
            <el-icon :size="20">
              <component :is="card.icon" />
            </el-icon>
          </div>
          <div class="stat-text">
            <div class="stat-value">
              {{ card.value }}
            </div>
            <div class="stat-label">
              {{ card.label }}
            </div>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- 人設待辦卡列：待辦導向，非權限裁切；多角色聯集去重 -->
    <el-row
      v-if="backlogCards.length"
      :gutter="16"
    >
      <el-col
        v-for="card in backlogCards"
        :key="card.label"
        :xs="12"
        :sm="12"
        :md="6"
      >
        <div
          class="stat-card stat-card-clickable"
          role="button"
          tabindex="0"
          @click="$router.push(card.to)"
          @keydown.enter.space.prevent="$router.push(card.to)"
        >
          <div
            class="stat-icon"
            :style="{ color: card.color, backgroundColor: card.bg }"
          >
            <el-icon :size="20">
              <component :is="card.icon" />
            </el-icon>
          </div>
          <div class="stat-text">
            <div class="stat-value">
              {{ card.value }}
            </div>
            <div class="stat-label">
              {{ card.label }}
            </div>
          </div>
        </div>
      </el-col>
    </el-row>

    <el-row
      :gutter="16"
      class="activity-row"
    >
      <el-col :md="12">
        <!-- 進行中連線（全域）屬稽核職能；一般 user 改顯示自己的連線摘要，
             不呼叫需 session:view 的端點 -->
        <div
          v-if="isPrivileged"
          class="activity-card"
        >
          <div class="activity-head">
            <span>{{ $t('dashboard.activeSessionsHead') }}</span>
            <el-link
              type="primary"
              :underline="false"
              @click="$router.push('/sessions')"
            >
              {{ $t('dashboard.viewAll') }}
            </el-link>
          </div>
          <EmptyState
            v-if="!recentActive.length"
            :title="$t('dashboard.emptyActiveTitle')"
            :hint="$t('dashboard.emptyActiveHint')"
          />
          <div
            v-for="s in recentActive"
            :key="s.id"
            class="activity-item"
          >
            <span class="activity-main">{{ s.user?.username || $t('dashboard.userFallback', { id: s.user_id }) }} → {{ s.asset?.name || $t('dashboard.assetFallback', { id: s.asset_id }) }}</span>
            <el-tag size="small">
              {{ (s.protocol || '').toUpperCase() }}
            </el-tag>
          </div>
        </div>
        <div
          v-else
          class="activity-card"
        >
          <div class="activity-head">
            <span>{{ $t('menu.myConnections') }}</span>
            <el-link
              type="primary"
              :underline="false"
              @click="$router.push('/my-connections')"
            >
              {{ $t('dashboard.viewAll') }}
            </el-link>
          </div>
          <EmptyState
            v-if="!myRecentConnections.length"
            :title="$t('myConnections.emptyTitle')"
            :hint="$t('dashboard.emptyMyConnectionsHint')"
          />
          <div
            v-for="(conn, idx) in myRecentConnections"
            :key="idx"
            class="activity-item"
          >
            <span class="activity-main">{{ conn.asset_name || $t('myConnections.manualConnection') }}</span>
            <span>
              <el-tag size="small">
                {{ (conn.protocol || '').toUpperCase() }}
              </el-tag>
              <el-tag
                size="small"
                :type="conn.status === 'active' ? 'success' : 'info'"
                class="status-tag"
              >
                {{ conn.status === 'active' ? $t('common.stateActive') : $t('common.stateEnded') }}
              </el-tag>
            </span>
          </div>
        </div>
      </el-col>
      <el-col
        v-if="isPrivileged"
        :md="12"
      >
        <div class="activity-card">
          <div class="activity-head">
            <span>{{ $t('dashboard.recentAlertsHead') }}</span>
            <el-link
              type="primary"
              :underline="false"
              @click="$router.push('/alerts')"
            >
              {{ $t('dashboard.viewAll') }}
            </el-link>
          </div>
          <EmptyState
            v-if="!recentAlerts.length"
            :title="$t('dashboard.emptyAlertsTitle')"
            :hint="$t('dashboard.emptyAlertsHint')"
          />
          <div
            v-for="a in recentAlerts"
            :key="a.id"
            class="activity-item activity-item-stacked"
          >
            <div class="activity-lines">
              <span class="activity-main">{{ $t('dashboard.alertLine', { rule: a.rule_name, command: a.command }) }}</span>
              <span class="activity-sub">
                {{ a.username || $t('dashboard.userFallback', { id: a.user_id }) }}
                <template v-if="a.asset_name"> → {{ a.asset_name }}</template>
                ·
                {{ formatRelativeTime(a.triggered_at) }}
              </span>
            </div>
            <el-tag
              size="small"
              :type="a.severity === 'high' ? 'danger' : a.severity === 'medium' ? 'warning' : 'info'"
            >
              {{ ['high', 'medium', 'low'].includes(a.severity) ? $t(`enum.alertLevel.${a.severity}`) : a.severity }}
            </el-tag>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- 每日安全審閱簽核卡（PCI 10.4.1）：功能未啟用時完全不渲染 -->
    <div
      v-if="reviewStatus.enabled"
      class="review-card"
    >
      <!-- 歷次簽核入口一律是真連結（href 同目標）：原生可 Tab 聚焦、Enter 觸發，
           修飾鍵點擊交還瀏覽器開新分頁 -->
      <div class="review-head">
        <div class="review-head-main">
          <a
            class="review-title review-link"
            :href="REVIEW_HISTORY_HREF"
            :aria-label="$t('dashboard.reviewTitleLinkLabel')"
            @click.exact.prevent="$router.push(REVIEW_HISTORY_ROUTE)"
          >
            {{ $t('dashboard.reviewTitle') }}
            <ChevronRight
              class="review-title-icon"
              :size="16"
              aria-hidden="true"
            />
          </a>
          <span class="review-date">{{ reviewSnapshot.date || '' }}</span>
        </div>
        <div class="review-head-actions">
          <a
            v-if="!reviewStatus.signed"
            class="review-link"
            :href="REVIEW_HISTORY_HREF"
            @click.exact.prevent="$router.push(REVIEW_HISTORY_ROUTE)"
          >
            {{ $t('dashboard.reviewHistoryLink') }}
          </a>
          <el-tag
            v-if="reviewStatus.signed"
            type="success"
            size="small"
          >
            {{ $t('dashboard.reviewSignedTag') }}
          </el-tag>
          <el-tag
            v-else
            type="warning"
            size="small"
          >
            {{ $t('dashboard.reviewPendingTag') }}
          </el-tag>
        </div>
      </div>

      <div class="review-counts">
        <div
          class="review-count"
          role="button"
          tabindex="0"
          @click="$router.push('/audit-logs')"
          @keydown.enter.space.prevent="$router.push('/audit-logs')"
        >
          <div class="review-count-value">
            {{ reviewCount('login_failures') }}
          </div>
          <div class="review-count-label">
            {{ $t('common.loginFailures') }}
          </div>
        </div>
        <div
          class="review-count"
          role="button"
          tabindex="0"
          @click="$router.push('/alerts')"
          @keydown.enter.space.prevent="$router.push('/alerts')"
        >
          <div class="review-count-value">
            {{ reviewCount('unreviewed_alerts') }}
          </div>
          <div class="review-count-label">
            {{ $t('common.unreviewedAlerts') }}
          </div>
        </div>
        <div
          class="review-count"
          role="button"
          tabindex="0"
          @click="$router.push('/audit-logs')"
          @keydown.enter.space.prevent="$router.push('/audit-logs')"
        >
          <div class="review-count-value">
            {{ reviewCount('high_risk_ops') }}
          </div>
          <div class="review-count-label">
            {{ $t('common.highRiskOps') }}
          </div>
        </div>
      </div>

      <div
        v-if="reviewStatus.signed"
        class="review-signed"
      >
        <span class="review-signed-text">
          {{ $t('dashboard.reviewSignedBy', {
            name: reviewStatus.review?.reviewer_name,
            time: formatDateTime(reviewStatus.review?.created_at),
          }) }}
          <span v-if="reviewStatus.review?.note">{{ $t('dashboard.reviewSignedNote', { note: reviewStatus.review.note }) }}</span>
        </span>
        <a
          class="review-link"
          :href="REVIEW_HISTORY_HREF"
          @click.exact.prevent="$router.push(REVIEW_HISTORY_ROUTE)"
        >
          {{ $t('dashboard.reviewHistoryLinkSigned') }}
        </a>
      </div>
      <div
        v-else-if="canSign"
        class="review-sign"
      >
        <el-input
          v-model="reviewNote"
          class="review-note-input"
          :placeholder="$t('dashboard.reviewNotePlaceholder')"
          maxlength="500"
        />
        <el-button
          type="primary"
          :loading="signing"
          @click="handleSignReview"
        >
          {{ reviewSnapshot.date
            ? $t('dashboard.signReviewForDate', { date: reviewSnapshot.date })
            : $t('dashboard.signReviewButton') }}
        </el-button>
      </div>
      <div
        v-else
        class="review-hint"
      >
        {{ reviewSnapshot.date
          ? $t('dashboard.reviewWaitingHintForDate', { date: reviewSnapshot.date })
          : $t('dashboard.reviewWaitingHint') }}
      </div>
    </div>

    <div class="quick-actions">
      <h2 class="section-title">
        {{ $t('dashboard.quickActions') }}
      </h2>
      <div class="action-grid">
        <div
          class="action-card"
          role="button"
          tabindex="0"
          @click="$router.push('/workspace')"
          @keydown.enter.space.prevent="$router.push('/workspace')"
        >
          <el-icon :size="22">
            <SquareTerminal />
          </el-icon>
          <div>
            <div class="action-title">
              {{ $t('dashboard.actionWorkspace') }}
            </div>
            <div class="action-desc">
              {{ $t('dashboard.actionWorkspaceDesc') }}
            </div>
          </div>
        </div>
        <div
          class="action-card"
          role="button"
          tabindex="0"
          @click="$router.push('/assets')"
          @keydown.enter.space.prevent="$router.push('/assets')"
        >
          <el-icon :size="22">
            <Server />
          </el-icon>
          <div>
            <div class="action-title">
              {{ isPrivileged ? $t('menu.assets') : $t('menu.myAssets') }}
            </div>
            <div class="action-desc">
              {{ isPrivileged ? $t('dashboard.actionAssetsDescAdmin') : $t('dashboard.actionAssetsDescUser') }}
            </div>
          </div>
        </div>
        <div
          v-if="isPrivileged"
          class="action-card"
          role="button"
          tabindex="0"
          @click="$router.push('/sessions')"
          @keydown.enter.space.prevent="$router.push('/sessions')"
        >
          <el-icon :size="22">
            <MonitorPlay />
          </el-icon>
          <div>
            <div class="action-title">
              {{ $t('menu.sessions') }}
            </div>
            <div class="action-desc">
              {{ $t('dashboard.actionSessionsDesc') }}
            </div>
          </div>
        </div>
        <div
          v-else
          class="action-card"
          role="button"
          tabindex="0"
          @click="$router.push('/my-connections')"
          @keydown.enter.space.prevent="$router.push('/my-connections')"
        >
          <el-icon :size="22">
            <Cable />
          </el-icon>
          <div>
            <div class="action-title">
              {{ $t('menu.myConnections') }}
            </div>
            <div class="action-desc">
              {{ $t('myConnections.headerDesc') }}
            </div>
          </div>
        </div>
        <div
          v-if="!isPrivileged"
          class="action-card"
          role="button"
          tabindex="0"
          @click="$router.push('/my-requests')"
          @keydown.enter.space.prevent="$router.push('/my-requests')"
        >
          <el-icon :size="22">
            <ClipboardList />
          </el-icon>
          <div>
            <div class="action-title">
              {{ $t('menu.myRequests') }}
            </div>
            <div class="action-desc">
              {{ $t('dashboard.actionMyRequestsDesc') }}
            </div>
          </div>
        </div>
        <div
          v-if="isPrivileged"
          class="action-card"
          role="button"
          tabindex="0"
          @click="$router.push('/audit-logs')"
          @keydown.enter.space.prevent="$router.push('/audit-logs')"
        >
          <el-icon :size="22">
            <ScrollText />
          </el-icon>
          <div>
            <div class="action-title">
              {{ $t('menu.auditLogs') }}
            </div>
            <div class="action-desc">
              {{ $t('auditLogs.headerDesc') }}
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import {
  Server,
  Cable,
  FileText,
  Timer,
  Bell,
  ClipboardList,
  Stamp,
  ClipboardCheck,
  Video,
  FolderOpen,
  SquareTerminal,
  MonitorPlay,
  ScrollText,
  RefreshCw,
  ChevronRight,
} from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import { BRAND } from '@/brand'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime, formatRelativeTime, formatBytes } from '@/utils/format'
import { useRoles, readEffectiveApprover } from '@/composables/useRoles'
import { getAssetList } from '@/api/assets'
import { getSessionStatistics, getActiveSessions, getRecordingStats } from '@/api/sessions'
import { getMyConnections } from '@/api/myConnections'
import { searchAlerts } from '@/api/alerts'
import { getDailyReviewStatus, signDailyReview } from '@/api/dailyReviews'
import {
  getMyAccessRequests,
  getPendingAccessRequestCount,
} from '@/api/accessRequests'
import { getAccessReviews } from '@/api/access-reviews'
import { t } from '@/i18n'

const loading = ref(false)
const assetTotal = ref(0)
const activeSessions = ref(0)
const todaySessions = ref(0)
const totalSessions = ref(0)
const todayAlerts = ref(0)
const recentActive = ref([])
const recentAlerts = ref([])
const myRecentConnections = ref([])
const myConnectionTotal = ref(0)
// 錄影目錄目前佔用（bytes）。null＝尚未取得或取得失敗，卡片以 '-' 呈現，
// 不以 0 冒充「沒有錄影」
const recordingStorageBytes = ref(null)

// 人設判定：以「不具 admin/auditor」認定一般 user
//（與後端 admin > auditor > user 優先序一致）；approver 為疊加角色獨立判定。
// 一般 user 的儀表板不呼叫需 session:view / alert:view 的端點（避免 403）
const { isAdmin, isAuditor, isEffectiveApprover, isPrivileged } = useRoles()

const statCards = computed(() => {
  const assetCard = {
    label: isPrivileged.value
      ? t('dashboard.statAssetTotal')
      : t('dashboard.statConnectableAssets'),
    to: '/assets',
    value: assetTotal.value,
    icon: Server,
    color: 'var(--ot-primary)',
    bg: 'var(--ot-primary-dim)',
  }
  // 一般 user：全域 session 統計與告警屬稽核職能，顯示自助導向卡
  if (!isPrivileged.value) {
    return [
      assetCard,
      {
        label: t('menu.myConnections'),
        to: '/my-connections',
        value: myConnectionTotal.value,
        icon: Cable,
        color: 'var(--ot-success)',
        bg: 'rgba(78, 196, 122, 0.15)',
      },
      {
        label: t('dashboard.statMyPendingRequests'),
        to: '/my-requests',
        value: myPendingRequests.value,
        icon: ClipboardList,
        color: 'var(--ot-warning)',
        bg: 'rgba(217, 169, 62, 0.15)',
      },
    ]
  }
  return [
    assetCard,
    {
      label: t('sessions.tabActive'),
      to: '/sessions',
      value: activeSessions.value,
      icon: Cable,
      color: 'var(--ot-success)',
      bg: 'rgba(78, 196, 122, 0.15)',
    },
    {
      label: t('dashboard.statTodaySessions'),
      to: '/sessions',
      value: todaySessions.value,
      icon: Timer,
      color: 'var(--ot-warning)',
      bg: 'rgba(217, 169, 62, 0.15)',
    },
    {
      label: t('dashboard.statTotalSessions'),
      to: '/sessions',
      value: totalSessions.value,
      icon: FileText,
      color: 'var(--ot-info)',
      bg: 'rgba(139, 148, 158, 0.15)',
    },
    {
      label: t('dashboard.statTodayAlerts'),
      to: '/alerts',
      value: todayAlerts.value,
      icon: Bell,
      color: 'var(--ot-danger)',
      bg: 'rgba(229, 96, 79, 0.15)',
    },
    // 錄影佔用：磁碟實際大小（錄影目錄檔案加總），**不是**可用空間或使用率
    //（系統不掌握磁碟總容量，沒有分母就沒有百分比）。無 `to`：不存在「錄影儲存」頁
    {
      label: t('dashboard.statRecordingStorage'),
      value: recordingStorageBytes.value === null
        ? '-'
        : formatBytes(recordingStorageBytes.value),
      icon: FolderOpen,
      color: 'var(--ot-info)',
      bg: 'rgba(139, 148, 158, 0.15)',
    },
  ]
})

// —— 人設待辦卡：一律以既有端點取數，不開新後端 ——
const myPendingRequests = ref(0)
const approvalPendingTotal = ref(0)
const unreviewedAlerts = ref(0)
const recordingFailures = ref(0)
const reviewDaysAgo = ref(-1)
const reviewOverdue = ref(false)

const backlogCards = computed(() => {
  const cards = []
  // 待審卡與其取數共用「有效審核資格」述詞（見 useRoles.isEffectiveApprover）：
  // admin 不兜底。述詞不成立就連卡片一起不出現——取不到數而顯示 0 會被讀成「無待辦」。
  if (isEffectiveApprover.value) {
    cards.push({
      label: t('dashboard.backlogPendingApprovals'),
      to: '/approvals',
      value: approvalPendingTotal.value,
      icon: Stamp,
      color: 'var(--ot-warning)',
      bg: 'rgba(217, 169, 62, 0.15)',
    })
  }
  if (isAdmin.value || isAuditor.value) {
    cards.push(
      {
        label: t('common.unreviewedAlerts'),
        to: '/alerts',
        value: unreviewedAlerts.value,
        icon: Bell,
        color: 'var(--ot-danger)',
        bg: 'rgba(229, 96, 79, 0.15)',
      },
      {
        label: t('dashboard.backlogRecordingFailures'),
        to: '/sessions',
        value: recordingFailures.value,
        icon: Video,
        color: recordingFailures.value > 0 ? 'var(--ot-danger)' : 'var(--ot-info)',
        bg:
          recordingFailures.value > 0
            ? 'rgba(229, 96, 79, 0.15)'
            : 'rgba(127, 214, 214, 0.15)',
      },
      {
        label: reviewOverdue.value
          ? t('dashboard.backlogLastReviewOverdue')
          : t('dashboard.backlogLastReview'),
        to: '/access-reviews',
        value: reviewDaysAgo.value < 0 ? '—' : reviewDaysAgo.value,
        icon: ClipboardCheck,
        color: reviewOverdue.value ? 'var(--ot-danger)' : 'var(--ot-info)',
        bg: reviewOverdue.value
          ? 'rgba(229, 96, 79, 0.15)'
          : 'rgba(127, 214, 214, 0.15)',
      }
    )
  }
  return cards
})

const loadBacklog = async () => {
  // 多角色聯集：各分支獨立判定，疊加人設同時取數
  if (!isPrivileged.value) {
    // 一般 user（含 user＋approver）：我的申請待審計數（自助端點全量回傳，前端計 pending）
    try {
      const res = await getMyAccessRequests()
      myPendingRequests.value = (res.data || []).filter(
        (r) => r.status === 'pending'
      ).length
    } catch (err) {
      console.error('載入我的申請計數失敗:', err)
    }
  }
  if (isEffectiveApprover.value) {
    // 待審件數：端點、述詞與容錯都與側邊欄 badge 相同（MainLayout 的 effectiveApprover）
    try {
      const res = await getPendingAccessRequestCount({ skipErrorToast: true })
      approvalPendingTotal.value = (res.count ?? 0) + (res.review_count ?? 0)
    } catch {
      // 靜默：badge 同款容錯
    }
  }
  if (isAdmin.value || isAuditor.value) {
    try {
      const res = await searchAlerts({ unreviewed: 'true', page: 1, page_size: 1 })
      unreviewedAlerts.value = res.total ?? 0
    } catch (err) {
      console.error('載入未審閱告警計數失敗:', err)
    }
    try {
      const res = await getAccessReviews()
      reviewDaysAgo.value =
        res.last_review_days_ago === undefined ? -1 : res.last_review_days_ago
      reviewOverdue.value = !!res.overdue
    } catch (err) {
      console.error('載入存取複審狀態失敗:', err)
    }
  }
}

// 落地頁活動列表（dashboard 補強）：各取前 5 筆；
// 一般 user 走自助端點，不觸發需 session:view / alert:view 的呼叫
const loadActivity = async () => {
  if (!isPrivileged.value) {
    try {
      const res = await getMyConnections({ page: 1, page_size: 5 })
      myRecentConnections.value = res.data || []
      myConnectionTotal.value = res.total ?? 0
    } catch (err) {
      console.error('載入我的連線失敗:', err)
    }
    return
  }
  try {
    const sessions = await getActiveSessions()
    const list = sessions || []
    // 錄影失敗連線計數（已標 recording_error）——
    // 與進行中列表同一回應，不另發請求
    recordingFailures.value = list.filter((s) => s.recording_error).length
    recentActive.value = list.slice(0, 5)
  } catch (err) {
    console.error('載入進行中連線失敗:', err)
  }
  try {
    const res = await searchAlerts({ page: 1, page_size: 5 })
    recentAlerts.value = res.data || []
  } catch (err) {
    console.error('載入最近告警失敗:', err)
  }
}


// 今日 00:00（本地時區）的 ISO 時間字串
const startOfTodayISO = () => {
  const now = new Date()
  return new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString()
}

// 今日告警數（API 失敗時容錯顯示 0，不影響其他統計）；一般 user 無 alert:view 不呼叫
const loadTodayAlerts = async () => {
  if (!isPrivileged.value) return
  try {
    const response = await searchAlerts({
      start_time: startOfTodayISO(),
      page: 1,
      page_size: 1,
    })
    todayAlerts.value = response.total ?? 0
  } catch (error) {
    console.error('載入今日告警統計失敗:', error)
    todayAlerts.value = 0
  }
}

const loadStatistics = async () => {
  loading.value = true
  try {
    // 一般 user 不呼叫 getSessionStatistics（需 session:view，必 403）
    if (!isPrivileged.value) {
      const assetResp = await getAssetList({ page: 1, page_size: 1 })
      assetTotal.value = assetResp.total ?? 0
      return
    }
    const [assetResp, stats] = await Promise.all([
      getAssetList({ page: 1, page_size: 1 }),
      getSessionStatistics(),
    ])
    assetTotal.value = assetResp.total ?? 0
    activeSessions.value = stats.active_sessions ?? 0
    todaySessions.value = stats.today_sessions ?? 0
    totalSessions.value = stats.total_sessions ?? 0
  } catch (error) {
    console.error('載入儀表板統計失敗:', error)
  } finally {
    loading.value = false
  }
}

// 錄影佔用（GET /recordings/stats，掛 audit:view）——一般 user 不發請求，
// 否則必 403 且全域攔截器會 toast「權限不足」。
// **按需取用不做輪詢**：後端走遞迴 filepath.Walk，成本隨錄影檔數成長，
// 做成輪詢等於讓一個閒置分頁持續掃檔案系統（指標側已有 30 秒背景刷新）
const loadRecordingStorage = async () => {
  if (!isPrivileged.value) {
    recordingStorageBytes.value = null
    return
  }
  try {
    const stats = await getRecordingStats()
    recordingStorageBytes.value = stats?.total_size ?? null
  } catch (error) {
    console.error('載入錄影佔用失敗:', error)
    recordingStorageBytes.value = null
  }
}

// —— 每日安全審閱簽核（PCI 10.4.1）——
const reviewStatus = ref({ enabled: false })
const reviewNote = ref('')
const signing = ref(false)

// 歷次簽核在操作日誌頁的「每日簽核」分頁；該頁只認白名單內的 tab 值
const REVIEW_HISTORY_ROUTE = Object.freeze({ path: '/audit-logs', query: Object.freeze({ tab: 'reviews' }) })
const REVIEW_HISTORY_HREF = '/audit-logs?tab=reviews'

// 簽核權限 alert:manage（admin/auditor＝isPrivileged）——與後端一致；其他角色唯讀計數
const canSign = isPrivileged

const parseFrozenSnapshot = (raw) => {
  if (!raw) return {}
  try {
    const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

// 卡片計數來源：狀態端點每次都回即時的 snapshot，已簽時另帶 review.snapshot_json
// （簽核當下固化的計數，歷次簽核頁顯示的也是它）。已簽只認後者，否則簽核後新增的
// 事件會讓卡片與歷次簽核那筆對不上；待簽才用即時計數。
const reviewSnapshot = computed(() => {
  const status = reviewStatus.value
  if (!status.signed) return status.snapshot || {}
  const frozen = parseFrozenSnapshot(status.review?.snapshot_json)
  return { ...frozen, date: status.review?.review_date || frozen.date || '' }
})

// 已簽快照缺少的計數照實顯示「—」，不拿即時值或 0 填
const reviewCount = (key) => {
  const value = reviewSnapshot.value[key]
  if (typeof value === 'number') return value
  return reviewStatus.value.signed ? '—' : 0
}

const loadReviewStatus = async () => {
  // 狀態查詢掛 audit:view（admin/auditor）——一般 user 不發請求，
  // 否則必 403 且全域攔截器會 toast「權限不足」
  if (!isPrivileged.value) {
    reviewStatus.value = { enabled: false }
    return
  }
  try {
    const res = await getDailyReviewStatus()
    reviewStatus.value = res.data || { enabled: false }
  } catch (error) {
    console.error('載入每日審閱狀態失敗:', error)
    reviewStatus.value = { enabled: false }
  }
}

const handleSignReview = async () => {
  signing.value = true
  try {
    const signedDate = reviewSnapshot.value.date
    const res = await signDailyReview({ note: reviewNote.value })
    // 以伺服器實際寫入的審閱日為準，缺時退回卡片所示日期
    const date = res?.data?.review_date || signedDate
    ElMessage.success(date
      ? t('dashboard.reviewSignedSuccessForDate', { date })
      : t('dashboard.reviewSignedSuccess'))
    reviewNote.value = ''
    await loadReviewStatus()
  } catch (error) {
    console.error('簽核每日審閱失敗:', error)
    // 409（他人已先簽核）：全域攔截器已 toast 後端訊息，此處刷新為已簽狀態
    if (error.response?.status === 409) {
      await loadReviewStatus()
    }
  } finally {
    signing.value = false
  }
}

// 重新整理：重載全部統計與面板（C4）
const handleRefresh = () => {
  loadStatistics()
  loadTodayAlerts()
  loadActivity()
  loadBacklog()
  loadReviewStatus()
  loadRecordingStorage()
}

// 審核資格是掛載當下的快照，而 /auth/me 在側欄掛載後才回來並回寫快取。
// 不接這個事件的話：剛被授予資格的人要重整才看得到待審卡，剛被撤銷的人
// 會繼續看得到、並在下次取數時打出一則必敗請求。
const syncApproverEligibility = async () => {
  const next = readEffectiveApprover()
  if (next === isEffectiveApprover.value) return
  isEffectiveApprover.value = next
  if (next) {
    await loadBacklog()
  } else {
    approvalPendingTotal.value = 0
  }
}

onMounted(() => {
  handleRefresh()
  window.addEventListener('ot-user-updated', syncApproverEligibility)
})

onUnmounted(() => {
  window.removeEventListener('ot-user-updated', syncApproverEligibility)
})
</script>

<style scoped>
.stat-card {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  padding: var(--ot-space-lg);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  margin-bottom: var(--ot-space-md);
}

.stat-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  border-radius: var(--ot-radius-md);
  flex-shrink: 0;
}

.stat-value {
  font-size: 28px;
  font-weight: 600;
  color: var(--ot-text-primary);
  line-height: 1.2;
}

.stat-label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  margin-top: 2px;
}

.stat-card-clickable {
  cursor: pointer;
  transition: border-color 0.15s;
}

.stat-card-clickable:hover {
  border-color: var(--el-color-primary);
}

.activity-row {
  margin-top: 16px;
}

.activity-card {
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: 6px;
  padding: 14px 16px;
  min-height: 220px;
}

.activity-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 10px;
}

.activity-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  padding: 7px 0;
  font-size: 13px;
  border-bottom: 1px solid var(--el-border-color-extra-light);
}

.activity-item:last-child {
  border-bottom: none;
}

.status-tag {
  margin-left: 6px;
}

.activity-main {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--el-text-color-regular);
}

.activity-item-stacked {
  align-items: flex-start;
}

.activity-lines {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
  flex: 1;
}

.activity-sub {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.review-card {
  margin-top: 16px;
  padding: 14px 16px;
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: 6px;
}

.review-head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px 12px;
  margin-bottom: 12px;
}

.review-head-main,
.review-head-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px 12px;
}

/* 連結樣式：品牌主色＋底線於 hover／焦點出現，與一般文字可區分 */
.review-link {
  color: var(--ot-primary);
  font-size: 13px;
  text-decoration: none;
  border-radius: 2px;
}

.review-link:hover,
.review-link:focus-visible {
  color: var(--ot-primary-hover);
  text-decoration: underline;
  text-underline-offset: 3px;
}

.review-link:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}

/* 標題本身維持標題字色，靠右側箭頭與 hover 底線表明可點 */
.review-title {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  font-weight: 600;
  font-size: 14px;
  color: var(--ot-text-primary);
}

.review-title-icon {
  color: var(--ot-primary);
  flex-shrink: 0;
}

.review-date {
  font-size: 13px;
  color: var(--ot-text-secondary);
}

.review-counts {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 12px;
}

.review-count {
  flex: 1;
  min-width: 120px;
  padding: 10px;
  text-align: center;
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  cursor: pointer;
  transition: border-color 0.15s;
}

.review-count:hover {
  border-color: var(--ot-primary);
}

.review-count-value {
  font-size: 22px;
  font-weight: 600;
  color: var(--ot-text-primary);
  line-height: 1.3;
}

.review-count-label {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.review-sign {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.review-note-input {
  max-width: 420px;
}

/* 按鈕文字帶日期，窄欄時允許換行而不溢出卡片 */
.review-sign :deep(.el-button) {
  max-width: 100%;
  height: auto;
  min-height: 32px;
  white-space: normal;
}

.review-signed,
.review-hint {
  font-size: 13px;
  color: var(--el-text-color-regular);
}

.review-signed {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 4px 12px;
}

.quick-actions {
  margin-top: var(--ot-space-lg);
}

.section-title {
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
  color: var(--ot-text-primary);
  margin: 0 0 var(--ot-space-md);
}

.action-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: var(--ot-space-md);
}

.action-card {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  padding: var(--ot-space-lg);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  color: var(--ot-primary);
  cursor: pointer;
  transition: border-color 0.15s ease, background-color 0.15s ease;
}

.action-card:hover {
  border-color: var(--ot-primary);
  background-color: var(--ot-bg-hover);
}

.action-title {
  font-size: var(--ot-font-size-md);
  font-weight: 500;
  color: var(--ot-text-primary);
}

.action-desc {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  margin-top: 2px;
}
</style>
