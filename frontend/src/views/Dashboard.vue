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

    <UpgradeGuidanceCard />

    <el-row :gutter="16">
      <el-col
        v-for="card in statCards"
        :key="card.key"
        :xs="12"
        :sm="12"
        :md="6"
      >
        <!-- 可點擊性依 card.target 是否存在而定：錄影佔用卡沒有可跳轉的目標頁；
             取不到值的卡也不可點，避免未帶條件就落到清單而被讀成「全部」 -->
        <div
          v-loading="card.status === 'loading'"
          class="stat-card"
          :class="{ 'stat-card-clickable': card.target }"
          :data-card="card.key"
          :role="card.target ? 'button' : undefined"
          :tabindex="card.target ? 0 : undefined"
          @click="card.target && $router.push(card.target)"
          @keydown.enter.space.prevent="card.target && $router.push(card.target)"
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
            <div
              class="stat-value"
              :class="{ 'stat-value-unavailable': card.status === 'error' }"
            >
              {{ card.text }}
            </div>
            <div class="stat-label">
              {{ card.label }}
            </div>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- 待辦卡列：待辦導向，非權限裁切；多角色聯集去重 -->
    <el-row
      v-if="backlogCards.length"
      :gutter="16"
    >
      <el-col
        v-for="card in backlogCards"
        :key="card.key"
        :xs="12"
        :sm="12"
        :md="6"
      >
        <div
          v-loading="card.status === 'loading'"
          class="stat-card"
          :class="{ 'stat-card-clickable': card.target }"
          :data-card="card.key"
          :role="card.target ? 'button' : undefined"
          :tabindex="card.target ? 0 : undefined"
          @click="card.target && $router.push(card.target)"
          @keydown.enter.space.prevent="card.target && $router.push(card.target)"
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
            <div
              class="stat-value"
              :class="{ 'stat-value-unavailable': card.status === 'error' }"
            >
              {{ card.text }}
            </div>
            <div class="stat-label">
              {{ card.label }}
            </div>
          </div>
        </div>
      </el-col>
    </el-row>

    <!-- 活動面板：三塊各依自己的能力、各自取數，可同時出現 -->
    <el-row
      v-if="activityPanelCount"
      :gutter="16"
      class="activity-row"
    >
      <el-col
        v-if="canSeeSessions"
        :md="activityColSpan"
      >
        <div
          class="activity-card"
          data-panel="active-sessions"
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
      </el-col>
      <el-col
        v-if="showsMine"
        :md="activityColSpan"
      >
        <div
          class="activity-card"
          data-panel="my-connections"
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
        v-if="canAuditRead"
        :md="activityColSpan"
      >
        <div
          class="activity-card"
          data-panel="recent-alerts"
        >
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
              <span class="activity-main">{{ alertLineText(a) }}</span>
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

    <!-- 每日安全審閱卡（PCI 10.4.1）：只提醒與提供入口，簽核在操作日誌頁的抽屜完成。
         只對 admin／auditor 取數與顯示（狀態端點掛 audit:view） -->
    <DailyReviewCard
      v-if="canAuditRead && reviewStatus"
      :status="reviewStatus"
      :can-open-policies="can('securitypolicy:manage')"
    />

    <div
      v-if="hasQuickActions"
      class="quick-actions"
    >
      <h2 class="section-title">
        {{ $t('dashboard.quickActions') }}
      </h2>
      <div class="action-grid">
        <div
          v-if="canViewAssets"
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
          v-if="canViewAssets"
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
              {{ showsGlobal ? $t('menu.assets') : $t('menu.myAssets') }}
            </div>
            <div class="action-desc">
              {{ showsGlobal ? $t('dashboard.actionAssetsDescAdmin') : $t('dashboard.actionAssetsDescUser') }}
            </div>
          </div>
        </div>
        <div
          v-if="enterable('/sessions')"
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
          v-else-if="selfService && enterable('/my-connections')"
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
          v-if="selfService && enterable('/my-requests')"
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
          v-if="enterable('/audit-logs')"
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
import { reactive, ref, computed, watch, onMounted } from 'vue'
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
} from 'lucide-vue-next'
import PageHeader from '@/components/PageHeader.vue'
import { BRAND } from '@/brand'
import EmptyState from '@/components/EmptyState.vue'
import { formatRelativeTime, formatBytes } from '@/utils/format'
import { useCapabilities } from '@/composables/useCapabilities'
import { getDashboardCard } from '@/api/dashboard'
import { getActiveSessions } from '@/api/sessions'
import { getMyConnections } from '@/api/myConnections'
import { searchAlerts } from '@/api/alerts'
import { alertLineText } from '@/constants/command-degrade'
import { getDailyReviewStatus } from '@/api/dailyReviews'
import DailyReviewCard from '@/components/daily-review/DailyReviewCard.vue'
import UpgradeGuidanceCard from '@/components/UpgradeGuidanceCard.vue'
import { canEnter, entryMeta } from '@/router/entryRules'
import { t } from '@/i18n'

// 呈現與取數都依後端 /auth/me 的能力，不看角色：
// - showsGlobal（ui:assets-global）：全域資產檢視的呈現（標題與文案）；
// - selfService（ui:self-service-actions）：僅管快速操作卡；我的連線與我的申請待審兩卡、本人近期連線面板改看入口規則（showsMine）；
// - 每張卡、每個面板各依自己的必要能力出現與取數，缺能力時不發請求；
// - 審核資格以 ui:approvals 為準，admin 不兜底。
const caps = useCapabilities()
const { can } = caps
const showsGlobal = computed(() => can('ui:assets-global'))
const selfService = computed(() => can('ui:self-service-actions'))
// 我的連線、我的申請待審：已登入者看自己的資料（authenticated owner/self），
// 與側欄「我的連線／我的申請」入口同一判準（entryRules 的 signedIn），不看 ui:self-service-actions
const showsMine = computed(() => canEnter(entryMeta('/my-connections')) && canEnter(entryMeta('/my-requests')))
const canSeeSessions = computed(() => can('session:view'))
const canAuditRead = computed(() => can('audit:view'))

// 落點是否可進入：與側欄、路由守衛共用同一個入口規則
const enterable = (path) => canEnter(entryMeta(path))
// 工作區與我的資產兩張快速操作卡的資料都來自需要 asset:view 的列表
const canViewAssets = computed(() => can('asset:view'))
const hasQuickActions = computed(
  () =>
    canViewAssets.value ||
    enterable('/sessions') ||
    (selfService.value && (enterable('/my-connections') || enterable('/my-requests'))) ||
    enterable('/audit-logs')
)

const GREEN = 'rgba(78, 196, 122, 0.15)'
const AMBER = 'rgba(217, 169, 62, 0.15)'
const RED = 'rgba(229, 96, 79, 0.15)'
const GREY = 'rgba(139, 148, 158, 0.15)'
const TEAL = 'rgba(127, 214, 214, 0.15)'

// 十二張卡的登錄。filters 由卡片回應帶來，導覽時原樣放進 route query（不經時間型別轉換）；
// extraQuery 是落點頁籤等與條件無關的導覽參數，與 filters 分開。
const CARD_DEFS = [
  {
    key: 'assets', row: 'stat', path: '/assets', icon: Server, color: 'var(--ot-primary)', bg: 'var(--ot-primary-dim)',
    visible: () => can('asset:view'),
    label: () => (showsGlobal.value ? t('dashboard.statAssetTotal') : t('menu.myAssets')),
  },
  {
    key: 'my-connections', row: 'stat', path: '/my-connections', icon: Cable, color: 'var(--ot-success)', bg: GREEN,
    visible: () => showsMine.value,
    label: () => t('menu.myConnections'),
  },
  {
    key: 'my-pending-requests', row: 'stat', path: '/my-requests', icon: ClipboardList, color: 'var(--ot-warning)', bg: AMBER,
    visible: () => showsMine.value,
    label: () => t('dashboard.statMyPendingRequests'),
  },
  {
    key: 'active-sessions', row: 'stat', path: '/sessions', extraQuery: { tab: 'active' }, icon: Cable, color: 'var(--ot-success)', bg: GREEN,
    visible: () => canSeeSessions.value,
    label: () => t('sessions.tabActive'),
  },
  {
    key: 'today-sessions', row: 'stat', path: '/sessions', extraQuery: { tab: 'history' }, icon: Timer, color: 'var(--ot-warning)', bg: AMBER,
    visible: () => canSeeSessions.value,
    label: () => t('dashboard.statTodaySessions'),
  },
  {
    key: 'total-sessions', row: 'stat', path: '/sessions', extraQuery: { tab: 'history' }, icon: FileText, color: 'var(--ot-info)', bg: GREY,
    visible: () => canSeeSessions.value,
    label: () => t('dashboard.statTotalSessions'),
  },
  {
    key: 'today-alerts', row: 'stat', path: '/alerts', icon: Bell, color: 'var(--ot-danger)', bg: RED,
    visible: () => canAuditRead.value,
    label: () => t('dashboard.statTodayAlerts'),
  },
  // 錄影佔用：磁碟實際大小（錄影目錄檔案加總），不是可用空間或使用率
  //（系統不掌握磁碟總容量，沒有分母就沒有百分比）。無 path：不存在「錄影儲存」頁，也不輪詢
  {
    key: 'recording-storage', row: 'stat', path: null, icon: FolderOpen, color: 'var(--ot-info)', bg: GREY,
    visible: () => canAuditRead.value,
    label: () => t('dashboard.statRecordingStorage'),
    format: (d) => formatBytes(d.value ?? 0),
  },
  {
    key: 'unreviewed-alerts', row: 'backlog', path: '/alerts', icon: Bell, color: 'var(--ot-danger)', bg: RED,
    visible: () => canAuditRead.value,
    label: () => t('common.unreviewedAlerts'),
  },
  {
    key: 'recording-failures', row: 'backlog', path: '/sessions', extraQuery: { tab: 'active' }, icon: Video,
    visible: () => canSeeSessions.value,
    label: () => t('dashboard.backlogRecordingFailures'),
    color: (d) => (d && d.value > 0 ? 'var(--ot-danger)' : 'var(--ot-info)'),
    bg: (d) => (d && d.value > 0 ? RED : TEAL),
  },
  {
    key: 'last-access-review', row: 'backlog', path: '/access-reviews', icon: ClipboardCheck,
    visible: () => canAuditRead.value,
    label: (d) => (d?.overdue ? t('dashboard.backlogLastReviewOverdue') : t('dashboard.backlogLastReview')),
    color: (d) => (d?.overdue ? 'var(--ot-danger)' : 'var(--ot-info)'),
    bg: (d) => (d?.overdue ? RED : TEAL),
    // 後端以 -1 表示從未複審
    format: (d) => (d.value < 0 ? '—' : d.value),
  },
  // 待審申請排最後（待辦列順序）
  {
    key: 'pending-approvals', row: 'backlog', path: '/approvals', icon: Stamp, color: 'var(--ot-warning)', bg: AMBER,
    visible: () => can('ui:approvals'),
    label: () => t('dashboard.backlogPendingApprovals'),
  },
]

// 取數槽：每張卡、每個面板各一個序號。重新取數、失權、換帳號都會遞增序號，
// 較早發出的回應回來時序號已不符，直接丟棄，不留舊數。
const slotSeq = {}
const runSlot = async (slot, enabled, fetchFn, onStart, onOk, onFail, onClear) => {
  const seq = (slotSeq[slot] = (slotSeq[slot] || 0) + 1)
  if (!enabled) {
    onClear()
    return
  }
  onStart()
  try {
    const res = await fetchFn()
    if (seq !== slotSeq[slot]) return
    onOk(res)
  } catch (err) {
    if (seq !== slotSeq[slot]) return
    console.error(`載入儀表板項目失敗 (${slot}):`, err)
    onFail(err)
  }
}

// 每張卡一份獨立狀態：idle | loading | ready | error。失敗只影響該卡。
const cardState = reactive(
  Object.fromEntries(CARD_DEFS.map((d) => [d.key, { status: 'idle', data: null }]))
)

const loadCard = (def) =>
  runSlot(
    `card:${def.key}`,
    def.visible(),
    () => getDashboardCard(def.key),
    () => {
      // 重新取數時保留舊值直到新值回來，只切換載入中
      cardState[def.key].status = 'loading'
    },
    (res) => {
      const data = res?.data && typeof res.data === 'object' && res.value === undefined ? res.data : res
      cardState[def.key] = { status: 'ready', data }
    },
    () => {
      // 含 403：該卡資料清掉，顯示「未取得」，不冒充 0
      cardState[def.key] = { status: 'error', data: null }
    },
    () => {
      cardState[def.key] = { status: 'idle', data: null }
    }
  )

const pick = (v, d) => (typeof v === 'function' ? v(d) : v)

const cardViews = computed(() =>
  CARD_DEFS.filter((d) => d.visible()).map((d) => {
    const st = cardState[d.key]
    const data = st.data
    let text = '-'
    if (st.status === 'error') text = t('dashboard.valueUnavailable')
    else if (data) text = d.format ? d.format(data) : (data.value ?? '-')
    const target =
      d.path && data && canEnter(entryMeta(d.path))
        ? { path: d.path, query: { ...(data.filters || {}), ...(d.extraQuery || {}) } }
        : null
    return {
      key: d.key,
      row: d.row,
      status: st.status,
      text,
      label: d.label(data),
      icon: d.icon,
      color: pick(d.color, data),
      bg: pick(d.bg, data),
      target,
    }
  })
)
const statCards = computed(() => cardViews.value.filter((c) => c.row === 'stat'))
const backlogCards = computed(() => cardViews.value.filter((c) => c.row === 'backlog'))

// —— 活動面板：各依自己的能力獨立取數 ——
const recentActive = ref([])
const recentAlerts = ref([])
const myRecentConnections = ref([])

const loadActiveSessions = () =>
  runSlot(
    'panel:active-sessions',
    canSeeSessions.value,
    () => getActiveSessions(),
    () => {},
    (sessions) => {
      recentActive.value = (sessions || []).slice(0, 5)
    },
    () => {},
    () => {
      recentActive.value = []
    }
  )

const loadMyConnections = () =>
  runSlot(
    'panel:my-connections',
    showsMine.value,
    () => getMyConnections({ page: 1, page_size: 5 }),
    () => {},
    (res) => {
      myRecentConnections.value = res.data || []
    },
    () => {},
    () => {
      myRecentConnections.value = []
    }
  )

const loadRecentAlerts = () =>
  runSlot(
    'panel:recent-alerts',
    canAuditRead.value,
    () => searchAlerts({ page: 1, page_size: 5 }),
    () => {},
    (res) => {
      recentAlerts.value = res.data || []
    },
    () => {},
    () => {
      recentAlerts.value = []
    }
  )

const activityPanelCount = computed(
  () => [canSeeSessions.value, showsMine.value, canAuditRead.value].filter(Boolean).length
)
const activityColSpan = computed(() => (activityPanelCount.value >= 3 ? 8 : 12))

// —— 每日安全審閱卡（PCI 10.4.1）——
// null＝尚未取得或無權取得：卡片不渲染。狀態端點掛 audit:view，無此能力者不發請求
const reviewStatus = ref(null)

const loadReviewStatus = () =>
  runSlot(
    'panel:daily-review',
    canAuditRead.value,
    () => getDailyReviewStatus(),
    () => {},
    (res) => {
      reviewStatus.value = res.data || null
    },
    () => {
      reviewStatus.value = null
    },
    () => {
      reviewStatus.value = null
    }
  )

// 重新整理：每張卡、每個面板各自重載，互不等待
const handleRefresh = () => {
  CARD_DEFS.forEach(loadCard)
  loadActiveSessions()
  loadMyConnections()
  loadRecentAlerts()
  loadReviewStatus()
}

// 能力由後端 /auth/me 取得，可能在掛載之後才就緒（登入即可的入口不等能力）：
// 就緒當下才取數；能力內容或使用者改變時整批重算（失去能力的卡清空，新取得的補取數）
watch(
  () => `${caps.ready.value}|${caps.loadedUserId.value}|${caps.permissions.value.join(',')}`,
  () => {
    // 能力不可用（登出、換帳號、載入中）時 visible 皆為否：全部清空並使在途回應作廢
    handleRefresh()
  }
)

onMounted(() => {
  if (caps.ready.value) handleRefresh()
  else caps.load()
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

.stat-value-unavailable {
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-secondary);
  font-weight: 500;
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
