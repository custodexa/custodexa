<template>
  <el-container class="layout-container">
    <el-aside
      :width="sidebarWidth"
      class="sidebar"
    >
      <!-- 收合鈕住在 logo 列（ui-navigation：可發現性）。
           它原本在側欄最底的 sidebar-footer，選單一長就被推到側欄的捲動摺線
           之下——1260px 起就看不見，而收合正是螢幕不夠高時最需要的動作。
           logo 列 flex-shrink: 0 且不在捲動區內，因此無論選單多長都留在
           初始視窗內；捲動改由 .sidebar-menu 自己承擔 -->
      <div
        class="logo"
        :class="{ collapsed: isCollapsed }"
      >
        <span class="logo-mark"><img
          :src="BRAND.icon"
          :alt="BRAND.name"
        ></span>
        <h2 v-show="!isCollapsed">
          {{ BRAND.name }}
        </h2>
        <el-button
          text
          class="collapse-btn"
          :aria-label="isCollapsed ? t('common.expandSidebar') : t('common.collapseSidebar')"
          :title="isCollapsed ? t('common.expandSidebar') : t('common.collapseSidebar')"
          @click="toggleCollapse"
        >
          <el-icon>
            <PanelLeftOpen v-if="isCollapsed" />
            <PanelLeftClose v-else />
          </el-icon>
        </el-button>
      </div>
      <el-menu
        :default-active="activeMenu"
        :collapse="isCollapsed"
        :collapse-transition="false"
        router
        class="sidebar-menu"
        tabindex="0"
        :aria-label="t('common.mainNav')"
      >
        <!-- 單一 v-for 渲染「常用」標題、組標題（可收合）與項目：
             側欄分組只改呈現，每個項目仍先經 canEnter 過濾 -->
        <template
          v-for="entry in sidebarEntries"
          :key="entry.key"
        >
          <div
            v-if="entry.kind === 'label'"
            v-show="!isCollapsed"
            class="menu-group-label"
            data-test="pinned-label"
          >
            {{ entry.text }}
          </div>
          <button
            v-else-if="entry.kind === 'toggle'"
            v-show="!isCollapsed"
            type="button"
            class="menu-group-label menu-group-toggle"
            :aria-expanded="String(!entry.collapsed)"
            :data-test="`group-toggle-${entry.groupId}`"
            @click="toggleGroup(entry.groupId)"
          >
            <el-icon class="menu-group-chevron">
              <ChevronRight v-if="entry.collapsed" />
              <ChevronDown v-else />
            </el-icon>
            {{ entry.text }}
          </button>
          <el-menu-item
            v-else
            v-show="!entry.hidden || isCollapsed"
            :index="entry.item.path"
            :route="menuRouteFor(entry.item)"
          >
            <el-icon><component :is="entry.item.icon" /></el-icon>
            <template #title>
              <span class="menu-title-with-badge">
                {{ entry.item.title }}
                <el-badge
                  v-if="entry.item.badge === 'approvals' && approvalPendingCount > 0"
                  :value="approvalPendingCount"
                  :max="99"
                  class="menu-badge"
                />
                <el-badge
                  v-else-if="entry.item.badge === 'dailyReviews' && canSignDailyReview && dailyReviewBadge.count.value > 0"
                  :value="dailyReviewBadge.count.value"
                  :max="99"
                  :title="t('dailyReview.badge.title', { n: dailyReviewBadge.count.value })"
                  :class="['menu-badge', dailyReviewBadge.overdueCount.value > 0 ? 'daily-review-badge--danger' : 'daily-review-badge--warning']"
                  data-test="daily-review-badge"
                />
              </span>
              <button
                v-if="!isCollapsed"
                type="button"
                class="menu-pin"
                :class="{ 'menu-pin--on': entry.pinned }"
                :aria-pressed="String(entry.pinned)"
                :aria-label="entry.pinned ? t('sidebar.unpinItem', { name: entry.item.title }) : t('sidebar.pinItem', { name: entry.item.title })"
                :title="entry.pinned ? t('sidebar.unpin') : t('sidebar.pin')"
                :data-test="`pin-${entry.item.id}`"
                @click.stop.prevent="togglePin(entry.item.id)"
              >
                <el-icon>
                  <PinOff v-if="entry.pinned" />
                  <Pin v-else />
                </el-icon>
              </button>
            </template>
          </el-menu-item>
        </template>
      </el-menu>
      <!-- 產品版本行：在選單捲動區之外，值來自能力載入已在打的 /auth/me -->
      <SidebarVersion
        :raw="productVersion"
        :collapsed="isCollapsed"
      />
    </el-aside>

    <el-container>
      <el-header class="header">
        <div class="header-left">
          <!-- 麵包屑：詳情頁沒有自己的選單項，若只顯示單一標題會落回「首頁」，
               讀起來像離開了那個功能。父層一律可點回列表 -->
          <nav
            class="current-path"
            :aria-label="t('common.breadcrumb')"
          >
            <template
              v-for="(crumb, index) in breadcrumbs"
              :key="index"
            >
              <span
                v-if="index"
                class="crumb-sep"
                aria-hidden="true"
              >›</span>
              <router-link
                v-if="crumb.to"
                :to="crumb.to"
                class="crumb-link"
              >
                {{ crumb.label }}
              </router-link><span
                v-else
                class="crumb-current"
              >{{ crumb.label }}</span>
            </template>
          </nav>
        </div>
        <div class="header-right">
          <!-- 語言切換：即時生效免 reload，偏好存 ot-lang -->
          <el-dropdown @command="setLanguage">
            <button
              type="button"
              class="lang-switch"
              :aria-label="t('common.switchLanguage')"
            >
              {{ LOCALE_LABELS[locale] }}
              <el-icon class="el-icon--right">
                <ChevronDown />
              </el-icon>
            </button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item
                  v-for="l in SUPPORTED_LOCALES"
                  :key="l"
                  :command="l"
                  :disabled="l === locale"
                >
                  {{ LOCALE_LABELS[l] }}
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <el-dropdown @command="handleCommand">
            <button
              type="button"
              class="user-info"
              :aria-label="t('common.accountMenu')"
            >
              <el-icon><CircleUserRound /></el-icon>
              {{ userName }}
              <el-icon class="el-icon--right">
                <ChevronDown />
              </el-icon>
            </button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="profile">
                  {{ t('common.profile') }}
                </el-dropdown-item>
                <el-dropdown-item command="guidance">
                  {{ t('upgradeGuidance.menu') }}
                </el-dropdown-item>
                <el-dropdown-item
                  divided
                  command="logout"
                >
                  {{ t('common.logout') }}
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>

      <!-- 單實例守衛常駐橫幅（single-instance-guard）：全頁寬、位於 header 與內容之間；
           沒有關閉鈕，狀態回到 held 且無對等連線即自然消失 -->
      <InstanceGuardBanner
        :status="instanceGuardStatus"
        :can-view-details="canViewInstanceGuard"
      />

      <!-- 能力載入失敗：受限入口在取得能力前一律不放行（沒有角色回退），提供重試 -->
      <el-alert
        v-if="capabilitiesFailed"
        class="capability-alert"
        type="warning"
        :closable="false"
        show-icon
        :title="t('capabilities.loadFailed')"
        data-test="capability-load-failed"
      >
        <el-button
          size="small"
          :loading="capabilitiesRetrying"
          data-test="capability-retry"
          @click="retryCapabilities"
        >
          {{ t('capabilities.retry') }}
        </el-button>
      </el-alert>

      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
// header 用到的 icon；側欄選單的宣告（含其 icon）在 ./sidebarMenu.js
import {
  ChevronDown,
  ChevronRight,
  CircleUserRound,
  PanelLeftOpen,
  PanelLeftClose,
  Pin,
  PinOff,
} from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { BRAND } from '@/brand'
import { SUPPORTED_LOCALES, LOCALE_LABELS, setLanguage } from '@/i18n'
import { getPendingAccessRequestCount } from '@/api/accessRequests'
import { logout } from '@/api/auth'
import { getSealStatus } from '@/api/seal'
import InstanceGuardBanner from './InstanceGuardBanner.vue'
import SidebarVersion from './SidebarVersion.vue'
import { clearSession } from '@/utils/session'
import { detailSubject } from '@/utils/detailTitle'
import { canEnter, entryRuleFor } from '@/router/entryRules'
import { MENU_GROUPS } from './sidebarMenu'
import { useDailyReviewBadge } from '@/composables/useDailyReviewBadge'
import { useCapabilities } from '@/composables/useCapabilities'
import { buildSidebarModel, useSidebarPrefs } from '@/composables/useSidebarNav'
import { GUIDANCE_VERSION } from '@/composables/useUpgradeGuidance'

const COLLAPSE_KEY = 'ot-sidebar-collapsed'

const { t, locale } = useI18n()
const router = useRouter()
const route = useRoute()

// 目前使用者能力（後端 /auth/me 的 permissions）：守衛與本版面共用同一次載入。
// 側欄可見性、徽章輪詢、版本行都只看這份能力，不看快取裡的角色
const caps = useCapabilities()
const { can } = caps

const rawUserName = ref('')
const userName = computed(() => rawUserName.value || t('common.defaultUserName'))
const isCollapsed = ref(localStorage.getItem(COLLAPSE_KEY) === 'true')

// 側欄底部的產品版本（/auth/me 的 product_version 原值；顯示判定在 SidebarVersion）
const productVersion = caps.productVersion
const capabilitiesFailed = caps.failed
const capabilitiesRetrying = ref(false)
const retryCapabilities = async () => {
  capabilitiesRetrying.value = true
  try {
    await caps.reload()
  } finally {
    capabilitiesRetrying.value = false
  }
}

// 選單可見性與路由守衛**同一個判斷**（router/entryRules.js 的 canEnter）：
// 同一份規則、同一份能力，選單看得到的就是網址進得去的。
// 規則表查不到的項目 fail-closed 不顯示
const isItemVisible = (item) => {
  const rule = entryRuleFor(item.path)
  return Boolean(rule) && canEnter(rule)
}

// 全域資產檢視的呈現點：非此身分的使用者以 userTitle 覆寫顯示名（我的資產）
const showsGlobalAssets = computed(() => can('ui:assets-global'))

// 側欄分組呈現：分組收合、常用釘選、過濾後只剩一組時攤平。只改呈現，
// 每個項目仍先經 canEnter 過濾；偏好只存同源 localStorage（每使用者、帶格式版本）
const { prefs: sidebarPrefs, toggleGroup, expandGroup, togglePin } = useSidebarPrefs(caps.loadedUserId)
const sidebar = computed(() => buildSidebarModel(MENU_GROUPS, isItemVisible, sidebarPrefs.value))
const titleOf = (item) =>
  !showsGlobalAssets.value && item.userTitleKey ? t(item.userTitleKey) : t(item.titleKey)

const sidebarEntries = computed(() => {
  const { flat, pinned, groups } = sidebar.value
  const entries = []
  const itemEntry = (item, isPinned, hidden) => ({
    kind: 'item',
    key: `${isPinned ? 'pin' : 'item'}:${item.id}`,
    item: { ...item, title: titleOf(item) },
    pinned: isPinned,
    hidden,
  })
  if (pinned.length > 0) {
    entries.push({ kind: 'label', key: 'label:pinned', text: t('sidebar.pinned') })
    for (const item of pinned) entries.push(itemEntry(item, true, false))
  }
  for (const group of groups) {
    if (!flat) {
      entries.push({
        kind: 'toggle',
        key: `toggle:${group.id}`,
        groupId: group.id,
        collapsed: group.collapsed,
        text: t(group.labelKey),
      })
    }
    for (const item of group.items) entries.push(itemEntry(item, false, group.collapsed))
  }
  return entries
})

// 每日簽核待簽天數：只對具簽核權限（alert:manage）者輪詢與顯示。
// 沒有權限的人每 30 秒打一次用不到的端點，只會多出審計讀取列
const dailyReviewBadge = useDailyReviewBadge()
const canSignDailyReview = computed(() => can('alert:manage'))
// 有待簽天數時點「操作日誌」直接進每日簽核分頁；沒有時維持原路徑
const menuRouteFor = (item) =>
  item.badge === 'dailyReviews' && canSignDailyReview.value && dailyReviewBadge.count.value > 0
    ? { path: item.path, query: { tab: 'reviews' } }
    : undefined

// 單實例守衛橫幅的細節端點每次呼叫留一列審計讀取，只對有此讀取能力者取
const canViewInstanceGuard = computed(() => can('instanceguard:view'))

const sidebarWidth = computed(() =>
  isCollapsed.value
    ? 'var(--ot-sidebar-width-collapsed)'
    : 'var(--ot-sidebar-width)'
)

// 有子路徑的功能頁（來源詳情）仍要讓所屬選單項保持選取：以完整路徑比對時，
// 進到詳情頁會整條側欄都不亮，讀起來像離開了那個功能
const SUBPATH_PARENTS = ['/identity-sources', '/users', '/user-groups', '/roles']
const menuPathOf = (path) =>
  SUBPATH_PARENTS.find((parent) => path === parent || path.startsWith(`${parent}/`)) || path

// 使用者管理與 AI agent 主體是同一個路徑的兩個入口，靠 query 區分選取
const activeMenu = computed(() =>
  route.path === '/users' && route.query.kind === 'agent'
    ? '/users?kind=agent'
    : menuPathOf(route.path)
)

// 目前所在的項目所屬的組若被收合，導覽到該處（或能力剛載入完成）時自動展開。
// 只監看路徑與能力就緒，不監看側欄模型——否則使用者手動收合目前所在的組會立刻被展開
watch(
  [activeMenu, () => caps.ready.value],
  ([path]) => {
    const owner = sidebar.value.groups.find((g) => g.collapsed && g.items.some((i) => i.path === path))
    if (owner) expandGroup(owner.id)
  },
  { immediate: true }
)

const pageTitleKeys = {
  '/dashboard': 'menu.dashboard',
  '/assets': 'menu.assets',
  '/sessions': 'menu.sessions',
  '/my-connections': 'menu.myConnections',
  '/my-requests': 'menu.myRequests',
  '/my-agents': 'menu.myAgents',
  '/approvals': 'menu.approvals',
  '/audit/workbench': 'menu.auditWorkbench',
  '/audit/agent-tasks': 'agentTasks.title',
  '/rotation-evidence': 'menu.rotationEvidence',
  '/audit/exports': 'menu.auditExports',
  '/audit-logs': 'menu.auditLogs',
  '/commands': 'menu.commands',
  '/alerts': 'menu.alerts',
  '/access-reviews': 'menu.accessReviews',
  '/compliance-map': 'menu.complianceMap',
  '/policy-groups': 'menu.policyGroups',
  '/checkpoint-verification': 'menu.checkpointVerification',
  '/authorizations': 'menu.authorizations',
  '/change-secret-plans': 'menu.changeSecretPlans',
  '/change-secret-batches': 'menu.changeSecretBatches',
  '/credentials': 'menu.credentials',
  '/users': 'menu.users',
  '/users?kind=agent': 'menu.agentPrincipals',
  '/profile': 'menu.profile',
  '/user-groups': 'menu.userGroups',
  '/identity-sources': 'menu.identitySources',
  '/roles': 'menu.roles',
  '/security-policies': 'menu.securityPolicies',
  '/access-control': 'menu.accessControl',
  '/key-management': 'menu.keyManagement',
  '/transmission-inventory': 'menu.transmissionInventory',
  '/offsite-storage': 'menu.offsiteStorage',
  '/notification-channels': 'alerts.tabChannels',
}

// 詳情頁以路由名稱取標題（帶參數，無法放進以路徑為鍵的表），
// 並各自指回所屬列表頁；沒有登錄的路由仍退回選單標題
const detailPages = {
  AgentTaskDetail: {
    // 主旨由詳情頁載入後寫進 detailSubject；還沒載到就只帶編號
    title: () => (detailSubject.value
      ? t('agentTasks.detailTitleNamed', { id: route.params.requestId, subject: detailSubject.value })
      : t('agentTasks.detailTitle', { id: route.params.requestId })),
    parent: { to: '/audit/agent-tasks', label: () => t('agentTasks.title') },
  },
  AgentBreakers: {
    title: () => t('agentBreaker.title'),
    parent: { to: '/alerts', label: () => t('menu.alerts') },
  },
  UserDetail: {
    title: () => detailSubject.value || t('menu.users'),
    parent: { to: '/users', label: () => t('menu.users') },
  },
  UserGroupDetail: {
    title: () => detailSubject.value || t('menu.userGroups'),
    parent: { to: '/user-groups', label: () => t('menu.userGroups') },
  },
  RoleNew: {
    title: () => t('roles.editor.titleNew'),
    parent: { to: '/roles', label: () => t('menu.roles') },
  },
  RoleDetail: {
    title: () => detailSubject.value || t('menu.roles'),
    parent: { to: '/roles', label: () => t('menu.roles') },
  },
  SessionDetail: {
    title: () => t('sessionDetail.title'),
    parent: { to: '/sessions', label: () => t('menu.sessions') },
  },
}

const currentPageTitle = computed(
  () =>
    detailPages[route.name]?.title() ||
    t(pageTitleKeys[activeMenu.value] || 'menu.home')
)

// 列表頁的所屬群組前綴（核可稿麵包屑「稽核 / 告警」）；群組本身沒有落點頁，不可點
const groupLeads = new Map([
  ['/alerts', () => t('menu.group.audit')],
])

const breadcrumbs = computed(() => {
  const parent = detailPages[route.name]?.parent
  const current = { label: currentPageTitle.value, to: '' }
  if (parent) return [{ label: parent.label(), to: parent.to }, current]
  const lead = groupLeads.get(activeMenu.value)
  return lead ? [{ label: lead(), to: '' }, current] : [current]
})

const toggleCollapse = () => {
  isCollapsed.value = !isCollapsed.value
  localStorage.setItem(COLLAPSE_KEY, String(isCollapsed.value))
}

const handleCommand = (command) => {
  switch (command) {
    case 'profile':
      router.push('/profile')
      break
    case 'guidance':
      // 回儀表板並由說明卡消費 query 重開；不碰伺服器端的關閉狀態
      router.push({ path: '/dashboard', query: { guidance: GUIDANCE_VERSION } })
      break
    case 'logout':
      handleLogout()
      break
  }
}

// 登出：先請後端撤銷 refresh 憑證並清除其 cookie（會話撤銷），再清本地並導向。
// 憑證由瀏覽器以 httpOnly cookie 自動附帶，前端不經手；
// 撤銷失敗不阻擋登出——本地清除後攻擊面只剩 ≤15 分的殘餘 access
const handleLogout = async () => {
  try {
    await logout()
  } catch (error) {
    console.error('登出撤銷失敗:', error)
  }
  // 廣播登出：同瀏覽器的其他分頁一併清除記憶體憑證並回到登入頁
  clearSession({ broadcast: true })
  router.push('/login')
  ElMessage.success(t('common.loggedOut'))
}

// 單實例守衛橫幅（single-instance-guard）：粗狀態走不寫審計列的 seal/status，
// 掛載即取一次、每 60 秒輪詢；失敗靜默沿用上一次值（橫幅是告知不是事實源，
// 事實源是後端日誌、指標與 audit_logs）。管理者細節由橫幅元件自行一次性取得，
// **不在此輪詢**（那條端點每次呼叫留一列審計讀取）
const instanceGuardStatus = ref(null)
const INSTANCE_GUARD_POLL_MS = 60000
let instanceGuardTimer = null

const refreshInstanceGuardStatus = async () => {
  try {
    const res = await getSealStatus({ skipErrorToast: true })
    if (res?.instance_guard) instanceGuardStatus.value = res.instance_guard
  } catch {
    // 靜默：網路抖動不打擾使用者，下一輪自然重試
  }
}

const startInstanceGuardPolling = () => {
  refreshInstanceGuardStatus()
  instanceGuardTimer = setInterval(refreshInstanceGuardStatus, INSTANCE_GUARD_POLL_MS)
}

// 審核中心待審 badge：僅具審核資格（ui:approvals）者輪詢；
// 輪詢失敗靜默（skipErrorToast），下一輪自然重試——badge 是提示不是事實源
const approvalPendingCount = ref(0)
const BADGE_POLL_MS = 30000
let badgeTimer = null

const refreshApprovalBadge = async () => {
  try {
    const res = await getPendingAccessRequestCount({ skipErrorToast: true })
    // 待審＋待補審合計（破窗補審共用審核中心收件匣）
    approvalPendingCount.value = (res.count ?? 0) + (res.review_count ?? 0)
  } catch {
    // 靜默：403（撤職殘窗）/網路抖動不打擾使用者
  }
}

const startApprovalBadgePolling = () => {
  // badge 端點與審核端點同一守衛，admin 打了必 403——
  // 判定與入口可見性收斂到同一個呈現點，避免對後端做無謂的必敗輪詢
  if (badgeTimer) return
  refreshApprovalBadge()
  badgeTimer = setInterval(refreshApprovalBadge, BADGE_POLL_MS)
}

// 資格由真轉假（撤角色／移出審核方群組）：停掉輪詢並清零。
// 不停的話 timer 會每 30 秒對必敗端點打一次，直到整個 layout 卸載為止
const stopApprovalBadgePolling = () => {
  if (badgeTimer) {
    clearInterval(badgeTimer)
    badgeTimer = null
  }
  approvalPendingCount.value = 0
}

watch(
  () => can('ui:approvals'),
  (eligible) => (eligible ? startApprovalBadgePolling() : stopApprovalBadgePolling()),
  { immediate: true }
)
watch(
  canSignDailyReview,
  (eligible) => (eligible ? dailyReviewBadge.start() : dailyReviewBadge.stop()),
  { immediate: true }
)

// 側欄自己的名字走 resolved display_name（僅自我檢視的
// 裝飾場景；身分敏感頁面另用 username）。自 localStorage 快取讀取，隨登入/自助更新同步。
// 這份快取只供顯示，**不是能力的來源**
const syncUserFromStorage = () => {
  const user = localStorage.getItem('user')
  if (!user) return
  try {
    const userData = JSON.parse(user)
    rawUserName.value = userData.display_name || userData.username || ''
  } catch (e) {
    console.error('解析使用者資料失敗:', e)
  }
}

// 審核送出後不必等下一輪輪詢：審核中心派 ot-approvals-changed，badge 立刻重算
const onApprovalsChanged = () => { if (can('ui:approvals')) refreshApprovalBadge() }

onUnmounted(() => {
  if (badgeTimer) clearInterval(badgeTimer)
  if (instanceGuardTimer) clearInterval(instanceGuardTimer)
  window.removeEventListener('ot-user-updated', syncUserFromStorage)
  window.removeEventListener('ot-approvals-changed', onApprovalsChanged)
  dailyReviewBadge.stop()
})

onMounted(() => {
  syncUserFromStorage()
  // 自助更新顯示名後同分頁即時反映（storage 事件不在同分頁觸發，改用自訂事件）
  window.addEventListener('ot-user-updated', syncUserFromStorage)
  window.addEventListener('ot-approvals-changed', onApprovalsChanged)
  // 與路由守衛共用同一次 /auth/me：守衛已載入則直接就緒，否則在這裡發起（登入即可的入口不等能力）
  caps.load()
  startInstanceGuardPolling()
})
</script>

<style scoped>
/* 每日簽核徽章：只有期限內的日子用警示色，有任一天逾期轉危險色 */
.daily-review-badge--warning :deep(.el-badge__content) {
  background-color: var(--ot-warning);
}

.daily-review-badge--danger :deep(.el-badge__content) {
  background-color: var(--ot-danger);
}

.layout-container {
  height: 100vh;
}

/* 側欄整體不再是捲動容器：它一捲，頂端的 logo 列（收合鈕現在住在那裡）
   就會跟著捲出視窗。改由選單自己捲，頂端那一列因此恆在初始視窗內 */
.sidebar {
  display: flex;
  flex-direction: column;
  background-color: var(--ot-bg-surface);
  border-right: 1px solid var(--ot-border-subtle);
  overflow: hidden;
  transition: width 0.2s ease;
}

.logo {
  height: var(--ot-header-height);
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: 0 var(--ot-space-md);
  border-bottom: 1px solid var(--ot-border-subtle);
  flex-shrink: 0;
}

/* 收合態只有 64px：標章與收合鈕都得留下（收合鈕消失＝再也展不開），
   故兩者一起縮到剛好放得下 */
.logo.collapsed {
  justify-content: space-between;
  gap: 2px;
  padding: 0 var(--ot-space-xs);
}

.logo-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: var(--ot-radius-md);
  background-color: var(--ot-brand-badge-bg);
  flex-shrink: 0;
}

.logo.collapsed .logo-mark {
  width: 24px;
  height: 24px;
}

.logo-mark img {
  width: 22px;
  height: 22px;
  display: block;
}

.logo.collapsed .logo-mark img {
  width: 18px;
  height: 18px;
}

.logo h2 {
  color: var(--ot-text-primary);
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
  margin: 0;
  white-space: nowrap;
}

/* 捲動的是選單本身（min-height: 0 讓 flex 子項真的收得下去，否則
   它會被內容撐開、捲軸長回側欄身上） */
.sidebar-menu {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  border-right: none;
  background-color: transparent;
}

.sidebar-menu:not(.el-menu--collapse) {
  width: 100%;
}

.menu-group-label {
  padding: var(--ot-space-md) var(--ot-space-md) var(--ot-space-xs);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  letter-spacing: 0.5px;
}

/* 組標題兼收合控制：維持標題的外觀，但是可聚焦的按鈕（鍵盤 Enter／Space 可操作） */
.menu-group-toggle {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  width: 100%;
  border: 0;
  background: transparent;
  text-align: left;
  cursor: pointer;
  font-family: inherit;
}

.menu-group-toggle:hover {
  color: var(--ot-text-primary);
}

.menu-group-toggle:focus-visible,
.menu-pin:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: -2px;
  border-radius: var(--ot-radius-sm);
}

.menu-group-chevron {
  font-size: 12px;
}

/* 釘選鈕：平常淡出，項目 hover／鍵盤聚焦或已釘選時顯現 */
.menu-pin {
  margin-left: auto;
  padding: 0 var(--ot-space-xs);
  border: 0;
  background: transparent;
  color: var(--ot-text-secondary);
  cursor: pointer;
  opacity: 0;
  line-height: 1;
}

.sidebar-menu :deep(.el-menu-item) .menu-pin--on,
.sidebar-menu :deep(.el-menu-item:hover) .menu-pin,
.sidebar-menu :deep(.el-menu-item:focus-within) .menu-pin,
.menu-pin:focus-visible {
  opacity: 1;
}

.capability-alert {
  margin: var(--ot-space-sm) var(--ot-space-lg) 0;
  width: auto;
}

.menu-title-with-badge {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

/* 選單列 line-height 40px：徽章外框若沿用 inline-block，sup 會落在 40px 行框的基線上，
   看起來像貼在文字右下的上標。改成 flex 收成徽章本身的高度，與文字垂直置中 */
.menu-badge {
  display: inline-flex;
  align-items: center;
  line-height: 1;
}

.menu-badge :deep(.el-badge__content) {
  position: static;
  transform: none;
  vertical-align: middle;
}

.sidebar-menu :deep(.el-menu-item) {
  height: 40px;
  line-height: 40px;
  margin: 2px var(--ot-space-sm);
  border-radius: var(--ot-radius-md);
  color: var(--ot-text-secondary);
}

.sidebar-menu :deep(.el-menu-item:hover) {
  color: var(--ot-text-primary);
  background-color: var(--ot-bg-hover);
}

.sidebar-menu :deep(.el-menu-item.is-active) {
  color: var(--ot-primary);
  background-color: var(--ot-primary-dim);
}

.collapse-btn {
  flex-shrink: 0;
  margin-left: auto;
  padding: 0;
  width: 28px;
  height: 28px;
  color: var(--ot-text-secondary);
}

.logo.collapsed .collapse-btn {
  margin-left: 0;
  width: 24px;
  height: 24px;
}

.collapse-btn:hover {
  color: var(--ot-text-primary);
}

.header {
  height: var(--ot-header-height);
  background-color: var(--ot-bg-surface);
  border-bottom: 1px solid var(--ot-border-subtle);
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 var(--ot-space-lg);
}

.header-left {
  display: flex;
  align-items: center;
}

.current-path {
  display: flex;
  align-items: baseline;
  gap: var(--ot-space-xs);
  font-size: var(--ot-font-size-lg);
  font-weight: 500;
  color: var(--ot-text-primary);
}

.crumb-link {
  color: var(--ot-text-secondary);
  text-decoration: none;
}

.crumb-link:hover {
  color: var(--ot-text-primary);
}

.crumb-sep {
  color: var(--ot-text-secondary);
}

.header-right {
  display: flex;
  align-items: center;
  gap: var(--ot-space-lg);
}

.user-info {
  cursor: pointer;
  border: 0;
  background: none;
  padding: 0;
  font: inherit;
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-secondary);
}

.user-info:hover {
  color: var(--ot-primary);
}

.lang-switch {
  cursor: pointer;
  border: 0;
  background: none;
  padding: 0;
  font: inherit;
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.lang-switch:hover {
  color: var(--ot-primary);
}

.main-content {
  background-color: var(--ot-bg-page);
  overflow-y: auto;
  padding: var(--ot-space-lg);
}

</style>
