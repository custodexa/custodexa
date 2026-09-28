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
        <template
          v-for="group in visibleGroups"
          :key="group.label"
        >
          <div
            v-show="!isCollapsed"
            class="menu-group-label"
          >
            {{ group.label }}
          </div>
          <el-menu-item
            v-for="item in group.items"
            :key="item.path"
            :index="item.path"
          >
            <el-icon><component :is="item.icon" /></el-icon>
            <template #title>
              <span class="menu-title-with-badge">
                {{ item.title }}
                <el-badge
                  v-if="item.badge === 'approvals' && approvalPendingCount > 0"
                  :value="approvalPendingCount"
                  :max="99"
                  class="menu-badge"
                />
              </span>
            </template>
          </el-menu-item>
        </template>
      </el-menu>
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
        :is-admin="isAdmin"
      />

      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
// header 用到的 icon；側欄選單的宣告（含其 icon）在 ./sidebarMenu.js
import {
  ChevronDown,
  CircleUserRound,
  PanelLeftOpen,
  PanelLeftClose,
} from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { BRAND } from '@/brand'
import { SUPPORTED_LOCALES, LOCALE_LABELS, setLanguage } from '@/i18n'
import { getPendingAccessRequestCount } from '@/api/accessRequests'
import { getCurrentUser } from '@/api/auth'
import { logout } from '@/api/auth'
import { getSealStatus } from '@/api/seal'
import InstanceGuardBanner from './InstanceGuardBanner.vue'
import { clearSession } from '@/utils/session'
import { detailSubject } from '@/utils/detailTitle'
import { canEnter, entryRuleFor, entrySubject } from '@/router/entryRules'
import { MENU_GROUPS } from './sidebarMenu'

const COLLAPSE_KEY = 'ot-sidebar-collapsed'

const { t, locale } = useI18n()
const router = useRouter()
const route = useRoute()

const rawUserName = ref('')
const userName = computed(() => rawUserName.value || t('common.defaultUserName'))
const isAdmin = ref(false)
const userRoles = ref([])
const isCollapsed = ref(localStorage.getItem(COLLAPSE_KEY) === 'true')

// 有效審核資格（群組即資格）：roles 快取蓋不到
// 「審核方群組成員」——以 /auth/me 的 is_approver 判定（後端即時計算）。
// 初值先取登入時寫入 localStorage 的 is_approver，避免首屏閃爍；掛載後以
// /auth/me 覆蓋（角色/群組變更即時反映）
const effectiveApprover = ref(false)
// 「我的 agent」入口資格的兩個成分（負責至少一個 agent／政策允許自建），
// 與 is_approver 同一條路徑取得：登入快取先用、掛載後以 /auth/me 覆蓋並回寫
const ownsAgents = ref(false)
const canSelfCreateAgent = ref(false)

// 選單可見性與路由守衛**同一個判斷**（router/entryRules.js 的 canEnter）：
// 同一份規則、同一種身分正規化，選單看得到的就是網址進得去的。
// 規則表查不到的項目 fail-closed 不顯示
const subject = computed(() =>
  entrySubject({
    roles: userRoles.value,
    is_approver: effectiveApprover.value,
    owns_agents: ownsAgents.value,
    can_self_create_agent: canSelfCreateAgent.value,
  })
)
const isItemVisible = (item) => {
  const rule = entryRuleFor(item.path)
  return Boolean(rule) && canEnter(rule, subject.value)
}

// 非特權角色以 userTitle 覆寫顯示名（我的資產）；判定與自助入口同口徑（不具 admin/auditor）
const isPrivileged = computed(
  () => userRoles.value.includes('admin') || userRoles.value.includes('auditor')
)

const visibleGroups = computed(() =>
  MENU_GROUPS
    .map((group) => ({
      ...group,
      label: t(group.labelKey),
      items: group.items.filter(isItemVisible).map((item) => ({
        ...item,
        title:
          !isPrivileged.value && item.userTitleKey
            ? t(item.userTitleKey)
            : t(item.titleKey),
      })),
    }))
    .filter((group) => group.items.length > 0)
)

const sidebarWidth = computed(() =>
  isCollapsed.value
    ? 'var(--ot-sidebar-width-collapsed)'
    : 'var(--ot-sidebar-width)'
)

// 有子路徑的功能頁（來源詳情）仍要讓所屬選單項保持選取：以完整路徑比對時，
// 進到詳情頁會整條側欄都不亮，讀起來像離開了那個功能
const SUBPATH_PARENTS = ['/identity-sources']
const menuPathOf = (path) =>
  SUBPATH_PARENTS.find((parent) => path === parent || path.startsWith(`${parent}/`)) || path

// 使用者管理與 AI agent 主體是同一個路徑的兩個入口，靠 query 區分選取
const activeMenu = computed(() =>
  route.path === '/users' && route.query.kind === 'agent'
    ? '/users?kind=agent'
    : menuPathOf(route.path)
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

const breadcrumbs = computed(() => {
  const parent = detailPages[route.name]?.parent
  const current = { label: currentPageTitle.value, to: '' }
  return parent ? [{ label: parent.label(), to: parent.to }, current] : [current]
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

// 審核中心待審 badge：僅 admin/approver 輪詢；
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
  // 判定與入口可見性收斂到同一述詞，避免對後端做無謂的必敗輪詢
  if (!effectiveApprover.value) return
  refreshApprovalBadge()
  badgeTimer = setInterval(refreshApprovalBadge, BADGE_POLL_MS)
}

// 入口資格的權威判定：/auth/me 現算的 is_approver（群組即資格、admin 不兜底）
// 與「我的 agent」兩欄（owns_agents／can_self_create_agent）。
// 查失敗靜默——沿用 localStorage 快取值（後端守衛才是強制點）。
// **回寫 localStorage**：路由守衛是同步讀快取的，不回寫的話
// 「剛被指派 approver 的人」或「剛成為 agent 負責人的人」選單會亮、
// 直接進頁卻被守衛擋掉（兩套述詞的老毛病）
const refreshEntryFlags = async () => {
  try {
    const me = await getCurrentUser()
    const info = me?.data && typeof me.data === 'object' && !Array.isArray(me.data) ? me.data : me
    const wasApprover = effectiveApprover.value
    effectiveApprover.value = !!(me?.is_approver ?? me?.data?.is_approver)
    // agent 兩欄只在回應帶了才採信：缺欄（例如舊版後端）不把快取改成 false
    const updates = { is_approver: effectiveApprover.value }
    for (const key of ['owns_agents', 'can_self_create_agent']) {
      if (info && typeof info[key] === 'boolean') updates[key] = info[key]
    }
    if ('owns_agents' in updates) ownsAgents.value = updates.owns_agents
    if ('can_self_create_agent' in updates) canSelfCreateAgent.value = updates.can_self_create_agent
    persistEntryFlags(updates)
    if (effectiveApprover.value && !wasApprover && !badgeTimer) {
      startApprovalBadgePolling()
    }
    // 資格由真轉假（撤角色／移出審核方群組）：停掉輪詢並清零。
    // 不停的話 timer 會每 30 秒對必敗端點打一次，直到整個 layout 卸載為止。
    if (!effectiveApprover.value && wasApprover) {
      if (badgeTimer) {
        clearInterval(badgeTimer)
        badgeTimer = null
      }
      approvalPendingCount.value = 0
    }
  } catch {
    // 靜默：入口顯示性判定失敗不打擾使用者
  }
}

// 把現算的入口資格寫回使用者快取，讓同步的路由守衛與選單同源。
// 值未變時不寫、不廣播（避免無謂喚醒下游）
const persistEntryFlags = (updates) => {
  const user = localStorage.getItem('user')
  if (!user) return
  try {
    const userData = JSON.parse(user)
    const changed = Object.entries(updates).filter(([key, value]) => userData[key] !== value)
    if (changed.length === 0) return
    for (const [key, value] of changed) userData[key] = value
    localStorage.setItem('user', JSON.stringify(userData))
    // 同分頁的其他元件（儀表板待審卡）沒有別的管道知道資格變了：
    // storage 事件不在同分頁觸發，故沿用自助更新那條自訂事件。
    window.dispatchEvent(new Event('ot-user-updated'))
  } catch {
    // 快取毀損時不覆寫：守衛自身對毀損快取已 fail-closed 導向登入
  }
}

// 側欄自己的名字走 resolved display_name（僅自我檢視的
// 裝飾場景；身分敏感頁面另用 username）。自 localStorage 快取讀取，隨登入/自助更新同步
const syncUserFromStorage = () => {
  const user = localStorage.getItem('user')
  if (!user) return
  try {
    const userData = JSON.parse(user)
    rawUserName.value = userData.display_name || userData.username || ''
    const roles = userData.roles || []
    userRoles.value = roles
    isAdmin.value = roles.includes('admin')
    // 首屏先用登入時寫入的入口資格，避免 /auth/me 回來前選單閃爍
    const cached = entrySubject(userData)
    effectiveApprover.value = cached.isApprover
    ownsAgents.value = cached.ownsAgents
    canSelfCreateAgent.value = cached.canSelfCreateAgent
  } catch (e) {
    console.error('解析使用者資料失敗:', e)
  }
}

// 審核送出後不必等下一輪輪詢：審核中心派 ot-approvals-changed，badge 立刻重算
const onApprovalsChanged = () => { if (effectiveApprover.value) refreshApprovalBadge() }

onUnmounted(() => {
  if (badgeTimer) clearInterval(badgeTimer)
  if (instanceGuardTimer) clearInterval(instanceGuardTimer)
  window.removeEventListener('ot-user-updated', syncUserFromStorage)
  window.removeEventListener('ot-approvals-changed', onApprovalsChanged)
})

onMounted(() => {
  syncUserFromStorage()
  // 自助更新顯示名後同分頁即時反映（storage 事件不在同分頁觸發，改用自訂事件）
  window.addEventListener('ot-user-updated', syncUserFromStorage)
  window.addEventListener('ot-approvals-changed', onApprovalsChanged)
  startApprovalBadgePolling()
  refreshEntryFlags()
  startInstanceGuardPolling()
})
</script>

<style scoped>
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

.menu-title-with-badge {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.menu-badge :deep(.el-badge__content) {
  position: static;
  transform: none;
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
