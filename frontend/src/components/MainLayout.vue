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
            <Expand v-if="isCollapsed" />
            <Fold v-else />
          </el-icon>
        </el-button>
      </div>
      <el-menu
        :default-active="activeMenu"
        :collapse="isCollapsed"
        :collapse-transition="false"
        router
        class="sidebar-menu"
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
          <span class="current-path">{{ currentPageTitle }}</span>
        </div>
        <div class="header-right">
          <!-- 語言切換：即時生效免 reload，偏好存 ot-lang -->
          <el-dropdown @command="setLanguage">
            <span class="lang-switch">
              {{ LOCALE_LABELS[locale] }}
              <el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </span>
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
            <span class="user-info">
              <el-icon><User /></el-icon>
              {{ userName }}
              <el-icon class="el-icon--right"><ArrowDown /></el-icon>
            </span>
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
import {
  Odometer,
  Lock,
  Monitor,
  Connection,
  Document,
  User,
  UserFilled,
  ArrowDown,
  Key,
  Tickets,
  Bell,
  Expand,
  Fold,
  Stamp,
  Finished,
  Position,
  OfficeBuilding,
  Search,
  Download,
  Upload,
} from '@element-plus/icons-vue'
import { useI18n } from 'vue-i18n'
import { BRAND } from '@/brand'
import { SUPPORTED_LOCALES, LOCALE_LABELS, setLanguage } from '@/i18n'
import { getPendingAccessRequestCount } from '@/api/accessRequests'
import { getCurrentUser } from '@/api/auth'
import { logout } from '@/api/auth'
import { getSealStatus } from '@/api/seal'
import InstanceGuardBanner from './InstanceGuardBanner.vue'

const COLLAPSE_KEY = 'ot-sidebar-collapsed'

const { t, locale } = useI18n()
const router = useRouter()
const route = useRoute()

const rawUserName = ref('')
const userName = computed(() => rawUserName.value || t('common.defaultUserName'))
const isAdmin = ref(false)
const userRoles = ref([])
const isCollapsed = ref(localStorage.getItem(COLLAPSE_KEY) === 'true')

// 選單資料只存 i18n key；譯文在 visibleGroups computed
// 內以 t() 解出——computed 追蹤 locale，切語言即時重繪
const menuGroups = [
  {
    labelKey: 'menu.group.overview',
    items: [
      { path: '/dashboard', titleKey: 'menu.dashboard', icon: Odometer },
      // 工作區入口：同分頁導航，工作區「◀」返回；
      // 工作區本體為純連線面，不因此新增任何門戶功能
      { path: '/workspace', titleKey: 'menu.workspace', icon: Position },
    ],
  },
  {
    labelKey: 'menu.group.assets',
    items: [
      // 一般 user 視角顯示「我的資產」：同一頁面、僅文案分角色
      {
        path: '/assets',
        titleKey: 'menu.assets',
        userTitleKey: 'menu.myAssets',
        icon: Monitor,
      },
      { path: '/authorizations', titleKey: 'menu.authorizations', icon: Key, adminOnly: true },
      { path: '/change-secret-plans', titleKey: 'menu.changeSecretPlans', icon: Lock, adminOnly: true },
    ],
  },
  {
    labelKey: 'menu.group.sessions',
    items: [
      // session 管理視圖收斂為稽核職能；
      // 一般 user 走自助「我的連線」，以「不具 admin/auditor」判定（非 roles 含 user）
      {
        path: '/sessions',
        titleKey: 'menu.sessions',
        icon: Connection,
        roles: ['admin', 'auditor'],
      },
      {
        path: '/my-connections',
        titleKey: 'menu.myConnections',
        icon: Connection,
        hideRoles: ['admin', 'auditor'],
      },
      {
        // 我的申請：申請人自助頁，
        // 與我的連線同屬一般 user 自助入口
        path: '/my-requests',
        titleKey: 'menu.myRequests',
        icon: Tickets,
        hideRoles: ['admin', 'auditor'],
      },
    ],
  },
  {
    labelKey: 'menu.group.approval',
    items: [
      // 審核中心。**不做 admin 兜底**
      // ——僅具 admin 者對審核端點一律 403，留著入口只會把他導向一個假空態頁面。
      // `approver` 述詞由 effectiveApprover（/auth/me 的 is_approver）判定，
      // 與路由守衛、badge 輪詢同一來源
      {
        path: '/approvals',
        titleKey: 'menu.approvals',
        icon: Stamp,
        roles: ['approver'],
        badge: 'approvals',
      },
    ],
  },
  {
    labelKey: 'menu.group.audit',
    items: [
      {
        // 稽核調查工作台（auditor-workbench）：置於審計群**首項**——
        // 調查是最高頻入口，其餘六頁承載的是審閱、簽核、監看等作業，
        // 工作台與它們並存而非取代
        path: '/audit/workbench',
        titleKey: 'menu.auditWorkbench',
        icon: Search,
        roles: ['admin', 'auditor'],
      },
      {
        // 下載中心：緊接工作台——證據包由工作台發起、
        // 在這裡取件，兩者是同一條動線的前後兩段
        path: '/audit/exports',
        titleKey: 'menu.auditExports',
        icon: Download,
        roles: ['admin', 'auditor'],
      },
      // 最小權限（7.2.x）：審計屬稽核職能，僅 admin/auditor
      {
        path: '/audit-logs',
        titleKey: 'menu.auditLogs',
        icon: Document,
        roles: ['admin', 'auditor'],
      },
      {
        path: '/commands',
        titleKey: 'menu.commands',
        icon: Tickets,
        roles: ['admin', 'auditor'],
      },
      {
        path: '/alerts',
        titleKey: 'menu.alerts',
        icon: Bell,
        roles: ['admin', 'auditor'],
      },
      {
        // 檢查點驗證（audit-checkpoint-chain）：序列完整性證明，稽核職能
        path: '/checkpoint-verification',
        titleKey: 'menu.checkpointVerification',
        icon: Finished,
        roles: ['admin', 'auditor'],
      },
      {
        // 存取複審：稽核職能歸審計區
        path: '/access-reviews',
        titleKey: 'menu.accessReviews',
        icon: Finished,
        roles: ['admin', 'auditor'],
      },
    ],
  },
  // 系統管理拆兩組：身分自成領域、政策開關收設定域
  {
    labelKey: 'menu.group.identity',
    adminOnly: true,
    items: [
      { path: '/users', titleKey: 'menu.users', icon: User, adminOnly: true },
      { path: '/roles', titleKey: 'menu.roles', icon: UserFilled, adminOnly: true },
      { path: '/user-groups', titleKey: 'menu.userGroups', icon: UserFilled, adminOnly: true },
      { path: '/approver-scopes', titleKey: 'menu.approverScopes', icon: Stamp, adminOnly: true },
      {
        // OIDC 身分提供者
        path: '/oidc-providers',
        titleKey: 'menu.oidcProviders',
        icon: Connection,
        adminOnly: true,
      },
      {
        // LDAP 目錄：與 OIDC 是同層的身分來源，
        // 故緊鄰並列。群組語彙維持「身分與權限」而非 SSO——LDAP 是目錄型身分來源，
        // 與 OIDC/SAML2 這類瀏覽器重導式 SSO 不同層，混為一組會誤導設定者
        path: '/ldap-directory',
        titleKey: 'menu.ldapDirectory',
        icon: OfficeBuilding,
        adminOnly: true,
      },
    ],
  },
  {
    labelKey: 'menu.group.settings',
    adminOnly: true,
    items: [
      {
        path: '/security-policies',
        titleKey: 'menu.securityPolicies',
        icon: Lock,
        adminOnly: true,
      },
      {
        path: '/access-control',
        titleKey: 'menu.accessControl',
        icon: Stamp,
        adminOnly: true,
      },
      {
        path: '/key-management',
        titleKey: 'menu.keyManagement',
        icon: Key,
        adminOnly: true,
      },
      {
        path: '/transmission-inventory',
        titleKey: 'menu.transmissionInventory',
        icon: Connection,
        adminOnly: true,
      },
      {
        // 離機儲存：證據副本的落點設定與上傳佇列。
        // 緊接金鑰管理與傳輸清冊——三者同屬「證據放哪裡、怎麼過去、誰解得開」
        path: '/offsite-storage',
        titleKey: 'menu.offsiteStorage',
        icon: Upload,
        adminOnly: true,
      },
    ],
  },
]

// 有效審核資格（群組即資格）：roles 快取蓋不到
// 「審核方群組成員」——以 /auth/me 的 is_approver 判定（後端即時計算）。
// 初值先取登入時寫入 localStorage 的 is_approver，避免首屏閃爍；掛載後以
// /auth/me 覆蓋（角色/群組變更即時反映）
const effectiveApprover = ref(false)

// 項目可見性：adminOnly 僅 admin；roles 列表需與使用者角色有交集；
// **`approver` 例外——不從 roles 快取比對，一律走 effectiveApprover**
//（僅具 admin 者沒有審核資格，群組審核方沒有 approver 角色卻有資格。
// 兩個方向都證明 roles 陣列不是這個述詞的正確來源）；
// hideRoles 命中任一即隱藏（自助入口「不具 admin/auditor 才顯示」）
const isItemVisible = (item) => {
  if (item.adminOnly && !isAdmin.value) return false
  if (item.roles) {
    const staticRoles = item.roles.filter((role) => role !== 'approver')
    const allowed =
      staticRoles.some((role) => userRoles.value.includes(role)) ||
      (item.roles.includes('approver') && effectiveApprover.value)
    if (!allowed) return false
  }
  if (item.hideRoles && item.hideRoles.some((role) => userRoles.value.includes(role))) {
    return false
  }
  return true
}

// 非特權角色以 userTitle 覆寫顯示名（我的資產）；判定與自助入口同口徑（不具 admin/auditor）
const isPrivileged = computed(
  () => userRoles.value.includes('admin') || userRoles.value.includes('auditor')
)

const visibleGroups = computed(() =>
  menuGroups
    .filter((group) => !group.adminOnly || isAdmin.value)
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

const activeMenu = computed(() => route.path)

const pageTitleKeys = {
  '/dashboard': 'menu.dashboard',
  '/assets': 'menu.assets',
  '/sessions': 'menu.sessions',
  '/my-connections': 'menu.myConnections',
  '/my-requests': 'menu.myRequests',
  '/approvals': 'menu.approvals',
  '/audit/workbench': 'menu.auditWorkbench',
  '/audit/exports': 'menu.auditExports',
  '/audit-logs': 'menu.auditLogs',
  '/commands': 'menu.commands',
  '/alerts': 'menu.alerts',
  '/access-reviews': 'menu.accessReviews',
  '/checkpoint-verification': 'menu.checkpointVerification',
  '/authorizations': 'menu.authorizations',
  '/change-secret-plans': 'menu.changeSecretPlans',
  '/users': 'menu.users',
  '/profile': 'menu.profile',
  '/user-groups': 'menu.userGroups',
  '/oidc-providers': 'menu.oidcProviders',
  '/ldap-directory': 'menu.ldapDirectory',
  '/roles': 'menu.roles',
  '/security-policies': 'menu.securityPolicies',
  '/access-control': 'menu.accessControl',
  '/key-management': 'menu.keyManagement',
  '/transmission-inventory': 'menu.transmissionInventory',
  '/offsite-storage': 'menu.offsiteStorage',
}

const currentPageTitle = computed(() =>
  t(pageTitleKeys[route.path] || 'menu.home')
)

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
  localStorage.removeItem('token')
  localStorage.removeItem('user')
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

// 審核資格的權威判定（群組即資格、admin 不兜底）：/auth/me 現算。
// 查失敗靜默——沿用 localStorage 快取值（後端守衛才是強制點）。
// **回寫 localStorage**：路由守衛是同步的、只讀得到快取，不回寫的話
// 「剛被指派 approver 的人」選單會亮但直接進頁被守衛擋掉（兩套述詞的老毛病）
const refreshEffectiveApprover = async () => {
  try {
    const me = await getCurrentUser()
    const wasApprover = effectiveApprover.value
    effectiveApprover.value = !!(me?.is_approver ?? me?.data?.is_approver)
    persistApproverFlag(effectiveApprover.value)
    if (effectiveApprover.value && !wasApprover && !badgeTimer) {
      startApprovalBadgePolling()
    }
  } catch {
    // 靜默：入口顯示性判定失敗不打擾使用者
  }
}

// 把現算的 is_approver 寫回使用者快取，讓同步的路由守衛與選單同源
const persistApproverFlag = (value) => {
  const user = localStorage.getItem('user')
  if (!user) return
  try {
    const userData = JSON.parse(user)
    if (userData.is_approver === value) return
    userData.is_approver = value
    localStorage.setItem('user', JSON.stringify(userData))
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
    // 首屏先用登入時寫入的 is_approver，避免 /auth/me 回來前選單閃爍
    effectiveApprover.value = userData.is_approver === true
  } catch (e) {
    console.error('解析使用者資料失敗:', e)
  }
}

onUnmounted(() => {
  if (badgeTimer) clearInterval(badgeTimer)
  if (instanceGuardTimer) clearInterval(instanceGuardTimer)
  window.removeEventListener('ot-user-updated', syncUserFromStorage)
})

onMounted(() => {
  syncUserFromStorage()
  // 自助更新顯示名後同分頁即時反映（storage 事件不在同分頁觸發，改用自訂事件）
  window.addEventListener('ot-user-updated', syncUserFromStorage)
  startApprovalBadgePolling()
  refreshEffectiveApprover()
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
  color: var(--ot-text-disabled);
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
  font-size: var(--ot-font-size-lg);
  font-weight: 500;
  color: var(--ot-text-primary);
}

.header-right {
  display: flex;
  align-items: center;
  gap: var(--ot-space-lg);
}

.user-info {
  cursor: pointer;
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
