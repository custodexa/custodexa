import { createRouter, createWebHistory } from 'vue-router'
import MainLayout from '../components/MainLayout.vue'
import {
  SEAL_PHASE_SEALED,
  SEAL_PHASE_UNSEALED,
  UNSEAL_PATH,
  ensureSealPhase,
} from '../utils/sealPhase'

const routes = [
  {
    path: '/',
    redirect: '/dashboard',
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
  },
  {
    // 解封頁：**封印期可達且不要求登入**。
    // 封印期後端只放行 /health、/seal/status、/seal/unseal，登入端點本身是 503，
    // 故此頁 SHALL NOT 帶 requiresAuth——否則管理員被導去一個打不通的登入頁。
    path: '/unseal',
    name: 'Unseal',
    component: () => import('../views/Unseal.vue'),
  },
  {
    path: '/',
    component: MainLayout,
    meta: { requiresAuth: true },
    children: [
      {
        path: 'dashboard',
        name: 'Dashboard',
        component: () => import('../views/Dashboard.vue'),
      },
      {
        path: 'assets',
        name: 'Assets',
        component: () => import('../views/Assets.vue'),
      },
      {
        path: 'sessions',
        name: 'Sessions',
        component: () => import('../views/Sessions.vue'),
        // session 管理視圖含他人連線紀錄，收斂為稽核職能
        meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
      },
      {
        path: 'my-connections',
        name: 'MyConnections',
        component: () => import('../views/MyConnections.vue'),
      },
      {
        // 個人資料：全角色自助頁——基本資料/自助改密/MFA 管理
        path: 'profile',
        name: 'Profile',
        component: () => import('../views/Profile.vue'),
      },
      {
        // 我的申請：申請人獨立自助頁——
        // 每角色功能頁單獨切開，不併入我的連線
        path: 'my-requests',
        name: 'MyRequests',
        component: () => import('../views/MyRequests.vue'),
      },
      {
        // 審核中心。**不做 admin 兜底**
        // ——僅具 admin 者對審核端點一律 403，若仍讓他進頁只會看到一個永遠是空的
        //「待審」表格（假空態，比擋住更危險）。`approver` 述詞的實際判定走
        // `is_approver`（見 createAuthGuard），與選單／badge 同一來源
        path: 'approvals',
        name: 'Approvals',
        component: () => import('../views/Approvals.vue'),
        meta: { requiresAuth: true, roles: ['approver'] },
      },
      {
        // 稽核調查工作台（auditor-workbench）：以人／資產為樞紐，把六類
        // 稽核紀錄併到同一條時間軸上。唯讀頁，與既有六頁**並存不取代**；
        // 權限沿既有稽核頁模式收斂為 admin/auditor
        path: 'audit/workbench',
        name: 'AuditWorkbench',
        component: () => import('../views/AuditWorkbench.vue'),
        meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
      },
      {
        path: 'audit-logs',
        name: 'AuditLogs',
        component: () => import('../views/AuditLogs.vue'),
        // 最小權限（7.2.x）：審計屬稽核職能，僅 admin/auditor
        meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
      },
      {
        // 檢查點驗證（audit-checkpoint-chain）：**獨立成頁**而非
        // AuditLogs 的對話框——資訊量（鏈健康、九態逐區間、離機錨定、
        // 誠實邊界 R0-R6、公鑰）遠超對話框容量。唯讀頁，auditor 亦可入
        path: 'checkpoint-verification',
        name: 'CheckpointVerification',
        component: () => import('../views/CheckpointVerification.vue'),
        meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
      },
      {
        path: 'access-reviews',
        name: 'AccessReviews',
        component: () => import('../views/AccessReviews.vue'),
        // 存取複審：稽核職能自授權頁遷出，
        // admin＋auditor 可見；簽核 admin only 由頁內與後端雙重控制
        meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
      },
      {
        path: 'commands',
        name: 'Commands',
        component: () => import('../views/Commands.vue'),
        meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
      },
      {
        path: 'alerts',
        name: 'Alerts',
        component: () => import('../views/Alerts.vue'),
        meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
      },
      {
        path: 'authorizations',
        name: 'Authorizations',
        component: () => import('../views/Authorizations.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'users',
        name: 'Users',
        component: () => import('../views/Users.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'roles',
        name: 'Roles',
        component: () => import('../views/Roles.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'user-groups',
        name: 'UserGroups',
        component: () => import('../views/UserGroups.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        // OIDC 身分提供者：身分域設定屬身分管理，
        // 與使用者/角色同組；admin only（後端 RequireRole 才是強制點）
        path: 'oidc-providers',
        name: 'OIDCProviders',
        component: () => import('../views/OIDCProviders.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        // LDAP 目錄設定：與 OIDC 同層的身分來源，
        // 兩者並列於身分管理群（分類語彙不是 SSO——LDAP 是 search-then-bind，
        // 實現差異屬內部細節）。singleton 資源，故路由無 :id
        path: 'ldap-directory',
        name: 'LDAPDirectory',
        component: () => import('../views/LDAPDirectory.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'approver-scopes',
        name: 'ApproverScopes',
        component: () => import('../views/ApproverScopes.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'security-policies',
        name: 'SecurityPolicies',
        component: () => import('../views/SecurityPolicies.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'access-control',
        name: 'AccessControl',
        component: () => import('../views/AccessControl.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'key-management',
        name: 'KeyManagement',
        component: () => import('../views/KeyManagement.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'transmission-inventory',
        name: 'TransmissionInventory',
        component: () => import('../views/TransmissionInventory.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'change-secret-plans',
        name: 'ChangeSecretPlans',
        component: () => import('../views/ChangeSecretPlans.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      // （TestConnection 手動連線頁已隨連線收口移除：手動輸入任意主機帳密屬繞過資產管理的旁路；
      //  RDPRecordingTest POC 頁已隨 JWT query fallback 移除，
      //  正式回放走 rtoken／Bearer blob）
    ],
  },
  {
    path: '/workspace',
    name: 'Workspace',
    component: () => import('../views/Workspace.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/terminal/:assetId',
    name: 'Terminal',
    component: () => import('../views/Terminal.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/sessions/:id',
    name: 'SessionDetail',
    component: () => import('../views/SessionDetail.vue'),
    // 與列表頁同步收斂：詳情含指令流與錄影入口
    meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
  },
  {
    path: '/share/:code',
    name: 'ShareView',
    component: () => import('../views/ShareView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/sessions/:id/monitor',
    name: 'SessionMonitor',
    component: () => import('../views/SessionMonitor.vue'),
    meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'NotFound',
    component: () => import('../views/NotFound.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// 封印導覽守衛：**單一守衛的兩個方向**。
//
// 缺陷史：`KEK_PROVIDER=ui` 的全新安裝，管理員登入後只得到「請先於解封頁提交
// 金鑰材料」而沒有任何東西把他送過去——ui 模式因此形同不可用。反向的
// 「已解封仍可開解封頁」則平白留一個對外的可互動表單。兩者是同一條規則的兩端，
// 拆成兩套判斷必然互相打架（例如各自快取相位而在解封成功當下互踢）。
//
// | 相位 | 目標 /unseal | 目標其他任何路徑 |
// |---|---|---|
// | sealed   | 放行 | 導向 /unseal |
// | unsealed | 導向 /（再由 auth guard 決定 /dashboard 或 /login） | 放行 |
// | unknown  | 放行 | 探測後依上兩列決定；探測失敗即放行 |
//
// **解封成功當下不會踢人**：守衛只在導覽時執行，而解封是在 `/unseal` 頁內
// 完成的（無導覽）。使用者停在成功畫面，由「前往登入」自行離開——那一次導覽
// 讀到的相位已由 Unseal.vue 發佈為 unsealed，故不會被彈回。
export function createSealGuard() {
  return async (to, from, next) => {
    const target = to.path === UNSEAL_PATH
    const phase = await ensureSealPhase()
    if (phase === SEAL_PHASE_SEALED && !target) {
      next(UNSEAL_PATH)
      return
    }
    if (phase === SEAL_PHASE_UNSEALED && target) {
      next('/')
      return
    }
    next()
  }
}

// Navigation guard for authentication (exported for unit testing)
export function createAuthGuard() {
  return (to, from, next) => {
    const token = localStorage.getItem('token')

    if (to.meta.requiresAuth && !token) {
      next('/login')
    } else if (to.path === '/login' && token) {
      next('/dashboard')
    } else if (to.meta.roles) {
      // Check role-based access（fail-closed：user 資料缺失視同未登入，
      // 不得跳過角色檢查放行——原實作在 token 在、user 缺時 fail-open）
      const user = localStorage.getItem('user')
      if (!user) {
        next('/login')
        return
      }
      try {
        const userData = JSON.parse(user)
        const userRoles = userData.roles || []

        // `approver` 是**唯一以 is_approver 裁決的述詞**：
        // 它不從 roles 快取比對——群組審核方的 roles 不含 approver 卻有資格
        // 而僅具 admin 者 roles 有 admin 卻**沒有**審核資格。故把它從
        // 靜態角色比對中排除，改由後端算出的 is_approver 單一來源決定，
        // 與選單可見性、badge 輪詢同源；其餘角色述詞維持 roles 交集判定
        const staticRoles = to.meta.roles.filter(role => role !== 'approver')
        const hasPermission = staticRoles.some(role => userRoles.includes(role))
        const approverEligible =
          to.meta.roles.includes('approver') && userData.is_approver === true

        if (!hasPermission && !approverEligible) {
          next('/dashboard')
          return
        }
      } catch (e) {
        console.error('解析使用者資料失敗:', e)
        next('/login')
        return
      }
      next()
    } else {
      next()
    }
  }
}

// 封印守衛註冊於認證守衛**之前**：封印期連登入端點都是 503，
// 先讓認證守衛把人送去一個打不通的登入頁，等於重現本次要修的鎖死。
router.beforeEach(createSealGuard())
router.beforeEach(createAuthGuard())

export default router
