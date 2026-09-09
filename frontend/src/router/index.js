import { createRouter, createWebHistory } from 'vue-router'
import MainLayout from '../components/MainLayout.vue'
import {
  INSTANCE_GUARD_PATH,
  SEAL_PHASE_HALTED,
  SEAL_PHASE_SEALED,
  SEAL_PHASE_UNKNOWN,
  SEAL_PHASE_UNSEALED,
  UNSEAL_PATH,
  ensureSealPhase,
} from '../utils/sealPhase'
import { ensureSession } from '../utils/session'

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
    // 守衛攔下頁：**攔下期可達且不要求登入**，理由同解封頁——
    // 攔下模式只開 /health、/seal/status 與兩條 instance-guard 端點，
    // 登入端點根本不存在於那份路由樹上。
    path: '/instance-guard',
    name: 'InstanceGuardHalted',
    component: () => import('../views/InstanceGuardHalted.vue'),
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
        // 輪替證據：資產帳號憑證輪替的合規現況與報告產出。
        // 排程管理是頁內的 admin 專屬區塊，不另立路由——它是這份報告的產出
        // 設定，獨立成頁就失去上下文。權限沿稽核頁模式（＝後端的 audit:view 閘）
        path: 'rotation-evidence',
        name: 'RotationEvidence',
        component: () => import('../views/RotationEvidence.vue'),
        meta: { requiresAuth: true, roles: ['admin', 'auditor'] },
      },
      {
        // 下載中心：證據包走非同步交付後，產物不再隨
        // 按鈕落地，必須有一個「我發起的產物在哪裡」的常設位置。獨立成頁而非
        // 掛在工作台對話框內——散落各功能的臨時進度介面正是本頁要取代的東西。
        // 權限沿稽核頁模式收斂為 admin/auditor（＝後端的 audit:view 閘）
        path: 'audit/exports',
        name: 'AuditExports',
        component: () => import('../views/AuditExports.vue'),
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
        // 合規對照：安全設定對每一個政策組的判定結果。**唯讀**——
        // 條文改在政策組頁、設定值改在安全政策頁，這一頁只是同一份判定的投影。
        // 權限沿稽核頁模式，admin 亦可讀（兩種角色看到的是同一個答案）
        path: 'compliance-map',
        name: 'ComplianceMap',
        component: () => import('../views/ComplianceMap.vue'),
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
        // 身分來源：目錄與身分提供者合併為一份清單，映射規則成為各來源詳情頁
        // 內的區段。admin only（後端 RequireRole 才是強制點）
        path: 'identity-sources',
        name: 'IdentitySources',
        component: () => import('../views/identity-sources/IdentitySources.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        // 新增流程只問型別，選定即進詳情頁；靜態段 `new` 的比對分數高於
        // 下方的 `:type`，故不會被詳情路由吃掉
        path: 'identity-sources/new/:type',
        name: 'IdentitySourceCreate',
        component: () => import('../views/identity-sources/SourceDetail.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'identity-sources/:type/:id',
        name: 'IdentitySourceDetail',
        component: () => import('../views/identity-sources/SourceDetail.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        // 兩個前身頁的深連結仍須可用（沿「改名後深連結仍可用」的既有立場）：
        // 書籤、文件與外部連結都指向舊路徑，直接移除等於製造 404
        path: 'oidc-providers',
        redirect: '/identity-sources',
      },
      {
        path: 'ldap-directory',
        redirect: '/identity-sources',
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
        // 政策組：條文與要求的維護面，也是政策組**所有寫入的唯一入口**。
        // 與安全政策頁相鄰——一邊是設定值、一邊是對照的條文，讀者是同一個人
        path: 'policy-groups',
        name: 'PolicyGroups',
        component: () => import('../views/PolicyGroups.vue'),
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
        // 離機儲存（evidence-offsite-storage）：儲存端連線設定、憑證世代、
        // 上傳佇列與失敗清單。與金鑰管理同層——兩者都是「證據放哪裡、
        // 誰解得開」的設定面，故並列於設定域
        path: 'offsite-storage',
        name: 'OffsiteStorage',
        component: () => import('../views/OffsiteStorage.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'change-secret-plans',
        name: 'ChangeSecretPlans',
        component: () => import('../views/ChangeSecretPlans.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        path: 'change-secret-batches',
        name: 'AccountBatchRotation',
        component: () => import('../views/AccountBatchRotation.vue'),
        meta: { requiresAuth: true, roles: ['admin'] },
      },
      {
        // 帳號憑證庫：登入憑證的單一管理面（範圍、掛載、整組改密）。
        // 第一段 `credentials` 須與後端的前端路由段枚舉同步登記，
        // 否則 SSO 登入後會被丟回首頁（雙向守衛盯著這件事）
        path: 'credentials',
        name: 'CredentialLibrary',
        component: () => import('../views/CredentialLibrary.vue'),
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
// | 相位 | 目標 /unseal | 目標 /instance-guard | 目標其他任何路徑 |
// |---|---|---|---|
// | halted   | 導向 /instance-guard | 放行 | 導向 /instance-guard |
// | sealed   | 放行 | 導向 / | 導向 /unseal |
// | unsealed | 導向 /（再由 auth guard 決定 /dashboard 或 /login） | 導向 / | 放行 |
// | unknown  | 放行 | 放行 | 探測後依上三列決定；探測失敗即放行 |
//
// **halted 先判**：攔下期 `/seal/status` 的 `state` 仍是 sealed（服務確實未上線），
// 若照 sealed 那列處理，人會被送去一個同樣打不通的解封頁——那正是本相位要修的東西。
// 未知相位（探測失敗）對 `/instance-guard` 放行而非導離：與 `/unseal` 同一條
// 「不猜、不阻擋」，且後端不在攔下模式時該頁自己會顯示「已啟動」。
//
// **解封成功當下不會踢人**：守衛只在導覽時執行，而解封是在 `/unseal` 頁內
// 完成的（無導覽）。使用者停在成功畫面，由「前往登入」自行離開——那一次導覽
// 讀到的相位已由 Unseal.vue 發佈為 unsealed，故不會被彈回。
export function createSealGuard() {
  return async (to, from, next) => {
    const target = to.path === UNSEAL_PATH
    const haltTarget = to.path === INSTANCE_GUARD_PATH
    const phase = await ensureSealPhase()
    if (phase === SEAL_PHASE_HALTED) {
      if (haltTarget) next()
      else next(INSTANCE_GUARD_PATH)
      return
    }
    // 已知非攔下相位下的攔下頁：導離（同 unsealed 對 /unseal 的處理，
    // 不留一個服務已上線卻仍可互動的接手表單）
    if (haltTarget && phase !== SEAL_PHASE_UNKNOWN) {
      next('/')
      return
    }
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
// 守衛是非同步的：access token 只存頁面記憶體，重新載入或開新分頁時記憶體是空的，
// 必須先以續期憑證換發一次才知道使用者到底登入了沒有。這一步發生在放行受保護
// 路由**之前**——放行後才發現沒憑證，等於讓頁面先閃一次再被踢走。
export function createAuthGuard() {
  return async (to, from, next) => {
    const authed = await ensureSession()

    if (to.meta.requiresAuth && !authed) {
      next('/login')
    } else if (to.path === '/login' && authed) {
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
