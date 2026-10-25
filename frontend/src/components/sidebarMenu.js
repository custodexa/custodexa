// 側欄選單的宣告：群組、順序、標題與圖示。
//
// **這裡不寫誰看得到**：可見性一律由 router/entryRules.js 依路徑判斷，
// 與路由守衛同一個來源。選單項目若在那裡查不到規則，
// 側欄 fail-closed 不顯示——新項目要先在規則表登記才會出現。
//
// 選單資料只存 i18n key；譯文在 MainLayout 的 visibleGroups computed 內以 t() 解出，
// 切語言即時重繪。icon 一律取自 lucide-vue-next（ISC；已入第三方授權清單）
import {
  ClipboardCheck,
  Gauge,
  Scale,
  SquareTerminal,
  Server,
  TicketCheck,
  RotateCcwKey,
  Layers,
  MonitorPlay,
  Cable,
  ClipboardList,
  Stamp,
  TextSearch,
  FileClock,
  HardDriveDownload,
  ScrollText,
  Terminal,
  BellRing,
  ShieldCheck,
  ListChecks,
  User,
  UserCog,
  Users,
  UserCheck,
  IdCard,
  Shield,
  SlidersHorizontal,
  KeyRound,
  KeySquare,
  Waypoints,
  CloudUpload,
  Send,
  Bot,
} from 'lucide-vue-next'

export const MENU_GROUPS = [
  {
    id: 'overview',
    labelKey: 'menu.group.overview',
    items: [
      { id: 'dashboard', path: '/dashboard', titleKey: 'menu.dashboard', icon: Gauge },
      // 工作區入口：同分頁導航，工作區「◀」返回；
      // 工作區本體為純連線面，不因此新增任何門戶功能
      { id: 'workspace', path: '/workspace', titleKey: 'menu.workspace', icon: SquareTerminal },
    ],
  },
  {
    id: 'assets',
    labelKey: 'menu.group.assets',
    items: [
      // 一般 user 視角顯示「我的資產」：同一頁面、僅文案分角色
      {
        id: 'assets',
        path: '/assets',
        titleKey: 'menu.assets',
        userTitleKey: 'menu.myAssets',
        icon: Server,
      },
      { id: 'credentials', path: '/credentials', titleKey: 'menu.credentials', icon: KeySquare },
      { id: 'authorizations', path: '/authorizations', titleKey: 'menu.authorizations', icon: TicketCheck },
      { id: 'change-secret-plans', path: '/change-secret-plans', titleKey: 'menu.changeSecretPlans', icon: RotateCcwKey },
      { id: 'change-secret-batches', path: '/change-secret-batches', titleKey: 'menu.changeSecretBatches', icon: Layers },
    ],
  },
  {
    id: 'sessions',
    labelKey: 'menu.group.sessions',
    items: [
      // session 管理視圖收斂為稽核職能；一般 user 走自助「我的連線」
      { id: 'sessions', path: '/sessions', titleKey: 'menu.sessions', icon: MonitorPlay },
      { id: 'my-connections', path: '/my-connections', titleKey: 'menu.myConnections', icon: Cable },
      // 我的申請：申請人自助頁，與我的連線同屬一般 user 自助入口
      { id: 'my-requests', path: '/my-requests', titleKey: 'menu.myRequests', icon: ClipboardList },
      // 我的 agent：圖示與「我的 agent」頁的空白狀態同一個機器人，和我的申請的清單圖示區分
      { id: 'my-agents', path: '/my-agents', titleKey: 'menu.myAgents', icon: Bot },
    ],
  },
  {
    id: 'approval',
    labelKey: 'menu.group.approval',
    items: [
      // 審核中心。**不做 admin 兜底**——僅具 admin 者對審核端點一律 403，
      // 留著入口只會把他導向一個假空態頁面
      { id: 'approvals', path: '/approvals', titleKey: 'menu.approvals', icon: Stamp, badge: 'approvals' },
    ],
  },
  {
    id: 'audit',
    labelKey: 'menu.group.audit',
    items: [
      // 稽核調查工作台：置於審計群**首項**——調查是最高頻入口，
      // 其餘各頁承載的是審閱、簽核、監看等作業，工作台與它們並存而非取代
      { id: 'audit-workbench', path: '/audit/workbench', titleKey: 'menu.auditWorkbench', icon: TextSearch },
      // 任務聚合與工作台共用稽核權限
      { id: 'audit-agent-tasks', path: '/audit/agent-tasks', titleKey: 'agentTasks.title', icon: TextSearch },
      { id: 'rotation-evidence', path: '/rotation-evidence', titleKey: 'menu.rotationEvidence', icon: FileClock },
      // 下載中心：緊接工作台——證據包由工作台發起、在這裡取件
      { id: 'audit-exports', path: '/audit/exports', titleKey: 'menu.auditExports', icon: HardDriveDownload },
      // 每日簽核待簽天數徽章：只對具簽核權限者輪詢與顯示（MainLayout 判定）
      { id: 'audit-logs', path: '/audit-logs', titleKey: 'menu.auditLogs', icon: ScrollText, badge: 'dailyReviews' },
      { id: 'commands', path: '/commands', titleKey: 'menu.commands', icon: Terminal },
      { id: 'alerts', path: '/alerts', titleKey: 'menu.alerts', icon: BellRing },
      // 檢查點驗證：序列完整性證明，稽核職能
      { id: 'checkpoint-verification', path: '/checkpoint-verification', titleKey: 'menu.checkpointVerification', icon: ShieldCheck },
      // 存取複審：稽核職能歸審計區
      { id: 'access-reviews', path: '/access-reviews', titleKey: 'menu.accessReviews', icon: ListChecks },
      // 合規對照：設定對各政策組的判定結果，唯讀。放稽核區而非設定區——
      // 它回答的是「符不符」而不是「怎麼設」，讀者是稽核人員
      { id: 'compliance-map', path: '/compliance-map', titleKey: 'menu.complianceMap', icon: ClipboardCheck },
    ],
  },
  // 系統管理拆兩組：身分自成領域、政策開關收設定域
  {
    id: 'identity',
    labelKey: 'menu.group.identity',
    items: [
      { id: 'users', path: '/users', titleKey: 'menu.users', icon: User },
      // AI agent 主體自成一個入口：從側欄走到某個 agent 的鑰匙，原本要先進
      // 使用者管理、再拉類型下拉、再挑人。預篩後只剩「進來、按鑰匙」兩步
      { id: 'agent-principals', path: '/users?kind=agent', titleKey: 'menu.agentPrincipals', icon: Bot },
      { id: 'roles', path: '/roles', titleKey: 'menu.roles', icon: UserCog },
      { id: 'user-groups', path: '/user-groups', titleKey: 'menu.userGroups', icon: Users },
      { id: 'approver-scopes', path: '/approver-scopes', titleKey: 'menu.approverScopes', icon: UserCheck },
      // 身分來源：目錄與身分提供者合併為一項。兩者是同一件事的兩種接法，
      // 分成兩個選單項會逼設定者先判斷「我要接的算哪一種」才找得到頁
      { id: 'identity-sources', path: '/identity-sources', titleKey: 'menu.identitySources', icon: IdCard },
    ],
  },
  {
    id: 'settings',
    labelKey: 'menu.group.settings',
    items: [
      { id: 'security-policies', path: '/security-policies', titleKey: 'menu.securityPolicies', icon: Shield },
      // 政策組：條文與要求的維護面。緊接安全政策——
      // 設定值與它要對照的條文是同一件事的兩面
      { id: 'policy-groups', path: '/policy-groups', titleKey: 'menu.policyGroups', icon: Scale },
      { id: 'access-control', path: '/access-control', titleKey: 'menu.accessControl', icon: SlidersHorizontal },
      { id: 'key-management', path: '/key-management', titleKey: 'menu.keyManagement', icon: KeyRound },
      { id: 'transmission-inventory', path: '/transmission-inventory', titleKey: 'menu.transmissionInventory', icon: Waypoints },
      // 離機儲存：證據副本的落點設定與上傳佇列。
      // 緊接金鑰管理與傳輸清冊——三者同屬「證據放哪裡、怎麼過去、誰解得開」
      { id: 'offsite-storage', path: '/offsite-storage', titleKey: 'menu.offsiteStorage', icon: CloudUpload },
      // 通知通道：原在告警頁的頁籤，搬到設定域讓只有通道能力的人也能管理
      { id: 'notification-channels', path: '/notification-channels', titleKey: 'alerts.tabChannels', icon: Send },
    ],
  },
]
