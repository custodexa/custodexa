// 入口規則的單一來源。
//
// 原則：**入口依「這個人在這件事上有沒有事可做」顯示；選單看得到 ⇔ 直接輸入網址進得去**。
// 側欄（MainLayout）與路由守衛（router/index.js 的 createAuthGuard）都只從這裡取規則，
// 不各自宣告——兩邊各寫一份時，「管理者看不到我的申請、打網址卻進得去」
// 與「沒有 agent 的人看得到我的 agent、點進去是空的」這類分歧必然再出現。
//
// 規則形狀即 route meta 的形狀：
// - `roles`：與使用者角色有交集即放行；`approver` 例外，一律看後端現算的 `is_approver`
//   （群組審核方的 roles 不含 approver 卻有資格；僅具 admin 者沒有資格）。
// - `entry`：不以角色表達的述詞（見 ENTRY_PREDICATES）。
// - 兩者皆無＝登入即可。
// UI 可見性只是 UX；強制點一律在後端。

export const ENTRY_SELF_SERVICE = 'self-service'
export const ENTRY_AGENT_OWNER = 'agent-owner'

const SIGNED_IN = Object.freeze({})
const ADMIN = Object.freeze({ roles: Object.freeze(['admin']) })
const AUDIT = Object.freeze({ roles: Object.freeze(['admin', 'auditor']) })
const APPROVER = Object.freeze({ roles: Object.freeze(['approver']) })
// 我的連線、我的申請：不具 admin、也不具 auditor（多角色帳號不得誤入自助模式）
const SELF_SERVICE = Object.freeze({ entry: ENTRY_SELF_SERVICE })
// 我的 agent：負責至少一個 agent，或政策允許自行建立——**不看角色**
const AGENT_OWNER = Object.freeze({ entry: ENTRY_AGENT_OWNER })

// 以路徑（不含 query）為鍵。詳情頁沿用所屬列表頁的規則（見 router/index.js）
export const ENTRY_RULES = Object.freeze({
  '/dashboard': SIGNED_IN,
  '/workspace': SIGNED_IN,
  '/profile': SIGNED_IN,
  '/assets': SIGNED_IN,
  '/credentials': ADMIN,
  '/authorizations': ADMIN,
  '/change-secret-plans': ADMIN,
  '/change-secret-batches': ADMIN,
  '/sessions': AUDIT,
  '/my-connections': SELF_SERVICE,
  '/my-requests': SELF_SERVICE,
  '/my-agents': AGENT_OWNER,
  '/approvals': APPROVER,
  '/audit/workbench': AUDIT,
  '/audit/agent-tasks': AUDIT,
  '/rotation-evidence': AUDIT,
  '/audit/exports': AUDIT,
  '/audit-logs': AUDIT,
  '/commands': AUDIT,
  '/alerts': AUDIT,
  '/checkpoint-verification': AUDIT,
  '/access-reviews': AUDIT,
  '/compliance-map': AUDIT,
  '/users': ADMIN,
  '/roles': ADMIN,
  '/user-groups': ADMIN,
  '/approver-scopes': ADMIN,
  '/identity-sources': ADMIN,
  '/security-policies': ADMIN,
  '/policy-groups': ADMIN,
  '/access-control': ADMIN,
  '/key-management': ADMIN,
  '/transmission-inventory': ADMIN,
  '/offsite-storage': ADMIN,
})

/** entryRuleFor 取某路徑的規則；未登記回 undefined（呼叫端須 fail-closed） */
export function entryRuleFor(path) {
  const bare = String(path || '').split('?')[0]
  return Object.prototype.hasOwnProperty.call(ENTRY_RULES, bare) ? ENTRY_RULES[bare] : undefined
}

/**
 * entryMeta 產生 route meta 的規則片段（展開進 `meta`）。
 * 未登記的路徑直接丟錯：路由表寫錯路徑時在載入期就炸，而不是悄悄變成「登入即可」。
 */
export function entryMeta(path) {
  const rule = entryRuleFor(path)
  if (!rule) throw new Error(`entry rule not registered: ${path}`)
  const meta = {}
  if (rule.roles) meta.roles = [...rule.roles]
  if (rule.entry) meta.entry = rule.entry
  return meta
}

/** hasEntryRule meta 是否帶任何入口限制（無限制＝登入即可） */
export function hasEntryRule(meta) {
  return Boolean(meta && (meta.roles || meta.entry))
}

/**
 * entrySubject 由使用者快取（登入回應／`GET /auth/me` 的 UserInfo）正規化出判斷所需的欄位。
 * 缺欄一律視為 false：舊快取（升級前登入）沒有 agent 兩欄時不給入口，
 * 側欄掛載後以 /auth/me 回寫即更新。
 */
export function entrySubject(user) {
  const roles = Array.isArray(user?.roles)
    ? user.roles.map((role) => (typeof role === 'object' ? role?.name : role)).filter(Boolean)
    : []
  return {
    roles,
    isApprover: user?.is_approver === true,
    ownsAgents: user?.owns_agents === true,
    canSelfCreateAgent: user?.can_self_create_agent === true,
  }
}

const ENTRY_PREDICATES = Object.freeze({
  [ENTRY_SELF_SERVICE]: (s) => !s.roles.includes('admin') && !s.roles.includes('auditor'),
  [ENTRY_AGENT_OWNER]: (s) => s.ownsAgents || s.canSelfCreateAgent,
})

/**
 * canEnter 給定規則（route meta 或 ENTRY_RULES 的一筆）與身分，回答「進不進得去」。
 * 側欄的「看不看得到」與路由守衛的「放不放行」都呼叫這一個函式。
 */
export function canEnter(rule, subject) {
  if (rule?.roles) {
    const staticRoles = rule.roles.filter((role) => role !== 'approver')
    const allowed =
      staticRoles.some((role) => subject.roles.includes(role)) ||
      (rule.roles.includes('approver') && subject.isApprover)
    if (!allowed) return false
  }
  if (rule?.entry) {
    const predicate = ENTRY_PREDICATES[rule.entry]
    // 未知述詞 fail-closed：拼錯字不能變成對所有人開放
    if (!predicate || !predicate(subject)) return false
  }
  return true
}
