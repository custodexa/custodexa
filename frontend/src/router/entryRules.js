// 入口規則的單一來源。
//
// 原則：**入口依「這個人在這件事上有沒有事可做」顯示；選單看得到 ⇔ 直接輸入網址進得去**。
// 側欄（MainLayout）與路由守衛（router/index.js 的 createAuthGuard）都只從這裡取規則，
// 不各自宣告——兩邊各寫一份時，「管理者看不到我的申請、打網址卻進得去」
// 與「沒有 agent 的人看得到我的 agent、點進去是空的」這類分歧必然再出現。
//
// 規則形狀即 route meta 的形狀：
// - `signedIn: true`：登入即可，不看任何能力。
// - `permissionsAll: [...]`：目前使用者持有清單內**每一個**權限點才放行。權限點取自後端
//   `/auth/me` 的 `permissions`（伺服器逐請求解析），含 `ui:` 呈現點（審核資格、agent 入口）；
//   完整鍵比對，不看角色名稱、不做前綴或萬用比對。
// - `permissionsAny: [...]`：持有清單內**任一**權限點即放行。只給「頁內分頁或動作各有各自能力」的入口用
//   （例如告警頁：記錄、通知通道、系統告警目錄；憑證庫：各語義管理能力）；頁內仍各自判定，API 授權不變。
// - 三者皆無、或任兩者並存、或清單為空＝未知規則，一律拒絕（fail-closed）。
// UI 可見性只是 UX；強制點一律在後端。

import { canAll } from '@/composables/useCapabilities'

const SIGNED_IN = Object.freeze({ signedIn: true })
const needs = (...perms) => Object.freeze({ permissionsAll: Object.freeze(perms) })
const needsAny = (...perms) => Object.freeze({ permissionsAny: Object.freeze(perms) })

// 以路徑（不含 query）為鍵。詳情頁沿用所屬列表頁的規則（見 router/index.js）。
// 每列的鍵對應該入口在後端的裁決來源。
export const ENTRY_RULES = Object.freeze({
  '/dashboard': SIGNED_IN,
  '/workspace': SIGNED_IN,
  '/profile': SIGNED_IN,
  '/assets': SIGNED_IN,
  // 我的連線、我的申請：所有已登入者可進。不新增申請資格或連線權，
  // 送件／連線的資格仍由後端與頁內既有說明決定
  '/my-connections': SIGNED_IN,
  '/my-requests': SIGNED_IN,
  '/my-agents': needs('ui:my-agents'),
  '/approvals': needs('ui:approvals'),
  '/sessions': needs('session:view'),
  '/audit/workbench': needs('audit:view'),
  '/audit/agent-tasks': needs('audit:view'),
  '/rotation-evidence': needs('audit:view'),
  '/audit/exports': needs('audit:view'),
  '/audit-logs': needs('audit:view'),
  '/commands': needs('audit:view'),
  // 頁內分頁各有能力：告警記錄 audit:view、告警規則 alertrule:manage、系統告警目錄 systemalert:manage；通知通道已移到獨立頁
  '/alerts': needsAny('audit:view', 'alertrule:manage', 'systemalert:manage'),
  '/checkpoint-verification': needs('audit:integrity_view'),
  '/access-reviews': needs('audit:view'),
  '/compliance-map': needs('compliance:view'),
  // 憑證庫：持任一憑證語義能力（含只讀的檢視）即可進；頁內動作逐項依能力呈現，寫入由伺服器逐項裁決
  '/credentials': needsAny(
    'credential:view', 'credential:create', 'credential:update', 'credential:set-secret',
    'credential:rotate', 'credential:convert-scope', 'credential:detach', 'credential:delete',
    'credential:bind', 'credential:manage',
  ),
  '/authorizations': needs('authorization:manage'),
  '/change-secret-plans': needs('changesecret:manage'),
  '/change-secret-batches': needs('changesecret:manage'),
  '/users': needs('user:manage'),
  '/roles': needs('role:view'),
  '/user-groups': needs('usergroup:manage'),
  '/approver-scopes': needs('approverscope:manage'),
  '/identity-sources': needs('identity_source:manage'),
  '/security-policies': needs('securitypolicy:manage'),
  '/policy-groups': needs('policygroup:manage'),
  '/access-control': needs('securitypolicy:manage'),
  '/key-management': needs('key:manage'),
  '/transmission-inventory': needs('transmission:manage'),
  '/offsite-storage': needs('offsite:manage'),
  // 通知通道：系統設定下的獨立頁，只看通道管理能力，不另要求告警檢視
  '/notification-channels': needs('notification_channel:manage'),
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
  if (rule.signedIn) return { signedIn: true }
  if (rule.permissionsAny) return { permissionsAny: [...rule.permissionsAny] }
  return { permissionsAll: [...rule.permissionsAll] }
}

/** hasEntryRule meta 是否帶入口規則（兩種形狀之一；沒有＝非受入口規則管轄的路由） */
export function hasEntryRule(meta) {
  return Boolean(meta && (meta.signedIn || meta.permissionsAll || meta.permissionsAny))
}

/** needsCapabilities 規則是否需要先取得能力投影才能裁決（登入即可的入口不必等） */
export function needsCapabilities(rule) {
  return Boolean(rule && !rule.signedIn && (Array.isArray(rule.permissionsAll) || Array.isArray(rule.permissionsAny)))
}

/**
 * canEnter 給定規則（route meta 或 ENTRY_RULES 的一筆），回答「進不進得去」。
 * 側欄的「看不看得到」與路由守衛的「放不放行」都呼叫這一個函式。
 * `has` 預設為目前使用者能力的 `canAll`；測試可注入。
 */
export function canEnter(rule, has = canAll) {
  if (!rule || typeof rule !== 'object') return false
  const signedIn = rule.signedIn === true
  const all = rule.permissionsAll
  const any = rule.permissionsAny
  // 規則形狀不明（三者皆無、任兩者並存、清單為空或含非字串）：拼錯字不能變成對所有人開放
  const shapes = [signedIn, Array.isArray(all), Array.isArray(any)].filter(Boolean).length
  if (shapes !== 1) return false
  if (signedIn) return true
  const perms = Array.isArray(all) ? all : any
  if (perms.length === 0 || !perms.every((p) => typeof p === 'string' && p !== '')) return false
  return Array.isArray(all) ? has(perms) === true : perms.some((p) => has([p]) === true)
}
