import { ref } from 'vue'

/**
 * 角色判定唯一入口：
 * 口徑與後端有效角色優先序一致（admin > auditor > user）；
 * 「一般 user」以「不具 admin/auditor」認定，不用 roles.includes('user')——
 * 多角色帳號不得誤入自助模式。
 * approver 為疊加角色獨立判定。UI 可見性僅為 UX，強制點一律在後端
 * （後端 approver 資格即時查 DB；本處讀登入快取，撤角色後重登才反映——顯示層容忍延遲）。
 */

/**
 * roleNames 角色清單正規化（自 Users.vue
 * hasApproverRole 收斂）：相容物件陣列（後端列表 API 的 roles）與字串陣列
 * （localStorage 登入快取）兩形，勿在頁面另寫同款判定
 */
export function roleNames(list) {
  return (list || [])
    .map((r) => (typeof r === 'object' ? r?.name : r))
    .filter(Boolean)
}

/** hasRole 指定角色判定（物件/字串兩形相容） */
export function hasRole(list, name) {
  return roleNames(list).includes(name)
}

/**
 * effectiveApproverFrom 由快取的使用者物件算「有效審核資格」，與審核端點守衛
 * （RequireApproverRole → evaluateEffectiveApprover）同一述詞：具 approver 角色
 * OR 屬任一審核方群組。群組那一支只有後端算得出來，經登入回應與 /auth/me 寫入
 * 快取的 is_approver。**admin 不在述詞內**——審核端點不認 admin 兜底。
 *
 * 三態而非 OR：`is_approver` 存在時它就是權威值，缺欄時才退回角色判定。
 * 寫成 `is_approver === true || roles.includes('approver')` 會在
 * 「/auth/me 已回寫 is_approver:false、roles 快取仍留著撤銷前的 approver」時判成真
 * ——那正是 persistApproverFlag 的寫法造成的狀態（它只改 is_approver、不動 roles）。
 */
export function effectiveApproverFrom(parsed) {
  if (!parsed) return false
  if (parsed.is_approver !== undefined && parsed.is_approver !== null) {
    return parsed.is_approver === true
  }
  return roleNames(parsed.roles).includes('approver')
}

/**
 * readEffectiveApprover 由 localStorage 現算有效審核資格。
 * 供需要「掛載後仍跟著 /auth/me 結果變動」的呼叫端（見 ot-user-updated 事件）；
 * useRoles 回傳的 ref 是建立當下的快照，不會自己更新。
 */
export function readEffectiveApprover() {
  try {
    const user = localStorage.getItem('user')
    return user ? effectiveApproverFrom(JSON.parse(user)) : false
  } catch {
    return false
  }
}

export function useRoles() {
  const roles = ref([])
  const currentUserId = ref(null)
  let effectiveApprover = false
  try {
    const user = localStorage.getItem('user')
    if (user) {
      const parsed = JSON.parse(user)
      roles.value = parsed.roles || []
      currentUserId.value = parsed.id ?? null
      effectiveApprover = effectiveApproverFrom(parsed)
    }
  } catch {
    roles.value = []
  }

  const isAdmin = ref(roles.value.includes('admin'))
  const isAuditor = ref(roles.value.includes('auditor'))
  const isApprover = ref(roles.value.includes('approver'))
  const isPrivileged = ref(isAdmin.value || isAuditor.value)
  // 述詞見 effectiveApproverFrom。與 isApprover 的分工：isApprover 只看角色，
  // 供確實要區分「角色 vs 資格」的呼叫端；凡是決定「要不要呼叫僅審核者可用的端點、
  // 要不要顯示審核入口或卡片」，一律用本旗標。
  // 本 ref 是建立當下的快照；要跟著 /auth/me 變動的呼叫端另接 ot-user-updated 事件
  // 並以 readEffectiveApprover() 現算。
  const isEffectiveApprover = ref(effectiveApprover)

  return {
    roles,
    currentUserId,
    isAdmin,
    isAuditor,
    isApprover,
    isEffectiveApprover,
    isPrivileged,
  }
}
