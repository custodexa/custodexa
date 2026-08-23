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

export function useRoles() {
  const roles = ref([])
  const currentUserId = ref(null)
  try {
    const user = localStorage.getItem('user')
    if (user) {
      const parsed = JSON.parse(user)
      roles.value = parsed.roles || []
      currentUserId.value = parsed.id ?? null
    }
  } catch {
    roles.value = []
  }

  const isAdmin = ref(roles.value.includes('admin'))
  const isAuditor = ref(roles.value.includes('auditor'))
  const isApprover = ref(roles.value.includes('approver'))
  const isPrivileged = ref(isAdmin.value || isAuditor.value)

  return { roles, currentUserId, isAdmin, isAuditor, isApprover, isPrivileged }
}
