import { ref } from 'vue'

/**
 * 角色**資料**與本人識別的取用點。
 *
 * 這裡不做授權判斷：操作者能不能做某件事，一律看後端 `/auth/me` 的 `permissions`
 * （`composables/useCapabilities.js` 的 `can(perm)`）。角色名稱只留在資料語義上——
 * 顯示某個帳號掛了哪些角色、指派角色的 payload、候選審核者的篩選，這些是在處理**另一位**
 * 使用者的資料，不能拿目前操作者的能力去判別。
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

/** hasRole 指定角色判定（物件/字串兩形相容）。僅用於列表列等「他人資料」的角色標籤。 */
export function hasRole(list, name) {
  return roleNames(list).includes(name)
}

/**
 * useRoles 目前使用者的角色顯示資料與本人 ID（讀登入快取，只供顯示與「是不是我自己」的比對）。
 * 不提供任何授權旗標。
 */
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
  return { roles, currentUserId }
}
