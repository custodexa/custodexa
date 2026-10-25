import { computed, ref, watch } from 'vue'

/**
 * 側欄的分組收合與常用釘選。
 *
 * 只改呈現：不增加入口、不改變任何入口資格。每個項目先經 `canSee`（＝入口規則的 `canEnter`）
 * 過濾，再移除空組；失去資格的釘選過濾掉，**收藏不是許可**。
 * 偏好（收合的組、釘選的項目）只存在同源 localStorage，鍵含使用者 ID 與格式版本，
 * 不跨帳號、不上傳；壞資料一律回預設。
 */

export const SIDEBAR_PREFS_VERSION = 1
export const prefsStorageKey = (userId) => `ot-sidebar-prefs:v${SIDEBAR_PREFS_VERSION}:${userId}`

const emptyPrefs = () => ({ collapsed: [], pinned: [] })

const isIdList = (value) =>
  Array.isArray(value) && value.every((id) => typeof id === 'string' && id !== '')

/** 讀偏好；任何一步不合格式（含版本不符）都回預設，不丟錯。 */
export function readSidebarPrefs(userId, storage = globalThis.localStorage) {
  if (userId === null || userId === undefined || userId === '') return emptyPrefs()
  try {
    const parsed = JSON.parse(storage.getItem(prefsStorageKey(userId)) || 'null')
    if (!parsed || parsed.v !== SIDEBAR_PREFS_VERSION) return emptyPrefs()
    if (!isIdList(parsed.collapsed) || !isIdList(parsed.pinned)) return emptyPrefs()
    return { collapsed: [...new Set(parsed.collapsed)], pinned: [...new Set(parsed.pinned)] }
  } catch {
    return emptyPrefs()
  }
}

export function writeSidebarPrefs(userId, prefs, storage = globalThis.localStorage) {
  if (userId === null || userId === undefined || userId === '') return false
  try {
    storage.setItem(
      prefsStorageKey(userId),
      JSON.stringify({ v: SIDEBAR_PREFS_VERSION, collapsed: prefs.collapsed, pinned: prefs.pinned })
    )
    return true
  } catch {
    return false // 儲存被封鎖：偏好只在本次頁面存活，不影響導覽
  }
}

/**
 * 由選單宣告、入口判斷與偏好算出側欄模型。
 * - `flat`：過濾後（釘選移出之前）只剩一個來源組時為真——不顯示組標題與收合控制；
 * - `pinned`：依釘選順序、僅含目前可進入的項目；原組省略同一項目，避免重複；
 * - 若某組項目全被釘選移走，該組不再出現。
 */
export function buildSidebarModel(menuGroups, canSee, prefs) {
  const visible = menuGroups
    .map((group) => ({ ...group, items: group.items.filter((item) => canSee(item)) }))
    .filter((group) => group.items.length > 0)
  const flat = visible.length <= 1
  const byId = new Map()
  for (const group of visible) for (const item of group.items) byId.set(item.id, item)
  const pinned = prefs.pinned.filter((id) => byId.has(id)).map((id) => byId.get(id))
  const pinnedIds = new Set(pinned.map((item) => item.id))
  const collapsed = new Set(prefs.collapsed)
  const groups = visible
    .map((group) => ({
      ...group,
      collapsed: !flat && collapsed.has(group.id),
      items: group.items.filter((item) => !pinnedIds.has(item.id)),
    }))
    .filter((group) => group.items.length > 0)
  return { flat, pinned, groups }
}

/** 偏好的反應式持有者；`userId` 變動（登入、換帳號）時重讀。 */
export function useSidebarPrefs(userIdRef) {
  const prefs = ref(emptyPrefs())
  watch(
    userIdRef,
    (id) => {
      prefs.value = readSidebarPrefs(id)
    },
    { immediate: true }
  )
  const commit = (next) => {
    prefs.value = next
    writeSidebarPrefs(userIdRef.value, next)
  }
  const toggleGroup = (groupId) => {
    const set = new Set(prefs.value.collapsed)
    if (set.has(groupId)) set.delete(groupId)
    else set.add(groupId)
    commit({ ...prefs.value, collapsed: [...set] })
  }
  const expandGroup = (groupId) => {
    if (!prefs.value.collapsed.includes(groupId)) return
    commit({ ...prefs.value, collapsed: prefs.value.collapsed.filter((id) => id !== groupId) })
  }
  const togglePin = (itemId) => {
    const pinned = prefs.value.pinned.includes(itemId)
      ? prefs.value.pinned.filter((id) => id !== itemId)
      : [...prefs.value.pinned, itemId]
    commit({ ...prefs.value, pinned })
  }
  return { prefs, toggleGroup, expandGroup, togglePin, pinnedSet: computed(() => new Set(prefs.value.pinned)) }
}
