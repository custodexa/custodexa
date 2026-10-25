/**
 * 審核範圍總覽的精簡資料路徑（非超級管理者）：列表回應帶 `coverage` 時，
 * 頁面只用列表與兩個選擇端點（approver-options、target-options），不讀使用者、群組、
 * 節點與安全政策列表。節點樹由 target-options(kind=node) 的 path 建出：
 * selectable 為假者是定位祖先，只顯示路徑、不給新增或移除。
 */

const PATH_SEPARATOR = ' / '

/** 列表回應是否走精簡路徑（伺服器只對非超級管理者帶 coverage） */
export const isScopedListResponse = (res) => Array.isArray(res?.coverage)

/** 節點 id → 全路徑（取伺服器回傳的 path，缺漏時退回名稱） */
export const nodePathMap = (nodeOptions) => {
  const out = {}
  for (const n of nodeOptions || []) {
    out[n.id] = n.path || n.name
  }
  return out
}

/** approver-options 的使用者轉成頁面列使用的形狀（顯示名稱與帳號相同時不重複顯示） */
export const scopedUsers = (users) =>
  (users || []).map((u) => ({
    id: u.id,
    username: u.username,
    full_name: u.display_name && u.display_name !== u.username ? u.display_name : '',
    is_approver: u.is_approver === true,
    selectable: u.selectable === true,
  }))

/**
 * 以節點候選建樹列。
 * - 父節點以 path 去掉最後一段對回；對不到者成為根列
 * - 可審人數取 coverage；定位祖先沒有 coverage，poolCount 為 null
 */
export const scopedNodeRows = (nodeOptions, scopes, coverage) => {
  const options = nodeOptions || []
  const byPath = new Map(options.map((n) => [n.path || n.name, n]))
  const poolByNode = new Map((coverage || []).map((c) => [c.node_id, c.approver_count]))
  const scopesByNode = new Map()
  for (const s of scopes || []) {
    if (!s.asset_group_id) continue
    const list = scopesByNode.get(s.asset_group_id) || []
    list.push(s)
    scopesByNode.set(s.asset_group_id, list)
  }
  const parentPath = (n) => {
    const parts = (n.path || n.name).split(PATH_SEPARATOR)
    return parts.length > 1 ? parts.slice(0, -1).join(PATH_SEPARATOR) : null
  }
  const childrenOf = new Map()
  const roots = []
  for (const n of options) {
    const pp = parentPath(n)
    if (pp !== null && byPath.has(pp)) {
      const list = childrenOf.get(pp) || []
      list.push(n)
      childrenOf.set(pp, list)
    } else {
      roots.push(n)
    }
  }
  const build = (n, depth) => {
    const locator = n.selectable === false
    return {
      key: `node-${n.id}`,
      id: n.id,
      name: n.name,
      locator,
      scopes: locator ? [] : scopesByNode.get(n.id) || [],
      poolCount: poolByNode.has(n.id) ? poolByNode.get(n.id) : null,
      poolNames: [],
      children: depth < 64 ? (childrenOf.get(n.path || n.name) || []).map((c) => build(c, depth + 1)) : [],
    }
  }
  return roots.map((n) => build(n, 0))
}
