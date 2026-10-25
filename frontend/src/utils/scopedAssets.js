// 範圍化資產頁的純函式。
//
// 伺服器對「範圍化檢視者」的資產回應多出三組欄位：列級旗標 actions、
// 範圍外歸屬計數 out_of_scope_node_count、列表頂層的 management_scope。
// 這裡只消費這些欄位，不以節點樹或權限集合重算可操作與否；強制點一律在後端。

export const ACTION_KEYS = ['edit', 'disable', 'delete', 'test_connection', 'manage_accounts']

/** 該列是否帶伺服器旗標（帶旗標的列不回退全域能力判斷）。 */
export function hasActions(row) {
  return !!row && typeof row.actions === 'object' && row.actions !== null
}

/**
 * 某個操作是否可做。帶旗標的列只看旗標（缺鍵視為不可）；
 * 不帶旗標的列沿用呼叫端給的全域判斷。
 */
export function actionAllowed(row, key, globalAllowed) {
  if (!hasActions(row)) return !!globalAllowed
  return row.actions[key]?.allowed === true
}

/** 旗標的原因碼與計數；不帶旗標或允許時回 null。 */
export function actionDenial(row, key) {
  if (!hasActions(row)) return null
  const a = row.actions[key]
  if (a?.allowed === true) return null
  return { reason: a?.reason || 'no_capability', count: Number(a?.count) || 0 }
}

const REASON_KEYS = {
  out_of_scope_nodes: 'assets.scopedReasonOutOfScopeNodes',
  out_of_scope: 'assets.scopedReasonOutOfScope',
  no_capability: 'assets.scopedReasonNoCapability',
}

/** 原因碼轉成當前語言的就地說明；未知碼一律落到「沒有權限」。 */
export function denialText(t, denial) {
  if (!denial) return ''
  const key = REASON_KEYS[denial.reason] || REASON_KEYS.no_capability
  return t(key, { n: denial.count })
}

/** 列上的範圍外歸屬數（只在範圍化回應出現）。 */
export function outOfScopeCount(row) {
  const n = Number(row?.out_of_scope_node_count)
  return Number.isFinite(n) && n > 0 ? n : 0
}

/** 連線入口是否存在：只經管理可視的列沒有連線欄，也就沒有連線入口。 */
export function isManagedOnly(row) {
  return hasActions(row) && !row.permission && !row.access_state
}

/**
 * 管理範圍頁面狀態（依 management_scope 與列表 total）：
 * none＝非範圍化檢視者；empty＝無有效節點且無資產；
 * connection_only＝無有效節點但仍有連線授權資產；normal＝其餘。
 */
export function scopeState(scope, total) {
  if (!scope || typeof scope !== 'object') return 'none'
  if (Number(scope.effective_node_count) === 0) {
    return Number(total) > 0 ? 'connection_only' : 'empty'
  }
  return 'normal'
}

export function inactiveNodeCount(scope) {
  const n = Number(scope?.inactive_node_count)
  return Number.isFinite(n) && n > 0 ? n : 0
}

/**
 * 以用途清單（getAssetGroups 的 data）組出掛載節點選項樹。
 * selectable=false 的節點只作定位或鎖定，disabled；
 * extraIds 是目前已選、但清單裡沒有的節點，補成 disabled 的葉子，避免標籤顯示成裸數字。
 */
export function buildNodeOptions(flat, { extra = [] } = {}) {
  const byId = new Map()
  for (const n of flat || []) {
    byId.set(n.id, {
      id: n.id,
      name: n.path || n.name,
      parent_id: n.parent_id,
      disabled: n.selectable === false,
      children: [],
    })
  }
  for (const e of extra) {
    if (!byId.has(e.id)) {
      byId.set(e.id, { id: e.id, name: e.name, parent_id: null, disabled: true, children: [] })
    }
  }
  const roots = []
  byId.forEach((n) => {
    if (n.parent_id && byId.has(n.parent_id)) byId.get(n.parent_id).children.push(n)
    else roots.push(n)
  })
  return roots
}

/** 選項樹中可選（未 disabled）節點的識別碼集合。 */
export function selectableIdSet(options) {
  const out = new Set()
  const walk = (list) => {
    for (const n of list) {
      if (!n.disabled) out.add(n.id)
      walk(n.children || [])
    }
  }
  walk(options)
  return out
}

const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x))

/**
 * 範圍化編輯送出的 node_ids：沒動節點欄回 undefined（本文不帶此鍵）；
 * 動過只送「已選且可選」者，鎖定項與範圍外歸屬由伺服器依合併語義保留。
 */
export function scopedUpdateNodeIds(selected, original, selectable) {
  if (sameSet(selected, original)) return undefined
  return selected.filter((id) => selectable.has(id))
}

/** 範圍化新增送出的 node_ids：全取自可選候選。 */
export function scopedCreateNodeIds(selected, selectable) {
  return selected.filter((id) => selectable.has(id))
}
