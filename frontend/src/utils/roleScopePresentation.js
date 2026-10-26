// 角色與管理範圍的共用呈現工具：映射頁目標欄與選單、使用者群組列表、群組與帳號的
// 「角色與範圍」分頁共用，避免各處各寫一套而口徑漂移。
//
// 只做呈現，不做授權判斷：
// - 角色能否限定節點、範圍會不會生效，一律取自伺服器欄位（角色列表的 scopable、
//   node_range_no_effect、builtin_key，以及指派選項的 node_range_no_effect_reasons），
//   不依角色名稱、權限集合推算。
// - 一筆指派的範圍種類取自讀取結果：群組讀取看 scope，帳號讀取看 node_ids 鍵是否存在；
//   空範圍與全數失效的範圍都是節點範圍，絕不讀成全系統。
import { t } from '@/i18n'

// —— (a) 角色的範圍分類 ——
export const SCOPE_CLASS = Object.freeze({
  EFFECTIVE: 'effective', // 可限定節點，範圍會生效
  BUILTIN_GLOBAL_ONLY: 'builtin_global_only', // 內建、只在全系統生效
  NO_SCOPED_PERMISSION: 'no_scoped_permission', // 權限不受節點限制
  NOT_SCOPABLE: 'not_scopable', // 不能限定節點
  UNKNOWN: 'unknown', // 角色列表未載入
})

/**
 * @param {object|null|undefined} def 角色列表的一列（scopable、node_range_no_effect、builtin_key）
 * @param {string} [reason] 指派選項 node_range_no_effect_reasons 對該角色的原因（能指派角色者才有）
 */
export function classifyRole(def, reason) {
  if (!def || typeof def.scopable !== 'boolean') return SCOPE_CLASS.UNKNOWN
  if (def.scopable === false) return SCOPE_CLASS.NOT_SCOPABLE
  if (def.node_range_no_effect !== true) return SCOPE_CLASS.EFFECTIVE
  if (reason === SCOPE_CLASS.BUILTIN_GLOBAL_ONLY) return SCOPE_CLASS.BUILTIN_GLOBAL_ONLY
  if (reason === SCOPE_CLASS.NO_SCOPED_PERMISSION) return SCOPE_CLASS.NO_SCOPED_PERMISSION
  // 沒有原因（不能指派角色者不讀指派選項）：伺服器先判內建，再判有無範圍過濾權限點，
  // 所以「不會生效且為內建」必為前者
  return def.builtin_key ? SCOPE_CLASS.BUILTIN_GLOBAL_ONLY : SCOPE_CLASS.NO_SCOPED_PERMISSION
}

// 範圍不會生效的兩類（以全系統持有時管理範圍欄的寫法不同於「會生效」）
export const isNoEffectClass = (cls) =>
  cls === SCOPE_CLASS.BUILTIN_GLOBAL_ONLY || cls === SCOPE_CLASS.NO_SCOPED_PERMISSION

// —— (b) 指派的管理範圍摘要 ——
// 正規化形狀：{ roleId, mode: 'all' | 'nodes', nodeIds: number[] }

/** 群組讀取：以 scope 判節點範圍；節點範圍列即使缺 node_ids 也是 0 個節點的節點範圍 */
export function fromGroupBinding(binding) {
  const b = binding || {}
  if (b.scope === 'nodes') {
    return { roleId: b.role_id, mode: 'nodes', nodeIds: Array.isArray(b.node_ids) ? [...b.node_ids] : [] }
  }
  return { roleId: b.role_id, mode: 'all', nodeIds: [] }
}

/** 帳號讀取：不帶 scope，以 node_ids 鍵是否存在判節點範圍（空陣列仍是節點範圍） */
export function fromUserBinding(binding) {
  const b = binding || {}
  if (Object.prototype.hasOwnProperty.call(b, 'node_ids')) {
    return { roleId: b.role_id, mode: 'nodes', nodeIds: Array.isArray(b.node_ids) ? [...b.node_ids] : [] }
  }
  return { roleId: b.role_id, mode: 'all', nodeIds: [] }
}

const PATH_LIMIT = 3

/**
 * 管理範圍摘要。
 * @param {{roleId:number, mode:'all'|'nodes', nodeIds:number[]}} norm 正規化後的指派
 * @param {{nodes?: Array<{id:number,path?:string,name?:string}>|null, canReadPaths?: boolean}} [ctx]
 *   nodes 為指派用節點清單（只列存活節點）；canReadPaths 為假（不能指派角色）或 nodes 為 null
 *   （讀取失敗）時只呈現節點數。
 * @returns {{mode:'all'|'nodes', text:string, items:string[], more:number, total:number, pathsKnown:boolean, missing:number}}
 */
export function summarizeScope(norm, ctx = {}) {
  const n = norm || { mode: 'all', nodeIds: [] }
  if (n.mode !== 'nodes') {
    return { mode: 'all', text: t('roleNodePicker.modeAll'), items: [], more: 0, total: 0, pathsKnown: true, missing: 0 }
  }
  const ids = n.nodeIds || []
  const total = ids.length
  const nodes = ctx.nodes
  const pathsKnown = ctx.canReadPaths !== false && Array.isArray(nodes)
  if (!pathsKnown) {
    return {
      mode: 'nodes',
      text: t('roleNodePicker.nodeCountOnly', { n: total }),
      items: [],
      more: 0,
      total,
      pathsKnown: false,
      missing: 0,
    }
  }
  if (total === 0) {
    return {
      mode: 'nodes',
      text: t('roleNodePicker.nodeCountOnly', { n: 0 }),
      items: [],
      more: 0,
      total: 0,
      pathsKnown: true,
      missing: 0,
    }
  }
  const byId = new Map(nodes.map((x) => [x.id, x]))
  const label = (id) => {
    const node = byId.get(id)
    return node ? node.path || node.name || '' : t('roleNodePicker.nodeMissing')
  }
  const shown = ids.slice(0, PATH_LIMIT).map(label)
  const more = Math.max(0, total - PATH_LIMIT)
  const missing = ids.filter((id) => !byId.has(id)).length
  let text = shown.join('、')
  if (more > 0) text += ` ${t('identityGroupMappings.targetScopeMore', { n: more })}`
  return { mode: 'nodes', text, items: shown, more, total, pathsKnown: true, missing }
}

/**
 * 一個角色在目標欄、列表欄、選單上的一段呈現：
 * - 會生效的角色一律寫管理範圍（含全系統）；
 * - 其他角色以全系統持有時只列名稱；
 * - 任何角色以節點範圍持有時一律寫出其節點，不呈現為全系統。
 * @returns {{showScope:boolean, scope:object}}  showScope 為假時呼叫端只列名稱
 */
export function describeAssignment(norm, def, reason, ctx) {
  const cls = classifyRole(def, reason)
  const scope = summarizeScope(norm, ctx)
  if (norm && norm.mode === 'nodes') return { cls, showScope: true, scope }
  return { cls, showScope: cls === SCOPE_CLASS.EFFECTIVE, scope }
}

/** 「{角色}・管理範圍 {範圍}」或只有角色名稱 */
export function roleScopeLine(roleName, described) {
  if (!described.showScope) return roleName
  return t('identityGroupMappings.targetRoleScope', { role: roleName, scope: described.scope.text })
}

// —— (c) 分配角色選單的內建／自訂分組 ——
/**
 * @param {Array} list 角色列表（保留伺服器順序）
 * @param {(item:any)=>string|null|undefined} [builtinKeyOf] 預設讀 item.builtin_key
 * @returns {{builtin:Array, custom:Array}}
 */
export function splitBuiltinCustom(list, builtinKeyOf = (x) => x?.builtin_key) {
  const builtin = []
  const custom = []
  for (const item of list || []) {
    if (builtinKeyOf(item)) builtin.push(item)
    else custom.push(item)
  }
  return { builtin, custom }
}

/**
 * 分配角色選單的篩選：與選單的預設篩選同口徑（不分大小寫、比對顯示名稱），
 * 但改在資料層做，讓兩組組標的數字隨篩選結果更新。
 * @param {Array} list
 * @param {string} query
 * @param {(item:any)=>string} labelOf
 */
export function filterByQuery(list, query, labelOf) {
  const q = String(query || '').trim().toLowerCase()
  if (!q) return list || []
  return (list || []).filter((x) => String(labelOf(x) || '').toLowerCase().includes(q))
}
