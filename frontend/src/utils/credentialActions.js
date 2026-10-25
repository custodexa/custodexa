// 憑證與帳號列的動作旗標讀取。
//
// 旗標由伺服器對範圍化檢視者標示：`actions[key] = { allowed, reason? }`，原因碼是受控值
// `no_capability`／`out_of_scope`。沒有 `actions` 鍵（全域主體、未判定）或該動作沒有旗標時，
// 一律視為可操作，由寫入端點自行裁決——旗標只決定畫面，不是授權依據。

const KNOWN_REASONS = ['no_capability', 'out_of_scope']

/**
 * 動作被伺服器標為不可操作時回原因碼，否則回空字串。
 * 原因碼不在受控值內時退回 `no_capability`，免得畫面出現機器碼。
 */
export function deniedReason(entity, key) {
  const flag = entity?.actions?.[key]
  if (!flag || flag.allowed !== false) return ''
  return KNOWN_REASONS.includes(flag.reason) ? flag.reason : 'no_capability'
}

/** 是否為範圍化檢視者的資料列（伺服器只對範圍化檢視者附 `actions`）。 */
export function hasActionFlags(entity) {
  return !!entity?.actions && typeof entity.actions === 'object'
}

/** 伺服器回報的範圍外台數；沒有該欄（非範圍化檢視者）或非正整數時為 0。 */
export function outOfScopeCount(entity) {
  const n = entity?.out_of_scope_asset_count
  return Number.isInteger(n) && n > 0 ? n : 0
}
