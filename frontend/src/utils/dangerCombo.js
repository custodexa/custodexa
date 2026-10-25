/**
 * 影響預覽回應的判讀：組合、是否通知、求值範圍都只來自伺服器回應。
 * 這裡不接收角色或權限清單，也不自行推算組合。
 */

const arr = (v) => (Array.isArray(v) ? v : [])

/** 預覽中所有主體的新命中組合：[{ code, count }]，依首次出現順序 */
export function collectNewCombos(preview) {
  const counts = new Map()
  for (const s of arr(preview?.subjects)) {
    for (const code of new Set(arr(s?.new_combos))) {
      counts.set(code, (counts.get(code) || 0) + 1)
    }
  }
  return [...counts.entries()].map(([code, count]) => ({ code, count }))
}

export const operationMarks = (preview) => arr(preview?.operation?.marks)

/** 是否需要在儲存前開確認框：有新組合，或 operation.marks 非空（即使 total 為 0 或沒有主體） */
export function needsDangerConfirm(preview) {
  if (!preview) return false
  return collectNewCombos(preview).length > 0 || operationMarks(preview).length > 0
}

/** 只求值了部分主體 */
export function isPartiallyEvaluated(preview) {
  const evaluated = preview?.operation?.evaluated
  const total = preview?.total
  return Number.isInteger(evaluated) && Number.isInteger(total) && evaluated < total
}
