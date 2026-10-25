// 授權畫面選擇器的共用小工具。範圍與可選性一律取自伺服器回應（actions、selectable、
// 選擇器結果），前端不以節點樹或權限集合自行計算範圍。

export const SELECTOR_PAGE_SIZE = 1000

/**
 * 呼叫一個選擇器並吞下錯誤：失敗回 { rows: [], failed: true }，讓各來源分開載入、
 * 任一來源失敗時其餘清單仍有值。
 */
export async function loadSelector(fetchFn, params) {
  try {
    const res = await fetchFn({ page: 1, page_size: SELECTOR_PAGE_SIZE, ...params })
    const rows = Array.isArray(res?.data) ? res.data : []
    return { rows, total: Number(res?.total) || rows.length, failed: false }
  } catch (err) {
    console.error('載入授權選擇器失敗:', err)
    return { rows: [], total: 0, failed: true }
  }
}

/** 使用者列的顯示：帳號為主，顯示名稱不同時附在括號內。 */
export function userOptionLabel(row) {
  if (!row) return ''
  const name = row.display_name
  return name && name !== row.username ? `${row.username} (${name})` : row.username
}

/** 節點候選是否可授權：只認伺服器的 selectable。 */
export function isSelectableNode(row) {
  return row?.selectable === true
}

/** 授權列動作的原因碼對應的 i18n 鍵（字面量，供 i18n 守衛掃描）。 */
export const ACTION_REASON_KEYS = {
  self_subject: 'authorizations.accountScopeSelfLocked',
  ticket_bound: 'authorizations.actionReason.ticket_bound',
  not_revocable: 'authorizations.actionReason.not_revocable',
  revoke_not_eligible: 'authorizations.actionReason.revoke_not_eligible',
}

export const ACTION_LIMIT_KEYS = {
  narrow_only: 'authorizations.actionLimit.narrow_only',
}

/** 動作旗標轉成畫面狀態；沒有旗標（超級管理者或舊回應）回 null，由呼叫端沿現行邏輯。 */
export function actionState(row, name, t) {
  const a = row?.actions?.[name]
  if (!a || typeof a !== 'object') return null
  const reasonKey = a.allowed ? '' : ACTION_REASON_KEYS[a.reason]
  const limitKey = a.allowed ? ACTION_LIMIT_KEYS[a.limit] : ''
  return {
    allowed: a.allowed === true,
    reason: a.reason || '',
    limit: a.limit || '',
    note: reasonKey ? t(reasonKey) : limitKey ? t(limitKey) : '',
  }
}
