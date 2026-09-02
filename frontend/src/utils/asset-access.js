/**
 * 資產連線入口的存取狀態判定（伺服端 `access_state` 的呈現層消費）。
 *
 * 值域（伺服端單一事實源）：`connectable`／`pending`／`reason_required`／
 * `approval_required`；僅具檢視授權者該欄為空字串。
 *
 * 兩條紀律：
 *   1. **前端不另創可見性判準**。此處只把伺服端已經算好的狀態翻成呈現態，
 *      強制點一律在 connect-token 簽發時的政策閘。
 *   2. **欄位缺席回退既有行為**。舊回應、僅具檢視授權者、值域外的新值都回
 *      `open`——入口照常顯示，拒絕發生在簽發點，而不是靜默把入口藏起來。
 *
 * 管理者與稽核角色不做前端分化：他們的連線資格由後端角色與政策決定，
 * 在此提前鎖定只會製造與實際結果矛盾的畫面。
 */

/** 需要先提出申請才能連線的兩個狀態 */
const REQUEST_STATES = ['reason_required', 'approval_required']

/**
 * 是否需要先申請（等同資產頁「申請連線」入口的判準）
 * @param {object} asset 資產列
 * @param {{ isPrivileged?: boolean }} viewer 檢視者角色
 */
export function needsAccessRequest(asset, { isPrivileged = false } = {}) {
  return (
    asset?.active !== false &&
    !isPrivileged &&
    REQUEST_STATES.includes(asset?.access_state)
  )
}

/**
 * 是否已送出申請待審（等同資產頁「申請中」入口的判準）
 * @param {object} asset 資產列
 * @param {{ isPrivileged?: boolean }} viewer 檢視者角色
 */
export function isAccessPending(asset, { isPrivileged = false } = {}) {
  return asset?.active !== false && !isPrivileged && asset?.access_state === 'pending'
}

/**
 * 連線入口的三種呈現態：
 *   `open`    照常提供入口（含欄位缺席的回退）
 *   `locked`  需申請：鎖定並指引至資產頁，本頁不內嵌申請流
 *   `pending` 審核中：停用，等待核准
 * @returns {'open'|'locked'|'pending'}
 */
export function assetEntryState(asset, viewer = {}) {
  if (isAccessPending(asset, viewer)) return 'pending'
  if (needsAccessRequest(asset, viewer)) return 'locked'
  return 'open'
}
