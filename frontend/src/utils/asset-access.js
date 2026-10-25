/**
 * 資產連線入口的存取狀態判定（伺服端 `access_state` 的呈現層消費）。
 *
 * 值域（伺服端單一事實源）：`connectable`／`pending`／`reason_required`／
 * `approval_required`；僅具檢視授權者該欄為空字串。
 *
 * 兩條紀律：
 *   1. **前端不另創可見性判準**。此處只把伺服端已經算好的狀態翻成呈現態，
 *      強制點一律在 connect-token 簽發時的政策閘。
 *   2. **欄位缺席回退既有行為**。舊回應、值域外的新值都回 `open`——入口照常
 *      顯示，拒絕發生在簽發點，而不是靜默把入口藏起來。僅具檢視授權者另由
 *      列表的 `permission` 欄判讀（`view`），呈現為僅檢視。
 *
 * 全域檢視與連線豁免的身分不顯示申請呈現（selfService 為否）：他們的連線資格由後端
 * 授權與政策決定，在此提前鎖定只會製造與實際結果矛盾的畫面。
 */

/** 需要先提出申請才能連線的兩個狀態 */
const REQUEST_STATES = ['reason_required', 'approval_required']

/**
 * 是否需要先申請（等同資產頁「申請連線」入口的判準）
 * @param {object} asset 資產列
 * @param {{ selfService?: boolean }} viewer 是否顯示申請／待申請操作（ui:self-service-actions 呈現點；預設顯示）
 */
export function needsAccessRequest(asset, { selfService = true } = {}) {
  return (
    asset?.active !== false &&
    selfService &&
    REQUEST_STATES.includes(asset?.access_state)
  )
}

/**
 * 是否已送出申請待審（等同資產頁「申請中」入口的判準）
 * @param {object} asset 資產列
 * @param {{ selfService?: boolean }} viewer 是否顯示申請／待申請操作（ui:self-service-actions 呈現點；預設顯示）
 */
export function isAccessPending(asset, { selfService = true } = {}) {
  return asset?.active !== false && selfService && asset?.access_state === 'pending'
}

/**
 * 是否僅具檢視授權（列表回應的 `permission` 欄；不顯示申請呈現者不分化）
 * @param {object} asset 資產列
 * @param {{ selfService?: boolean }} viewer 是否顯示申請／待申請操作（ui:self-service-actions 呈現點；預設顯示）
 */
export function isViewOnly(asset, { selfService = true } = {}) {
  return asset?.active !== false && selfService && asset?.permission === 'view'
}

/**
 * 連線入口的五種呈現態（判定順序即優先序）：
 *   `view_only` 僅具檢視授權：不發簽發，點擊說明無法連線
 *   `pending`   申請審核中：不發簽發，點擊說明核准後重新整理即可連
 *   `approval`  需審核：鎖定，點擊說明並指引到資產頁申請（本頁不內嵌申請流）
 *   `reason`    需填理由：照常發起連線，由連線流程就地要求填理由
 *   `open`      照常提供入口（含欄位缺席、不顯示申請呈現、停用資產的回退）
 * @returns {'view_only'|'pending'|'approval'|'reason'|'open'}
 */
export function assetEntryState(asset, viewer = {}) {
  if (isViewOnly(asset, viewer)) return 'view_only'
  if (isAccessPending(asset, viewer)) return 'pending'
  if (needsAccessRequest(asset, viewer)) {
    return asset.access_state === 'approval_required' ? 'approval' : 'reason'
  }
  return 'open'
}

/** 不發起連線票簽發的呈現態（點擊只給說明） */
export const BLOCKED_ENTRY_STATES = Object.freeze(['view_only', 'pending', 'approval'])
