/**
 * 破壞性動作的確認框。
 *
 * 為什麼要獨立一個 helper 而不是每處各自傳選項：
 *   Element Plus 的 ElMessageBox 預設 `autofocus: true`，開啟後焦點落在**確認鈕**上，
 *   於是「Enter 關掉這個框」這個肌肉記憶動作等同於執行該破壞性操作。錯誤通知型的
 *   對話框（例如「無法解綁，是否改為解綁並停用帳號？」）尤其危險——管理者的自然
 *   反應是按 Enter 表示「知道了」，實際卻是停用帳號。
 *
 *   `autofocus: false` 時 Element Plus 把焦點起點設為對話框根節點（focus trap 的
 *   容器）而非確認鈕，Enter 不再直接觸發確認；Esc 仍可取消，鍵盤操作者以 Tab
 *   進入按鈕列後由自己決定落在哪一顆。
 *
 * 另附 `confirmButtonClass: el-button--danger`：破壞性確認鈕與一般確認鈕在視覺上
 * 分色，避免「所有確認框長得一樣」而被無意識連按。
 */
import { ElMessageBox } from 'element-plus'

export const DESTRUCTIVE_CONFIRM_CLASS = 'el-button--danger'

/**
 * @param {string} message 完整後果文案（呼叫端負責把影響面講完）
 * @param {string} title 對話框標題
 * @param {object} [options] 覆寫用選項（confirmButtonText/cancelButtonText 等）
 * @returns {Promise} resolve=確認、reject=取消（與 ElMessageBox.confirm 一致）
 */
export function confirmDestructive(message, title, options = {}) {
  return ElMessageBox.confirm(message, title, {
    type: 'warning',
    autofocus: false,
    confirmButtonClass: DESTRUCTIVE_CONFIRM_CLASS,
    ...options,
  })
}
