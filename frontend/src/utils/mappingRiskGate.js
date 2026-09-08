/**
 * 群組映射的「警告加確認」閘門（規則儲存與提供者儲存共用同一套）。
 *
 * 為什麼要抽出來共用：伺服端把同一支 `MAPPING_ACK_REQUIRED` 用在兩條路徑上——
 * 規則的建立／更新，以及提供者設定的儲存（設了群組宣告名卻沒請求對應授權範圍）。
 * 兩處若各寫一份確認流程，警告文案與「確認後重送」的語義遲早會分岔，
 * 而分岔的方向是其中一處把警告吞掉、直接顯示泛用錯誤。
 *
 * **這是警告不是阻擋**：確認後一律以 `risk_acknowledged: true` 重送並存下，
 * 確認本身在伺服端留痕。
 */
import i18n, { t } from '@/i18n'
import { confirmDestructive } from './confirm'

/** 伺服端要求先確認風險的機器碼 */
export const ACK_REQUIRED_CODE = 'MAPPING_ACK_REQUIRED'

/**
 * 警告碼的譯文。缺詞條時回空字串由呼叫端決定退路，不把機器碼直接丟給使用者。
 * @param {string} code 警告機器碼
 * @returns {string}
 */
export function warningText(code) {
  const key = `warnings.${code}`
  return i18n.global.te(key) ? t(key) : ''
}

/**
 * 從錯誤回應取出警告碼清單；不是「需要確認」的回應一律回 null。
 *
 * 回應本體的形狀兩種都認：契約文件把警告包在 `error` 物件內，
 * 實作回的是扁平物件。差一層外框就漏接等於整條確認流程失效，
 * 故此處以「兩種都試」換取形狀無關。
 * @param {Error} error axios 錯誤
 * @returns {string[]|null} 警告碼清單（可能為空陣列）；非確認型錯誤回 null
 */
export function ackWarningCodes(error) {
  const resp = error?.response
  if (resp?.status !== 422) return null
  const nested = resp?.data?.error
  const body = nested && typeof nested === 'object' ? nested : resp?.data
  if (body?.code !== ACK_REQUIRED_CODE) return null
  return (body.warnings || []).map((w) => w?.code).filter(Boolean)
}

/**
 * 顯示警告並取得使用者確認。
 * @param {string[]} codes 警告機器碼
 * @returns {Promise<boolean>} 使用者是否確認；無可顯示的警告時視為已確認
 */
export async function confirmWarnings(codes) {
  const lines = codes.map(warningText).filter(Boolean)
  if (lines.length === 0) return true
  try {
    await confirmDestructive(
      // 各條警告本身即完整句子（自帶句號），直接相接；對話框不渲染換行
      lines.join(''),
      t('identitySources.mapping.riskTitle'),
      {
        confirmButtonText: t('identitySources.mapping.riskConfirm'),
        cancelButtonText: t('common.cancel'),
      }
    )
    return true
  } catch {
    return false
  }
}

/**
 * 送出並處理伺服端的確認迴圈：422 時顯示警告，確認後帶旗標重送一次。
 *
 * 只重送一次（`acknowledged` 一旦為真就不再攔）——否則伺服端若因別的理由
 * 持續回同一支碼，畫面會變成關不掉的確認框。
 * @param {(acknowledged: boolean) => Promise} send 以是否已確認為參數的送出函式
 * @param {boolean} [initial] 呼叫端已就近確認過時傳 true
 * @returns {Promise} 成功時的回應；使用者取消時回 undefined
 */
export async function withRiskGate(send, initial = false) {
  let acknowledged = initial === true
  for (;;) {
    try {
      return await send(acknowledged)
    } catch (error) {
      const codes = acknowledged ? null : ackWarningCodes(error)
      if (codes === null) throw error
      if (!(await confirmWarnings(codes))) return undefined
      acknowledged = true
    }
  }
}
