import request from './request'
import { getOIDCProviders } from './oidc'

/**
 * 身分來源（目錄與 OIDC 提供者）合併視圖的 API 客戶端。
 *
 * 本檔的端點分兩批：
 *   - **合併與映射規則**（`/identity-sources…`）、**狀態彙總**、**探索預覽**：
 *     皆為新端點，後端可能尚未提供。故一律 `skipErrorToast`，由呼叫端把
 *     「尚未提供」呈現成該區塊的降級態，而不是全頁 toast 洪水。
 *   - **既有端點**（`/oidc-providers`、`/ldap-directory`）：形狀不變，
 *     沿用 `./oidc.js` 與 `./ldapDirectory.js`，此處只補一支尚不存在的單筆讀取。
 *
 * 呼叫端判斷「後端尚未提供」的唯一判準是 `isNotImplemented(error)`——
 * 不可拿「回應是空的」當判準：空清單是合法且常見的現況。
 */

export const SOURCE_TYPE_OIDC = 'oidc'
export const SOURCE_TYPE_LDAP = 'ldap'

/**
 * 端點尚未實作的判定。
 *
 * 404 是「路由不存在」的訊號；405 保留給「路徑存在但方法未掛」。
 * 其餘狀態（401/403/500）是**真的錯誤**，不得被當成降級態靜默吞掉——
 * 那會讓權限問題與伺服器故障都表現為「後端尚未提供」。
 *
 * **但 404 也可能是路由存在且回答了「這個資源不存在」**——例如目錄尚未設定時的
 * 狀態彙總。兩者的差別在回應本體：路由不存在時框架回的是純文字，沒有機器碼；
 * 已掛上的路由一律走機器碼出口。故帶機器碼的 404 是答案而非缺席，
 * 由呼叫端依該碼呈現「尚未設定」，不得說成「後端尚未提供」。
 * @param {Error} error axios 錯誤
 * @returns {boolean}
 */
export function isNotImplemented(error) {
  const status = error?.response?.status
  if (status !== 404 && status !== 405) return false
  return !errorCode(error)
}

/**
 * 取出回應本體的機器碼；沒有就回空字串。
 *
 * 兩種外框都認（頂層與包在 `error` 物件內），理由同 `mappingRiskGate`：
 * 差一層外框就漏接，而漏接的方向是把有答案的回應誤判成端點缺席。
 * @param {Error} error axios 錯誤
 * @returns {string}
 */
export function errorCode(error) {
  const data = error?.response?.data
  if (!data || typeof data !== 'object') return ''
  const nested = data.error
  const body = nested && typeof nested === 'object' ? nested : data
  return typeof body.code === 'string' ? body.code : ''
}

/** 目錄尚未設定：狀態彙總在此情形回 404 加此碼（不是端點缺席） */
export const CODE_LDAP_DIRECTORY_NOT_FOUND = 'NOTFOUND_LDAP_DIRECTORY'

const mappingBase = (type, id) =>
  `/identity-sources/${encodeURIComponent(type)}/${encodeURIComponent(id)}/mappings`

/**
 * 合併列表：目錄與提供者同列。
 * @returns {Promise} { data: SourceRow[] }
 */
export function getIdentitySources() {
  return request({
    url: '/identity-sources',
    method: 'get',
    skipErrorToast: true,
  })
}

/**
 * 某來源的映射規則清單
 * @param {string} type 'oidc' 或 'ldap'
 * @param {number|string} id 來源識別（目錄為其單例 id）
 * @returns {Promise} { data: Rule[] }
 */
export function getSourceMappings(type, id) {
  return request({ url: mappingBase(type, id), method: 'get', skipErrorToast: true })
}

/**
 * 建立映射規則。
 *
 * 未帶 `risk_acknowledged` 而命中風險情形時後端回 422＋警告碼清單，
 * 呼叫端顯示警告、確認後以 `risk_acknowledged: true` 重送。
 * @param {string} type
 * @param {number|string} id
 * @param {Object} data RuleInput
 * @returns {Promise}
 */
export function createSourceMapping(type, id, data) {
  return request({ url: mappingBase(type, id), method: 'post', data, skipErrorToast: true })
}

/**
 * 更新映射規則（語義同 create）
 * @param {string} type
 * @param {number|string} id
 * @param {number|string} ruleId
 * @param {Object} data RuleInput
 * @returns {Promise}
 */
export function updateSourceMapping(type, id, ruleId, data) {
  return request({
    url: `${mappingBase(type, id)}/${encodeURIComponent(ruleId)}`,
    method: 'put',
    data,
    skipErrorToast: true,
  })
}

/**
 * 刪除映射規則
 * @param {string} type
 * @param {number|string} id
 * @param {number|string} ruleId
 * @returns {Promise}
 */
export function deleteSourceMapping(type, id, ruleId) {
  return request({
    url: `${mappingBase(type, id)}/${encodeURIComponent(ruleId)}`,
    method: 'delete',
    skipErrorToast: true,
  })
}

/**
 * 檢核面板的狀態彙總（一支端點回齊全部燈號，不由前端拼多支）
 * @param {string} type
 * @param {number|string} id 提供者識別；目錄型別忽略此值（單例）
 * @returns {Promise}
 */
export function getSourceStatus(type, id) {
  const url =
    type === SOURCE_TYPE_LDAP
      ? '/ldap-directory/status'
      : `/oidc-providers/${encodeURIComponent(id)}/status`
  return request({ url, method: 'get', skipErrorToast: true })
}

/**
 * 探索預覽（唯讀、不落庫）
 * @param {string} issuer
 * @returns {Promise}
 */
export function previewOIDCDiscovery(issuer) {
  return request({
    url: '/oidc-providers/discovery-preview',
    method: 'post',
    data: { issuer },
    // 探索要往外撥號，比一般管理端請求慢；沿用連線測試的客戶端界線
    timeout: 20000,
    skipErrorToast: true,
  })
}

/**
 * 單一提供者詳情。
 *
 * 單筆讀取端點是本波新增的（回呼網址與宣告對應欄位隨它回）。
 * **未提供時退回列表再挑出該筆**——舊形狀的欄位本來就都在列表裡，
 * 退回後畫面少的只有新欄位，而不是整頁打不開。
 * @param {number|string} id
 * @returns {Promise} provider 視圖
 */
export async function getOIDCProviderDetail(id) {
  try {
    const res = await request({
      url: `/oidc-providers/${encodeURIComponent(id)}`,
      method: 'get',
      skipErrorToast: true,
    })
    return res?.data || res
  } catch (error) {
    if (!isNotImplemented(error)) throw error
    const list = await getOIDCProviders()
    const hit = (list?.data || []).find((p) => String(p.id) === String(id))
    if (!hit) {
      const notFound = new Error('provider_not_found')
      notFound.response = { status: 404 }
      throw notFound
    }
    return hit
  }
}
