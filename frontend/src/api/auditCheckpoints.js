import request from './request'

/**
 * 審計檢查點鏈（audit-checkpoint-chain D10）。
 *
 * 三支端點皆為 admin 與 auditor 可讀的**唯讀**面：本模組刻意沒有任何寫入
 * 方法——檢查點的補蓋、重簽、修鏈能力本身即偽造面，後端亦不存在對應端點。
 */

/**
 * 檢查點列表（seq 倒序、分頁）
 * @param {Object} params - { page, page_size }
 * @returns {Promise} { data: { items, total } }
 */
export function listCheckpoints(params) {
  return request({ url: '/audit-checkpoints', method: 'get', params })
}

/**
 * 結構層驗證（全鏈；不讀 audit_logs）。
 * 不帶任何範圍參數即只回結構層——內容層是數十億列級掃描，必須明確指定範圍。
 * @returns {Promise} { data: { chain } }
 */
export function verifyChain() {
  return request({ url: '/audit-checkpoints/verify', method: 'get' })
}

/**
 * 內容層驗證（必須帶範圍：seq 區間或日期區間）。
 * @param {Object} params - { seq_from, seq_to } 或 { from, to }（YYYY-MM-DD）
 * @returns {Promise} { data: { chain, content } }
 */
export function verifyCheckpointContent(params) {
  return request({ url: '/audit-checkpoints/verify', method: 'get', params })
}

/**
 * 簽章公鑰（Ed25519 base64）＋版本＋指紋，供離線驗章
 * @returns {Promise} { data: { algorithm, version, public_key, fingerprint } }
 */
export function getCheckpointPublicKey() {
  return request({ url: '/audit-checkpoints/public-key', method: 'get' })
}
