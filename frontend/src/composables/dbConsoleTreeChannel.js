// 樹的請求／回應對位。
//
// 主控台的訊息通道沒有請求識別碼，樹的回應只帶層級與座標（層級、schema、table），
// 對位就以這三者為鍵。抽成獨立模組是因為它有自己的失敗語義：
// 伺服端的錯誤與連線關閉都會使某些請求永遠等不到回應，而讓載入指示轉到分頁
// 關閉為止是最糟的呈現——寧可 reject，讓樹收束成空層並由錯誤面板說明成因。

const waiterKey = (level, schema, table) => `${level}|${schema || ''}|${table || ''}`

/**
 * @param {(payload: object) => boolean} send 送出訊息；回傳是否真的送出
 */
export function createTreeChannel(send) {
  const waiters = new Map()

  /**
   * 請求一層。
   * @param {{level: string, schema?: string, table?: string}} request
   * @returns {Promise<object>} 對應的 tree_result 訊息
   */
  function request({ level, schema = '', table = '' }) {
    return new Promise((resolve, reject) => {
      if (!send({ type: 'tree', level, schema, table })) {
        reject(new Error('socket_not_open'))
        return
      }
      waiters.set(waiterKey(level, schema, table), { resolve, reject })
    })
  }

  /**
   * 以收到的 tree_result 兌現對應的請求。
   * @param {object} msg
   */
  function settle(msg) {
    const key = waiterKey(msg.level, msg.schema, msg.table)
    const waiter = waiters.get(key)
    if (!waiter) return
    waiters.delete(key)
    waiter.resolve(msg)
  }

  /**
   * 讓所有未兌現的請求失敗。
   * @param {string} reason 受控原因碼
   */
  function rejectAll(reason) {
    for (const waiter of waiters.values()) waiter.reject(new Error(reason))
    waiters.clear()
  }

  return { request, settle, rejectAll }
}
