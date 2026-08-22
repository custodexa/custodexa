// 「為什麼又要我登入」的跨頁載體（codeql-rescan-settlement 決策 3）。
//
// **問題**：明文 HTTP 部署下若 refresh cookie 帶 Secure，瀏覽器不保存它，
// 續期必失敗——使用者每 15 分鐘被踢回登入頁，畫面只說「會話已過期」，
// 沒有任何線索指向真正的原因。啟動日誌有寫，但沒有人會去讀一個看起來
// 還在運作的系統的啟動日誌。
//
// 本模組只做兩件事：記下「本分頁曾成功續期」，以及在刷新終敗且符合條件時
// 留一則給登入頁讀的脈絡。判定只用前端可觀察的事實（頁面協定、本分頁歷史），
// 不需要也不引入任何來自後端的區分訊號——統一認證失敗回應是既有紅線。
//
// 載體選 sessionStorage：`clearSessionAndRedirect` 是整頁載入，記憶體活不過去；
// sessionStorage 分頁隔離、關分頁即清，不污染其他分頁。

// 本分頁曾有一次成功續期。它是**誤報抑制器**：cookie 被瀏覽器丟棄的部署，
// 首次續期必失敗；健康的明文部署（Secure 已關閉）續期失敗幾乎都發生在多次
// 成功續期之後（閒置逾時預設 60 分、絕對壽命 12 小時，都遠長於 access 的 15 分）。
// 少了它，健康部署的每次正常會話過期都會被扣上「協定問題」的帽子——
// 狼來了三次，訊息就死了
const REFRESH_OK_KEY = 'ot-refresh-ok'

// 登入頁待讀的脈絡（讀後即清）
const RELOGIN_CONTEXT_KEY = 'ot-relogin-context'

/** 脈絡值：明文連線下登入狀態無法保存。 */
export const RELOGIN_INSECURE_TRANSPORT = 'insecure-transport'

// sessionStorage 在少數瀏覽器設定下會擲例外（隱私模式、封鎖儲存）。
// 這條路徑是「附加說明」而非功能本體，取不到就當作沒有，絕不讓它擋住登入流程
const readItem = (key) => {
  try {
    return window.sessionStorage?.getItem(key) || ''
  } catch {
    return ''
  }
}

const writeItem = (key, value) => {
  try {
    window.sessionStorage?.setItem(key, value)
  } catch {
    // 忽略
  }
}

const removeItem = (key) => {
  try {
    window.sessionStorage?.removeItem(key)
  } catch {
    // 忽略
  }
}

/** 本分頁取得過一次有效的續期結果（含他分頁已刷新而本分頁沿用的情形）。 */
export function markRefreshSucceeded() {
  writeItem(REFRESH_OK_KEY, '1')
}

/** 本分頁是否曾成功續期。 */
export function hasRefreshSucceeded() {
  return readItem(REFRESH_OK_KEY) === '1'
}

/**
 * 刷新終敗時記錄脈絡。三個條件同時成立才寫：
 * 頁面協定為 http、本分頁未曾成功續期、（呼叫點本身即「刷新終敗」）。
 *
 * @returns {boolean} 是否寫入（測試與除錯用；呼叫端不需要理會）
 */
export function recordInsecureTransportRelogin() {
  if (window.location.protocol !== 'http:') return false
  if (hasRefreshSucceeded()) return false
  writeItem(RELOGIN_CONTEXT_KEY, RELOGIN_INSECURE_TRANSPORT)
  return true
}

/**
 * 讀取並清除脈絡。登入頁 onMounted 呼叫——讀後即清使得重新整理登入頁
 * 不會重播同一則訊息。
 *
 * @returns {string} 脈絡值，無則空字串
 */
export function consumeReloginContext() {
  const value = readItem(RELOGIN_CONTEXT_KEY)
  removeItem(RELOGIN_CONTEXT_KEY)
  return value
}

/** 測試用：清空本模組的全部分頁狀態。 */
export function resetReloginContext() {
  removeItem(REFRESH_OK_KEY)
  removeItem(RELOGIN_CONTEXT_KEY)
}
