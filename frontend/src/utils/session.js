// access token 的單一持有者。
//
// **問題**：access token 原本存在 localStorage。那份明文對任何在頁面上執行的
// script 完全可讀，而且跨頁面載入存續——一次注入就能把它整個帶走，且帶走的是
// 一份離開瀏覽器後仍可用的憑證。憑證改為只活在頁面執行期記憶體：關掉分頁即消失，
// 磁碟上沒有副本，重新載入時以 httpOnly 的續期憑證重新換發一份。
//
// **不是安全邊界的部分**：強制點在後端（middleware 只認 Authorization header）。
// 本模組換到的是「憑證不落地、不跨載入存續」，不是「頁面上的 script 讀不到它」——
// 同一個執行環境內的程式碼當然拿得到，那從來不是這個改動要處理的事。
//
// **走裸 axios、不 import `@/api/request`**：request 需要本模組的取值函式，
// 本模組若回頭 import 它就構成模組環，而環在 bundler 下的求值順序不是我們能
// 保證的東西（沿封印相位模組的既有理由）。續期請求也因此不經攔截器，
// 它自己的 401 不會遞迴觸發續期。
import axios from 'axios'
import {
  markRefreshSucceeded,
  recordInsecureTransportRelogin,
} from '@/utils/reloginContext'

// 使用者資料快取的鍵。它不是憑證（帳號名、角色、顯示名），留在 localStorage；
// 同時兼作下面的「登入跡象」
const USER_KEY = 'user'

// 跨分頁訊號的鍵。值只有事件型別與時戳，**絕不含任何憑證**——
// localStorage 是同源共享的，放憑證進去等於把記憶體持有這件事整個抵銷
const SIGNAL_KEY = 'ot-session-signal'

export const SIGNAL_LOGOUT = 'logout'
export const SIGNAL_LOGIN = 'login'

const LOGIN_PATH = '/login'

// 續期端點：本文為空，憑證由瀏覽器以 httpOnly cookie 自動附帶（同源部署，
// 無需 withCredentials）；憑證不可讀也就無從由 JS 帶入請求本文
const REFRESH_URL = '/api/v1/auth/refresh'
const REFRESH_TIMEOUT_MS = 10000

// 唯一的持有處：模組閉包變數，不掛 window、不落任何儲存
let accessToken = ''

// single-flight：同一 JS context 併發的續期共用一次請求，避免以同一枚續期憑證
// 併發輪替而誤觸後端的重放偵測（家族撤銷）
let refreshInFlight = null

// 頁面載入恢復的 single-flight：多條守衛同時觸發時只走一次
let restoreInFlight = null

/** 目前記憶體中的 access token（無則空字串）。不觸發任何請求。 */
export function getAccessToken() {
  return accessToken
}

/** 登入終點、自助改密、續期成功後寫入。 */
export function setAccessToken(token) {
  accessToken = token || ''
}

/**
 * 前端可觀察的「曾登入且未登出」訊號。
 *
 * 續期憑證是 httpOnly cookie，script 無從得知它在不在。少了跡象判定，
 * 每個未登入訪客開啟登入頁都會對續期端點打一次必然失敗的請求，
 * 在稽核紀錄裡製造一列拒絕事件——失敗事件對稽核有意義，不該被雜訊淹沒。
 */
export function hasSessionHint() {
  try {
    return !!window.localStorage?.getItem(USER_KEY)
  } catch {
    return false
  }
}

const clearSessionHint = () => {
  try {
    window.localStorage?.removeItem(USER_KEY)
  } catch {
    // 忽略：儲存被封鎖時本來就沒有跡象可清
  }
}

const broadcastSignal = (type) => {
  try {
    // 時戳必帶：localStorage 寫入同值不觸發他分頁的 storage 事件，
    // 連續兩次登出就會有一次不通知
    window.localStorage?.setItem(
      SIGNAL_KEY,
      JSON.stringify({ type, at: Date.now() })
    )
  } catch {
    // 忽略：訊號是附加的一致性，不是登出本身
  }
}

/**
 * 清除本分頁的會話：記憶體 token 與使用者快取。
 *
 * @param {{broadcast?: boolean}} [options] broadcast 為真時通知同瀏覽器的其他分頁登出。
 *   只有**使用者明確登出**才廣播；續期終敗不廣播——他分頁可能正開著連線終端，
 *   而已建立的連線本來就不隨 access token 到期而中斷，整頁導向會把它殺掉。
 */
export function clearSession(options = {}) {
  accessToken = ''
  clearSessionHint()
  if (options.broadcast) broadcastSignal(SIGNAL_LOGOUT)
}

/** 使用者於本分頁完成登入後通知其他分頁（停在登入頁的那些可以自行前進）。 */
export function announceLogin() {
  broadcastSignal(SIGNAL_LOGIN)
}

const postRefresh = () =>
  axios.post(REFRESH_URL, {}, { timeout: REFRESH_TIMEOUT_MS })

const doRefresh = async (staleToken) => {
  // 同頁短路：自助改密剛換過 token，而某個以舊 token 發出的請求此刻才回 401。
  // 記憶體裡已經是新的，直接沿用即可，不必再輪替一次憑證。
  // staleToken 取不到（原請求無 Authorization header）時不可短路，
  // 否則會誤判「已更新」而拿同一個失效 token 重試
  if (staleToken && accessToken && accessToken !== staleToken) {
    return accessToken
  }
  // 無「本地有沒有憑證」的前置檢查：cookie 對 script 不可見，有無一律交給
  // 後端回答——沒帶 cookie 時後端回 401，呼叫端據以導向登入
  const { data } = await postRefresh()
  setAccessToken(data.token)
  markRefreshSucceeded()
  return data.token
}

/**
 * 換發一枚新的 access token。
 *
 * @param {string} [staleToken] 觸發本次換發的那枚失效 token（用於同頁短路判定）
 * @returns {Promise<string>} 新的 access token
 */
export function refreshAccessToken(staleToken) {
  if (!refreshInFlight) {
    // Web Locks 可用時跨分頁序列化：兩個分頁同時以同一枚續期憑證輪替會觸發
    // 重放偵測而全部登出。不支援的瀏覽器退回單頁去重，不另做相容分支
    const run =
      typeof navigator !== 'undefined' && navigator.locks?.request
        ? navigator.locks.request('custodexa-token-refresh', () =>
            doRefresh(staleToken)
          )
        : doRefresh(staleToken)
    refreshInFlight = Promise.resolve(run).finally(() => {
      refreshInFlight = null
    })
  }
  return refreshInFlight
}

/**
 * 頁面載入時恢復登入態。導覽守衛在放行受保護路由**之前**呼叫。
 *
 * @returns {Promise<boolean>} 是否處於已登入狀態
 */
export function ensureSession() {
  if (accessToken) return Promise.resolve(true)
  if (!hasSessionHint()) return Promise.resolve(false)
  if (!restoreInFlight) {
    restoreInFlight = refreshAccessToken('')
      .then(() => true)
      .catch(() => {
        // 續期終敗：登入頁要能回答「為什麼又要我登入」。條件判定在該模組內，
        // 且寫入必須發生在導向之前
        recordInsecureTransportRelogin()
        clearSession()
        return false
      })
      .finally(() => {
        restoreInFlight = null
      })
  }
  return restoreInFlight
}

const redirectToLogin = () => {
  if (window.location.pathname !== LOGIN_PATH) {
    window.location.replace(LOGIN_PATH)
  }
}

const handleSignal = (event) => {
  if (event.key !== SIGNAL_KEY || !event.newValue) return
  let payload
  try {
    payload = JSON.parse(event.newValue)
  } catch {
    return
  }
  if (payload?.type === SIGNAL_LOGOUT) {
    // 收訊端不再廣播，否則兩個分頁會互相回彈
    clearSession()
    redirectToLogin()
    return
  }
  if (payload?.type === SIGNAL_LOGIN) {
    // 停在登入頁的分頁自行前進；帶 ticket 參數者正在進行單一登入交換，不打斷它
    if (window.location.pathname !== LOGIN_PATH) return
    if (new URLSearchParams(window.location.search).has('ticket')) return
    window.location.reload()
  }
}

/** 掛上跨分頁訊號監聽（應用入口呼叫一次）。 */
export function installCrossTabSync() {
  window.addEventListener('storage', handleSignal)
}

/** 測試用：清空模組層狀態（單例在測試間會殘留）。 */
export function resetSessionForTests() {
  accessToken = ''
  refreshInFlight = null
  restoreInFlight = null
}
