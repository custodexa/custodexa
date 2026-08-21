import axios from 'axios'
import { ElMessage } from 'element-plus'
import { t } from '@/i18n'
import { resolveApiError } from './error'
import { redactAxiosError } from './redact'
import { SEAL_GATE_CODE, UNSEAL_PATH, markSealed } from '@/utils/sealPhase'

// 建立 axios 實例
const request = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
})

// 請求攔截器
request.interceptors.request.use(
  (config) => {
    // 從 localStorage 取得 token；呼叫端已顯式帶 Authorization 時不覆蓋
    //（強制改密流程以 change_token 呼叫，此時 localStorage 尚無正式 token）
    const token = localStorage.getItem('token')
    if (token && !config.headers.Authorization) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    // 只印去識別摘要：error 物件本身帶 config.data（明文憑證）與
    // config.headers.Authorization（有效 token）
    console.error('請求錯誤:', redactAxiosError(error))
    return Promise.reject(error)
  }
)

// —— access token 到期的透明刷新（auth-hardening D6/D10）——
// access 固定短效 15 分；401 時以 refresh 憑證換發後重試原請求，使用者無感。
// 僅「access token 失效」型 401 值得刷新（換新 access token）；其餘 401——帳密錯、
// MFA 驗證碼錯、scoped token 狀態、權限不足——是業務語義，刷新無用且會誤把業務錯誤
// 當 session 過期。以**後端回傳的 code** 判定，不用 URL 前綴（i18n-backend-error-codes
// New-C2／實作審查 P2）：同一端點可能回兩類 401（如 /auth/mfa/disable 密碼錯回
// AUTH_INVALID_CREDENTIALS vs access token 過期由 middleware 回 AUTH_TOKEN_INVALID），
// URL 無法區分；middleware 對 access token 失效一律發下列 code，故以此為準最穩健。
const REFRESHABLE_401_CODES = new Set(['AUTH_TOKEN_INVALID', 'AUTH_TOKEN_MISSING'])

// 錯版相容（實作審查 P2）：新前端＋舊後端時，舊 middleware 的 token 過期回應**無 code**。
// 對「無 code 的 401」退回既有 URL 規則（非 /auth/* 才刷新），維持與舊後端的相容窗口；
// 有 code 時才採 code-based 判定。/auth/* 業務端點的無-code 401 沿用舊行為（不刷新）。
const isAuthPath = (url) => (url || '').startsWith('/auth/')
const shouldRefresh401 = (data, url) => {
  const code = data?.code
  return code ? REFRESHABLE_401_CODES.has(code) : !isAuthPath(url)
}

// single-flight：同一 JS context 併發 401 共用一次刷新，避免同 refresh 憑證
// 併發輪替誤觸後端 reuse detection（家族撤銷）
let refreshInFlight = null

// 刷新走裸 axios：不經本攔截器，refresh 自身的 401 不會遞迴觸發刷新
const postRefresh = (refreshToken) =>
  axios.post(
    '/api/v1/auth/refresh',
    { refresh_token: refreshToken },
    { timeout: 10000 }
  )

const doRefresh = async (staleToken) => {
  // 跨 tab：他分頁可能已刷新並寫回 localStorage（rotation 後舊憑證已作廢），
  // 先比對 access token 是否已更新，避免拿已輪替的 refresh 憑證重放。
  // staleToken 取不到（原請求無 Authorization header）時不可短路，否則
  // 會誤判「已更新」而拿同一個失效 token 重試
  const current = localStorage.getItem('token')
  if (staleToken && current && current !== staleToken) {
    return current
  }
  const refreshToken = localStorage.getItem('refresh_token')
  if (!refreshToken) {
    throw new Error('無 refresh 憑證')
  }
  const { data } = await postRefresh(refreshToken)
  localStorage.setItem('token', data.token)
  localStorage.setItem('refresh_token', data.refresh_token)
  return data.token
}

const refreshAccessToken = (staleToken) => {
  if (!refreshInFlight) {
    // Web Locks 可用時跨分頁序列化刷新（localStorage 為分頁共享，
    // 兩個分頁同時刷新同一憑證會觸發 reuse detection 全登出）；不支援則退回單頁去重
    const run =
      typeof navigator !== 'undefined' && navigator.locks?.request
        ? navigator.locks.request('custodexa-token-refresh', () =>
            doRefresh(staleToken)
          )
        : doRefresh(staleToken)
    refreshInFlight = run.finally(() => {
      refreshInFlight = null
    })
  }
  return refreshInFlight
}

// 封印的執行期訊號（kek-encoding-and-unseal-entry 決策 6 的第 3 個相位來源）：
// 使用者停留在頁面上時後端行程重啟而重新封印，導覽守衛不會再跑一次——
// 唯一會撞到的就是下一個 API 呼叫的 503。此時把相位改回封印並導向解封頁，
// 否則使用者只會看到一連串「服務未上線」的 toast 而不知道要去哪。
//
// **不清 session**：封印不是認證失敗，token 仍然有效，解封後照常可用。
const redirectToUnsealIfSealed = (data) => {
  if (data?.code !== SEAL_GATE_CODE) return
  markSealed()
  if (window.location.pathname !== UNSEAL_PATH) {
    window.location.href = UNSEAL_PATH
  }
}

const clearSessionAndRedirect = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('refresh_token')
  localStorage.removeItem('user')
  if (window.location.pathname !== '/login') {
    window.location.href = '/login'
  }
}

// 回應攔截器：全域唯一的 API 錯誤 toast 來源（error-message-consistency）。
// 後端統一以 {"error": <使用者可讀訊息>} 回應，呼叫端需自行呈現錯誤時
// 以 { skipErrorToast: true } 關閉全域 toast。
request.interceptors.response.use(
  (response) => {
    return response.data
  },
  async (error) => {
    // 全域唯一的 API 錯誤日誌出口——**絕不印 error 本體**（對抗審查 HIGH-2）：
    // AxiosError 的 config.data 是原始請求本文，帳號 CRUD 帶明文密碼／私鑰，
    // config.headers 帶有效 Authorization，寫進 console 即 DevTools 可見外洩
    console.error('回應錯誤:', redactAxiosError(error))

    let message = t('api.requestFailed')
    let httpStatus = 0
    if (error.response) {
      const { status, data } = error.response
      const config = error.config || {}
      httpStatus = status

      if (status === 401 && shouldRefresh401(data, config.url)) {
        // access token 失效：未重試過先透明刷新後重試原請求；終敗才清憑證導向
        if (!config._retried) {
          const staleToken = (config.headers?.Authorization || '').replace(
            'Bearer ',
            ''
          )
          try {
            const newToken = await refreshAccessToken(staleToken)
            return request({
              ...config,
              _retried: true,
              headers: { ...config.headers, Authorization: `Bearer ${newToken}` },
            })
          } catch (refreshError) {
            // refresh 請求本文含 refresh_token，同樣不得印本體
            console.error('會話刷新失敗:', redactAxiosError(refreshError))
          }
        }
        message = t('api.sessionExpired')
        clearSessionAndRedirect()
      } else {
        // 業務 401 與所有非 401：code 三層降級（code 譯文 → 後端 error → 通用語），
        // 不刷新、不導向——業務錯誤刷新無用，且不該把帳密/驗證碼錯當 session 過期
        message = resolveApiError(data, status)
        // 例外：封印閘的 503 需要導向解封頁（見上方說明）。
        // 判定走**機器碼**而非狀態碼：503 也可能來自其他不可用情形
        redirectToUnsealIfSealed(data)
      }
    } else if (error.request) {
      // 請求已發送但沒有收到回應
      message = t('api.networkError')
    }

    // 423 帳號鎖定一律由登入/MFA 視圖以 inline locked-alert 明示（含剩餘策略文案），
    // 攔截器不再重複 toast——避免同一鎖定錯誤顯示兩次（實作審查 I4）。
    if (!error.config?.skipErrorToast && httpStatus !== 423) {
      ElMessage.error(message)
    }
    return Promise.reject(error)
  }
)

export default request
