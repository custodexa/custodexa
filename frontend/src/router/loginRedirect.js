// 導向登入頁時要不要帶「登入後回到原頁」的目的地。
//
// 只有「登入後可回到的路由」清單（loginReturnRoutes.js）內的頁面才帶；其他頁面、
// 主動登出、跨分頁登出一律只導向 /login。清單只決定要不要帶，登入後的目的地由伺服端
// 判定（登入頁只採用回應的 redirect_next）。
import { isLoginReturnRoute } from './loginReturnRoutes'

export const LOGIN_PATH = '/login'

/**
 * 認證守衛導向登入頁的目標。
 * 回傳路由器位置物件：目的地放在 query，由路由器編碼一次（不自行 encodeURIComponent，
 * 否則登入頁讀到的是編碼過一次的字串）。
 * @param {{ name?: string|symbol, fullPath?: string }} to 目的路由
 */
export function loginLocationFor(to) {
  if (to && isLoginReturnRoute(to.name) && typeof to.fullPath === 'string' && to.fullPath.startsWith('/')) {
    return { path: LOGIN_PATH, query: { next: to.fullPath } }
  }
  return LOGIN_PATH
}

// API 認證失敗時的整頁導向不經過路由器，需要知道「當下的頁面」是哪一個路由。
// 路由器每次導覽完成時記下（afterEach），只記名稱與完整路徑。
let current = null

/** 記下目前停留的路由（router.afterEach 呼叫）。 */
export function rememberCurrentRoute(route) {
  current = route && typeof route.fullPath === 'string'
    ? { name: route.name, path: route.path, fullPath: route.fullPath }
    : null
}

/**
 * API 認證失敗時整頁導向的網址。
 * 記下的路由與網址列的路徑一致、且屬清單時才帶目的地；查詢字串以 URLSearchParams 編碼一次。
 */
export function loginHrefForCurrentPage(pathname = window.location.pathname) {
  if (!current || current.path !== pathname || !isLoginReturnRoute(current.name)) return LOGIN_PATH
  if (!current.fullPath.startsWith('/')) return LOGIN_PATH
  return `${LOGIN_PATH}?${new URLSearchParams({ next: current.fullPath }).toString()}`
}

/** 測試用：清掉記下的路由。 */
export function resetCurrentRouteForTests() {
  current = null
}
