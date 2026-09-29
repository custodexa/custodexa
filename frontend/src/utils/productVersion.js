// 側欄版本行的顯示判定。
//
// 版本值來自 GET /auth/me 的 `product_version`，後端原樣轉出建置時注入的版本
// （與 /health 同一個變數），前端不持有任何版本字面值。
//
// **只顯示發布版號的形狀**（X.Y.Z，可帶預發版後綴如 1.14.0-rc.1）：開發建置的
// `dev`、空字串、缺欄、以及任何不像版號的字樣一律不顯示——顯示一個不是版本的
// 字串，比不顯示更容易讓人誤判自己跑的是哪一版。
const RELEASE_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/

/**
 * 可顯示的版本號；不可顯示時回空字串。
 * @param {unknown} raw `/auth/me` 的 product_version 原值
 * @returns {string}
 */
export function displayableVersion(raw) {
  if (typeof raw !== 'string') return ''
  const value = raw.trim()
  return RELEASE_VERSION.test(value) ? value : ''
}
