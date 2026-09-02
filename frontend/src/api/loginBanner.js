import request from './request'

/**
 * 登入前告示的 API 客戶端。
 *
 * 端點未認證可讀，回 { enabled: false } 或 { enabled: true, title, body }。
 * 告示是顯示型內容——失敗（含封印期 503 與網路錯誤）只降級為不顯示，
 * 不該把錯誤彈到使用者面前，故不走全域 toast。
 * @returns {Promise}
 */
export function getLoginBanner() {
  return request({
    url: '/auth/banner',
    method: 'get',
    skipErrorToast: true,
  })
}
