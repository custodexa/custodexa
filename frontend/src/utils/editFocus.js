/**
 * 資產編輯深連結的落點流程：?edit=<id>&focus=<鍵>。
 *
 * 落點表每列兩個欄位：scroll（必填，落點選擇器）與 focus（選填，捲動後要聚焦的選擇器）。
 * 等待目標出現用 MutationObserver 加逾時，不輪詢；抽屜在等待期間被關閉即中止，不捲動、不聚焦。
 */

/**
 * 等選擇器出現；已存在則立即回傳。逾時或中止回傳 null。
 * @param {ParentNode} root
 * @param {string} selector
 * @param {number} timeoutMs
 * @param {() => boolean} [isAborted]
 * @returns {Promise<Element|null>}
 */
export function waitForElement(root, selector, timeoutMs, isAborted = () => false) {
  const found = root.querySelector(selector)
  if (found || timeoutMs <= 0) return Promise.resolve(found)
  return new Promise((resolve) => {
    let done = false
    let observer = null
    let timer = null
    const finish = (value) => {
      if (done) return
      done = true
      if (observer) observer.disconnect()
      if (timer) clearTimeout(timer)
      resolve(value)
    }
    const check = () => {
      if (isAborted()) return finish(null)
      const el = root.querySelector(selector)
      if (el) finish(el)
    }
    observer = new MutationObserver(check)
    observer.observe(root === document ? document.body : root, { childList: true, subtree: true, attributes: true })
    timer = setTimeout(() => finish(root.querySelector(selector)), timeoutMs)
  })
}

/**
 * 依落點表捲動並（若該列有 focus 欄）聚焦。查無鍵或未帶時沿用主機金鑰。
 * @param {Object} options
 * @param {Record<string, {scroll: string, focus?: string}>} options.targets
 * @param {string} [options.key]
 * @param {() => boolean} options.isOpen - 抽屜是否仍開著
 * @param {ParentNode} [options.root]
 */
export async function applyEditFocus({ targets, key, isOpen, root = document, scrollTimeout = 2000, focusTimeout = 3000 }) {
  const target = targets[key] || targets['host-key']
  const aborted = () => !isOpen()
  const el = await waitForElement(root, target.scroll, scrollTimeout, aborted)
  if (aborted()) return
  el?.scrollIntoView({ block: 'center' })
  if (!target.focus) return
  const focusEl = await waitForElement(root, target.focus, focusTimeout, aborted)
  if (aborted() || !focusEl) return
  // 深連結的落點要讓視線找得到：要求瀏覽器畫出焦點框（:focus-visible），不支援此選項的瀏覽器忽略它
  focusEl.focus({ focusVisible: true })
  focusEl.scrollIntoView({ block: 'center' })
}
