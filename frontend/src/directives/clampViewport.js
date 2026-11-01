/**
 * 錨定浮層夾在視窗內：預設與錨點右緣對齊；左緣跑出視窗時改與錨點左緣對齊，
 * 仍放不下再整個推回，左右各留 MARGIN。
 *
 * 用法：浮層是 position:absolute、right:0 的錨定元素（例如按鈕旁的彈出框）。
 * 元素掛載與更新時量一次；量不到尺寸（無版面的環境）什麼都不做。
 */

const MARGIN = 8

export function clampToViewport(el) {
  if (!el || typeof window === 'undefined') return
  el.style.left = ''
  el.style.right = ''
  el.style.maxWidth = ''
  const vw = window.innerWidth || document.documentElement.clientWidth
  let rect = el.getBoundingClientRect()
  if (!rect.width || !vw) return
  // 比視窗還寬：先收窄
  if (rect.width > vw - MARGIN * 2) {
    el.style.maxWidth = `${vw - MARGIN * 2}px`
    rect = el.getBoundingClientRect()
  }
  if (rect.left >= MARGIN && rect.right <= vw - MARGIN) return
  const parent = el.offsetParent || el.parentElement
  const anchor = parent ? parent.getBoundingClientRect() : null
  if (rect.left < MARGIN && anchor) {
    // 改為左對齊錨點
    el.style.left = '0px'
    el.style.right = 'auto'
    rect = el.getBoundingClientRect()
  }
  let shift = 0
  if (rect.right > vw - MARGIN) shift = vw - MARGIN - rect.right
  if (rect.left + shift < MARGIN) shift = MARGIN - rect.left
  if (shift) {
    const cs = window.getComputedStyle(el)
    if (el.style.left && el.style.left !== 'auto') {
      el.style.left = `${(parseFloat(cs.left) || 0) + shift}px`
    } else {
      // 右對齊時：right 值減去位移
      el.style.right = `${(parseFloat(cs.right) || 0) - shift}px`
    }
  }
}

export const vClampViewport = {
  mounted: (el) => clampToViewport(el),
  updated: (el) => clampToViewport(el),
}
