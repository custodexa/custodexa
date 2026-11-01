import './previewHintCard.css'

/**
 * 預覽中的錨定說明卡：出現在被指到的元素正下方（空間不足時改在正上方），
 * 有可選的標題與內文。全頁共用一張，同時只顯示一處。
 * 停用按鈕、節點列都用它，讓說明停在使用者視線所在的位置。
 */

const GAP = 6
const MARGIN = 8

let card = null
let titleEl = null
let bodyEl = null
let owner = null
let anchorEl = null

const ensure = () => {
  if (card && card.isConnected) return card
  card = document.createElement('div')
  card.className = 'preview-hint-card'
  card.setAttribute('role', 'tooltip')
  card.setAttribute('data-test', 'preview-hint-card')
  card.hidden = true
  titleEl = document.createElement('p')
  titleEl.className = 'preview-hint-card__title'
  bodyEl = document.createElement('p')
  bodyEl.className = 'preview-hint-card__body'
  card.append(titleEl, bodyEl)
  document.body.appendChild(card)
  return card
}

const place = (anchor) => {
  const rect = anchor.getBoundingClientRect()
  const w = card.offsetWidth
  const h = card.offsetHeight
  const vw = window.innerWidth || document.documentElement.clientWidth
  const vh = window.innerHeight || document.documentElement.clientHeight
  // 優先與錨點右緣對齊；放不下才往左（或往右）推，左右各留 MARGIN
  let left = rect.right - w
  if (left + w > vw - MARGIN) left = vw - MARGIN - w
  if (left < MARGIN) left = Math.min(rect.left, vw - MARGIN - w)
  if (left < MARGIN) left = MARGIN
  let top = rect.bottom + GAP
  if (top + h > vh - MARGIN && rect.top - GAP - h >= MARGIN) top = rect.top - GAP - h
  card.style.left = `${Math.round(left)}px`
  card.style.top = `${Math.round(top)}px`
}

/**
 * 有其他選單或 tooltip 展開時不顯示說明卡（卡會蓋住它們）。
 * 錨點本身就在那張浮層裡（例如下拉選單的項目）不算。
 */
export const overlayBlocks = (anchor) => {
  if (typeof document === 'undefined') return false
  for (const p of document.querySelectorAll('.el-popper')) {
    if (p.style.display === 'none' || p.getAttribute('aria-hidden') === 'true') continue
    if (p.contains(anchor)) continue
    return true
  }
  return false
}

/** 重新檢查：被浮層擋住就收起，否則維持原狀 */
export const recheckHintCard = () => {
  if (!card || card.hidden || !owner) return
  if (anchorEl && overlayBlocks(anchorEl)) hideHintCard()
}

/** 在 anchor 正下方顯示說明卡；who 用來標記目前是誰在顯示，供 hideHintCard 比對 */
export const showHintCard = (anchor, { title = '', body = '' } = {}, who = anchor) => {
  if (!anchor || typeof document === 'undefined') return
  if (overlayBlocks(anchor)) {
    hideHintCard()
    return
  }
  ensure()
  titleEl.textContent = title
  titleEl.hidden = !title
  bodyEl.textContent = body
  card.hidden = false
  owner = who
  anchorEl = anchor
  place(anchor)
}

export const hideHintCard = (who) => {
  if (!card) return
  if (who !== undefined && owner !== who) return
  card.hidden = true
  owner = null
}
