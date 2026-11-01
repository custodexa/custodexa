import { watch } from 'vue'
import { t } from '@/i18n'
import { previewOverlay } from '@/utils/previewOverlay'
import { showHintCard, hideHintCard, recheckHintCard } from '@/utils/previewHintCard'

/**
 * 寫入動作標記：`v-preview-write`（一般寫入類）、`v-preview-write:create`（新增類）、
 * `v-preview-write:ticket`（需簽發票證的動作：播放錄影、監看、連線、分享）。
 *
 * 以此角色預覽期間，帶標記的元素呈現但停用；滑過或聚焦時在元素正下方顯示錨定說明卡，
 * 同一句也寫進 aria-description 供輔助科技讀取；點擊在捕獲階段被吃掉，處理函式不會執行。
 * 滑過以文件層級的座標比對判斷（停用的表單元素在部分瀏覽器不送滑鼠事件）。
 * 覆蓋不存在時什麼都不做，DOM 與未加指令時完全相同。
 *
 * 標記只是呈現。保證寫入不送出的是 `request.js` 的預覽攔截，漏標只會看到預覽拒絕訊息。
 */

const STATE = Symbol('previewWrite')

const messageKey = (binding) => {
  const kind = binding?.arg || binding?.value
  if (kind === 'create') return 'rolePreview.disabledCreate'
  if (kind === 'ticket') return 'rolePreview.disabledTicket'
  return 'rolePreview.disabledAction'
}

const swallow = (event) => {
  event.preventDefault()
  event.stopImmediatePropagation()
}
// 非原生按鈕的元素（整列可點的 div）以 Enter／空白鍵啟動，一併吃掉
const swallowKey = (event) => {
  if (event.key === 'Enter' || event.key === ' ') swallow(event)
}

// 已套用停用的元素；有元素時才掛文件層級的監聽
const active = new Set()
let listening = false
let hovered = null

const hit = (x, y) => {
  for (const el of active) {
    if (!el.isConnected) continue
    const r = el.getBoundingClientRect()
    if (r.width && x >= r.left && x <= r.right && y >= r.top && y <= r.bottom) return el
  }
  return null
}
const showFor = (el) => showHintCard(el, { body: el.getAttribute('aria-description') || '' }, el)
const onMove = (event) => {
  const el = hit(event.clientX, event.clientY)
  if (el === hovered) {
    // 同一個元素：浮層收掉之後補顯示（被擋住時 showFor 會自行維持收起）
    if (el) showFor(el)
    return
  }
  if (hovered) hideHintCard(hovered)
  hovered = el
  if (el) showFor(el)
}
// 點擊可能展開選單：稍後檢查，被浮層擋住就收起說明卡
const onClickAny = () => {
  setTimeout(recheckHintCard, 0)
  setTimeout(recheckHintCard, 200)
}
const onDismiss = () => {
  if (hovered) hideHintCard(hovered)
  hovered = null
}
const onKey = (event) => {
  if (event.key === 'Escape') onDismiss()
}
const onFocus = (event) => showFor(event.currentTarget)
const onBlur = (event) => hideHintCard(event.currentTarget)

const track = (el) => {
  active.add(el)
  el.addEventListener('click', swallow, true)
  el.addEventListener('keydown', swallowKey, true)
  el.addEventListener('focus', onFocus)
  el.addEventListener('blur', onBlur)
  if (listening) return
  listening = true
  document.addEventListener('mousemove', onMove, true)
  document.addEventListener('scroll', onDismiss, true)
  document.addEventListener('keydown', onKey, true)
  document.addEventListener('click', onClickAny, true)
}
const untrack = (el) => {
  active.delete(el)
  el.removeEventListener('click', swallow, true)
  el.removeEventListener('keydown', swallowKey, true)
  el.removeEventListener('focus', onFocus)
  el.removeEventListener('blur', onBlur)
  hideHintCard(el)
  if (hovered === el) hovered = null
  if (active.size || !listening) return
  listening = false
  document.removeEventListener('mousemove', onMove, true)
  document.removeEventListener('scroll', onDismiss, true)
  document.removeEventListener('keydown', onKey, true)
  document.removeEventListener('click', onClickAny, true)
}

const apply = (el, binding) => {
  const st = el[STATE]
  if (!st) return
  if (previewOverlay.value) {
    if (!st.applied) {
      st.saved = {
        disabled: el.hasAttribute('disabled') ? el.getAttribute('disabled') : null,
        ariaDisabled: el.getAttribute('aria-disabled'),
        ariaDescription: el.getAttribute('aria-description'),
        disabledClass: el.classList.contains('is-disabled'),
      }
      st.applied = true
      track(el)
    }
    const message = t(messageKey(binding))
    el.setAttribute('disabled', '')
    el.setAttribute('aria-disabled', 'true')
    el.setAttribute('aria-description', message)
    el.setAttribute('data-preview-disabled', '')
    el.classList.add('is-disabled')
  } else if (st.applied) {
    st.applied = false
    untrack(el)
    const restore = (name, value) => {
      if (value === null) el.removeAttribute(name)
      else el.setAttribute(name, value)
    }
    restore('disabled', st.saved.disabled)
    restore('aria-disabled', st.saved.ariaDisabled)
    restore('aria-description', st.saved.ariaDescription)
    el.removeAttribute('data-preview-disabled')
    if (!st.saved.disabledClass) el.classList.remove('is-disabled')
  }
}

export const previewWrite = {
  mounted(el, binding) {
    el[STATE] = { applied: false, saved: null, binding, stop: null }
    el[STATE].stop = watch(previewOverlay, () => apply(el, el[STATE].binding), { flush: 'sync' })
    apply(el, binding)
  },
  updated(el, binding) {
    if (!el[STATE]) return
    el[STATE].binding = binding
    // 元件重繪可能把屬性寫回去：預覽中重新套用
    apply(el, binding)
  },
  unmounted(el) {
    const st = el[STATE]
    if (!st) return
    st.stop?.()
    untrack(el)
    delete el[STATE]
  },
}

export default previewWrite
