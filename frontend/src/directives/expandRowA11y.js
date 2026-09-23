import { t } from '@/i18n'

// Element Plus 的 `type="expand"` 欄自行渲染展開箭頭，且渲染成一個只掛 onClick
// 的 div：沒有 role、tabIndex 是 -1、也不處理鍵盤。那顆箭頭在好幾張表上是唯一
// 的展開入口，等於「只有滑鼠能用」。EP 不開放這顆圖示的 slot，所以在表格層
// 補齊語意與鍵盤：加 role/tabindex/可及名稱，並讓 Enter 與 Space 等同點擊。
const ICON_SELECTOR = '.el-table__expand-icon'
const EXPANDED_CLASS = 'el-table__expand-icon--expanded'
const BOUND = 'expandA11yBound'

function onKeydown(event) {
  if (event.key !== 'Enter' && event.key !== ' ' && event.key !== 'Spacebar') return
  // Space 預設會捲動頁面；這顆現在是按鈕，行為要與按鈕一致
  event.preventDefault()
  event.currentTarget.click()
}

function decorate(icon) {
  icon.setAttribute('role', 'button')
  icon.setAttribute('tabindex', '0')
  icon.setAttribute('aria-expanded', String(icon.classList.contains(EXPANDED_CLASS)))
  // 名稱不可省：有 role=button 卻沒有可及名稱會被 axe 判為 serious
  icon.setAttribute('aria-label', t('common.toggleRowDetail'))
  if (icon.dataset[BOUND] === 'true') return
  icon.dataset[BOUND] = 'true'
  icon.addEventListener('keydown', onKeydown)
}

function apply(el) {
  el.querySelectorAll(ICON_SELECTOR).forEach(decorate)
}

// mounted 與 updated 都要跑：列資料換頁、展開狀態改變都會重繪箭頭
export const expandRowA11y = {
  mounted: apply,
  updated: apply,
}

export default expandRowA11y
