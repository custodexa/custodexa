import { onBeforeUnmount, watch } from 'vue'

/**
 * 錨定彈出框開著時，Esc 只關這個彈出框。
 *
 * 外層抽屜與對話框在 document 上監聽 Esc，彈出框內外按下的 Esc 都會冒泡到那裡，
 * 連外層一起關掉。這裡在 window 的捕獲階段先處理並停止傳遞，外層就收不到同一個 Esc。
 * 只在彈出框開著時掛監聽，關閉或元件卸載即移除。
 *
 * @param {() => boolean} isOpen - 彈出框是否開著
 * @param {() => void} close - 關閉彈出框（含焦點回到觸發處）
 */
export function useEscapeToClose(isOpen, close) {
  const onKeydown = (event) => {
    if (event.key !== 'Escape' || event.isComposing) return
    event.stopPropagation()
    event.preventDefault()
    close()
  }
  const detach = () => window.removeEventListener('keydown', onKeydown, true)
  watch(
    isOpen,
    (open) => {
      detach()
      if (open) window.addEventListener('keydown', onKeydown, true)
    },
    { immediate: true },
  )
  onBeforeUnmount(detach)
}
