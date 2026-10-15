import { reactive } from 'vue'
import { formatAssetLabel } from '@/utils/asset-label'

// 平均字寬每種字型量一次並快取；量不到（無 canvas）時以 13px 介面字型的經驗值代替
const FALLBACK_CHAR_WIDTH = 7
let textMeasurer
function getTextMeasurer() {
  if (textMeasurer !== undefined) return textMeasurer
  textMeasurer = null
  try {
    const ctx = document.createElement('canvas').getContext('2d')
    if (ctx) {
      const family = getComputedStyle(document.documentElement).getPropertyValue('--ot-font-sans').trim() || 'sans-serif'
      ctx.font = `13px ${family}`
      const sample = 'abcdefghijklmnopqrstuvwxyz0123456789-.'
      const avg = ctx.measureText(sample).width / sample.length
      if (avg > 0) textMeasurer = { avg, width: (text) => ctx.measureText(text).width }
    }
  } catch { /* 無 canvas：退回經驗值 */ }
  return textMeasurer
}

function fitLabel(name, width) {
  const text = String(name ?? '')
  const measurer = getTextMeasurer()
  if (measurer && measurer.width(text) <= width) return text
  let n = Math.floor(width / (measurer ? measurer.avg : FALLBACK_CHAR_WIDTH))
  if (n >= text.length) return text
  // 平均字寬只是起點：實際量一次，超出就逐字退，確保尾碼不被 CSS 省略吃掉
  if (measurer) {
    while (n > 0 && measurer.width(formatAssetLabel(text, n)) > width) n -= 1
  }
  return formatAssetLabel(text, n)
}

/**
 * 側欄名稱截斷：依名稱欄實際寬度換算可放字數。
 * 名稱欄 flex:1、min-width:0，寬度只由列寬決定、與文字無關：量它即得可用寬度。
 * 全部列共用一個 ResizeObserver。
 */
export function useAssetNameFit() {
  const nameWidths = reactive(new Map())
  const nameElements = new Map()
  const nameRefFns = new Map()
  let nameObserver = null

  function ensureNameObserver() {
    if (nameObserver || typeof ResizeObserver === 'undefined') return nameObserver
    nameObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const key = entry.target?.dataset?.rowKey
        if (key) nameWidths.set(key, Math.floor(entry.contentRect.width))
      }
    })
    return nameObserver
  }

  function nameRef(key) {
    if (!nameRefFns.has(key)) {
      nameRefFns.set(key, (el) => {
        const prev = nameElements.get(key)
        if (prev === el) return
        if (prev) nameObserver?.unobserve(prev)
        if (el) {
          nameElements.set(key, el)
          ensureNameObserver()?.observe(el)
        } else {
          nameElements.delete(key)
          nameRefFns.delete(key)
          nameWidths.delete(key)
        }
      })
    }
    return nameRefFns.get(key)
  }

  const assetLabel = (row) => {
    const width = nameWidths.get(row.rowKey)
    return width === undefined ? String(row.asset.name ?? '') : fitLabel(row.asset.name, width)
  }

  function dispose() {
    nameObserver?.disconnect()
    nameObserver = null
  }

  return { nameRef, assetLabel, dispose }
}
