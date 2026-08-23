/**
 * 頁籤批次關閉的純函數集
 * 一律回傳 { tabs, activeKey } 新值，不變更輸入
 */

function resolveActive(tabs, currentActive) {
  if (tabs.some((t) => t.key === currentActive)) return currentActive
  return tabs.length ? tabs[tabs.length - 1].key : ''
}

/** 關閉指定 key 以外的全部頁籤 */
export function closeOthers(tabs, targetKey) {
  const next = tabs.filter((t) => t.key === targetKey)
  return { tabs: next, activeKey: targetKey }
}

/** 關閉指定 key 左側的全部頁籤 */
export function closeLeft(tabs, targetKey, currentActive) {
  const idx = tabs.findIndex((t) => t.key === targetKey)
  if (idx <= 0) return { tabs, activeKey: currentActive }
  const next = tabs.slice(idx)
  return { tabs: next, activeKey: resolveActive(next, currentActive) }
}

/** 關閉指定 key 右側的全部頁籤 */
export function closeRight(tabs, targetKey, currentActive) {
  const idx = tabs.findIndex((t) => t.key === targetKey)
  if (idx < 0 || idx === tabs.length - 1) return { tabs, activeKey: currentActive }
  const next = tabs.slice(0, idx + 1)
  return { tabs: next, activeKey: resolveActive(next, currentActive) }
}

/** 關閉全部頁籤 */
export function closeAll() {
  return { tabs: [], activeKey: '' }
}
