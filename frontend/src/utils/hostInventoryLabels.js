// 主機帳號盤點檢查範圍的三語標籤：檢查項、狀態、原因與固定說明。
// 未知值一律走退路鍵並以可見化的原值呈現，不直接顯示主機回傳的原始字串。
import { t, te } from '@/i18n'
import { visibleText } from '@/utils/visibleName'
import { coveragePath } from '@/utils/hostInventoryPresentation'

export function checkLabel(c) {
  const key = `hostInventory.coverage.check.${c}`
  return te(key) ? t(key) : t('hostInventory.coverage.check.unknown', { raw: visibleText(c) })
}

/** 檢查項名稱，有檔案路徑的項目帶上路徑：「sudo 主規則檔（/etc/sudoers）」 */
export function checkLabelWithPath(item) {
  const label = checkLabel(item.check)
  const path = coveragePath(item)
  return path ? t('hostInventory.coverage.checkWithPath', { label, path: visibleText(path) }) : label
}

export function stateLabel(c) {
  const key = `hostInventory.coverage.state.${c.state}`
  if (!te(key)) return t('hostInventory.coverage.state.unknown', { raw: visibleText(c.state) })
  return t(key, { n: c.count || 0 })
}

export function reasonLabel(r) {
  const key = `hostInventory.coverage.reason.${r}`
  return te(key) ? t(key) : t('hostInventory.coverage.reason.other', { raw: visibleText(r) })
}

export function fixedLabel(n) {
  const key = `hostInventory.coverage.fixed.${n}`
  return te(key) ? t(key) : t('hostInventory.coverage.fixed.unknown', { raw: visibleText(n) })
}

/** 部分完成警示帶的一條缺項：「{項目}：{狀態}（原因）」 */
export function gapText(g) {
  const path = coveragePath(g)
  // sudo 規則因權限讀不到：照畫面稿寫成「讀不到 sudo 規則（路徑）：登入帳號沒有讀取權限。」
  if (path && g.state === 'unreadable' && g.reason === 'permission_denied') {
    return t('hostInventory.partial.gapSudo', { path: visibleText(path) })
  }
  // 專用帳號的提權讀取也被拒：與一般的「沒有讀取權限」分開寫，避免同一句原因重複
  if (path && g.state === 'unreadable' && g.reason === 'escalation_denied') {
    return t('hostInventory.partial.gapSudoEscalation', { path: visibleText(path) })
  }
  const base = t('hostInventory.partial.gap', { check: checkLabelWithPath(g), state: stateLabel(g) })
  return g.reason ? `${base}（${reasonLabel(g.reason)}）` : base
}
