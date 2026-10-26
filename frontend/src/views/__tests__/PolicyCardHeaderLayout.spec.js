import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

// 兩欄版面下卡片變窄，標題與偏離數不得被擠成直排。
// jsdom 類環境不做版面計算，這裡斷言關鍵樣式規則存在；實際寬螢幕 1440 與 900px 斷點由截圖確認。
const src = readFileSync(resolve(__dirname, '../../components/PolicyKeySections.vue'), 'utf8')
const rule = (selector) => {
  const m = new RegExp(`${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\{([^}]*)\\}`).exec(src.split('<style')[1])
  return m ? m[1] : ''
}

describe('分區卡片標題列的版面規則', () => {
  it('標題列可換行，標題與偏離數不折行', () => {
    expect(rule('.card-header')).toMatch(/flex-wrap:\s*wrap/)
    expect(rule('.card-title')).toMatch(/white-space:\s*nowrap/)
    expect(rule('.card-deviation')).toMatch(/white-space:\s*nowrap/)
    expect(rule('.card-deviation')).toMatch(/flex-shrink:\s*0/)
  })

  it('描述有基準寬度與 min-width: 0，放不下時整段換行而不是壓縮標題', () => {
    expect(rule('.card-hint')).toMatch(/flex:\s*1 1 16rem/)
    expect(rule('.card-hint')).toMatch(/min-width:\s*0/)
  })
})
