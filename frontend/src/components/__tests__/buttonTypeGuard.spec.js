import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

// ui-design-system：Buttons declare their type
//
// HTML 把未宣告 type 的 button 預設為 submit。目前這些按鈕多半不在表單內，沒有實害，
// 但預設值使它們在日後被移進表單時**靜默改變行為**——不會有任何一行程式碼被編輯，
// 按鈕卻開始送出表單。條文沒有守衛就擋不住下一個漏寫的人，故本測試掃全樹。
//
// 只管原生 <button>。元件庫的按鈕（el-button 等）由該元件自己決定 type，不在射程內。

// 路徑以 cwd（frontend 根）為錨，對齊 audit-enums.spec.js／i18n.spec.js 的既有慣例
const SRC = join(process.cwd(), 'src')

const vueFiles = (dir) => {
  const out = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      if (entry === 'node_modules' || entry === '__tests__') continue
      out.push(...vueFiles(full))
    } else if (entry.endsWith('.vue')) {
      out.push(full)
    }
  }
  return out
}

// 取出每個 <button ...> 起始標籤的完整屬性區（可能跨多行），連同行號。
const buttonTags = (source) => {
  const tags = []
  const re = /<button(?=[\s>])/g
  let match
  while ((match = re.exec(source)) !== null) {
    const close = source.indexOf('>', match.index)
    if (close === -1) continue
    tags.push({
      attrs: source.slice(match.index, close),
      line: source.slice(0, match.index).split('\n').length,
    })
  }
  return tags
}

describe('原生 button 一律宣告 type', () => {
  it('全樹掃描：沒有任何 <button> 缺少 type', () => {
    const offenders = []
    for (const file of vueFiles(SRC)) {
      const source = readFileSync(file, 'utf8')
      for (const tag of buttonTags(source)) {
        if (!/\stype\s*=/.test(tag.attrs)) {
          offenders.push(`${relative(SRC, file)}:${tag.line}`)
        }
      }
    }

    // 失敗訊息要指得出是哪一個，而不是只說「有問題」
    expect(offenders).toEqual([])
  })

  it('掃描器本身有掃到東西（防止 glob 壞掉造成的空掃全綠）', () => {
    const total = vueFiles(SRC).reduce(
      (n, file) => n + buttonTags(readFileSync(file, 'utf8')).length,
      0
    )
    expect(total).toBeGreaterThan(5)
  })
})
