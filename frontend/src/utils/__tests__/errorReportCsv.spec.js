// T4：錯誤清單 CSV 會回寫使用者填的值，使用者多半用 Excel 打開它。
// 擋的威脅：以 = + - @ Tab CR 開頭的值被試算表當成公式執行（CSV 公式注入）。
import { describe, it, expect } from 'vitest'
import { buildErrorReportCsv } from '../errorReportCsv'

const HEADER = ['列', '欄位', '填寫內容', '問題']

// 解析一列（本測試的值不含引號內換行，以逗號外的引號規則切）
function parseLine(line) {
  const cells = []
  let cur = ''
  let quoted = false
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]
    if (quoted) {
      if (ch === '"' && line[i + 1] === '"') {
        cur += '"'
        i += 1
      } else if (ch === '"') quoted = false
      else cur += ch
    } else if (ch === '"') quoted = true
    else if (ch === ',') {
      cells.push(cur)
      cur = ''
    } else cur += ch
  }
  cells.push(cur)
  return cells
}

describe('buildErrorReportCsv：錯誤清單 CSV 防公式注入', () => {
  it('六種公式前綴的值一律前置單引號，其餘值原樣輸出，檔首帶 BOM', () => {
    const risky = ['=1+1', '+SUM(1)', '-2+3', '@cmd', '\tTAB', '\rCR']
    const safe = ['web-prod-01', '10.0.0.1', '70000', '#99', 'a=b', '總部 / 機房A']
    const rows = [...risky, ...safe].map((value, i) => [i + 2, '名稱', value, '問題'])

    const csv = buildErrorReportCsv(HEADER, rows)

    expect(csv.charCodeAt(0)).toBe(0xfeff)
    const lines = csv.slice(1).split('\r\n').filter((l) => l !== '')
    // \r 開頭的值含 CR，必被引號包住；切行前先以引號規則還原
    const body = csv.slice(1)
    const values = []
    let rest = body.slice(body.indexOf('\r\n') + 2)
    while (rest.length) {
      let end = 0
      let quoted = false
      for (; end < rest.length; end += 1) {
        if (rest[end] === '"') quoted = !quoted
        if (!quoted && rest.startsWith('\r\n', end)) break
      }
      values.push(parseLine(rest.slice(0, end))[2])
      rest = rest.slice(end + 2)
    }

    expect(parseLine(lines[0])).toEqual(HEADER)
    expect(values.slice(0, risky.length)).toEqual(risky.map((v) => `'${v}`))
    expect(values.slice(risky.length)).toEqual(safe)
  })
})
