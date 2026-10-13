// 實心危險鈕的底色 token 須讓白字達 WCAG AA（4.5:1）。
// jsdom／happy-dom 不算 CSS 層疊，按鈕實際底色由 dev 實走量測；這裡只守 token 數值：
// 有人改了實底階的色值、或把文字階 --ot-danger 也一併調掉時會擋下。
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// vitest 以 frontend/ 為根執行
const tokensCss = readFileSync(join(process.cwd(), 'src/styles/tokens.css'), 'utf8')

function tokenValue(name) {
  const m = tokensCss.match(new RegExp(`${name}\\s*:\\s*(#[0-9a-fA-F]{6})\\s*;`))
  if (!m) throw new Error(`token ${name} not found as a 6-digit hex value`)
  return m[1].toLowerCase()
}

function relativeLuminance(hex) {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255)
  const [r, g, b] = channels.map((c) =>
    c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  )
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function contrastWithWhite(hex) {
  return (1 + 0.05) / (relativeLuminance(hex) + 0.05)
}

describe('danger fill tokens', () => {
  it.each(['--ot-danger-fill', '--ot-danger-fill-hover'])(
    '%s carries a white label at 4.5:1 or more',
    (name) => {
      expect(contrastWithWhite(tokenValue(name))).toBeGreaterThanOrEqual(4.5)
    }
  )

  it('--ot-danger stays the text step value', () => {
    expect(tokenValue('--ot-danger')).toBe('#e5604f')
  })
})
