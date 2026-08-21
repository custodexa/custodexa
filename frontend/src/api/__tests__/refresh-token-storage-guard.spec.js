import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// refresh 憑證不得回到 script 可讀的儲存（refresh-token-httponly-cookie）。
//
// # 這個守衛在守什麼
//
// CodeQL 告警 #3／#4／#7／#8（js/clear-text-storage-of-sensitive-data）指的正是
// 「refresh 憑證明文存於 localStorage」。憑證遷入 httpOnly cookie 之後，寫回
// localStorage 的那三行如果哪天被補回來（例如某人為了「方便除錯」或誤以為
// 新端點需要），整個遷移就白做了，而**不會有任何行為測試轉紅**——
// 刷新照樣能用（cookie 仍在），只是憑證同時又躺在 XSS 讀得到的地方。
//
// 故本檔是源碼層的結構守衛：全 src/ 掃描，任何對 refresh_token 的儲存**寫入**
// 一律不允許。啟動清理用的 removeItem 是唯一例外，且它必須存在。
//
// # 突變自檢
//
//	在任一 .vue／.js 補上 localStorage.setItem('refresh_token', x) ⇒ 第一格轉紅。
//	拿掉 main.js 的 localStorage.removeItem('refresh_token') ⇒ 第二格轉紅。

const SRC_ROOT = join(process.cwd(), 'src')
const SCANNED_EXTENSIONS = ['.js', '.vue']

// 儲存寫入的形態：localStorage／sessionStorage 的 setItem，鍵為 refresh_token。
// 引號兩式都涵蓋——只擋一種等於留一條同效路徑
const WRITE_PATTERNS = [
  /(?:local|session)Storage\.setItem\(\s*['"]refresh_token['"]/,
  // 屬性式寫法（localStorage.refresh_token = x）同樣是寫入
  /(?:local|session)Storage\.refresh_token\s*=/,
]

function collectSourceFiles(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) {
      if (entry === 'node_modules' || entry === '__tests__') continue
      out.push(...collectSourceFiles(full))
      continue
    }
    if (SCANNED_EXTENSIONS.some((ext) => entry.endsWith(ext))) out.push(full)
  }
  return out
}

describe('refresh 憑證不落 script 可讀儲存', () => {
  const files = collectSourceFiles(SRC_ROOT)

  it('掃描檔數不得退化為空集合（否則本守衛永遠通過）', () => {
    // 空集合假綠是這類掃描守衛的頭號失效模式：目錄改名或副檔名清單漏項時，
    // 掃到零個檔案照樣「沒有違規」
    expect(files.length).toBeGreaterThan(50)
  })

  it('全 src/ 無任何 refresh_token 的儲存寫入', () => {
    const offenders = files.filter((f) => {
      const src = readFileSync(f, 'utf8')
      return WRITE_PATTERNS.some((re) => re.test(src))
    })
    expect(
      offenders,
      'refresh 憑證寫回 localStorage／sessionStorage：憑證重新變成 XSS 可外帶的明文，' +
        '而刷新功能照樣能用（cookie 仍在），沒有任何行為測試會轉紅'
    ).toEqual([])
  })

  it('應用入口無條件清除歷史殘值', () => {
    // 舊版登入過的瀏覽器仍留著一份明文。判斷式（if 有才刪）沒有意義——
    // 判斷本身就是一次讀取，這裡要的只是「確保它不在」
    const main = readFileSync(join(SRC_ROOT, 'main.js'), 'utf8')
    expect(main).toContain("localStorage.removeItem('refresh_token')")
  })
})
