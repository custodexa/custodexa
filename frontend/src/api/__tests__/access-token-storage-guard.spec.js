import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

// access token 不得回到 script 可讀的儲存。
//
// # 這個守衛在守什麼
//
// access token 已改為只存頁面執行期記憶體。若哪天有人把它寫回 localStorage
// （為了「方便除錯」、或誤以為新頁面需要自行取用），整個遷移就白做了，而
// **不會有任何行為測試轉紅**——功能照樣能用，只是憑證同時又躺在一個跨頁面
// 載入存續、且頁面上任何 script 都讀得到的地方。
//
// 故本檔是源碼層的結構守衛：全 src/ 掃描，任何對 token 鍵的儲存讀寫一律不允許。
// 啟動清理用的 removeItem 是唯一例外，且它必須存在。
//
// # 守衛自檢
//
//	在任一 .vue／.js 補上 localStorage.setItem('token', x) ⇒ 第二格轉紅。
//	拿掉 main.js 的 localStorage.removeItem('token') ⇒ 第三格轉紅。

const SRC_ROOT = join(process.cwd(), 'src')
const SCANNED_EXTENSIONS = ['.js', '.vue']

// 讀與寫都擋：讀取一個不該存在的鍵，本身就代表某處還在寫它。
// 引號兩式都涵蓋——只擋一種等於留一條同效路徑
const ACCESS_PATTERNS = [
  /(?:local|session)Storage\.(?:getItem|setItem)\(\s*['"]token['"]/,
  // 屬性式寫法（localStorage.token = x／const t = localStorage.token）同樣是存取
  /(?:local|session)Storage\.token\b/,
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

describe('access token 不落 script 可讀儲存', () => {
  const files = collectSourceFiles(SRC_ROOT)

  it('掃描檔數不得退化為空集合（否則本守衛永遠通過）', () => {
    // 空集合假綠是這類掃描守衛的頭號失效模式：目錄改名或副檔名清單漏項時，
    // 掃到零個檔案照樣「沒有違規」
    expect(files.length).toBeGreaterThan(50)
  })

  it('全 src/ 無任何 access token 的儲存讀寫', () => {
    const offenders = files.filter((f) => {
      const src = readFileSync(f, 'utf8')
      return ACCESS_PATTERNS.some((re) => re.test(src))
    })
    expect(
      offenders,
      'access token 進了 localStorage／sessionStorage：憑證重新變成跨頁面載入存續的明文，' +
        '而功能照樣能用，沒有任何行為測試會轉紅'
    ).toEqual([])
  })

  it('應用入口無條件清除歷史殘值', () => {
    // 舊版登入過的瀏覽器仍留著一份明文。判斷式（if 有才刪）沒有意義——
    // 判斷本身就是一次讀取，這裡要的只是「確保它不在」
    const main = readFileSync(join(SRC_ROOT, 'main.js'), 'utf8')
    expect(main).toContain("localStorage.removeItem('token')")
  })

  it('使用者資料快取仍留在 localStorage（非憑證，且是登入跡象的載體）', () => {
    // 對照組：本守衛擋的是憑證，不是「所有 localStorage 使用」。
    // user 快取存的是帳號名、角色與顯示名——後端才是權限強制點，
    // 而它同時是「曾登入且未登出」的唯一前端可觀察訊號（見會話模組）
    const session = readFileSync(join(SRC_ROOT, 'utils', 'session.js'), 'utf8')
    expect(session).toContain("const USER_KEY = 'user'")
  })
})
