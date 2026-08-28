import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  SOURCE_POLICY_MAX_ENTRIES,
  looksLikeSourceAddress,
  looksLikeSourcePrefix,
  sourceFamiliesKey,
} from '../sourcePolicy'

// 前端格式提示 vs 後端判定的**單向**契約：
// 前端可以放過後端會拒的（送出後端點回 error_code，就近顯示），
// 但**不可擋下後端會收的**——擋錯的那一項使用者連送都送不出去，
// 而畫面上只會說「格式不對」，不會說其實它是合法的。
//
// 共用向量檔由 docker-compose.dev.yml 以唯讀掛載送進前端容器
// （沿 audit-enums.spec.js 的 /repo 慣例）；無掛載時該案例 skip 並印出原因，
// 不是紅——純前端 CI 沒有後端原始碼可讀。

const resolveVectors = () =>
  [
    join(process.cwd(), '../backend/internal/sourceip/testdata/policy_vectors.json'),
    join(process.cwd(), '../../backend/internal/sourceip/testdata/policy_vectors.json'),
    '/repo/backend/internal/sourceip/testdata/policy_vectors.json',
  ].find((p) => existsSync(p))

const vectorPath = resolveVectors()
if (!vectorPath) {
  // eslint-disable-next-line no-console
  console.warn(
    '[sourcePolicyFormat] 共用向量檔不可讀，跳過向量案例。' +
      '開發環境請確認 docker-compose.dev.yml 已掛載 ' +
      'backend/internal/sourceip/testdata 至 /repo'
  )
}

describe('共用測試向量：格式提示不得拒絕後端判為合法的項目', () => {
  it.skipIf(!vectorPath)('valid=true 的每一項都通過格式提示', () => {
    const vectors = JSON.parse(readFileSync(vectorPath, 'utf8'))
    // 檔案讀成空陣列時整組斷言會「意外全綠」——先鎖下界（起草時 31 條）
    expect(
      vectors.length,
      '共用向量檔載到 0 條（路徑或格式變了？）'
    ).toBeGreaterThanOrEqual(31)

    const accepted = []
    const rejected = []
    for (const v of vectors) {
      if (v.valid !== true) continue
      for (const item of v.list || []) {
        (looksLikeSourcePrefix(item) ? accepted : rejected).push(
          `${v.name}：${JSON.stringify(item)}`
        )
      }
    }
    // 下界：向量裡確實有合法項目被檢查過（全部 valid 條目都是空清單時會假綠）
    expect(accepted.length, '沒有任何合法項目被檢查到').toBeGreaterThan(0)
    expect(
      rejected,
      `以下項目後端判為合法、卻被前端格式提示擋下（判準方向反了）：\n${rejected.join('\n')}`
    ).toEqual([])
  })

  it.skipIf(!vectorPath)('向量中的來源位址（非空者）亦不被位址格式提示擋下', () => {
    const vectors = JSON.parse(readFileSync(vectorPath, 'utf8'))
    const rejected = vectors
      .filter((v) => v.valid === true && v.address && v.allowed === true)
      .filter((v) => !looksLikeSourceAddress(v.address))
      .map((v) => `${v.name}：${JSON.stringify(v.address)}`)
    expect(
      rejected,
      `以下來源位址後端判定為放行、卻不被前端視為位址：\n${rejected.join('\n')}`
    ).toEqual([])
  })
})

describe('looksLikeSourcePrefix（寬鬆格式層）', () => {
  it('接受裸位址、CIDR、IPv6 縮寫、zone 與 IPv4-mapped', () => {
    for (const v of [
      '10.1.2.3',
      '10.0.0.0/8',
      '0.0.0.0/0',
      '::/0',
      '2001:db8::/32',
      '2001:0db8:0000:0000:0000:0000:0000:0000/32',
      'fe80::1%eth0',
      '::ffff:10.1.2.3',
      '::ffff:10.0.0.0/104',
      '  10.0.0.0/8  ',
    ]) {
      expect(looksLikeSourcePrefix(v), `${v} 應通過`).toBe(true)
    }
  })

  it('擋下明顯不是位址的輸入', () => {
    for (const v of ['gateway.example', 'not an address', '', '   ', '10.0.0.0/x', null]) {
      expect(looksLikeSourcePrefix(v), `${JSON.stringify(v)} 應被擋下`).toBe(false)
    }
  })

  it('後端才拒的邊界一律放行（判定權在後端，前端不預先擋）', () => {
    // 位址值域越界與前綴長度越界都由端點回 invalid，前端不重複判斷——
    // 重複判斷的兩套規則遲早分歧，而分歧的那一側會擋下合法輸入
    expect(looksLikeSourcePrefix('10.0.0.999/24')).toBe(true)
    expect(looksLikeSourcePrefix('10.0.0.0/33')).toBe(true)
  })
})

describe('looksLikeSourceAddress（位址樞紐的自由輸入）', () => {
  it('不接受帶前綴長度的網段——樞紐是單一位址，不是網段查詢', () => {
    expect(looksLikeSourceAddress('10.0.0.0/8')).toBe(false)
    expect(looksLikeSourceAddress('10.1.2.3')).toBe(true)
    expect(looksLikeSourceAddress('2001:db8::1')).toBe(true)
  })
})

describe('sourceFamiliesKey', () => {
  it('三種家族組合各自對到一個文案鍵尾碼', () => {
    expect(sourceFamiliesKey(['v4'])).toBe('v4')
    expect(sourceFamiliesKey(['v6'])).toBe('v6')
    expect(sourceFamiliesKey(['v6', 'v4'])).toBe('both')
  })

  it('缺席或空陣列回空字串（呼叫端據此不顯示該句）', () => {
    expect(sourceFamiliesKey(undefined)).toBe('')
    expect(sourceFamiliesKey([])).toBe('')
  })
})

describe('上限常數與後端同值', () => {
  it('每帳號 32 項', () => {
    expect(SOURCE_POLICY_MAX_ENTRIES).toBe(32)
  })
})

// looksLikeSourceAddress 的 IPv6 比對式在 2026-08 改寫過：把冒號移出段內字元集，
// 消除分割點歧義（原式耗時隨長度呈平方成長）。改寫的唯一驗收依據是**判定集合不變**，
// 故下表逐筆釘住接受與拒絕兩面。
//
// 注意本函式的語義是「看起來像不像位址」而非嚴格驗證：`:`、`::::`、`2001:db8::1:`
// 這些不是合法 IPv6，但**刻意仍為接受**。日後若有人覺得該收緊，那是行為變更，
// 要先改這張表並說明為什麼，不是順手改式子。
describe('looksLikeSourceAddress 的判定集合（改寫比對式的防退化基準）', () => {
  const ACCEPTED = [
    // 合法 IPv6：壓縮、全展開、邊界
    '2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001', '::1', '::', 'fe80::1',
    '2001:db8:0:0:1::1', 'ff02::1:2', 'a::b', '1:2:3:4:5:6:7:8',
    // 帶區域識別碼
    'fe80::1%eth0', 'fe80::1%en0', 'fe80::1%1', 'fe80::1%eth-0', 'fe80::1%eth_0', 'fe80::1%eth.0',
    // IPv4-mapped / embedded
    '::ffff:192.0.2.1', '::ffff:0:192.0.2.1', '64:ff9b::192.0.2.1',
    // 大小寫不敏感
    '2001:DB8::1', '2001:Db8::AbC',
    // 非合法位址但刻意接受（本函式只判「像不像」）
    ':', '::::', '2001:db8::1:',
    // 前後空白：函式先 trim 再比對，故仍為接受。
    // 這兩筆是差分驗證時的教訓——基準若只對比對式取樣，會漏掉函式層的正規化，
    // 把「函式接受」誤記成「應拒絕」。判定表要對函式取樣，不是對式子。
    '2001:db8::1 ', ' 2001:db8::1',
  ]

  const REJECTED = [
    // 空與純分隔符
    '', '.', '...', '%', '%eth0',
    // 非法字元、帶前綴長度
    'g::1', '2001:db8::z', 'hello',
    '2001:db8::1/64', '10.0.0.0/8', 'http://[::1]',
    // 區域識別碼形狀不合
    'fe80::1%', 'fe80::1%eth 0', 'fe80::1%%eth0',
    // 沒有冒號者不歸這條式子管（IPv4 由另一條負責，此處只驗 v6 式不誤收）
    '1.2.3.4.5', 'abc.def',
  ]

  it.each(ACCEPTED)('接受 %j', (value) => {
    expect(looksLikeSourceAddress(value)).toBe(true)
  })

  it.each(REJECTED)('拒絕 %j', (value) => {
    expect(looksLikeSourceAddress(value)).toBe(false)
  })

  it('IPv4 走另一條式子，不受本次改寫影響', () => {
    expect(looksLikeSourceAddress('10.1.2.3')).toBe(true)
    expect(looksLikeSourceAddress('0.0.0.0')).toBe(true)
    expect(looksLikeSourceAddress('255.255.255.255')).toBe(true)
  })

  // 回溯防護：以「耗時對長度的成長倍率」判定，不用絕對毫秒——
  // 絕對值隨機器與當下負載漂移，倍率可攜。原式在長度翻倍時耗時約成四倍（平方成長），
  // 改寫後接近線性。
  //
  // 取樣方式是這條測試能不能用的關鍵。改寫後單次比對只有數十微秒，在那個尺度上
  // 排程抖動會主導比值：單次取樣實測 20 回有 1 回衝破 2.5，正確的實碼被判紅。
  // 故改取多回合的中位數（抖動是單邊的偶發尖峰，中位數不受其影響），
  // 門檻放到 3.0——線性為 2、平方為 4，退化實測落在 3.9 以上，分離度仍足夠。
  it('比對耗時不隨輸入長度呈平方成長', () => {
    const measure = (n) => {
      const input = `${'1:'.repeat(n)}!` // 結尾字元不在任何字元集內，強制走完所有回溯
      const started = process.hrtime.bigint()
      looksLikeSourceAddress(input)
      return Number(process.hrtime.bigint() - started) / 1e6
    }

    measure(1000) // 暖身，避免首次呼叫的 JIT 成本混進比較

    const ratios = []
    for (let round = 0; round < 9; round += 1) {
      const short = Math.max(measure(4000), 0.001)
      const long = measure(8000)
      ratios.push(long / short)
    }
    ratios.sort((a, b) => a - b)
    const median = ratios[Math.floor(ratios.length / 2)]

    expect(median).toBeLessThan(3)
  })
})
