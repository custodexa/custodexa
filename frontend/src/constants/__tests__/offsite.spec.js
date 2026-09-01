// 離機保管值域的三方一致性：**後端值域 ↔ 前端枚舉 ↔ 會話詳情對照表**。
//
// 形態沿 audit-enums.spec.js：硬拷對照組把「前端寫了什麼」釘住，
// 直讀 Go 原始碼的兩支把「後端有什麼」釘住——只有硬拷組時，兩邊一起漏補會互相
// 對照仍全綠（該檔註解記載的真實事故：後端 24 值、兩邊各只有 20 值）。
//
// 會話詳情對照表這一角不是抽象的：`offsite.state.*` 與 `offsite.stateHint.*`
// 各缺一個鍵，畫面上就是一個沒有文案的狀態。三語逐一斷言。
import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  OFFSITE_STATES,
  OFFSITE_CACHE_EXTRA_STATUSES,
  OFFSITE_STATUS_VALUES,
  OFFSITE_STATUS_TAG_TYPES,
  OFFSITE_EXPORT_ROW_STATUSES,
  OFFSITE_PROVIDERS,
  OFFSITE_CREDENTIAL_MODES,
  OFFSITE_TEST_STEPS,
  OFFSITE_TEST_STEPS_DISCLOSURE,
  OFFSITE_TEST_STEPS_ROUNDTRIP,
  OFFSITE_TEST_OUTCOMES,
  OFFSITE_TEST_CODES,
  OFFSITE_ERROR_CODES,
  OFFSITE_ORIGINS,
  offsiteStatusTagType,
  isKnownOffsiteStatus,
} from '../offsite'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

const LOCALES = { 'zh-TW': zhTW, 'en-US': enUS, 'ja-JP': jaJP }

const lookup = (messages, path) =>
  path.split('.').reduce((o, k) => (o == null ? o : o[k]), messages)

const expectKeyInAllLocales = (path) => {
  for (const [locale, messages] of Object.entries(LOCALES)) {
    const value = lookup(messages, path)
    expect(value, `${locale} 缺 ${path}`).toBeTruthy()
    expect(typeof value, `${locale} 的 ${path} 應為字串`).toBe('string')
  }
}

// 值域硬拷後端 `internal/offsite/state.go` 的 `AllStates()`
const BACKEND_STATES = [
  'pending',
  'uploading',
  'uploaded',
  'failed',
  'integrity_mismatch',
  'foreign',
  'local_purged',
]
// 擁有表快取的額外分類（同檔 `CacheSkipped*`）
const BACKEND_CACHE_EXTRA = ['skipped_missing', 'skipped_expired']
// 測試連線步驟（`internal/offsite/testconnection.go` 的 `Step*` 步驟名）
const BACKEND_TEST_STEPS = [
  'probe_bucket',
  'versioning',
  'retention',
  'write',
  'read',
  'delete',
]

// 直讀後端原始碼：路徑以 cwd（frontend 根）為錨，沿 audit-enums.spec.js 的
// 候選清單形態。docker-compose.dev.yml 已為 frontend 掛載
// ./backend/internal/offsite:/repo/backend/internal/offsite:ro；
// 無掛載的環境該案例 skip（測試清單可見 skipped，非靜默通過）
const resolveBackendSource = (file) =>
  [
    join(process.cwd(), `../backend/internal/offsite/${file}`),
    join(process.cwd(), `../../backend/internal/offsite/${file}`),
    `/repo/backend/internal/offsite/${file}`,
  ].find((p) => existsSync(p))

const statePath = resolveBackendSource('state.go')
const testConnPath = resolveBackendSource('testconnection.go')

// 抽 `StateXxx = "value"`。`StateCount` 是結構型別名而非狀態常數，
// 要求 `=` 與雙引號才不會誤收
const parseBackendStates = (src) => [
  ...new Set([...src.matchAll(/^\s*State\w+\s*=\s*"([a-z0-9_]+)"/gm)].map((m) => m[1])),
]
const parseBackendCacheExtra = (src) => [
  ...new Set(
    [...src.matchAll(/^\s*CacheSkipped\w+\s*=\s*"([a-z0-9_]+)"/gm)].map((m) => m[1])
  ),
]
// 抽 `ErrCodeXxx = "offsite.value"`
const parseBackendErrCodes = (src) => [
  ...new Set(
    [...src.matchAll(/^\s*ErrCode\w+\s*=\s*"(offsite\.[a-z0-9_]+)"/gm)].map((m) => m[1])
  ),
]
// 步驟名常數是 `StepProbeBucket = "probe_bucket"` 一族；
// `StepOK`／`StepWarn`／`StepFail` 是結果三態，值域不同故分開抽
const parseBackendTestSteps = (src) => {
  const outcomes = new Set(['ok', 'warn', 'fail'])
  return [
    ...new Set(
      [...src.matchAll(/^\s*Step\w+\s*=\s*"([a-z0-9_]+)"/gm)]
        .map((m) => m[1])
        .filter((v) => !outcomes.has(v))
    ),
  ]
}
const parseBackendTestOutcomes = (src) => [
  ...new Set(
    [...src.matchAll(/^\s*Step(?:OK|Warn|Fail)\s*=\s*"([a-z0-9_]+)"/gm)].map((m) => m[1])
  ),
]
const parseBackendTestCodes = (src) => [
  ...new Set(
    [...src.matchAll(/^\s*CodeTest\w+\s*=\s*"(offsite\.[a-z0-9_]+)"/gm)].map((m) => m[1])
  ),
]

describe('離機狀態值域（前端枚舉 ↔ 硬拷對照組）', () => {
  it('帳冊七態與硬拷組逐一相等', () => {
    expect([...OFFSITE_STATES].sort()).toEqual([...BACKEND_STATES].sort())
  })

  it('快取欄的額外兩分類與硬拷組逐一相等', () => {
    expect([...OFFSITE_CACHE_EXTRA_STATUSES].sort()).toEqual([...BACKEND_CACHE_EXTRA].sort())
  })

  it('會話詳情對照表的值域＝七態＋兩分類＋空字串，共十態', () => {
    expect(OFFSITE_STATUS_VALUES).toHaveLength(10)
    expect(OFFSITE_STATUS_VALUES).toContain('')
  })

  it('測試步驟六步與硬拷組相等，且兩段分組的聯集恰為全集且不重疊', () => {
    expect([...OFFSITE_TEST_STEPS].sort()).toEqual([...BACKEND_TEST_STEPS].sort())
    expect([...OFFSITE_TEST_STEPS_DISCLOSURE, ...OFFSITE_TEST_STEPS_ROUNDTRIP]).toEqual(
      OFFSITE_TEST_STEPS
    )
    const overlap = OFFSITE_TEST_STEPS_DISCLOSURE.filter((s) =>
      OFFSITE_TEST_STEPS_ROUNDTRIP.includes(s)
    )
    expect(overlap).toEqual([])
  })

  it('下載中心的子集全部落在十態值域內', () => {
    for (const s of OFFSITE_EXPORT_ROW_STATUSES) {
      expect(OFFSITE_STATUS_VALUES, `${s} 不在十態值域內`).toContain(s)
    }
  })

  it('tag 對照表涵蓋十態且無多餘鍵', () => {
    expect(Object.keys(OFFSITE_STATUS_TAG_TYPES).sort()).toEqual(
      [...OFFSITE_STATUS_VALUES].sort()
    )
  })

  it('未知狀態退回 info 且不被視為已知值（不顯示裸機器碼）', () => {
    expect(offsiteStatusTagType('brand_new_state')).toBe('info')
    expect(isKnownOffsiteStatus('brand_new_state')).toBe(false)
    expect(isKnownOffsiteStatus('')).toBe(true)
    expect(isKnownOffsiteStatus(undefined)).toBe(true)
  })
})

describe('離機值域（直讀後端 Go 常數，雙向）', () => {
  it.skipIf(!statePath)('帳冊狀態：Go 常數與前端枚舉互為全集', () => {
    const src = readFileSync(statePath, 'utf8')
    expect([...parseBackendStates(src)].sort()).toEqual([...OFFSITE_STATES].sort())
    expect([...parseBackendCacheExtra(src)].sort()).toEqual(
      [...OFFSITE_CACHE_EXTRA_STATUSES].sort()
    )
  })

  it.skipIf(!statePath)('帳冊錯誤碼：Go 常數與前端枚舉互為全集', () => {
    const src = readFileSync(statePath, 'utf8')
    expect([...parseBackendErrCodes(src)].sort()).toEqual([...OFFSITE_ERROR_CODES].sort())
  })

  it.skipIf(!testConnPath)('測試步驟、結果三態與步驟碼：Go 常數與前端枚舉互為全集', () => {
    const src = readFileSync(testConnPath, 'utf8')
    expect([...parseBackendTestSteps(src)].sort()).toEqual([...OFFSITE_TEST_STEPS].sort())
    expect([...parseBackendTestOutcomes(src)].sort()).toEqual(
      [...OFFSITE_TEST_OUTCOMES].sort()
    )
    expect([...parseBackendTestCodes(src)].sort()).toEqual([...OFFSITE_TEST_CODES].sort())
  })
})

describe('離機枚舉三語完備性（值域 × locale）', () => {
  it('十態的 tag 文案與 tooltip 三語皆有非空 key', () => {
    for (const v of OFFSITE_STATUS_VALUES) {
      const id = v === '' ? 'none' : v
      expectKeyInAllLocales(`offsite.state.${id}`)
      expectKeyInAllLocales(`offsite.stateHint.${id}`)
    }
  })

  it('下載中心狀態行三語皆有非空 key', () => {
    for (const v of OFFSITE_EXPORT_ROW_STATUSES) {
      expectKeyInAllLocales(`offsite.exportRow.${v}`)
    }
  })

  it('佇列摘要各態計數三語皆有非空 key', () => {
    for (const v of [...OFFSITE_STATES, 'total']) {
      expectKeyInAllLocales(`offsite.count.${v}`)
    }
  })

  it('測試步驟、結果三態與步驟碼三語皆有非空 key', () => {
    for (const v of OFFSITE_TEST_STEPS) {
      expectKeyInAllLocales(`offsite.testStep.${v}`)
    }
    for (const v of [...OFFSITE_TEST_OUTCOMES, 'skipped']) {
      expectKeyInAllLocales(`offsite.testOutcome.${v}`)
    }
    for (const v of OFFSITE_TEST_CODES) {
      expectKeyInAllLocales(`offsite.testCode.${v.replace(/^offsite\./, '')}`)
    }
  })

  it('帳冊錯誤碼三語皆有非空 key', () => {
    for (const v of OFFSITE_ERROR_CODES) {
      expectKeyInAllLocales(`offsite.errorCode.${v.replace(/^offsite\./, '')}`)
    }
  })

  it('provider、憑證模式與車道三語皆有非空 key', () => {
    for (const v of OFFSITE_PROVIDERS) {
      expectKeyInAllLocales(`offsite.provider.${v}`)
    }
    for (const v of [...OFFSITE_CREDENTIAL_MODES, 'none']) {
      expectKeyInAllLocales(`offsite.credentialMode.${v}`)
    }
    for (const v of OFFSITE_ORIGINS) {
      expectKeyInAllLocales(`offsite.origin.${v}`)
    }
  })
})
