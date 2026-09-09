// 條文標題與摘要的查譯與回落。
//
// 資料庫存的條文文字只有一種語言，換語言不會跟著換；內建組另有三語譯文。
// 本檔釘住兩件事：條號轉鍵的規則（含國字款次與括號），以及「查得到譯文就用、
// 查不到就回落資料庫文字」在內建組、內建組的未知條號、機構自建組三種情境下
// 各自走對分支。
//
// 內建條號清單與後端種子同源但各存一份，兩邊漂了本檔就紅——條文增刪時譯文
// 沒跟上，畫面上是英日語使用者看到中文，不會有任何錯誤訊息。
import { describe, it, expect, afterEach } from 'vitest'
import i18n, { DEFAULT_LOCALE } from '@/i18n'
import { clauseLocaleKey, clauseSummary, clauseTitle } from '@/utils/policyClauseText'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

const LOCALES = { 'zh-TW': zhTW, 'en-US': enUS, 'ja-JP': jaJP }

const PCI_GROUP = 'pci_dss_4_0_1'
const EPAYMENT_GROUP = 'epayment_baseline'

// 內建組條號。標題三語齊備；摘要只在條文本身有摘要時存在。
const PCI_CLAUSE_NOS = [
  '8.3.4', '8.3.6', '8.3.7', '8.3.9', '8.6.3', '8.3.5', '8.4.2', '8.2.8',
  '8.2.6', '10.5.1', '10.4.1', '10.7.2', '10.2', '3.7.4', '4.2.1', '7.2',
]

const EPAYMENT_CLAUSE_NOS = [
  '15-1', '15-2', '15-3(一)', '15-3(二)', '15-3(三)', '15-3(四)', '15-4', '15-6',
  '15-7', '15-9', '4-7(一)', '4-7(二)', '4-7(五)', '4-7(六)', '4-7(七)', '4-7(八)',
  '15-8', '17-2', '21-8(三)', '16-3', '17-4', '17-5', '21-8(一)', '21-8(四)',
  '21-8(二)', '24-1', '19-4', '24-3', '16-5', '21-8(五)', '19-7', '21-6',
  '17-1(二)', '6-1', '15-5', '21-8(七)3', '21-8(七)1', '16-6', '24-2', '20-6',
]

const setLocale = (locale) => {
  i18n.global.locale.value = locale
}

afterEach(() => setLocale(DEFAULT_LOCALE))

describe('clauseLocaleKey 條號轉鍵', () => {
  it('點分條號的點換成底線', () => {
    expect(clauseLocaleKey('8.3.4')).toBe('c8_3_4')
    expect(clauseLocaleKey('10.2')).toBe('c10_2')
  })

  it('國字款次換成數字、括號併成底線', () => {
    expect(clauseLocaleKey('15-3(一)')).toBe('c15_3_1')
    expect(clauseLocaleKey('17-1(二)')).toBe('c17_1_2')
    expect(clauseLocaleKey('21-8(七)1')).toBe('c21_8_7_1')
  })

  it('尾端不留底線，且鍵不以數字開頭', () => {
    expect(clauseLocaleKey('4-7(八)')).toBe('c4_7_8')
    expect(clauseLocaleKey('24-1')).toBe('c24_1')
  })

  it('空條號回空字串（呼叫端據此回落）', () => {
    expect(clauseLocaleKey('')).toBe('')
    expect(clauseLocaleKey(undefined)).toBe('')
  })

  it('內建 56 條各自轉出不同的鍵', () => {
    for (const nos of [PCI_CLAUSE_NOS, EPAYMENT_CLAUSE_NOS]) {
      const keys = nos.map(clauseLocaleKey)
      expect(new Set(keys).size, `重複：${keys}`).toBe(nos.length)
    }
  })
})

describe('內建條文譯文完備性', () => {
  const titlePaths = [
    ...PCI_CLAUSE_NOS.map((no) => [PCI_GROUP, no]),
    ...EPAYMENT_CLAUSE_NOS.map((no) => [EPAYMENT_GROUP, no]),
  ]

  it.each(titlePaths)('%s %s 的標題三語齊備', (group, no) => {
    for (const [locale, messages] of Object.entries(LOCALES)) {
      const value = messages.policyClause?.[group]?.[clauseLocaleKey(no)]?.title
      expect(value, `${locale} 缺 ${group} ${no} 的標題`).toBeTruthy()
    }
  })

  it('有摘要的條文三語都有摘要，沒有的三語都沒有（不得只補一兩語）', () => {
    for (const [group, nos] of [
      [PCI_GROUP, PCI_CLAUSE_NOS],
      [EPAYMENT_GROUP, EPAYMENT_CLAUSE_NOS],
    ]) {
      for (const no of nos) {
        const key = clauseLocaleKey(no)
        const has = Object.entries(LOCALES).map(
          ([locale, messages]) => [locale, Boolean(messages.policyClause[group][key].summary)]
        )
        const distinct = new Set(has.map(([, v]) => v))
        expect(distinct.size, `${group} ${no} 三語摘要不一致：${JSON.stringify(has)}`).toBe(1)
      }
    }
  })

  it('譯文檔沒有多出種子以外的條文（條號改了就要一起改譯文）', () => {
    const expected = {
      [PCI_GROUP]: new Set(PCI_CLAUSE_NOS.map(clauseLocaleKey)),
      [EPAYMENT_GROUP]: new Set(EPAYMENT_CLAUSE_NOS.map(clauseLocaleKey)),
    }
    for (const [locale, messages] of Object.entries(LOCALES)) {
      expect(Object.keys(messages.policyClause).sort()).toEqual(
        Object.keys(expected).sort()
      )
      for (const [group, keys] of Object.entries(expected)) {
        const extra = Object.keys(messages.policyClause[group]).filter((k) => !keys.has(k))
        expect(extra, `${locale} 的 ${group} 多出 ${extra}`).toEqual([])
      }
    }
  })
})

describe('clauseTitle 與 clauseSummary 的查譯與回落', () => {
  const builtinClause = {
    group_code: EPAYMENT_GROUP,
    clause_no: '15-3(四)',
    title: '資料庫裡的中文正本',
    summary: '資料庫裡的中文摘要',
  }

  it('內建組：譯文優先於資料庫文字', () => {
    expect(clauseTitle(builtinClause)).toBe('對外主機要雙因子')
    expect(clauseSummary(builtinClause)).toBe(
      '用於提供網際網路服務之伺服器及目錄服務主機，應採雙因子認證'
    )
  })

  it('內建組：切語言即換譯文，不再顯示中文', () => {
    setLocale('en-US')
    expect(clauseTitle(builtinClause)).toBe(
      'Two-factor authentication for internet-facing hosts'
    )
    setLocale('ja-JP')
    expect(clauseTitle(builtinClause)).toBe('インターネット公開ホストの二要素認証')
  })

  it('內建組的未知條號：回落資料庫文字', () => {
    const removed = {
      group_code: PCI_GROUP,
      clause_no: '9.9.9',
      title: '已自規範移除的舊條文',
      summary: '',
    }
    setLocale('en-US')
    expect(clauseTitle(removed)).toBe('已自規範移除的舊條文')
    expect(clauseSummary(removed)).toBe('')
  })

  it('機構自建組：永遠回落資料庫文字（切語言也不變）', () => {
    const custom = {
      group_code: 'house_rules',
      clause_no: '1',
      title: '密碼至少 14 字元',
      summary: '內規要求高於外部基準',
    }
    for (const locale of ['zh-TW', 'en-US', 'ja-JP']) {
      setLocale(locale)
      expect(clauseTitle(custom)).toBe('密碼至少 14 字元')
      expect(clauseSummary(custom)).toBe('內規要求高於外部基準')
    }
  })

  it('沒有摘要的條文回空字串，呼叫端據此不顯示', () => {
    setLocale('en-US')
    expect(
      clauseSummary({ group_code: PCI_GROUP, clause_no: '8.3.6', title: 'x', summary: '' })
    ).toBe('')
  })

  it('缺欄位不炸（後端回的物件不完整時仍能渲染）', () => {
    expect(clauseTitle(null)).toBe('')
    expect(clauseTitle({})).toBe('')
    expect(clauseSummary({ group_code: PCI_GROUP })).toBe('')
  })
})
