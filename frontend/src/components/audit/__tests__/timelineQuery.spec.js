import { describe, it, expect } from 'vitest'
import {
  UNKNOWN_SOURCE,
  WORKBENCH_PATH,
  buildAddressPivotLink,
  buildWorkbenchQuery,
  localDayRange,
  parseWorkbenchQuery,
  sameQuery,
} from '../timelineQuery'
import { TIMELINE_TYPES } from '../timelineSummary'

// 工作台狀態 ↔ query string 的唯一轉換點。位址樞紐把一個**字串**主體鍵放進
// 原本只裝整數 id 的位置，本檔盯住那條路徑不再退化成人樞紐。

const ADDRESS = '203.0.113.5'
const V6 = '2001:db8::1'
const FROM = '2026-08-26T00:00:00+08:00'
const TO = '2026-08-27T00:00:00+08:00'

describe('三樞紐往返', () => {
  it('人／資產樞紐的主體鍵仍是整數', () => {
    for (const subject of ['user', 'asset']) {
      const parsed = parseWorkbenchQuery({ subject, id: '7' })
      expect(parsed.subject).toBe(subject)
      expect(parsed.subjectId).toBe(7)
      expect(parsed.subjectIp).toBe('')
      expect(buildWorkbenchQuery(parsed)).toMatchObject({ subject, id: '7' })
    }
  })

  it('位址樞紐的主體鍵原樣保留字串，不轉整數、不壓成人樞紐', () => {
    const parsed = parseWorkbenchQuery({ subject: 'ip', id: ADDRESS })
    expect(parsed.subject).toBe('ip')
    expect(parsed.subjectIp).toBe(ADDRESS)
    // Number('203.0.113.5') 是 NaN：走整數路徑會把合法範圍靜默丟成「沒選對象」
    expect(parsed.subjectId).toBeNull()
    expect(buildWorkbenchQuery(parsed).id).toBe(ADDRESS)
  })

  it('IPv6 縮寫形式逐字往返（正規化是後端的事）', () => {
    const parsed = parseWorkbenchQuery({ subject: 'ip', id: V6 })
    expect(parsed.subjectIp).toBe(V6)
    expect(buildWorkbenchQuery(parsed).id).toBe(V6)
  })

  it('未知樞紐值退回人樞紐（不放隱藏樞紐進來）', () => {
    expect(parseWorkbenchQuery({ subject: 'network' }).subject).toBe('user')
  })

  it('位址樞紐無主體時不寫 id（避免 ?id= 噪音）', () => {
    expect(
      buildWorkbenchQuery({ subject: 'ip', subjectIp: '', types: [...TIMELINE_TYPES] })
    ).toEqual({ subject: 'ip' })
  })
})

describe('來源位址篩選（人／資產樞紐）', () => {
  it('ip 參數往返，並與主體鍵各自獨立', () => {
    const parsed = parseWorkbenchQuery({ subject: 'user', id: '7', ip: ADDRESS })
    expect(parsed.subjectId).toBe(7)
    expect(parsed.clientIp).toBe(ADDRESS)
    expect(buildWorkbenchQuery(parsed)).toMatchObject({
      subject: 'user',
      id: '7',
      ip: ADDRESS,
    })
  })

  it('保留字 unknown 原樣往返（後端於正規化之前判定）', () => {
    const parsed = parseWorkbenchQuery({ subject: 'asset', id: '3', ip: UNKNOWN_SOURCE })
    expect(parsed.clientIp).toBe('unknown')
    expect(buildWorkbenchQuery(parsed).ip).toBe('unknown')
  })

  it('位址樞紐下不承載位址篩選（兩者並存後端回 400）', () => {
    const parsed = parseWorkbenchQuery({ subject: 'ip', id: ADDRESS, ip: '10.0.0.1' })
    expect(parsed.clientIp).toBe('')
    expect(buildWorkbenchQuery(parsed).ip).toBeUndefined()
  })

  it('空篩選不寫入 URL', () => {
    expect(buildWorkbenchQuery({ subject: 'user', subjectId: 7, clientIp: '' }).ip)
      .toBeUndefined()
  })
})

describe('buildAddressPivotLink', () => {
  it('保留時間窗與類別選擇（點下去是接續同一段調查）', () => {
    const link = buildAddressPivotLink(ADDRESS, {
      from: FROM,
      to: TO,
      types: ['session', 'command'],
    })
    expect(link.path).toBe(WORKBENCH_PATH)
    expect(link.query).toEqual({
      subject: 'ip',
      id: ADDRESS,
      from: FROM,
      to: TO,
      types: 'session,command',
    })
  })

  it('類別全開時省略 types（缺席＝全部，與 URL 三態一致）', () => {
    const link = buildAddressPivotLink(ADDRESS, {
      from: FROM,
      to: TO,
      types: [...TIMELINE_TYPES],
    })
    expect(link.query.types).toBeUndefined()
  })

  it('未給範圍時預設全部類別、不帶時間窗', () => {
    expect(buildAddressPivotLink(ADDRESS).query).toEqual({ subject: 'ip', id: ADDRESS })
  })

  it('focus 與 view 不隨深連結帶走（前者屬另一樞紐、後者是個人偏好）', () => {
    const link = buildAddressPivotLink(ADDRESS, { from: FROM, to: TO })
    expect(link.query.focus).toBeUndefined()
    expect(link.query.view).toBeUndefined()
  })

  it('位址為空時回 null——沒有目的地的連結是假話', () => {
    expect(buildAddressPivotLink('')).toBeNull()
    expect(buildAddressPivotLink(null)).toBeNull()
    expect(buildAddressPivotLink('   ')).toBeNull()
  })

  it('產出的連結可被 parse 還原成同一個範圍', () => {
    const link = buildAddressPivotLink(V6, { from: FROM, to: TO, types: ['alert'] })
    const parsed = parseWorkbenchQuery(link.query)
    expect(parsed.subject).toBe('ip')
    expect(parsed.subjectIp).toBe(V6)
    expect(parsed.from).toBe(FROM)
    expect(parsed.to).toBe(TO)
    expect(parsed.types).toEqual(['alert'])
  })
})

describe('localDayRange（告警深連結的當日窗）', () => {
  it('回傳本地整日起訖，長度恰 24 小時', () => {
    const [from, to] = localDayRange('2026-08-26T13:45:12Z')
    expect(from).toMatch(/T00:00:00/)
    expect(new Date(to) - new Date(from)).toBe(24 * 3600 * 1000)
  })

  it('無效時刻回兩個空字串（不捏造一個窗）', () => {
    expect(localDayRange('not-a-time')).toEqual(['', ''])
  })
})

describe('sameQuery 對新參數同樣分辨缺席與空值', () => {
  it('ip 缺席與 ip="" 不相等（否則篩選清空寫不回 URL）', () => {
    expect(sameQuery({ subject: 'user' }, { subject: 'user', ip: '' })).toBe(false)
  })

  it('同一組位址參數視為相等（避免 router.replace 自我觸發）', () => {
    expect(
      sameQuery({ subject: 'ip', id: ADDRESS }, { subject: 'ip', id: ADDRESS })
    ).toBe(true)
  })
})
