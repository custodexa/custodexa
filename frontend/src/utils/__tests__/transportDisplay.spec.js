import { describe, it, expect, vi, afterEach } from 'vitest'
import i18n from '@/i18n'
import {
  riskLabel,
  inventoryNote,
  inventoryPreflight,
  inventoryDetail,
  RISK_REQUIRED_PARAMS,
  NOTE_REQUIRED_PARAMS,
  PREFLIGHT_COUNT_CODES,
} from '@/utils/transportDisplay'
import zhTW from '@/i18n/locales/zh-TW.json'

// i18n 由 setupFiles 全域注入、每測前重設 zh-TW。切語言＝設 locale.value。
function setLocale(l) {
  i18n.global.locale.value = l
}
afterEach(() => vi.restoreAllMocks())

describe('riskLabel — 當前語言查譯 + 降級', () => {
  const vnc = { key: 'vnc_unencrypted', label: 'VNC 協議未加密' }

  it('zh：查 riskLabel.<key> 得繁中', () => {
    expect(riskLabel(vnc)).toBe('VNC 協議未加密')
  })

  it('en：切語言即得英文（getter 反應性）', () => {
    setLocale('en-US')
    expect(riskLabel(vnc)).toBe('VNC protocol unencrypted')
  })

  it('syslog 帶 protocol params → 內插', () => {
    setLocale('en-US')
    const r = { key: 'syslog_non_tls', label: 'syslog 轉發未加密（udp）' }
    expect(riskLabel(r, { protocol: 'udp' })).toBe('Syslog forwarding unencrypted (udp)')
  })

  it('syslog 缺 protocol params → 降級後端 zh label，不露裸 slot／空括號', () => {
    setLocale('en-US')
    const r = { key: 'syslog_non_tls', label: 'syslog 轉發未加密（udp）' }
    const out = riskLabel(r)
    expect(out).toBe('syslog 轉發未加密（udp）')
    expect(out).not.toContain('{protocol}')
    expect(out).not.toContain('()')
  })

  it('缺鍵（舊後端無 key）→ 降級後端 label', () => {
    setLocale('en-US')
    expect(riskLabel({ label: '後端中文' })).toBe('後端中文')
  })

  it('未知 code → 降級 label 且 dev 期 console.warn', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    setLocale('en-US')
    expect(riskLabel({ key: 'made_up_risk', label: '後端中文' })).toBe('後端中文')
    expect(warn).toHaveBeenCalled()
  })
})

describe('inventoryNote / inventoryPreflight — 碼查譯 + 降級', () => {
  it('note：ssh_encrypted en', () => {
    setLocale('en-US')
    expect(inventoryNote({ note_code: 'ssh_encrypted', note: 'SSH 協議本身加密，不在政策範疇' }))
      .toBe('SSH is encrypted by protocol, outside policy scope')
  })

  it('note：syslog_protocol 帶 params 內插', () => {
    setLocale('en-US')
    expect(inventoryNote({ note_code: 'syslog_protocol', note_params: { protocol: 'udp' }, note: '轉發協議：udp' }))
      .toBe('Forwarding protocol: udp')
  })

  it('note：syslog_protocol 缺 params → 降級 zh note', () => {
    setLocale('en-US')
    expect(inventoryNote({ note_code: 'syslog_protocol', note: '轉發協議：udp' })).toBe('轉發協議：udp')
  })

  it('note：無 code → 舊 note', () => {
    setLocale('en-US')
    expect(inventoryNote({ note: 'x' })).toBe('x')
  })

  it('preflight：rdp_reject count plural（1 單數 / 3 複數）', () => {
    setLocale('en-US')
    expect(inventoryPreflight({ preflight_code: 'rdp_reject', preflight_params: { n: 1 }, strict_preflight: 'zh' }))
      .toBe('Switching to strict will reject 1 RDP asset')
    expect(inventoryPreflight({ preflight_code: 'rdp_reject', preflight_params: { n: 3 }, strict_preflight: 'zh' }))
      .toBe('Switching to strict will reject 3 RDP assets')
  })

  it('preflight：ldap_reject 無參', () => {
    setLocale('en-US')
    expect(inventoryPreflight({ preflight_code: 'ldap_reject', strict_preflight: 'zh' }))
      .toBe('Switching to strict will reject all LDAP logins (local accounts unaffected)')
  })

  it('preflight：rdp_reject 缺 n → 降級 zh strict_preflight', () => {
    setLocale('en-US')
    expect(inventoryPreflight({ preflight_code: 'rdp_reject', strict_preflight: '若切 strict 將拒絕 3 台 RDP 資產連線' }))
      .toBe('若切 strict 將拒絕 3 台 RDP 資產連線')
  })

  it('ja：清冊 syslog risk 經 display_params 成功翻譯（rr-I2）', () => {
    setLocale('ja-JP')
    const r = { key: 'syslog_non_tls', label: 'syslog 轉發未加密（udp）' }
    const out = riskLabel(r, { protocol: 'udp' })
    expect(out).toBe('syslog 転送が未暗号化（udp）')
    expect(out).not.toContain('{protocol}')
  })
})

describe('前端 required-param 常數防漂移', () => {
  // 從 zh-TW locale 的 {placeholder} 導出「哪些碼需 param」，比對前端三常數。
  // locale 由後端完備性測試釘死 ↔ registry，故此測試補上 locale↔前端常數 一環，成閉環。
  const slotRe = /\{([a-zA-Z_][a-zA-Z0-9_]*)\}/g
  const paramsOf = (s) => {
    const set = new Set()
    let m
    while ((m = slotRe.exec(s)) !== null) set.add(m[1])
    return set
  }

  it('riskLabel：帶 param 的碼恰為 RISK_REQUIRED_PARAMS 所列', () => {
    for (const [code, val] of Object.entries(zhTW.riskLabel)) {
      const slots = paramsOf(val)
      const declared = new Set(RISK_REQUIRED_PARAMS[code] || [])
      expect([...slots].sort()).toEqual([...declared].sort())
    }
  })

  it('transportNote：帶 param 的碼恰為 NOTE_REQUIRED_PARAMS 所列', () => {
    for (const [code, val] of Object.entries(zhTW.transportNote)) {
      const slots = paramsOf(val)
      const declared = new Set(NOTE_REQUIRED_PARAMS[code] || [])
      expect([...slots].sort()).toEqual([...declared].sort())
    }
  })

  it('transportPreflight：帶 {n} 的碼恰為 PREFLIGHT_COUNT_CODES', () => {
    const withN = Object.entries(zhTW.transportPreflight)
      .filter(([, val]) => paramsOf(val).has('n'))
      .map(([code]) => code)
    expect(new Set(withN)).toEqual(PREFLIGHT_COUNT_CODES)
  })
})

describe('inventoryDetail — detail_codes 完整 map（rr-I4）', () => {
  it('en：unset 譯、技術鍵原樣，不合併', () => {
    setLocale('en-US')
    expect(inventoryDetail({ detail_codes: { unset: 2, disable: 1 } }))
      .toEqual({ '(not set)': 2, disable: 1 })
  })

  it('ja：unset 全形括號（與 zh 不同）', () => {
    setLocale('ja-JP')
    expect(inventoryDetail({ detail_codes: { unset: 2 } })).toEqual({ '（未設定）': 2 })
  })

  it('無 detail_codes（舊後端）→ 回舊 detail', () => {
    setLocale('en-US')
    expect(inventoryDetail({ detail: { '(未設定)': 2, disable: 1 } }))
      .toEqual({ '(未設定)': 2, disable: 1 })
  })

  it('顯示鍵碰撞 → count 累加不覆蓋', () => {
    // zh：unset→"(未設定)"；髒資料若另有字面技術鍵 "(未設定)"（穿透），兩者累加
    expect(inventoryDetail({ detail_codes: { unset: 2, '(未設定)': 3 } })).toEqual({ '(未設定)': 5 })
  })
})
