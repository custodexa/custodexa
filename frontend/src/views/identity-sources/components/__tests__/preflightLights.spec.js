// 接通前確認的燈號純函式。守的是「綠燈只代表驗過且通過」：
// 任何無資料的輸入都不得得到 ok，且以時間最新的觀測決定群組燈。
import { describe, it, expect } from 'vitest'
import {
  discoveryLight,
  credentialLight,
  groupsLight,
  rulesLight,
  ldapLights,
  computeLights,
  computeSummary,
} from '../preflightLights'

const fmt = (v) => `T(${v})`
const L = 'identitySources.preflight.light.'
const T1 = '2026-10-13T06:00:00Z'
const T2 = '2026-10-13T07:00:00Z'
const T3 = '2026-10-13T08:00:00Z'

const ISSUER = 'https://idp.example.com'
const rec = (over = {}) => ({
  result: { issuer: ISSUER, issuer_matches: true, signing_alg_compatible: true },
  errorKind: null,
  at: T2,
  issuer: ISSUER,
  ...over,
})
const disc = (over = {}, flags = {}) => ({ record: rec(over), stale: false, unsaved: false, ...flags })

describe('探索燈', () => {
  it('本頁成功：綠、附時間', () => {
    const l = discoveryLight(disc(), {}, fmt)
    expect(l.state).toBe('ok')
    expect(l.text).toEqual({ key: L + 'discOkLocal', params: { time: `T(${T2})` } })
    expect(l.note).toBeNull()
  })

  it('本頁 400：黃、列格式要求', () => {
    const l = discoveryLight(disc({ result: null, errorKind: 'invalid' }), {}, fmt)
    expect(l.state).toBe('warn')
    expect(l.text.key).toBe(L + 'discInvalid')
    expect(l.list.items).toHaveLength(2)
  })

  it('本頁 502：黃、列四種可能原因', () => {
    const l = discoveryLight(disc({ result: null, errorKind: 'unreachable' }), {}, fmt)
    expect(l.state).toBe('warn')
    expect(l.text.key).toBe(L + 'discUnreachable')
    expect(l.list.items).toHaveLength(4)
  })

  it('issuer 不一致：黃、對照你填的與提供者宣告的', () => {
    const declared = 'https://login.example.com/{tenantid}/v2.0'
    const l = discoveryLight(disc({ result: { issuer: declared, issuer_matches: false, signing_alg_compatible: true } }), {}, fmt)
    expect(l.state).toBe('warn')
    expect(l.text.key).toBe(L + 'discIssuerMismatch')
    expect(l.compare.map((c) => c.value)).toEqual([ISSUER, declared])
  })

  it('演算法不相容：黃、寫出宣告與支援的演算法', () => {
    const l = discoveryLight(disc({
      result: { issuer: ISSUER, issuer_matches: true, signing_alg_compatible: false, id_token_signing_alg_values_supported: ['HS256'] },
    }), {}, fmt)
    expect(l.state).toBe('warn')
    expect(l.text.key).toBe(L + 'discAlgIncompatible')
    expect(l.compare.map((c) => c.value)).toEqual(['HS256', 'RS256、ES256'])
  })

  it('已過期：灰，不沿用舊結果', () => {
    const l = discoveryLight(disc({}, { stale: true }), {}, fmt)
    expect(l.state).toBe('gray')
    expect(l.text.key).toBe(L + 'discStale')
  })

  it('受測值未儲存：仍為通過並附註記', () => {
    const l = discoveryLight(disc({}, { unsaved: true }), {}, fmt)
    expect(l.state).toBe('ok')
    expect(l.note.key).toBe(L + 'discUnsaved')
  })

  it('只有快取時間：綠、寫系統取得的時間', () => {
    const l = discoveryLight(null, { discovery_reachable: true, discovery_checked_at: T1 }, fmt)
    expect(l.state).toBe('ok')
    expect(l.text).toEqual({ key: L + 'discOkCached', params: { time: `T(${T1})` } })
  })

  it('全無：灰、尚未檢查', () => {
    const l = discoveryLight(null, {}, fmt)
    expect(l.state).toBe('gray')
    expect(l.text.key).toBe(L + 'discUnchecked')
  })
})

const attempt = (reason_code, at = T2, outcome = 'success') => ({ at, reason_code, outcome })

describe('憑證燈', () => {
  it('未填：黃', () => {
    expect(credentialLight({ credential_set: false }, fmt).state).toBe('warn')
  })

  it('通過換權杖：綠、附登入時間', () => {
    const l = credentialLight({ credential_set: true, last_attempt: attempt('admission_tid', T2, 'denied'), source_updated_at: T1 }, fmt)
    expect(l.state).toBe('ok')
    expect(l.text).toEqual({ key: L + 'credVerified', params: { time: `T(${T2})` } })
  })

  it('code_exchange_failed：黃', () => {
    const l = credentialLight({ credential_set: true, last_attempt: attempt('code_exchange_failed', T2, 'failed'), source_updated_at: T1 }, fmt)
    expect(l.state).toBe('warn')
    expect(l.text.key).toBe(L + 'credExchangeFailed')
  })

  it('無紀錄：灰', () => {
    const l = credentialLight({ credential_set: true, last_attempt: null }, fmt)
    expect(l.state).toBe('gray')
    expect(l.text.key).toBe(L + 'credUnverified')
  })

  it('設定晚於最近登入：灰、請再測一次', () => {
    const l = credentialLight({ credential_set: true, last_attempt: attempt('success', T1), source_updated_at: T2 }, fmt)
    expect(l.state).toBe('gray')
    expect(l.text.key).toBe(L + 'credRetest')
  })
})

describe('群組燈', () => {
  it('未設定群組宣告：中性', () => {
    expect(groupsLight({ group_attr_configured: false }, fmt).state).toBe('neutral')
  })

  it('只有快照：綠、群組數與觀測時間', () => {
    const l = groupsLight({ group_attr_configured: true, last_login_groups_at: T1, last_login_groups_seen: true, last_login_groups_count: 12 }, fmt)
    expect(l.state).toBe('ok')
    expect(l.text).toEqual({ key: L + 'groupsSeenCount', params: { count: 12, time: `T(${T1})` } })
  })

  it('空快照：黃', () => {
    const l = groupsLight({ group_attr_configured: true, last_login_groups_at: T1, last_login_groups_seen: false, last_login_groups_count: 0 }, fmt)
    expect(l.state).toBe('warn')
    expect(l.text.key).toBe(L + 'groupsEmpty')
  })

  it('無觀測：灰', () => {
    const l = groupsLight({ group_attr_configured: true }, fmt)
    expect(l.state).toBe('gray')
    expect(l.text.key).toBe(L + 'groupsNone')
  })

  const snap = { group_attr_configured: true, last_login_groups_at: T1, last_login_groups_seen: true, last_login_groups_count: 3 }

  it('舊快照＋較新的讀不到完整群組：黃', () => {
    const l = groupsLight({ ...snap, groups_unknown_at: T2 }, fmt)
    expect(l.state).toBe('warn')
    expect(l.text.key).toBe(L + 'groupsIncomplete')
  })

  it('舊快照＋較新的本地帳號登入：灰', () => {
    const l = groupsLight({ ...snap, last_success: { at: T2, mapping_eligible: false } }, fmt)
    expect(l.state).toBe('gray')
    expect(l.text.key).toBe(L + 'groupsLocalAccount')
  })

  it('較新的成功登入帳號已刪除：灰，不說成本地帳號', () => {
    const l = groupsLight({ ...snap, last_success: { at: T2, mapping_eligible: false, account_removed: true } }, fmt)
    expect(l.state).toBe('gray')
    expect(l.text.key).toBe(L + 'groupsAccountRemoved')
  })

  it('同時間：取非綠者', () => {
    expect(groupsLight({ ...snap, last_success: { at: T1, mapping_eligible: false } }, fmt).state).toBe('gray')
    expect(groupsLight({ ...snap, groups_unknown_at: T1, last_success: { at: T1, mapping_eligible: false } }, fmt).state).toBe('warn')
  })

  it('快照比其他觀測新：以快照為準', () => {
    expect(groupsLight({ ...snap, last_login_groups_at: T3, groups_unknown_at: T2 }, fmt).state).toBe('ok')
  })
})

describe('規則燈', () => {
  it('0 條：中性未使用', () => {
    const l = rulesLight({ rule_count: 0, enabled_rule_count: 0 })
    expect([l.state, l.text.key]).toEqual(['neutral', L + 'rulesNone'])
  })

  it('全部停用：中性未啟用', () => {
    const l = rulesLight({ rule_count: 2, enabled_rule_count: 0 })
    expect([l.state, l.text.key]).toEqual(['neutral', L + 'rulesAllDisabled'])
  })

  it('正常：綠', () => {
    const l = rulesLight({ rule_count: 3, enabled_rule_count: 3, last_recompute_matched_users: 8 })
    expect([l.state, l.text.key]).toEqual(['ok', L + 'rulesAll'])
  })
})

const stages = (dial, bind, search) => [
  { stage: 'dial', ok: dial },
  { stage: 'bind', ok: bind },
  { stage: 'search', ok: search },
]
const ldap = (result, { current = 'A', saved = 'A', snapshot = 'A' } = {}) => ({
  record: { result, at: T2, snapshot, attr: 'memberOf' },
  current,
  saved,
})
const SAMPLE = { sampled: true, group_configured: true, group_present: true }

describe('目錄兩盞燈', () => {
  it('未測：兩燈灰', () => {
    expect(ldapLights(null, fmt).map((l) => [l.state, l.text.key])).toEqual([
      ['gray', L + 'ldapUntested'],
      ['gray', L + 'ldapUntested'],
    ])
  })

  it('成功：兩燈綠並附時間', () => {
    const [conn, attr] = ldapLights(ldap({ stages: stages(true, true, true), attr_sample: SAMPLE }), fmt)
    expect([conn.state, attr.state]).toEqual(['ok', 'ok'])
    expect(conn.text.params.time).toBe(`T(${T2})`)
    expect(attr.text.params).toEqual({ time: `T(${T2})`, attr: 'memberOf' })
  })

  it('bind 失敗：連線黃、抽樣無法判斷', () => {
    const [conn, attr] = ldapLights(ldap({ stages: stages(true, false, false), attr_sample: SAMPLE }), fmt)
    expect([conn.state, conn.text.key]).toEqual(['warn', L + 'ldapBindFailed'])
    expect([attr.state, attr.text.key]).toEqual(['gray', L + 'ldapAttrNoSample'])
  })

  it('bind 或連線失敗、後端未抽樣（group_configured=false）：抽樣燈仍為無法判斷', () => {
    const unsampled = { sampled: false, group_configured: false, group_present: false }
    for (const st of [stages(true, false, false), stages(false, false, false)]) {
      const [, attr] = ldapLights(ldap({ stages: st, attr_sample: unsampled }), fmt)
      expect([attr.state, attr.text.key]).toEqual(['gray', L + 'ldapAttrNoSample'])
      const [, noSample] = ldapLights(ldap({ stages: st }), fmt)
      expect([noSample.state, noSample.text.key]).toEqual(['gray', L + 'ldapAttrNoSample'])
    }
  })

  it('群組屬性未設定：抽樣燈中性', () => {
    const [, attr] = ldapLights(ldap({ stages: stages(true, true, true), attr_sample: { sampled: true, group_configured: false } }), fmt)
    expect([attr.state, attr.text.key]).toEqual(['neutral', L + 'ldapAttrUnset'])
  })

  it('無可抽樣的使用者：灰', () => {
    const [, attr] = ldapLights(ldap({ stages: stages(true, true, true), attr_sample: { sampled: false, group_configured: true } }), fmt)
    expect([attr.state, attr.text.key]).toEqual(['gray', L + 'ldapAttrNoUsers'])
  })

  it('表單未儲存：綠並附註記', () => {
    const [conn] = ldapLights(ldap({ stages: stages(true, true, true), attr_sample: SAMPLE }, { saved: 'S' }), fmt)
    expect(conn.state).toBe('ok')
    expect(conn.note.key).toBe(L + 'ldapUnsaved')
  })

  it('已過期：兩燈灰、無未儲存註記', () => {
    const lights = ldapLights(ldap({ stages: stages(true, true, true), attr_sample: SAMPLE }, { current: 'B', saved: 'B' }), fmt)
    expect(lights.map((l) => [l.state, l.text.key, l.note ?? null])).toEqual([
      ['gray', L + 'ldapStale', null],
      ['gray', L + 'ldapStale', null],
    ])
  })
})

describe('無資料不得為綠', () => {
  it('OIDC 與 LDAP 在全空輸入下沒有任何 ok', () => {
    for (const status of [null, {}, { credential_set: true, group_attr_configured: true }]) {
      for (const type of ['oidc', 'ldap']) {
        const lights = computeLights({ type, status, discovery: null, ldapTest: null })
        expect(lights.filter((l) => l.state === 'ok'), `${type} ${JSON.stringify(status)}`).toEqual([])
      }
    }
  })
})

describe('總結句', () => {
  const S = 'identitySources.preflight.summary.'
  const okStatus = {
    credential_set: true,
    group_attr_configured: false,
    rule_count: 0,
    discovery_reachable: true,
    discovery_checked_at: T1,
    source_updated_at: T1,
  }

  it('准入未通過：黃，第一項為准入並附說明', () => {
    const status = { ...okStatus, last_attempt: attempt('admission_tid', T2, 'denied') }
    const s = computeSummary({ type: 'oidc', lights: computeLights({ type: 'oidc', status, fmt }), status })
    expect(s.state).toBe('warn')
    expect(s.text.params.count).toBe(1)
    expect(s.text.itemKey).toBe(S + 'item.admission')
    expect(s.detail.key).toBe(S + 'detail.admission')
  })

  it('換權杖失敗只算一項（憑證燈），不重複計入最近登入', () => {
    const status = { ...okStatus, last_attempt: attempt('code_exchange_failed', T2, 'failed') }
    const s = computeSummary({ type: 'oidc', lights: computeLights({ type: 'oidc', status, fmt }), status })
    expect([s.state, s.text.params.count, s.text.itemKey]).toEqual(['warn', 1, S + 'item.credentialExchange'])
  })

  it('近 30 天無嘗試：灰', () => {
    const status = { ...okStatus, last_attempt: null }
    const s = computeSummary({ type: 'oidc', lights: computeLights({ type: 'oidc', status, fmt }), status })
    expect([s.state, s.text.key]).toEqual(['gray', S + 'unknownNoAttempt'])
  })

  it('全部通過且最近一次登入成功：綠', () => {
    const status = { ...okStatus, last_attempt: attempt('success', T2) }
    const s = computeSummary({ type: 'oidc', lights: computeLights({ type: 'oidc', status, fmt }), status })
    expect([s.state, s.text.key]).toEqual(['ok', S + 'okOidc'])
  })

  it('LDAP 未測：還沒測試連線', () => {
    const status = { rule_count: 1, enabled_rule_count: 1 }
    const s = computeSummary({ type: 'ldap', lights: computeLights({ type: 'ldap', status, ldapTest: null, fmt }), status })
    expect([s.state, s.text.key]).toEqual(['gray', S + 'ldapUntested'])
  })
})
