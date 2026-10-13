// 接通前確認面板的燈號與總結句（純函式，不碰 DOM、不打請求）。
//
// 每盞燈回傳 i18n 鍵與參數，由面板翻譯；時間一律經呼叫端給的 fmt 格式化。
// 四種狀態：ok 通過、warn 需處理、gray 還沒驗或無法判斷、neutral 合法地不使用。
// **任何「無資料」的輸入都不得得到 ok**：沒驗過與驗過且通過是兩件事。

export const SUPPORTED_SIGNING_ALGS = ['RS256', 'ES256']

const L = 'identitySources.preflight.light.'
const W = 'identitySources.preflight.word.'
const LABEL = 'identitySources.preflight.label.'
const LDAP_KEYS = ['connection', 'groupAttr']

// 走到換權杖之後才會出現的結果：這些登入證明用戶端密碼可用
const PAST_TOKEN_EXCHANGE = new Set([
  'success',
  'pending_mfa',
  'pending_mfa_enrollment',
  'pending_password_change',
  'source_denied',
  'admission_tid',
  'admission_hd',
  'admission_email_domain',
  'admission_email_verified',
  'admission_not_prebound',
  'admission_rules_noncompliant',
  'id_token_missing',
  'id_token_invalid',
  'username_conflict',
  'account_removed',
  'user_inactive',
])

const ts = (v) => {
  const n = v ? Date.parse(v) : NaN
  return Number.isNaN(n) ? null : n
}

const light = (key, state, word, textKey, params = {}, extra = {}) => ({
  key,
  label: LABEL + key,
  state,
  word: W + word,
  text: { key: L + textKey, params },
  ...extra,
})

/**
 * 探索燈。discovery＝{ record, stale, unsaved }（本頁最近一次預覽，見 useDiscoveryPreview）；
 * 本頁沒按過時退回後端快取的取得時間
 */
export function discoveryLight(discovery, status, fmt) {
  const rec = discovery?.record
  if (rec) {
    if (discovery.stale) return light('discovery', 'gray', 'expired', 'discStale', {}, { action: 'rediscover' })
    const time = fmt(rec.at)
    const note = discovery.unsaved ? { key: L + 'discUnsaved' } : null
    const base = { action: 'rediscover', note }
    if (rec.errorKind === 'invalid') {
      return light('discovery', 'warn', 'warn', 'discInvalid', { time }, {
        ...base,
        item: 'discoveryInvalid',
        list: { head: L + 'discInvalidHead', items: ['https', 'query'].map((k) => L + 'discInvalidCauses.' + k) },
      })
    }
    if (rec.errorKind === 'unreachable') {
      return light('discovery', 'warn', 'warn', 'discUnreachable', { time }, {
        ...base,
        item: 'discoveryUnreachable',
        list: {
          head: L + 'discCausesHead',
          items: ['typo', 'egress', 'internal', 'temporary'].map((k) => L + 'discCauses.' + k),
        },
      })
    }
    if (rec.errorKind) {
      return light('discovery', 'warn', 'warn', 'discError', { time }, { ...base, item: 'discoveryError' })
    }
    const r = rec.result || {}
    if (r.issuer_matches === false) {
      return light('discovery', 'warn', 'warn', 'discIssuerMismatch', { time }, {
        ...base,
        item: 'issuerMismatch',
        compare: [
          { label: L + 'discEntered', value: rec.issuer },
          { label: L + 'discDeclared', value: r.issuer || '' },
        ],
        hint: { key: L + 'discIssuerHint', params: { placeholder: '{tenantid}' } },
      })
    }
    if (r.signing_alg_compatible === false) {
      return light('discovery', 'warn', 'warn', 'discAlgIncompatible', { time }, {
        ...base,
        item: 'algIncompatible',
        compare: [
          { label: L + 'discDeclared', value: (r.id_token_signing_alg_values_supported || []).join('、') },
          { label: L + 'discSupported', value: SUPPORTED_SIGNING_ALGS.join('、') },
        ],
        hint: { key: L + 'discAlgHint', params: {} },
      })
    }
    return light('discovery', 'ok', 'ok', 'discOkLocal', { time }, base)
  }
  if (status?.discovery_reachable === true && status?.discovery_checked_at) {
    return light('discovery', 'ok', 'ok', 'discOkCached', { time: fmt(status.discovery_checked_at) }, {
      action: 'rediscover',
    })
  }
  return light('discovery', 'gray', 'unchecked', 'discUnchecked', {}, { action: 'rediscover' })
}

/** 憑證燈：密鑰非空不等於可用，看最近一次登入有沒有走過換權杖 */
export function credentialLight(status, fmt) {
  const s = status || {}
  if (s.credential_set === false) {
    return light('credential', 'warn', 'warn', 'credUnset', {}, { item: 'credentialUnset' })
  }
  if (s.credential_set !== true) return light('credential', 'gray', 'unverified', 'rulesUnknown')
  const a = s.last_attempt
  if (!a) return light('credential', 'gray', 'unverified', 'credUnverified')
  const updated = ts(s.source_updated_at)
  const at = ts(a.at)
  if (updated !== null && at !== null && updated > at) {
    return light('credential', 'gray', 'retest', 'credRetest')
  }
  if (a.reason_code === 'code_exchange_failed') {
    return light('credential', 'warn', 'warn', 'credExchangeFailed', { time: fmt(a.at) }, {
      item: 'credentialExchange',
      detail: 'credentialExchange',
    })
  }
  if (PAST_TOKEN_EXCHANGE.has(a.reason_code)) {
    return light('credential', 'ok', 'ok', 'credVerified', { time: fmt(a.at) })
  }
  return light('credential', 'gray', 'unverified', 'credUnverified')
}

/**
 * 群組燈：先看設定；其餘取時間最新的觀測，時間相同時取非綠者
 * （讀不到完整群組 > 本地帳號登入 > 快照），寧可少報綠
 */
export function groupsLight(status, fmt) {
  const s = status || {}
  if (s.group_attr_configured === false) return light('groups', 'neutral', 'notUsed', 'groupsNotConfigured')
  const obs = []
  const unknownAt = ts(s.groups_unknown_at)
  if (unknownAt !== null) {
    obs.push({ at: unknownAt, rank: 0, make: () => light('groups', 'warn', 'warn', 'groupsIncomplete',
      { time: fmt(s.groups_unknown_at) }, { item: 'groupsIncomplete' }) })
  }
  const localAt = s.last_success && s.last_success.mapping_eligible === false ? ts(s.last_success.at) : null
  if (localAt !== null) {
    // 帳號已刪除時不知道它原本是哪一種帳號，不說成本地帳號
    const textKey = s.last_success.account_removed === true ? 'groupsAccountRemoved' : 'groupsLocalAccount'
    obs.push({ at: localAt, rank: 1, make: () => light('groups', 'gray', 'indeterminate', textKey,
      { time: fmt(s.last_success.at) }) })
  }
  const snapAt = ts(s.last_login_groups_at)
  if (snapAt !== null && typeof s.last_login_groups_seen === 'boolean') {
    const count = s.last_login_groups_count ?? 0
    obs.push({ at: snapAt, rank: 2, make: () => (s.last_login_groups_seen && count > 0
      ? light('groups', 'ok', 'ok', 'groupsSeenCount', { count, time: fmt(s.last_login_groups_at) })
      : light('groups', 'warn', 'warn', 'groupsEmpty', { time: fmt(s.last_login_groups_at) }, { item: 'groupsEmpty' })) })
  }
  if (!obs.length) return light('groups', 'gray', 'unverified', 'groupsNone')
  obs.sort((x, y) => y.at - x.at || x.rank - y.rank)
  return obs[0].make()
}

/** 規則燈：0 條或全部停用是合法設定，用中性而非綠 */
export function rulesLight(status) {
  const s = status || {}
  if (typeof s.rule_count !== 'number') return light('rules', 'gray', 'unverified', 'rulesUnknown')
  const count = s.rule_count
  const enabled = s.enabled_rule_count ?? 0
  const matched = s.last_recompute_matched_users ?? 0
  if (count === 0) return light('rules', 'neutral', 'notUsed', 'rulesNone')
  if (enabled === 0) return light('rules', 'neutral', 'disabled', 'rulesAllDisabled', { count })
  if (enabled === count) return light('rules', 'ok', 'ok', 'rulesAll', { count, matched })
  return light('rules', 'ok', 'ok', 'rulesSome', { count, enabled, matched })
}

/**
 * 目錄兩盞燈（本頁測試結果）：ldapTest＝{ record, current, saved }，record＝{ result, at, snapshot, attr }。
 * 表單目前值與受測快照不同即過期；受測快照與已儲存值不同（且未過期）時註明尚未儲存
 */
export function ldapLights(ldapTest, fmt) {
  const rec = ldapTest?.record
  if (!rec) return LDAP_KEYS.map((k) => light(k, 'gray', 'untested', 'ldapUntested'))
  if (ldapTest.current !== rec.snapshot) return LDAP_KEYS.map((k) => light(k, 'gray', 'expired', 'ldapStale'))
  const time = fmt(rec.at)
  const r = rec.result || {}
  const stage = new Map((r.stages || []).map((x) => [x.stage, x.ok === true]))
  const note = ldapTest.saved !== rec.snapshot ? { key: L + 'ldapUnsaved' } : null
  let conn
  if (stage.get('dial') !== true) {
    conn = light('connection', 'warn', 'warn', 'ldapDialFailed', { time }, { item: 'ldapConnection', note })
  } else if (stage.get('bind') !== true) {
    conn = light('connection', 'warn', 'warn', 'ldapBindFailed', { time }, { item: 'ldapBind', note })
  } else {
    conn = light('connection', 'ok', 'ok', 'ldapConnOk', { time }, { note })
  }
  const sample = r.attr_sample || {}
  let attr
  // 連線或 bind 沒過就沒有抽樣，後端此時也不回群組屬性是否設定：一律無法判斷
  if (conn.state !== 'ok') {
    attr = light('groupAttr', 'gray', 'indeterminate', 'ldapAttrNoSample')
  } else if (sample.group_configured !== true) {
    attr = light('groupAttr', 'neutral', 'notSet', 'ldapAttrUnset')
  } else if (stage.get('search') !== true) {
    attr = light('groupAttr', 'warn', 'warn', 'ldapAttrSearchFailed', { time }, { item: 'ldapSearch' })
  } else if (sample.sampled !== true) {
    attr = light('groupAttr', 'gray', 'indeterminate', 'ldapAttrNoUsers', { time })
  } else if (sample.group_present === true) {
    attr = light('groupAttr', 'ok', 'ok', 'ldapAttrOk', { time, attr: rec.attr || '' })
  } else {
    attr = light('groupAttr', 'warn', 'warn', 'ldapAttrUnreadable', { time, attr: rec.attr || '' },
      { item: 'ldapAttrUnreadable' })
  }
  return [conn, attr]
}

/** 後端回報的設定警告：每一則一盞黃燈 */
export function warningLights(status, hasKey) {
  return (status?.warnings || []).map((w) => ({
    key: `warn_${w.code}`,
    label: null,
    state: 'warn',
    word: W + 'warn',
    text: { key: hasKey(`warnings.${w.code}`) ? `warnings.${w.code}` : L + 'warningGeneric', params: {} },
    sub: { key: L + 'warningAction' },
    item: 'warning',
  }))
}

/** 依來源類型組出全部燈號 */
export function computeLights({ type, status, discovery, ldapTest, fmt = (v) => v, hasKey = () => false }) {
  const out = type === 'ldap'
    ? [...ldapLights(ldapTest, fmt), rulesLight(status)]
    : [discoveryLight(discovery, status, fmt), credentialLight(status, fmt), groupsLight(status, fmt), rulesLight(status)]
  return [...out, ...warningLights(status, hasKey)]
}

/** 最近一次登入本身是否算一項需要處理（換權杖失敗已由憑證燈計入，不重複） */
export function attemptItem(attempt) {
  if (!attempt || !['denied', 'failed'].includes(attempt.outcome)) return null
  if (attempt.reason_code === 'code_exchange_failed') return null
  if (String(attempt.reason_code).startsWith('admission_')) return { item: 'admission', detail: 'admission' }
  if (attempt.reason_code === 'provider_error') return { item: 'providerError', detail: 'providerError' }
  return { item: 'attemptFailed' }
}

const S = 'identitySources.preflight.summary.'

/**
 * 面板頂端的總結句：有一項黃就用黃（第一句寫最優先的一項）；
 * 全部通過且最近一次登入成功或等待後續步驟才用綠；其餘為灰
 */
export function computeSummary({ type, lights, status }) {
  const items = []
  for (const l of lights) {
    if (l.state === 'warn') items.push({ item: l.item, detail: l.detail })
    if (type !== 'ldap' && l.key === 'credential') {
      const a = attemptItem(status?.last_attempt)
      if (a) items.push(a)
    }
  }
  if (items.length) {
    const first = items[0]
    return {
      state: 'warn',
      text: { key: S + 'warn', params: { count: items.length }, itemKey: S + 'item.' + first.item },
      detail: first.detail ? { key: S + 'detail.' + first.detail } : null,
    }
  }
  const gray = lights.find((l) => l.state === 'gray')
  if (type === 'ldap') {
    if (lights[0]?.word === W + 'untested') return { state: 'gray', text: { key: S + 'ldapUntested', params: {} } }
    if (!gray) return { state: 'ok', text: { key: S + 'okLdap', params: {} } }
    return { state: 'gray', text: { key: S + 'unknownLight', params: {}, nameKey: gray.label } }
  }
  const attempt = status?.last_attempt
  if (!attempt) {
    return {
      state: 'gray',
      text: { key: S + 'unknownNoAttempt', params: { days: 30 } },
      detail: { key: S + 'detail.noAttempt' },
    }
  }
  if (gray) return { state: 'gray', text: { key: S + 'unknownLight', params: {}, nameKey: gray.label } }
  return { state: 'ok', text: { key: S + 'okOidc', params: {} } }
}
