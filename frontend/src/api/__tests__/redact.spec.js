// 日誌去識別（對抗審查 HIGH-2）：全域攔截器印的是 AxiosError，其 config.data
// 為原始請求本文——帳號 CRUD 帶明文密碼／私鑰。以欄位名（非端點清單）遮蔽，
// 新端點沿用同一組命名即自動受保護。
import { describe, it, expect } from 'vitest'
import { redactSensitive, redactAxiosError, isSensitiveKey, REDACTED } from '../redact'

describe('欄位名敏感判定', () => {
  it.each([
    'password',
    'Password',
    'passwd',
    'passphrase',
    'private_key',
    'privateKey',
    'PRIVATE-KEY',
    'client_secret',
    'connect_token',
    'refresh_token',
    'Authorization',
    'cookie',
    'credentials',
    'api_key',
    'otp',
  ])('%s 視為敏感', (key) => {
    expect(isSensitiveKey(key)).toBe(true)
  })

  it.each(['username', 'asset_id', 'account_id', 'risk_keys', 'note', 'privileged', 'path'])(
    '%s 不誤殺',
    (key) => {
      expect(isSensitiveKey(key)).toBe(false)
    }
  )
})

describe('redactSensitive', () => {
  it('遮蔽物件內的憑證欄位，保留其餘鍵值供除錯', () => {
    expect(
      redactSensitive({ username: 'root', password: 'p@ss', privileged: true })
    ).toEqual({ username: 'root', password: REDACTED, privileged: true })
  })

  it('JSON 字串（axios 序列化後的 config.data）先解析再遮蔽', () => {
    const body = JSON.stringify({ username: 'root', private_key: '-----BEGIN...' })
    expect(redactSensitive(body)).toEqual({ username: 'root', private_key: REDACTED })
  })

  it('巢狀與陣列一併遮蔽', () => {
    expect(
      redactSensitive({ items: [{ token: 'abc' }], nested: { deep: { secret: 's' } } })
    ).toEqual({ items: [{ token: REDACTED }], nested: { deep: { secret: REDACTED } } })
  })

  it('FormData 不展開（可能含檔案內容）', () => {
    expect(redactSensitive(new FormData())).toBe('[form-data]')
  })

  it('看似 JSON 卻解析失敗的字串整串遮掉（寧可少除錯資訊）', () => {
    expect(redactSensitive('{not json')).toBe(REDACTED)
  })

  it('一般字串與數字原樣保留', () => {
    expect(redactSensitive('/assets/1/accounts')).toBe('/assets/1/accounts')
    expect(redactSensitive(42)).toBe(42)
    expect(redactSensitive(null)).toBe(null)
  })

  it('超過深度上限一律回 placeholder，不得原樣吐回未檢查的值（輪 2 codex MEDIUM-4）', () => {
    // 深度上限的語義必須是「這裡不再檢查，所以不輸出」——回原值等於
    // 「巢狀夠深就免檢查」，深層 payload 可原封帶出 password
    const deep = { l1: { l2: { l3: { l4: { l5: { l6: { l7: { password: 'hunter2' } } } } } } } }
    const out = redactSensitive(deep)
    expect(JSON.stringify(out)).not.toContain('hunter2')
    expect(out.l1.l2.l3.l4.l5.l6.l7).toBe(REDACTED)
  })

  it('深度上限也擋純字串葉節點（不只物件）', () => {
    const deep = { a: { b: { c: { d: { e: { f: { g: 'deep-secret-value' } } } } } } }
    expect(JSON.stringify(redactSensitive(deep))).not.toContain('deep-secret-value')
  })
})

describe('redactAxiosError', () => {
  const error = {
    message: 'Request failed with status code 409',
    config: {
      method: 'post',
      url: '/assets/1/accounts',
      data: JSON.stringify({ username: 'root', password: 'hunter2', private_key: 'KEY' }),
      headers: { Authorization: 'Bearer real-token' },
    },
    response: {
      status: 409,
      data: { code: 'CONFLICT_ACCOUNT_USERNAME', error: '同一資產下已有同名帳號' },
    },
  }

  it('只輸出白名單四欄（方法／路徑／狀態／機器碼）', () => {
    const out = redactAxiosError(error)
    expect(out).toEqual({
      method: 'POST',
      url: '/assets/1/accounts',
      status: 409,
      code: 'CONFLICT_ACCOUNT_USERNAME',
    })
  })

  it('不輸出請求本文與後端訊息（輪 2 codex MEDIUM-5：欄位名遮蔽擋不住個資欄位）', () => {
    // password/token 靠欄位名可擋，subject／email／username／full_name 本身就是
    // 個資；後端錯誤訊息又常回顯衝突值。console 會被截圖與集中收集，一律不輸出
    const out = redactAxiosError({
      config: {
        method: 'post',
        url: '/users/165/external-identities',
        data: JSON.stringify({ subject: 'CiQxMTEx-real-subject', email: 'oidcuser@corp.example' }),
      },
      response: {
        status: 409,
        data: { code: 'CONFLICT_EXTERNAL_IDENTITY', error: '此 subject 已綁定至帳號 alice' },
      },
      message: 'Request failed with status code 409',
    })
    expect(out.requestData).toBeUndefined()
    expect(out.error).toBeUndefined()
    expect(out.message).toBeUndefined()
    const serialized = JSON.stringify(out)
    expect(serialized).not.toContain('real-subject')
    expect(serialized).not.toContain('oidcuser@corp.example')
    expect(serialized).not.toContain('alice')
  })

  it('URL 只留路徑，查詢字串一律丟棄（search=<email> 之類）', () => {
    const out = redactAxiosError({
      config: { method: 'get', url: '/users?search=alice%40corp.example&page=1' },
      response: { status: 500, data: {} },
    })
    expect(out.url).toBe('/users')
    expect(JSON.stringify(out)).not.toContain('alice')
  })

  it('輸出序列化後不得含明文憑證或 Authorization（回歸鎖）', () => {
    const serialized = JSON.stringify(redactAxiosError(error))
    expect(serialized).not.toContain('hunter2')
    expect(serialized).not.toContain('KEY')
    expect(serialized).not.toContain('real-token')
    expect(serialized).not.toContain('Authorization')
  })

  it('無 config／response 時不炸（網路層錯誤）', () => {
    expect(() => redactAxiosError(new Error('Network Error'))).not.toThrow()
    const out = redactAxiosError(new Error('Network Error'))
    expect(out.status).toBeUndefined()
    expect(out.method).toBeUndefined()
  })
})
