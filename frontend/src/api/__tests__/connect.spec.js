import { describe, it, expect, vi, beforeEach } from 'vitest'
import i18n from '@/i18n'

// 連線前同意流程（428→對話框→立據→重試）

const requestMock = vi.fn()
vi.mock('../request', () => ({ default: (...args) => requestMock(...args) }))

const confirmMock = vi.fn()
const alertMock = vi.fn()
const promptMock = vi.fn()
const messageErrorMock = vi.fn()
vi.mock('element-plus', () => ({
  ElMessageBox: {
    confirm: (...args) => confirmMock(...args),
    alert: (...args) => alertMock(...args),
    prompt: (...args) => promptMock(...args),
  },
  ElMessage: { error: (...args) => messageErrorMock(...args) },
}))

import {
  createConnectToken,
  createConnectTokenWithConsent,
  createTransmissionConsent,
} from '../connect'

const gate428 = (risks) => {
  const err = new Error('precondition required')
  err.response = { status: 428, data: { risks } }
  return err
}

describe('createConnectTokenWithConsent', () => {
  beforeEach(() => vi.clearAllMocks())

  it('無風險時直接簽發，不彈對話框', async () => {
    requestMock.mockResolvedValueOnce({ connect_token: 'ct-1' })
    const resp = await createConnectTokenWithConsent(9)
    expect(resp.connect_token).toBe('ct-1')
    expect(confirmMock).not.toHaveBeenCalled()
  })

  it('428→同意→立據→重試簽發', async () => {
    const risks = [{ key: 'vnc_unencrypted', label: 'VNC 協議未加密' }]
    requestMock
      .mockRejectedValueOnce(gate428(risks)) // 首次簽發：需同意
      .mockResolvedValueOnce({}) // 立據
      .mockResolvedValueOnce({ connect_token: 'ct-2' }) // 重試簽發
    confirmMock.mockResolvedValueOnce('confirm')

    const resp = await createConnectTokenWithConsent(9)

    expect(confirmMock).toHaveBeenCalledTimes(1)
    // 立據帶使用者看到的 risk key
    const consentCall = requestMock.mock.calls[1][0]
    expect(consentCall.url).toBe('/transmission-consents')
    expect(consentCall.data).toEqual({ asset_id: 9, risk_keys: ['vnc_unencrypted'] })
    expect(resp.connect_token).toBe('ct-2')
  })

  it('使用者取消同意→中止（不立據不重試）', async () => {
    requestMock.mockRejectedValueOnce(gate428([{ key: 'vnc_unencrypted', label: 'x' }]))
    confirmMock.mockRejectedValueOnce('cancel')

    await expect(createConnectTokenWithConsent(9)).rejects.toBe('cancel')
    // 僅首次簽發被呼叫，無立據
    expect(requestMock).toHaveBeenCalledTimes(1)
  })

  it('403 recording_unavailable→顯式對話框告知並中止（不落 generic toast）', async () => {
    // 阻斷性狀態走 reason 分流，不依賴
    // 後端文案經 generic 呈現轉述
    const err = new Error('forbidden')
    err.response = {
      status: 403,
      data: { error: '錄影儲存異常', reason: 'recording_unavailable' },
    }
    requestMock.mockRejectedValueOnce(err)
    alertMock.mockResolvedValueOnce('ok')

    await expect(createConnectTokenWithConsent(9)).rejects.toBe(err)
    expect(alertMock).toHaveBeenCalledTimes(1)
    expect(messageErrorMock).not.toHaveBeenCalled()
    expect(requestMock).toHaveBeenCalledTimes(1)
  })

  it('非 428 失敗→補全域錯誤呈現並拋出', async () => {
    const err = new Error('strict')
    err.response = { status: 400, data: { error: '傳輸安全政策（嚴格）拒絕連線' } }
    requestMock.mockRejectedValueOnce(err)

    await expect(createConnectTokenWithConsent(9)).rejects.toBe(err)
    expect(messageErrorMock).toHaveBeenCalledWith('傳輸安全政策（嚴格）拒絕連線')
  })

  it('存在性 404 與既有政策回應正確分流', async () => {
    const localeBefore = i18n.global.locale.value
    const { default: actualRequest } = await vi.importActual('../request')
    const { setAccessToken, getAccessToken, resetSessionForTests } = await import('@/utils/session')
    const interceptor = actualRequest.interceptors.response.handlers[0]
    const codes = ['NOTFOUND_ASSET', 'NOTFOUND_SESSION', 'NOTFOUND_ACCESS_REQUEST']
    const translations = {
      'zh-TW': ['資產不存在', 'Session 不存在', '申請單不存在'],
      'en-US': ['Asset not found', 'Session not found', 'Access request not found'],
      'ja-JP': ['アセットが存在しません', 'セッションが存在しません', '申請が存在しません'],
    }
    const risks = [{ key: 'vnc_unencrypted', label: 'VNC' }]
    try {
      for (const [locale, messages] of Object.entries(translations)) {
        i18n.global.locale.value = locale
        for (const mode of ['missing', 'consent-revoked', 'reason', 'approval', 'consent']) {
          for (const mock of [requestMock, confirmMock, alertMock, promptMock, messageErrorMock]) mock.mockReset()
          const missing = Object.assign(new Error('not found'), {
            response: { status: 404, data: { code: 'NOTFOUND_ASSET', error: '資產不存在' } },
          })
          const policy = Object.assign(new Error('policy'), {
            response: { status: 403, data: { reason: `${mode}_required` } },
          })
          confirmMock.mockResolvedValue('confirm')
          alertMock.mockResolvedValue('ok')
          promptMock.mockResolvedValue({ value: 'maintenance' })
          if (mode === 'missing') requestMock.mockRejectedValueOnce(missing)
          if (mode === 'consent-revoked') requestMock.mockRejectedValueOnce(gate428(risks)).mockRejectedValueOnce(missing)
          if (mode === 'reason') requestMock.mockRejectedValueOnce(policy).mockResolvedValueOnce({}).mockResolvedValueOnce({ connect_token: 'ct' })
          if (mode === 'approval') requestMock.mockRejectedValueOnce(policy)
          if (mode === 'consent') requestMock.mockRejectedValueOnce(gate428(risks)).mockResolvedValueOnce({}).mockResolvedValueOnce({ connect_token: 'ct' })

          if (['missing', 'consent-revoked'].includes(mode)) {
            await expect(createConnectTokenWithConsent(9)).rejects.toBe(missing)
          } else if (mode === 'approval') {
            await expect(createConnectTokenWithConsent(9)).rejects.toBe(policy)
          } else {
            await expect(createConnectTokenWithConsent(9)).resolves.toEqual({ connect_token: 'ct' })
          }
          const paths = requestMock.mock.calls.map(([config]) => config.url)
          expect(paths).toEqual({
            missing: ['/connect-tokens'],
            'consent-revoked': ['/connect-tokens', '/transmission-consents'],
            reason: ['/connect-tokens', '/access-requests', '/connect-tokens'],
            approval: ['/connect-tokens'],
            consent: ['/connect-tokens', '/transmission-consents', '/connect-tokens'],
          }[mode])
          expect(promptMock).toHaveBeenCalledTimes(mode === 'reason' ? 1 : 0)
          expect(alertMock).toHaveBeenCalledTimes(mode === 'approval' ? 1 : 0)
          expect(confirmMock).toHaveBeenCalledTimes(mode.startsWith('consent') ? 1 : 0)
          if (mode === 'missing') expect(messageErrorMock).toHaveBeenCalledExactlyOnceWith(messages[0])
          else expect(messageErrorMock).not.toHaveBeenCalled()
        }
        // The real interceptor presents consent/share/report errors and keeps login state.
        setAccessToken('existence-probe-test-token')
        const locationBefore = window.location.href
        for (const [index, code] of codes.entries()) {
          messageErrorMock.mockClear()
          const error = { config: { url: '/fixture' }, response: { status: 404, data: { code, error: 'fallback' } } }
          await expect(interceptor.rejected(error)).rejects.toBe(error)
          expect(messageErrorMock).toHaveBeenCalledExactlyOnceWith(messages[index])
          expect(getAccessToken()).toBe('existence-probe-test-token')
          expect(window.location.href).toBe(locationBefore)
        }
      }
    } finally {
      i18n.global.locale.value = localeBefore
      resetSessionForTests()
      for (const mock of [requestMock, confirmMock, alertMock, promptMock, messageErrorMock]) mock.mockReset()
    }
  })
})

// account_id 為憑證選擇器，簽發與兌換兩點皆 DB 現查
describe('connect-token 的帳號綁定', () => {
  beforeEach(() => vi.clearAllMocks())

  it('未指定帳號時 body 不帶 account_id（K8s 帶了會被後端擋）', async () => {
    requestMock.mockResolvedValueOnce({ connect_token: 'ct' })
    await createConnectToken(7)
    expect(requestMock.mock.calls[0][0].data).toEqual({ asset_id: 7 })
  })

  it('指定帳號時 body 帶 account_id', async () => {
    requestMock.mockResolvedValueOnce({ connect_token: 'ct' })
    await createConnectToken(7, { accountId: 3 })
    expect(requestMock.mock.calls[0][0].data).toEqual({ asset_id: 7, account_id: 3 })
  })

  it('同意流程重試沿用同一帳號（不得靜默退回預設帳號）', async () => {
    requestMock
      .mockRejectedValueOnce(gate428([{ key: 'vnc_unencrypted', label: 'x' }]))
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({ connect_token: 'ct-3' })
    confirmMock.mockResolvedValueOnce('confirm')

    await createConnectTokenWithConsent(9, 4)

    expect(requestMock.mock.calls[0][0].data).toEqual({ asset_id: 9, account_id: 4 })
    // 第 3 次呼叫＝立據後的重試簽發
    expect(requestMock.mock.calls[2][0].data).toEqual({ asset_id: 9, account_id: 4 })
  })
})

describe('createTransmissionConsent', () => {
  beforeEach(() => vi.clearAllMocks())

  it('送 asset_id 與 risk_keys', async () => {
    requestMock.mockResolvedValueOnce({})
    await createTransmissionConsent(5, ['rdp_ignore_cert'])
    expect(requestMock).toHaveBeenCalledWith({
      url: '/transmission-consents',
      method: 'post',
      data: { asset_id: 5, risk_keys: ['rdp_ignore_cert'] },
    })
  })
})
