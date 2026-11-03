import { describe, it, expect, vi, beforeEach } from 'vitest'
import * as api from '../assetExecutor'
import { getCredential } from '../credentials'

const request = vi.hoisted(() => vi.fn())
vi.mock('../request', () => ({ default: request }))

describe('assetExecutor api', () => {
  beforeEach(() => request.mockReset())

  it('getAssetExecutor 以 GET 讀取並預設關閉全域錯誤提示', async () => {
    request.mockResolvedValueOnce({ configured: false })
    await api.getAssetExecutor(5)
    expect(request).toHaveBeenLastCalledWith({ url: '/assets/5/executor', method: 'get', skipErrorToast: true })
  })

  it('putAssetExecutor 原樣送出 expected_account_id 與各來源欄位', async () => {
    const body = { source: 'shared', credential_id: 12, acknowledged_host_count: 7, expected_account_id: 56 }
    await api.putAssetExecutor(5, body)
    expect(request).toHaveBeenLastCalledWith({ url: '/assets/5/executor', method: 'put', data: body, skipErrorToast: true })
    const gen = { source: 'generate', username: 'cx-exec', expected_account_id: 0 }
    await api.putAssetExecutor(5, gen)
    expect(request.mock.calls.at(-1)[0].data).toEqual(gen)
    expect(request.mock.calls.at(-1)[0].data.expected_account_id).toBe(0)
  })

  it('deleteAssetExecutor 以查詢參數帶 expected_account_id，未傳則不帶', async () => {
    await api.deleteAssetExecutor(5, 9)
    expect(request).toHaveBeenLastCalledWith({
      url: '/assets/5/executor', method: 'delete', params: { expected_account_id: 9 }, skipErrorToast: true,
    })
    await api.deleteAssetExecutor(5)
    expect(request.mock.calls.at(-1)[0]).not.toHaveProperty('params')
  })

  it('exportAssetExecutorPublicKey 取純文字回應', async () => {
    await api.exportAssetExecutorPublicKey(5)
    expect(request).toHaveBeenLastCalledWith({
      url: '/assets/5/executor/public-key', method: 'get', responseType: 'text', skipErrorToast: true,
    })
  })

  it.each([
    ['getAssetExecutor', [5]],
    ['putAssetExecutor', [5, { source: 'generate' }]],
    ['deleteAssetExecutor', [5, 1]],
    ['exportAssetExecutorPublicKey', [5]],
  ])('%s 呼叫端傳其他設定時仍保留 skipErrorToast', async (name, args) => {
    await api[name](...args, { timeout: 1000, skipErrorToast: false })
    const sent = request.mock.calls.at(-1)[0]
    expect(sent.skipErrorToast).toBe(true)
    expect(sent.timeout).toBe(1000)
  })

  it('getCredential 不傳 config 時與修改前相同，傳入時原樣帶上', async () => {
    await getCredential(12)
    expect(request).toHaveBeenLastCalledWith({ url: '/credentials/12', method: 'get' })
    const fn = () => true
    await getCredential(12, { skipErrorToast: fn })
    expect(request).toHaveBeenLastCalledWith({ url: '/credentials/12', method: 'get', skipErrorToast: fn })
  })
})
