// 探索預覽的結果綁定：結果屬於送出當下的 issuer，較舊的回覆不得蓋掉較新的結果。
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { ref, nextTick } from 'vue'
import { flushPromises } from '@vue/test-utils'

const previewMock = vi.fn()
vi.mock('@/api/identitySources', () => ({
  previewOIDCDiscovery: (...a) => previewMock(...a),
  isNotImplemented: () => false,
}))

const { useDiscoveryPreview } = await import('../useDiscoveryPreview')

const httpError = (status) => {
  const err = new Error(`HTTP ${status}`)
  err.response = { status, data: {} }
  return err
}

const deferred = () => {
  let resolve
  const promise = new Promise((r) => {
    resolve = r
  })
  return { promise, resolve }
}

const setup = () => {
  const current = ref('https://a.example.com')
  const saved = ref('https://a.example.com')
  const key = ref(1)
  const onError = vi.fn()
  const p = useDiscoveryPreview({
    currentIssuer: () => current.value,
    savedIssuer: () => saved.value,
    sourceKey: () => key.value,
    onError,
  })
  return { p, current, saved, key, onError }
}

describe('useDiscoveryPreview', () => {
  beforeEach(() => {
    previewMock.mockReset()
  })

  it('成功：記下結果、受測 issuer 與時間', async () => {
    previewMock.mockResolvedValue({ issuer: 'https://a.example.com', issuer_matches: true })
    const { p } = setup()
    await p.run()
    expect(p.record.value.issuer).toBe('https://a.example.com')
    expect(p.record.value.errorKind).toBeNull()
    expect(Number.isNaN(Date.parse(p.record.value.at))).toBe(false)
    expect(p.result.value.issuer_matches).toBe(true)
    expect([p.stale.value, p.unsaved.value]).toEqual([false, false])
  })

  it('400 與 502 分類為格式不符與取不到；其他為未完成', async () => {
    const { p, onError } = setup()
    previewMock.mockRejectedValueOnce(httpError(400))
    await p.run()
    expect(p.record.value.errorKind).toBe('invalid')
    previewMock.mockRejectedValueOnce(httpError(502))
    await p.run()
    expect(p.record.value.errorKind).toBe('unreachable')
    previewMock.mockRejectedValueOnce(httpError(500))
    await p.run()
    expect(p.record.value.errorKind).toBe('error')
    expect(p.errorText.value).not.toBe('')
    expect(onError).toHaveBeenCalledTimes(3)
  })

  it('受測值與已儲存值不同為 unsaved；之後改 issuer 為 stale；改完儲存仍 stale 且不再 unsaved', async () => {
    previewMock.mockResolvedValue({ issuer_matches: true })
    const { p, current, saved } = setup()
    current.value = 'https://b.example.com'
    await p.run()
    expect([p.stale.value, p.unsaved.value]).toEqual([false, true])

    current.value = 'https://c.example.com'
    await nextTick()
    expect([p.stale.value, p.unsaved.value]).toEqual([true, false])

    saved.value = 'https://c.example.com'
    await nextTick()
    expect([p.stale.value, p.unsaved.value]).toEqual([true, false])
  })

  it('先送 A 再送 B，B 先回 A 後回：最終結果為 B', async () => {
    const a = deferred()
    const b = deferred()
    previewMock.mockReturnValueOnce(a.promise).mockReturnValueOnce(b.promise)
    const { p, current } = setup()
    const runA = p.run()
    current.value = 'https://b.example.com'
    const runB = p.run()
    b.resolve({ marker: 'B' })
    await runB
    a.resolve({ marker: 'A' })
    await runA
    await flushPromises()
    expect(p.record.value.result.marker).toBe('B')
    expect(p.record.value.issuer).toBe('https://b.example.com')
    expect(p.running.value).toBe(false)
  })

  it('換 provider id 後結果清空，進行中的回覆也丟棄', async () => {
    const pending = deferred()
    previewMock.mockResolvedValueOnce({ marker: 'first' }).mockReturnValueOnce(pending.promise)
    const { p, key } = setup()
    await p.run()
    expect(p.record.value).not.toBeNull()
    const late = p.run()
    key.value = 2
    await nextTick()
    expect(p.record.value).toBeNull()
    pending.resolve({ marker: 'late' })
    await late
    expect(p.record.value).toBeNull()
  })
})
