import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import MfaQrCode from '../MfaQrCode.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 無真 canvas 2d context——mock qrcode（D-2），真值渲染由 live 走查驗證
const toCanvasMock = vi.fn()
vi.mock('qrcode', () => ({
  default: { toCanvas: (...a) => toCanvasMock(...a) },
}))

describe('MfaQrCode 共用元件（mfa-qr-and-button-contrast）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    toCanvasMock.mockResolvedValue(undefined)
  })

  it('掛載即以 otpauth URL 本地渲染（掃碼器亮底深碼配色）', async () => {
    const url = 'otpauth://totp/Custodexa:admin?secret=ABC&issuer=Custodexa'
    mount(MfaQrCode, { props: { value: url } })
    await flushPromises()

    expect(toCanvasMock).toHaveBeenCalledTimes(1)
    const [canvas, value, opts] = toCanvasMock.mock.calls[0]
    expect(canvas).toBeTruthy()
    expect(value).toBe(url)
    expect(opts.color.light).toBe('#ffffff')
  })

  it('value 變更時重渲染（重新產生金鑰情境）', async () => {
    const wrapper = mount(MfaQrCode, { props: { value: 'otpauth://totp/a' } })
    await flushPromises()
    await wrapper.setProps({ value: 'otpauth://totp/b' })
    await flushPromises()

    expect(toCanvasMock).toHaveBeenCalledTimes(2)
    expect(toCanvasMock.mock.calls[1][1]).toBe('otpauth://totp/b')
  })

  it('渲染失敗靜默隱藏，不擋手動輸入路徑（漸進增強）', async () => {
    toCanvasMock.mockRejectedValue(new Error('no canvas'))
    const wrapper = mount(MfaQrCode, { props: { value: 'otpauth://totp/x' } })
    await flushPromises()

    expect(wrapper.find('.mfa-qr').exists()).toBe(false)
  })
})
