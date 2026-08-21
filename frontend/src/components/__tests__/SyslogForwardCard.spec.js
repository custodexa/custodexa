import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import SyslogForwardCard from '../SyslogForwardCard.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// API 與 Element Plus 的互動式元件在單元層以 mock 取代：本檔驗的是
// 「回應形狀 -> UI 狀態」的契約（asset-syslog-debt-cleanup D2），不是網路層
const getSyslogSettingsMock = vi.fn()
const testSyslogSettingsMock = vi.fn()
const updateSyslogSettingsMock = vi.fn()
vi.mock('@/api/syslogSettings', () => ({
  getSyslogSettings: (...a) => getSyslogSettingsMock(...a),
  testSyslogSettings: (...a) => testSyslogSettingsMock(...a),
  updateSyslogSettings: (...a) => updateSyslogSettingsMock(...a),
}))

const confirmMock = vi.fn()
const errorToastMock = vi.fn()
vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    ElMessage: { error: (...a) => errorToastMock(...a), success: vi.fn(), warning: vi.fn() },
    ElMessageBox: { confirm: (...a) => confirmMock(...a) },
  }
})

const SETTING = { enabled: false, host: 'siem.example.com', port: 514, protocol: 'udp', tls_ca: '' }

function axiosError(status, data) {
  const err = new Error(`HTTP ${status}`)
  err.response = { status, data }
  return err
}

// 全域 setup 只注入 i18n，故本檔自行掛 Element Plus（需要真 button／alert 的
// DOM 與 class，才能斷言失敗回饋確實可見）
async function mountCard() {
  const wrapper = mount(SyslogForwardCard, { global: { plugins: [ElementPlus] } })
  await flushPromises()
  return wrapper
}

// 找到「發送測試訊息」按鈕（第一顆 action 按鈕）
function testButton(wrapper) {
  return wrapper.findAll('.syslog-actions button')[0]
}

// 結果 alert：外層 el-alert 帶 transition，VTU 預設 stub 掉 transition，
// 故 .syslog-test-result 落在 transition-stub 上，真正的 alert 在其內部
function resultAlert(wrapper) {
  return wrapper.find('.el-alert')
}

describe('SyslogForwardCard 測試訊息回應契約（asset-syslog-debt-cleanup）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getSyslogSettingsMock.mockResolvedValue({ data: { dropped: 0, setting: { ...SETTING } } })
  })

  it('成功時呈現成功 alert（成功由 2xx 表達，不依賴 body 的 success 旗標）', async () => {
    testSyslogSettingsMock.mockResolvedValue({ data: { success: true } })
    const wrapper = await mountCard()

    await testButton(wrapper).trigger('click')
    await flushPromises()

    const alert = resultAlert(wrapper)
    expect(alert.exists()).toBe(true)
    expect(alert.classes()).toContain('el-alert--success')
    expect(errorToastMock).not.toHaveBeenCalled()
  })

  it('502＋registered code 時仍呈現失敗 alert，文案取自前端譯文', async () => {
    testSyslogSettingsMock.mockRejectedValue(
      axiosError(502, { error: '後端 zh fallback', code: 'INTERNAL_SYSLOG_TEST_FAILED' })
    )
    const wrapper = await mountCard()

    await testButton(wrapper).trigger('click')
    await flushPromises()

    const alert = resultAlert(wrapper)
    // 契約核心：狀態碼由 200 改為 502 後，失敗回饋不得靜默消失
    expect(alert.exists()).toBe(true)
    expect(alert.classes()).toContain('el-alert--error')
    // 查譯結果而非後端 zh fallback（resolveApiError 第一層）
    expect(alert.text()).toContain('syslog 測試訊息傳送失敗')
    expect(alert.text()).not.toContain('後端 zh fallback')
    // toast 與 alert 同源
    expect(errorToastMock).toHaveBeenCalledTimes(1)
    expect(errorToastMock.mock.calls[0][0]).toContain('syslog 測試訊息傳送失敗')
  })

  it('400 ack_required 仍走確認重送迴圈，不被失敗分支吃掉', async () => {
    testSyslogSettingsMock
      .mockRejectedValueOnce(axiosError(400, { code: 'VALIDATION_TRANSMISSION_ACK_REQUIRED', risks: ['plaintext'] }))
      .mockResolvedValueOnce({ data: { success: true } })
    confirmMock.mockResolvedValue('confirm')
    const wrapper = await mountCard()

    await testButton(wrapper).trigger('click')
    await flushPromises()

    expect(confirmMock).toHaveBeenCalledTimes(1)
    expect(testSyslogSettingsMock).toHaveBeenCalledTimes(2)
    expect(testSyslogSettingsMock.mock.calls[0][0].risk_acknowledged).toBe(false)
    expect(testSyslogSettingsMock.mock.calls[1][0].risk_acknowledged).toBe(true)
    // 重送成功後呈現成功，且不誤報失敗
    expect(resultAlert(wrapper).classes()).toContain('el-alert--success')
    expect(errorToastMock).not.toHaveBeenCalled()
  })

  it('使用者取消風險確認時不留下失敗 alert 也不重送', async () => {
    testSyslogSettingsMock.mockRejectedValue(
      axiosError(400, { code: 'VALIDATION_TRANSMISSION_ACK_REQUIRED', risks: ['plaintext'] })
    )
    confirmMock.mockRejectedValue(new Error('cancel'))
    const wrapper = await mountCard()

    await testButton(wrapper).trigger('click')
    await flushPromises()

    expect(testSyslogSettingsMock).toHaveBeenCalledTimes(1)
    expect(resultAlert(wrapper).exists()).toBe(false)
  })
})
