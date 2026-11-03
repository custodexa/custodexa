import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ExecutorPublicKeyPanel from '@/components/asset/ExecutorPublicKeyPanel.vue'
import AssetExecutorSection from '@/components/asset/AssetExecutorSection.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const exportMock = vi.fn()
const getMock = vi.fn()
vi.mock('@/api/assetExecutor', () => ({
  exportAssetExecutorPublicKey: (...a) => exportMock(...a),
  getAssetExecutor: (...a) => getMock(...a),
}))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/credentials', () => ({ listCredentials: vi.fn().mockResolvedValue({ data: [] }) }))

const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLACEHOLDER cx-exec'

beforeEach(() => {
  vi.clearAllMocks()
  exportMock.mockResolvedValue(KEY)
})

const mountPanel = (props = {}) =>
  mount(ExecutorPublicKeyPanel, {
    global: { plugins: [ElementPlus] },
    props: { assetId: 5, account: 'cx-exec', ...props },
  })

describe('ExecutorPublicKeyPanel', () => {
  it('彈出框每次打開都重新匯出（打開兩次呼叫兩次）', async () => {
    const anchor = document.createElement('button')
    document.body.appendChild(anchor)
    const wrapper = mountPanel({ anchor, visible: false })
    await wrapper.setProps({ visible: true })
    await flushPromises()
    await wrapper.setProps({ visible: false })
    await wrapper.setProps({ visible: true })
    await flushPromises()
    expect(exportMock).toHaveBeenCalledTimes(2)
    expect(wrapper.get('[data-test="pk-logged"]').text()).toContain('操作日誌')
    expect(wrapper.get('[data-test="pk-line"]').text()).toBe(KEY)
  })

  it('404 時面板句存在並通知區塊重新讀取', async () => {
    exportMock.mockRejectedValue({ response: { status: 404, data: { code: 'NOTFOUND_ASSET_EXECUTOR_PUBLIC_KEY' } } })
    const wrapper = mountPanel({ inline: true })
    await flushPromises()
    expect(wrapper.get('[data-test="pk-error"]').text()).toContain('目前取不到這把公鑰')
    expect(wrapper.emitted('unavailable')).toHaveLength(1)
  })

  it('內嵌用法掛載即匯出一次', async () => {
    const wrapper = mountPanel({ inline: true })
    await flushPromises()
    expect(exportMock).toHaveBeenCalledTimes(1)
    expect(wrapper.find('[data-test="pk-download"]').exists()).toBe(true)
  })

  it('讀取執行身分的回應即使含 public_key 欄也不顯示（畫面公鑰只來自匯出回應）', async () => {
    setCapabilitiesForTests(['asset:executor-manage'])
    getMock.mockResolvedValue({
      configured: true,
      account_id: 7,
      username: 'cx-exec',
      secret_type: 'ssh_key',
      source: 'generate',
      credential: { credential_id: 31, credential_name: 'web-01 / cx-exec', shared_credential: false, binding_count: 1 },
      has_public_key: true,
      fingerprint: 'SHA256:abcd',
      public_key: KEY,
    })
    const wrapper = mount(AssetExecutorSection, {
      global: { plugins: [ElementPlus] },
      props: { assetId: 5, assetName: 'web-01', protocol: 'ssh', windowsFamily: false, hostKeyRecorded: true },
      attachTo: document.body,
    })
    await flushPromises()
    expect(wrapper.find('[data-test="executor-section"]').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('AAAAC3NzaC1lZDI1NTE5AAAAIPLACEHOLDER')
    expect(wrapper.find('[data-test="pk-line"]').exists()).toBe(false)
    expect(document.body.textContent).not.toContain('AAAAC3NzaC1lZDI1NTE5AAAAIPLACEHOLDER')
    expect(exportMock).toHaveBeenCalledTimes(0)
    resetCapabilities()
  })
})

describe('ExecutorPublicKeyPopover', () => {
  it('彈出框：複製／下載為有圖示的按鈕元件、有日誌句與加到登入金鑰清單的一句', async () => {
    const anchor = document.createElement('button')
    document.body.appendChild(anchor)
    const wrapper = mountPanel({ anchor, visible: false })
    await wrapper.setProps({ visible: true })
    await flushPromises()
    for (const k of ['pk-copy', 'pk-download']) {
      const b = wrapper.get(`[data-test="${k}"]`)
      expect(b.classes()).toContain('el-button')
      expect(b.find('svg').exists()).toBe(true)
    }
    expect(wrapper.get('[data-test="pk-add-hint"]').text()).toBe('加到這台主機上 cx-exec 的登入金鑰清單。')
    expect(wrapper.find('[data-test="pk-fingerprint"]').exists()).toBe(false)
    anchor.remove()
  })

  it('Esc 只關彈出框：外層的 document 監聽收不到，焦點回到錨點；關閉後監聽移除', async () => {
    const anchor = document.createElement('button')
    document.body.appendChild(anchor)
    const outer = vi.fn()
    document.addEventListener('keydown', outer)
    const wrapper = mount(ExecutorPublicKeyPanel, {
      global: { plugins: [ElementPlus] },
      props: { assetId: 5, account: 'cx-exec', anchor, visible: false },
      attachTo: document.body,
    })
    await wrapper.setProps({ visible: true })
    await flushPromises()
    expect(document.activeElement?.getAttribute('data-test')).toBe('pk-title')
    document.activeElement.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }))
    expect(wrapper.emitted('update:visible').at(-1)).toEqual([false])
    expect(outer).not.toHaveBeenCalled()
    expect(document.activeElement).toBe(anchor)
    await wrapper.setProps({ visible: false })
    anchor.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true }))
    expect(outer).toHaveBeenCalledTimes(1)
    document.removeEventListener('keydown', outer)
    anchor.remove()
  })
})
