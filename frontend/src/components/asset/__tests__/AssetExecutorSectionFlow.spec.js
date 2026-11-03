import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { nextTick } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AssetExecutorSection from '@/components/asset/AssetExecutorSection.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

// 區塊的流程面：權限晚到、抽屜重開重讀、Esc 只關彈出框、動作後焦點落點，以及區塊的呈現細節。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const getMock = vi.fn()
const deleteMock = vi.fn()
const exportMock = vi.fn()
const putMock = vi.fn()
vi.mock('@/api/assetExecutor', () => ({
  getAssetExecutor: (...a) => getMock(...a),
  deleteAssetExecutor: (...a) => deleteMock(...a),
  exportAssetExecutorPublicKey: (...a) => exportMock(...a),
  putAssetExecutor: (...a) => putMock(...a),
}))
vi.mock('@/api/assetAccounts', () => ({ listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }) }))
vi.mock('@/api/credentials', () => ({ listCredentials: vi.fn().mockResolvedValue({ data: [] }) }))

const PERMS = ['asset:executor-manage', 'credential:create', 'credential:bind', 'credential:update']
const generated = (over = {}) => ({
  configured: true,
  account_id: 7,
  username: 'cx-exec',
  secret_type: 'ssh_key',
  source: 'generate',
  credential: { credential_id: 31, credential_name: 'web-01 / cx-exec', shared_credential: false, binding_count: 1 },
  has_public_key: true,
  fingerprint: 'SHA256:abcd',
  ...over,
})
const shared = (count = 7) => generated({
  source: 'shared',
  secret_type: 'password',
  has_public_key: false,
  fingerprint: undefined,
  credential: { credential_id: 40, credential_name: 'fleet-exec', shared_credential: true, binding_count: count },
})

const baseProps = { assetId: 5, assetName: 'web-01', protocol: 'ssh', windowsFamily: false, hostKeyRecorded: true }
const mountSection = (props = {}) =>
  mount(AssetExecutorSection, {
    global: { plugins: [ElementPlus] },
    props: { ...baseProps, ...props },
    attachTo: document.body,
  })

// 模擬瀏覽器的點擊：按下時焦點先落到按鈕上，再觸發 click
const press = async (w) => {
  w.element.focus()
  await w.trigger('click')
}

const esc = (target = document.activeElement || document.body) =>
  target.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', code: 'Escape', bubbles: true, cancelable: true }))

beforeEach(() => {
  vi.clearAllMocks()
  setCapabilitiesForTests(PERMS)
  getMock.mockResolvedValue({ configured: false })
  exportMock.mockResolvedValue('ssh-ed25519 AAAA cx-exec')
})
afterEach(() => resetCapabilities())

describe('ExecutorSectionCapabilitiesLate', () => {
  it('能力尚未載入時不渲染也不讀取；載入後區塊出現並讀取一次', async () => {
    resetCapabilities()
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.find('[data-test="executor-section"]').exists()).toBe(false)
    expect(getMock).toHaveBeenCalledTimes(0)
    setCapabilitiesForTests(PERMS)
    await flushPromises()
    expect(wrapper.find('[data-test="executor-section"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="executor-unconfigured"]').exists()).toBe(true)
    expect(getMock).toHaveBeenCalledTimes(1)
  })

  it('能力晚到但不含管理權：仍不渲染、不讀取；之後權限被收回時區塊消失', async () => {
    resetCapabilities()
    const wrapper = mountSection()
    await flushPromises()
    setCapabilitiesForTests(['asset:view'])
    await flushPromises()
    expect(wrapper.find('[data-test="executor-section"]').exists()).toBe(false)
    expect(getMock).toHaveBeenCalledTimes(0)
    setCapabilitiesForTests(PERMS)
    await flushPromises()
    expect(wrapper.find('[data-test="executor-section"]').exists()).toBe(true)
    setCapabilitiesForTests(['asset:view'])
    await flushPromises()
    expect(wrapper.find('[data-test="executor-section"]').exists()).toBe(false)
  })
})

describe('ExecutorSectionReopen', () => {
  it('抽屜重新開啟（openKey 變動）時重新讀取，並清掉「剛設定」與完成提示', async () => {
    getMock.mockResolvedValueOnce({ configured: false }).mockResolvedValueOnce(generated())
    const wrapper = mountSection({ openKey: 1 })
    await flushPromises()
    wrapper.findComponent({ name: 'ExecutorSetupDialog' }).vm.$emit('done', { kind: 'set' })
    await flushPromises()
    expect(wrapper.find('[data-test="executor-just-tag"]').exists()).toBe(true)
    getMock.mockResolvedValue(generated({ account_id: 9, username: 'cx-ops2' }))
    const calls = getMock.mock.calls.length
    await wrapper.setProps({ openKey: 2 })
    await flushPromises()
    expect(getMock.mock.calls.length).toBe(calls + 1)
    expect(wrapper.find('[data-test="executor-just-tag"]').exists()).toBe(false)
    expect(wrapper.get('[data-test="executor-username"]').text()).toBe('cx-ops2')
  })

  it('清除完成句留到重新開啟為止', async () => {
    getMock.mockResolvedValueOnce(generated()).mockResolvedValue({ configured: false })
    deleteMock.mockResolvedValue({})
    const wrapper = mountSection({ openKey: 1 })
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="executor-notice-cleared"]').exists()).toBe(true)
    await wrapper.setProps({ openKey: 2 })
    await flushPromises()
    expect(wrapper.find('[data-test="executor-notice-cleared"]').exists()).toBe(false)
  })
})

describe('ExecutorSectionEscape', () => {
  // 外層抽屜與對話框以 document 上的 keydown 監聽處理 Esc（Element Plus 的 useEscapeKeydown），
  // 這裡以同一位置的監聽代表外層：收不到即代表外層不會被一起關掉
  let outer
  beforeEach(() => {
    outer = vi.fn()
    document.addEventListener('keydown', outer)
  })
  afterEach(() => document.removeEventListener('keydown', outer))

  it('對照：沒有彈出框時 Esc 照常傳到外層', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    esc(wrapper.get('[data-test="executor-replace"]').element)
    expect(outer).toHaveBeenCalledTimes(1)
  })

  it('公鑰彈出框開著時 Esc 只關彈出框、外層收不到，焦點回到「取得公鑰」', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    const btn = wrapper.get('[data-test="executor-get-public-key"]')
    await press(btn)
    await flushPromises()
    expect(wrapper.vm.$.setupState.pkVisible).toBe(true)
    esc()
    await flushPromises()
    expect(wrapper.vm.$.setupState.pkVisible).toBe(false)
    expect(outer).not.toHaveBeenCalled()
    expect(document.activeElement).toBe(btn.element)
  })

  it('清除確認開著時 Esc 只關確認框、外層收不到，焦點回到「清除」，不送出清除', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    const btn = wrapper.get('[data-test="executor-clear"]')
    await press(btn)
    await flushPromises()
    expect(wrapper.vm.$.setupState.clearVisible).toBe(true)
    esc()
    await flushPromises()
    expect(wrapper.vm.$.setupState.clearVisible).toBe(false)
    expect(outer).not.toHaveBeenCalled()
    expect(document.activeElement).toBe(btn.element)
    expect(deleteMock).not.toHaveBeenCalled()
  })

  it('設定方式彈出框開著時 Esc 只關它，焦點回到觸發處', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    const trigger = document.createElement('button')
    document.body.appendChild(trigger)
    trigger.focus()
    await wrapper.vm.openSetupHelp(trigger)
    await flushPromises()
    esc()
    await flushPromises()
    expect(wrapper.vm.$.setupState.helpPopoverVisible).toBe(false)
    expect(outer).not.toHaveBeenCalled()
    expect(document.activeElement).toBe(trigger)
    trigger.remove()
  })

  it('彈出框關閉後監聽即移除：再按 Esc 照常傳到外層', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-get-public-key"]').trigger('click')
    await flushPromises()
    esc()
    await flushPromises()
    expect(outer).not.toHaveBeenCalled()
    esc()
    expect(outer).toHaveBeenCalledTimes(1)
  })
})

describe('ExecutorSectionFocus', () => {
  const title = (w) => w.get('[data-test="executor-title"]').element

  it('清除成功後焦點在區塊標題，不落在 body', async () => {
    getMock.mockResolvedValueOnce(generated()).mockResolvedValue({ configured: false })
    deleteMock.mockResolvedValue({})
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    expect(document.activeElement).toBe(title(wrapper))
    expect(document.activeElement).not.toBe(document.body)
  })

  it('取消清除後焦點回到「清除」鈕', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    await press(wrapper.get('[data-test="executor-clear"]'))
    await flushPromises()
    await press(wrapper.get('[data-test="executor-clear-cancel"]'))
    await flushPromises()
    expect(document.activeElement).toBe(wrapper.get('[data-test="executor-clear"]').element)
  })

  it('設定完成（對話框 done）後焦點在區塊標題', async () => {
    getMock.mockResolvedValueOnce({ configured: false }).mockResolvedValue(shared(7))
    const wrapper = mountSection()
    await flushPromises()
    wrapper.findComponent({ name: 'ExecutorSetupDialog' }).vm.$emit('done', { kind: 'set' })
    await flushPromises()
    expect(document.activeElement).toBe(title(wrapper))
  })

  it('對話框關閉後若焦點掉在 body，改落在區塊標題；焦點在別處時不搶', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    document.activeElement?.blur?.()
    wrapper.findComponent({ name: 'ExecutorSetupDialog' }).vm.$emit('closed')
    await flushPromises()
    expect(document.activeElement).toBe(title(wrapper))
    const replace = wrapper.get('[data-test="executor-replace"]').element
    replace.focus()
    wrapper.findComponent({ name: 'ExecutorSetupDialog' }).vm.$emit('closed')
    await flushPromises()
    expect(document.activeElement).toBe(replace)
  })

  it('公鑰彈出框按「關閉」後焦點回到「取得公鑰」', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    await press(wrapper.get('[data-test="executor-get-public-key"]'))
    await flushPromises()
    await nextTick()
    await press(wrapper.get('[data-test="executor-public-key-close"]'))
    await flushPromises()
    expect(document.activeElement).toBe(wrapper.get('[data-test="executor-get-public-key"]').element)
  })
})

describe('ExecutorSectionPresentation', () => {
  it('卡片化區塊：標題前盾牌圖示、標籤前禁止圖示、即時生效一行前資訊圖示', async () => {
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.get('[data-test="executor-title"]').find('svg').exists()).toBe(true)
    expect(wrapper.get('[data-test="executor-not-for-users"]').find('svg').exists()).toBe(true)
    expect(wrapper.get('[data-test="executor-immediate-note"]').find('svg').exists()).toBe(true)
  })

  it('未設定時「設定」與「這個帳號要怎麼準備」同一列', async () => {
    const wrapper = mountSection()
    await flushPromises()
    const row = wrapper.get('[data-test="executor-row-actions"]')
    expect(row.find('[data-test="executor-set"]').exists()).toBe(true)
    expect(row.find('[data-test="executor-help-link"]').exists()).toBe(true)
  })

  it('不支援協定的原因句在資訊框內並有圖示', async () => {
    const wrapper = mountSection({ protocol: 'mysql' })
    await flushPromises()
    const box = wrapper.get('[data-test="executor-unsupported"]')
    expect(box.classes()).toContain('info-box')
    expect(box.find('svg').exists()).toBe(true)
  })

  it('資訊列第一欄為「帳號名稱」；憑證庫一行有前半句與連結', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.get('[data-test="executor-info"] dt').text()).toBe('帳號名稱')
    const line = wrapper.get('[data-test="executor-credential-line"]').text()
    expect(line).toContain('改密與定期排程在憑證庫處理。')
    expect(line).toContain('到憑證庫改密或設定排程')
    for (const loc of [zhTW, enUS, jaJP]) {
      expect(loc.assetExecutor.credentialLead.length).toBeGreaterThan(5)
      expect(loc.assetExecutor.fields.account).not.toBe('')
    }
    expect(enUS.assetExecutor.fields.account).toBe('Account name')
    expect(jaJP.assetExecutor.fields.account).toBe('アカウント名')
  })

  it('共用台數標籤為琥珀色（warning）', async () => {
    getMock.mockResolvedValue(shared(7))
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.get('[data-test="executor-shared-tag"]').text()).toBe('共用 · 7 台')
    expect(wrapper.get('[data-test="executor-info"] .el-tag--warning').text()).toBe('共用 · 7 台')
  })

  it('清除確認鈕字為「清除」；完成句在「設定」列之後、不把設定與說明連結隔開', async () => {
    getMock.mockResolvedValueOnce(generated()).mockResolvedValue({ configured: false })
    deleteMock.mockResolvedValue({})
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    expect(wrapper.get('[data-test="executor-clear-confirm-btn"]').text()).toBe('清除')
    expect([enUS.assetExecutor.clearConfirm.confirm, jaJP.assetExecutor.clearConfirm.confirm]).toEqual(['Clear', '解除'])
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    const row = wrapper.get('[data-test="executor-row-actions"]').element
    const notice = wrapper.get('[data-test="executor-notice-cleared"]')
    expect(row.compareDocumentPosition(notice.element) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(notice.classes()).toContain('notice')
  })

  it('轉換後的建議改密是一般提示行，不是警示框', async () => {
    getMock.mockResolvedValueOnce({ configured: false }).mockResolvedValue(generated({ source: 'convert', username: 'ops', has_public_key: false, fingerprint: undefined, secret_type: 'password' }))
    const wrapper = mountSection()
    await flushPromises()
    wrapper.findComponent({ name: 'ExecutorSetupDialog' }).vm.$emit('done', { kind: 'convert' })
    await flushPromises()
    const hint = wrapper.get('[data-test="executor-converted-hint"]')
    expect(hint.element.tagName).toBe('P')
    expect(hint.text()).toContain('ops 的密碼過去可能有人知道')
    // 提示位置在憑證庫那一行之後
    const credLine = wrapper.get('[data-test="executor-credential-line"]').element
    expect(credLine.compareDocumentPosition(hint.element) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })
})
