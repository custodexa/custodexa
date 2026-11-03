import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { defineComponent, h } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AssetExecutorSection from '@/components/asset/AssetExecutorSection.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import zhTW from '@/i18n/locales/zh-TW.json'
import enUS from '@/i18n/locales/en-US.json'
import jaJP from '@/i18n/locales/ja-JP.json'

// 堡壘機專用帳號區塊。動作按下即生效，不碰抽屜表單，錯誤就地顯示。

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
const outOfScope = () => generated({
  source: 'shared',
  has_public_key: undefined,
  fingerprint: undefined,
  credential: { credential_out_of_scope: true, shared_credential: true },
})

const mountSection = (props = {}, slots = {}) =>
  mount(AssetExecutorSection, {
    global: { plugins: [ElementPlus] },
    props: { assetId: 5, assetName: 'web-01', protocol: 'ssh', windowsFamily: false, hostKeyRecorded: true, ...props },
    slots,
    attachTo: document.body,
  })

beforeEach(() => {
  vi.clearAllMocks()
  setCapabilitiesForTests(['asset:executor-manage', 'credential:create', 'credential:bind', 'credential:update'])
  getMock.mockResolvedValue({ configured: false })
})
afterEach(() => resetCapabilities())

describe('ExecutorSectionVisibility', () => {
  it('無權限時區塊不存在且不發請求', async () => {
    setCapabilitiesForTests([])
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.find('[data-test="executor-section"]').exists()).toBe(false)
    expect(getMock).toHaveBeenCalledTimes(0)
  })

  it('不支援的協定顯示用途說明與原因句、無設定鈕、不發請求', async () => {
    const wrapper = mountSection({ protocol: 'mysql' })
    await flushPromises()
    const purpose = wrapper.get('[data-test="executor-unsupported-purpose"]')
    const reason = wrapper.get('[data-test="executor-unsupported"]')
    expect(purpose.text()).toBe(zhTW.assetExecutor.unconfiguredHint)
    expect(reason.text()).toContain('MySQL 資產')
    expect(reason.text()).not.toContain('MYSQL')
    expect(reason.text()).toContain('只支援 SSH 與 RDP')
    // 用途說明在原因句之前
    expect(purpose.element.compareDocumentPosition(reason.element) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(wrapper.find('[data-test="executor-unconfigured"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="executor-help-area"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="executor-set"]').exists()).toBe(false)
    expect(getMock).toHaveBeenCalledTimes(0)
  })

  it('不支援協定時的用途說明與原因句三語皆有且不同句', () => {
    for (const loc of [zhTW, enUS, jaJP]) {
      const purpose = loc.assetExecutor.unconfiguredHint
      const reason = loc.assetExecutor.unsupportedProtocol
      expect(typeof purpose === 'string' && purpose.length > 0).toBe(true)
      expect(reason).toContain('{protocol}')
      expect(purpose).not.toBe(reason)
    }
  })

  it('不支援協定名照官方大小寫顯示，三語都有顯示名', async () => {
    const expected = { postgres: 'PostgreSQL', mssql: 'SQL Server', redis: 'Redis', vnc: 'VNC', k8s: 'Kubernetes', mysql: 'MySQL' }
    for (const [protocol, label] of Object.entries(expected)) {
      const wrapper = mountSection({ protocol })
      await flushPromises()
      expect(wrapper.get('[data-test="executor-unsupported"]').text()).toContain(label)
      wrapper.unmount()
      for (const loc of [zhTW, enUS, jaJP]) expect(loc.assetExecutor.protocolLabel[protocol]).toBe(label)
    }
  })

  it('讀取 404 時整區不存在', async () => {
    getMock.mockRejectedValue({ response: { status: 404, data: {} } })
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.find('[data-test="executor-section"]').exists()).toBe(false)
  })

  it('讀取 500 時顯示原因句與重新讀取，按下再讀一次', async () => {
    getMock.mockRejectedValueOnce({ response: { status: 500, data: {} } })
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.get('[data-test="executor-load-failed"]').text()).toContain('目前讀不到')
    await wrapper.get('[data-test="executor-reload"]').trigger('click')
    await flushPromises()
    expect(getMock).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-test="executor-unconfigured"]').exists()).toBe(true)
  })

  it('未設定顯示說明、設定鈕與準備說明入口，並有即時生效一行', async () => {
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.get('[data-test="executor-unconfigured"]').text()).toContain('人員不能用它連線')
    expect(wrapper.find('[data-test="executor-set"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="executor-help-link"]').exists()).toBe(true)
    expect(wrapper.get('[data-test="executor-immediate-note"]').text()).toContain('與下方的「儲存」無關')
    expect(wrapper.get('[data-test="executor-section"]').attributes('data-focus')).toBe('executor')
  })
})

describe('ExecutorSectionConfigured', () => {
  it('平台產生金鑰有指紋與三個動作', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.get('[data-test="executor-fingerprint"]').text()).toBe('SHA256:abcd')
    expect(wrapper.get('[data-test="executor-source"]').text()).toContain('平台產生的金鑰')
    for (const k of ['get-public-key', 'replace', 'clear']) expect(wrapper.find(`[data-test="executor-${k}"]`).exists()).toBe(true)
  })

  it('頂端三個動作是有外框的小按鈕，清除為危險色外框', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    for (const k of ['get-public-key', 'replace', 'clear']) {
      const cls = wrapper.get(`[data-test="executor-${k}"]`).classes()
      expect(cls).toContain('el-button--small')
      expect(cls).not.toContain('is-link')
    }
    const clear = wrapper.get('[data-test="executor-clear"]').classes()
    expect(clear).toContain('el-button--danger')
    expect(clear).toContain('is-plain')
    expect(wrapper.get('[data-test="executor-replace"]').classes()).not.toContain('el-button--danger')
  })

  it('指紋複製是圖示鈕：有可及性名稱、無文字，按下寫入剪貼簿', async () => {
    getMock.mockResolvedValue(generated())
    const writeText = vi.fn().mockResolvedValue()
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    const wrapper = mountSection()
    await flushPromises()
    const btn = wrapper.get('[data-test="executor-copy-fingerprint"]')
    expect(btn.attributes('aria-label')).toBe(zhTW.assetExecutor.copyFingerprint)
    expect(btn.find('svg').exists()).toBe(true)
    expect(btn.text()).toBe('')
    await btn.trigger('click')
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith('SHA256:abcd')
    for (const loc of [zhTW, enUS, jaJP]) expect(loc.assetExecutor.copyFingerprint.length > 0).toBe(true)
  })

  it('已設定時不渲染說明第一層句；經入口展開時只出現展開內容', async () => {
    for (const data of [generated(), shared(7)]) {
      getMock.mockResolvedValue(data)
      const wrapper = mountSection()
      await flushPromises()
      expect(wrapper.find('[data-test="executor-help-first"]').exists()).toBe(false)
      expect(wrapper.text()).not.toContain(zhTW.assetExecutor.help.first)
      await wrapper.vm.openSetupHelp(null)
      await flushPromises()
      expect(wrapper.find('[data-test="executor-help-area"] [data-test="executor-help-body"]').exists()).toBe(true)
      expect(wrapper.find('[data-test="executor-help-area"] [data-test="executor-help-first"]').exists()).toBe(false)
      wrapper.unmount()
    }
  })

  it('未設定時說明照舊：展開後有第一層句', async () => {
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-help-link"]').trigger('click')
    expect(wrapper.find('[data-test="executor-help-area"] [data-test="executor-help-first"]').exists()).toBe(true)
  })

  it('共用 7 台顯示「共用 · 7 台」；密碼型無取得公鑰', async () => {
    getMock.mockResolvedValue(shared(7))
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.get('[data-test="executor-shared-tag"]').text()).toBe('共用 · 7 台')
    expect(wrapper.find('[data-test="executor-get-public-key"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="executor-credential-link"]').attributes('href')).toBe('/credentials?credential=40')
  })

  it('範圍外：無指紋、無取得公鑰、有範圍外說明、更換與清除在、憑證庫連結不存在', async () => {
    getMock.mockResolvedValue(outOfScope())
    const wrapper = mountSection()
    await flushPromises()
    expect(wrapper.find('[data-test="executor-fingerprint"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="executor-get-public-key"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="executor-out-of-scope-note"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="executor-replace"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="executor-clear"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="executor-credential-link"]').exists()).toBe(false)
  })
})

describe('ExecutorClear', () => {
  it('確認打開後焦點不在確認清除鈕；共用 7 台末句含 6', async () => {
    getMock.mockResolvedValue(shared(7))
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-test="executor-clear-body"]').text()).toContain('其他 6 台不受影響')
    expect(document.activeElement).not.toBe(wrapper.get('[data-test="executor-clear-confirm-btn"]').element)
  })

  it('範圍外共用來源末句不含任何數字', async () => {
    getMock.mockResolvedValue(outOfScope())
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    expect(wrapper.get('[data-test="executor-clear-body"]').text()).not.toMatch(/[0-9]/)
  })

  it('成功後區塊為未設定且完成句存在、不宣稱撤銷', async () => {
    getMock.mockResolvedValueOnce(generated()).mockResolvedValue({ configured: false })
    deleteMock.mockResolvedValue({})
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    expect(deleteMock).toHaveBeenCalledWith(5, 7)
    expect(wrapper.find('[data-test="executor-unconfigured"]').exists()).toBe(true)
    const done = wrapper.get('[data-test="executor-notice-cleared"]').text()
    expect(done).toContain('仍在')
    expect(done).not.toContain('撤銷')
    expect(wrapper.emitted('changed')).toHaveLength(1)
  })

  it('409 改密中時區塊內句子與新分頁鈕存在', async () => {
    getMock.mockResolvedValue(generated())
    deleteMock.mockRejectedValue({ response: { status: 409, data: { code: 'RULE_CREDENTIAL_ROTATION_ACTIVE' } } })
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-test="executor-notice-rotation"]').text()).toContain('尚未清除：這組秘密正在改密')
    await wrapper.get('[data-test="executor-notice-open-rotation"]').trigger('click')
    expect(open).toHaveBeenCalledWith('/credentials?credential=31', '_blank', 'noopener')
    open.mockRestore()
  })

  it('範圍外共用憑證改密中：有原因句，不給沒有去處的新分頁鈕', async () => {
    getMock.mockResolvedValue(outOfScope())
    deleteMock.mockRejectedValue({ response: { status: 409, data: { code: 'RULE_CREDENTIAL_ROTATION_ACTIVE' } } })
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-test="executor-notice-rotation"]').text()).toContain('尚未清除：這組秘密正在改密')
    expect(wrapper.find('[data-test="executor-notice-open-rotation"]').exists()).toBe(false)
    expect(open).not.toHaveBeenCalled()
    open.mockRestore()
  })

  it('範圍外共用憑證更換時遇改密中：同樣不給新分頁鈕', async () => {
    getMock.mockResolvedValue(outOfScope())
    const wrapper = mountSection()
    await flushPromises()
    wrapper.findComponent({ name: 'ExecutorSetupDialog' }).vm.$emit('rotation-blocked')
    await flushPromises()
    expect(wrapper.get('[data-test="executor-notice-rotation"]').text()).toContain('尚未更換')
    expect(wrapper.find('[data-test="executor-notice-open-rotation"]').exists()).toBe(false)
  })
})

describe('ExecutorStateChanged', () => {
  it('清除收到 409：DELETE 只 1 次、GET 再 1 次、提示含新帳號名、revision 加 1', async () => {
    getMock.mockResolvedValueOnce(generated()).mockResolvedValue(generated({ account_id: 9, username: 'cx-ops2' }))
    deleteMock.mockRejectedValue({ response: { status: 409, data: { code: 'RULE_EXECUTOR_STATE_CHANGED' } } })
    const wrapper = mountSection()
    await flushPromises()
    const before = wrapper.vm.revision
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    expect(deleteMock).toHaveBeenCalledTimes(1)
    expect(getMock).toHaveBeenCalledTimes(2)
    expect(wrapper.get('[data-test="executor-notice-state"]').text()).toContain('cx-ops2')
    expect(wrapper.vm.revision).toBe(before + 1)
  })

  it('重新讀到未設定時用「剛被其他管理員清除」句', async () => {
    getMock.mockResolvedValueOnce(generated()).mockResolvedValue({ configured: false })
    deleteMock.mockRejectedValue({ response: { status: 404, data: {} } })
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-test="executor-notice-state"]').text()).toContain('剛被其他管理員清除')
  })
})

describe('ExecutorLoginStatusSlot', () => {
  const probe = defineComponent({
    props: {
      assetId: { type: Number, default: 0 },
      executor: { type: Object, default: null },
      revision: { type: Number, default: 0 },
      protocol: { type: String, default: '' },
      windowsFamily: { type: Boolean, default: false },
      hostKeyRecorded: { type: Boolean, default: false },
      actions: { type: Object, default: null },
    },
    setup(p) {
      return () => h('div', { 'data-test': 'probe' }, [
        h('button', { 'data-test': 'probe-pk', onClick: (e) => p.actions.openPublicKey(e.currentTarget) }, 'pk'),
        h('button', { 'data-test': 'probe-replace', onClick: () => p.actions.openReplace() }, 'rp'),
        h('a', { 'data-test': 'probe-help', href: '#', onClick: (e) => { e.preventDefault(); p.actions.openSetupHelp(e.currentTarget) } }, 'help'),
        h('button', { 'data-test': 'probe-reload', onClick: () => p.actions.reload() }, 'rl'),
        h('button', { 'data-test': 'probe-cred', onClick: () => p.actions.openCredential() }, 'cr'),
      ])
    },
  })

  it('未設定時插槽不渲染；已設定時 props 鍵集合恰為七個且不含秘密', async () => {
    const empty = mountSection({}, { 'login-status': probe })
    await flushPromises()
    expect(empty.find('[data-test="probe"]').exists()).toBe(false)
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection({}, { 'login-status': (props) => h(probe, props) })
    await flushPromises()
    const p = wrapper.getComponent(probe).props()
    expect(Object.keys(p).sort()).toEqual(['actions', 'assetId', 'executor', 'hostKeyRecorded', 'protocol', 'revision', 'windowsFamily'])
    expect(JSON.stringify(p.executor)).not.toMatch(/password|private_key|BEGIN/)
    await wrapper.setProps({ hostKeyRecorded: false })
    expect(wrapper.getComponent(probe).props('hostKeyRecorded')).toBe(false)
  })

  it('五個回呼：公鑰錨定在插槽按鈕、更換、說明錨定、reload、憑證庫', async () => {
    getMock.mockResolvedValue(generated())
    exportMock.mockResolvedValue('ssh-ed25519 AAAA cx-exec')
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    const wrapper = mountSection({}, { 'login-status': (props) => h(probe, props) })
    await flushPromises()
    await wrapper.get('[data-test="probe-pk"]').trigger('click')
    await flushPromises()
    expect(exportMock).toHaveBeenCalledTimes(1)
    expect(wrapper.vm.$.setupState.pkAnchor).toBe(wrapper.get('[data-test="probe-pk"]').element)
    await wrapper.get('[data-test="probe-replace"]').trigger('click')
    expect(wrapper.vm.$.setupState.dialogMode).toBe('replace')
    expect(wrapper.vm.$.setupState.dialogVisible).toBe(true)
    await wrapper.get('[data-test="probe-help"]').trigger('click')
    await flushPromises()
    expect(wrapper.vm.$.setupState.helpAnchor).toBe(wrapper.get('[data-test="probe-help"]').element)
    expect(wrapper.vm.$.setupState.helpPopoverVisible).toBe(true)
    const rev = wrapper.vm.revision
    await wrapper.get('[data-test="probe-reload"]').trigger('click')
    await flushPromises()
    expect(wrapper.vm.revision).toBe(rev + 1)
    await wrapper.get('[data-test="probe-cred"]').trigger('click')
    expect(open).toHaveBeenCalledWith('/credentials?credential=31', '_blank', 'noopener')
    open.mockRestore()
  })

  it('插槽內容位於資訊列之後、憑證庫連結之前；未填時沒有登入狀態文字', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection({}, { 'login-status': (props) => h(probe, props) })
    await flushPromises()
    const html = wrapper.html()
    expect(html.indexOf('executor-info')).toBeLessThan(html.indexOf('data-test="probe"'))
    expect(html.indexOf('data-test="probe"')).toBeLessThan(html.indexOf('executor-credential-link'))
    const bare = mountSection()
    await flushPromises()
    expect(bare.text()).not.toContain('尚未確認能登入')
  })
})
