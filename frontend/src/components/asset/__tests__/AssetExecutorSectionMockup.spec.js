import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { RefreshCw } from 'lucide-vue-next'
import ExecutorNoticeBox from '@/components/asset/ExecutorNoticeBox.vue'
import AssetExecutorSection from '@/components/asset/AssetExecutorSection.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'

// 區塊的呈現（二）：結果頁期間背後即時更新、被擋與狀態已變的提示框、清除確認圖示、焦點框、暗色 plain danger 鈕。

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

describe('ExecutorResultAppliesImmediately', () => {
  it('結果頁開著時背後區塊已換成已設定、帶「剛設定」，對話框仍開著', async () => {
    getMock.mockResolvedValueOnce({ configured: false }).mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-set"]').trigger('click')
    await flushPromises()
    const dlg = wrapper.findComponent({ name: 'ExecutorSetupDialog' })
    dlg.vm.$emit('applied')
    await flushPromises()
    expect(getMock).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-test="executor-set"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="executor-clear"]').exists()).toBe(true)
    expect(wrapper.get('[data-test="executor-just-tag"]').text()).toBe('剛設定')
    expect(dlg.props('modelValue')).toBe(true)
    expect(wrapper.emitted('changed')).toHaveLength(1)
  })
})

describe('ExecutorBlockNotices', () => {
  it('狀態已變：警示框用重新整理圖示，首句粗體、說明另起', async () => {
    getMock.mockResolvedValueOnce(generated()).mockResolvedValue(generated({ account_id: 9, username: 'cx-ops2' }))
    deleteMock.mockRejectedValue({ response: { status: 409, data: { code: 'RULE_EXECUTOR_STATE_CHANGED' } } })
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    const box = wrapper.getComponent(ExecutorNoticeBox)
    expect(box.attributes('data-test')).toBe('executor-notice-state')
    expect(box.props('icon')).toBe(RefreshCw)
    expect(box.get('[data-test="notice-box-title"]').text()).toBe('尚未清除：這台的堡壘機專用帳號剛被其他管理員換成 cx-ops2。')
    expect(box.text()).toContain('下方已更新為目前的設定，確認後再操作。')
  })

  it('改密中：修正入口是主要按鈕並帶外部連結圖示，在新分頁開啟', async () => {
    getMock.mockResolvedValue(generated())
    deleteMock.mockRejectedValue({ response: { status: 409, data: { code: 'RULE_CREDENTIAL_ROTATION_ACTIVE' } } })
    const open = vi.spyOn(window, 'open').mockImplementation(() => null)
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    const box = wrapper.getComponent(ExecutorNoticeBox)
    expect(box.props('icon')).toBeNull()
    expect(box.get('[data-test="notice-box-title"]').text()).toBe('尚未清除：這組秘密正在改密。')
    const btn = wrapper.get('[data-test="executor-notice-open-rotation"]')
    expect(btn.classes()).toContain('el-button--primary')
    expect(btn.classes()).not.toContain('is-link')
    expect(btn.find('svg').exists()).toBe(true)
    await btn.trigger('click')
    expect(open).toHaveBeenCalledWith('/credentials?credential=31', '_blank', 'noopener')
    open.mockRestore()
  })

  it('清除完成句為細綠框白字的提示框（細勾號），不是 el-alert', async () => {
    getMock.mockResolvedValueOnce(generated()).mockResolvedValue({ configured: false })
    deleteMock.mockResolvedValue({})
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await wrapper.get('[data-test="executor-clear-confirm-btn"]').trigger('click')
    await flushPromises()
    const box = wrapper.findAllComponents(ExecutorNoticeBox).find((c) => c.attributes('data-test') === 'executor-notice-cleared')
    expect(box.props('tone')).toBe('success')
    expect(box.classes()).toEqual(expect.arrayContaining(['notice-box', 'is-success', 'notice']))
    expect(box.find('[data-test="notice-box-icon"]').classes()).toContain('lucide-check')
    expect(box.find('[data-test="notice-box-title"]').exists()).toBe(false)
    expect(box.text()).toContain('已清除')
    expect(wrapper.find('.el-alert').exists()).toBe(false)
  })

  it('確認「清除」為紅框紅字（plain danger），與區塊頂端清除鈕同型', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await flushPromises()
    const btns = wrapper.findAllComponents({ name: 'ElButton' })
    const confirm = btns.find((c) => c.attributes('data-test') === 'executor-clear-confirm-btn')
    const top = btns.find((c) => c.attributes('data-test') === 'executor-clear')
    expect(confirm.props('type')).toBe('danger')
    expect(confirm.props('plain')).toBe(true)
    expect([top.props('type'), top.props('plain')]).toEqual([confirm.props('type'), confirm.props('plain')])
  })
})

describe('ExecutorClearConfirmIcon', () => {
  it('清除確認標題前有警示圖示', async () => {
    getMock.mockResolvedValue(generated())
    const wrapper = mountSection()
    await flushPromises()
    await wrapper.get('[data-test="executor-clear"]').trigger('click')
    await flushPromises()
    const title = wrapper.get('[data-test="executor-clear-title"]')
    expect(title.find('svg').exists()).toBe(true)
    expect(title.text()).toBe('清除這台的堡壘機專用帳號？')
  })
})

describe('ExecutorStyleRules', () => {
  const read = (p) => readFileSync(join(process.cwd(), p), 'utf8')

  it('成功提示框：細綠框、淡綠底、白字（主文字色）、綠色細勾號', () => {
    const sfc = read('src/components/asset/ExecutorNoticeBox.vue')
    const box = /\.notice-box\.is-success \{[^}]*\}/.exec(sfc)?.[0] || ''
    expect(box).toMatch(/border-color: color-mix\(in srgb, var\(--ot-success\)/)
    expect(box).toMatch(/background-color: color-mix\(in srgb, var\(--ot-success\)/)
    expect(/\.notice-box \{[^}]*\}/.exec(sfc)[0]).toMatch(/color: var\(--ot-text-primary\)/)
    expect(sfc).toMatch(/\.is-success \.nb-icon \{[^}]*color: var\(--ot-success\)/)
  })

  it('深連結聚焦區塊標題時有可見焦點框：標題不再無條件拿掉 outline，:focus-visible 畫框', () => {
    const sfc = read('src/components/asset/AssetExecutorSection.vue')
    const titleBlock = /\.section-title \{[^}]*\}/.exec(sfc)[0]
    expect(titleBlock).not.toMatch(/outline:\s*none/)
    expect(sfc).toMatch(/\.section-title:focus-visible \{[^}]*outline: 2px solid var\(--ot-primary\)/)
  })

  it('暗色 plain danger 鈕滑過與按下：白字配危險填色階，不再字底同色', () => {
    const css = read('src/styles/dark-theme.css')
    const hover = /html\.dark \.el-button--danger\.is-plain:not\(\.is-disabled\):hover \{[^}]*\}/.exec(css)?.[0] || ''
    expect(hover).toMatch(/color: var\(--el-color-white\)/)
    expect(hover).toMatch(/background-color: var\(--ot-danger-fill\)/)
    const active = /html\.dark \.el-button--danger\.is-plain:not\(\.is-disabled\):active \{[^}]*\}/.exec(css)?.[0] || ''
    expect(active).toMatch(/color: var\(--el-color-white\)/)
    expect(active).toMatch(/background-color: var\(--ot-danger-fill-hover\)/)
    // 滑過規則須排在把各狀態文字釘成紅色的那條之後，才蓋得過 :focus
    expect(css.indexOf(hover)).toBeGreaterThan(css.indexOf('html.dark .el-button--danger.is-plain:not(.is-disabled):focus {'))
  })
})
