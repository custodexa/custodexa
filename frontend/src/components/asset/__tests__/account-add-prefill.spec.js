import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AssetAccountRows from '../AssetAccountRows.vue'
import previewWrite from '@/directives/previewWrite'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'

// 主機帳號盤點「納管」預填：帶入帳號名與特權、依命名能力切換憑證方式、隱藏字元警示、不自動送出、只用一次。

const createMock = vi.fn()
vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }),
  createAssetAccount: (...a) => createMock(...a),
  updateAssetAccount: vi.fn(),
  deleteAssetAccount: vi.fn(),
  setDefaultAssetAccount: vi.fn(),
}))
vi.mock('@/api/credentials', () => ({
  listCredentials: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  rebindAccountCredential: vi.fn(),
}))
vi.mock('@/api/authorizations', () => ({ getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }) }))

class ObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)
enableAutoUnmount(afterEach)

const ZWSP = String.fromCodePoint(0x200b)
const prefillOf = (o = {}) => ({ assetId: 7, username: 'deploy', privileged: true, fromInventory: true, ...o })

async function mountRows(prefill, perms = ['asset:update', 'credential:create']) {
  setCapabilitiesForTests(perms)
  const w = mount(AssetAccountRows, {
    attachTo: document.body,
    props: { assetId: 7, assetName: 'web-01', protocol: 'ssh', prefill },
    global: { plugins: [ElementPlus], directives: { 'preview-write': previewWrite } },
  })
  await flushPromises()
  return w
}

beforeEach(() => {
  vi.clearAllMocks()
})
afterEach(() => resetCapabilities())

describe('納管預填', () => {
  it('有命名能力：切專用、帶帳號名與特權、資訊條、焦點落密碼欄', async () => {
    const w = await mountRows(prefillOf())
    const row = w.findComponent({ name: 'AssetAccountAddRow' })
    expect(row.exists()).toBe(true)
    expect(row.vm.model.credential_mode).toBe('dedicated')
    expect(row.vm.model.username).toBe('deploy')
    expect(row.vm.model.privileged).toBe(true)
    expect(w.find('[data-test="prefill-info"]').text()).toContain('deploy')
    expect(w.find('[data-test="prefill-info"]').text()).toContain('請補上密碼或私鑰')
    expect(document.activeElement?.getAttribute('type')).toBe('password')
  })

  it('沒有命名能力：維持共用並說明同名共用憑證', async () => {
    const w = await mountRows(prefillOf(), ['asset:update'])
    const row = w.findComponent({ name: 'AssetAccountAddRow' })
    expect(row.vm.model.credential_mode).toBe('shared')
    expect(row.vm.model.username).toBe('')
    expect(w.find('[data-test="prefill-info"]').text()).toContain('共用憑證')
    expect(w.find('[data-test="prefill-info"]').text()).toContain('deploy')
  })

  it('含 U+200B 的名稱：照原值帶入並顯示警示', async () => {
    const name = `dep${ZWSP}loy`
    const w = await mountRows(prefillOf({ username: name }))
    const row = w.findComponent({ name: 'AssetAccountAddRow' })
    expect(row.vm.model.username).toBe(name)
    const warn = w.find('[data-test="prefill-hidden-warning"]')
    expect(warn.exists()).toBe(true)
    expect(warn.text()).toContain('<U+200B>')
  })

  it('普通名稱沒有隱藏字元警示', async () => {
    const w = await mountRows(prefillOf())
    expect(w.find('[data-test="prefill-hidden-warning"]').exists()).toBe(false)
  })

  it('掛載後沒有任何寫入請求（不自動送出）', async () => {
    await mountRows(prefillOf())
    expect(createMock).not.toHaveBeenCalled()
  })

  it('資產識別不符：不開新增列', async () => {
    const w = await mountRows(prefillOf({ assetId: 99 }))
    expect(w.findComponent({ name: 'AssetAccountAddRow' }).exists()).toBe(false)
  })

  it('預填只使用一次：取消後再按新增是空白表單', async () => {
    const w = await mountRows(prefillOf())
    await w.find('[data-test="account-add-cancel"]').trigger('click')
    await flushPromises()
    expect(w.findComponent({ name: 'AssetAccountAddRow' }).exists()).toBe(false)
    expect(w.find('[data-test="manage-done"]').exists()).toBe(false)
    await w.find('[data-test="account-add"]').trigger('click')
    await flushPromises()
    const row = w.findComponent({ name: 'AssetAccountAddRow' })
    expect(row.vm.model.username).toBe('')
    expect(row.vm.model.privileged).toBe(false)
    expect(w.find('[data-test="prefill-info"]').exists()).toBe(false)
  })

  it('新增成功：成功條帶回到盤點連結，點擊發出事件', async () => {
    createMock.mockResolvedValue({})
    const w = await mountRows(prefillOf())
    const row = w.findComponent({ name: 'AssetAccountAddRow' })
    row.vm.model.password = 'p'
    await row.vm.submit()
    await flushPromises()
    expect(createMock).toHaveBeenCalledTimes(1)
    expect(createMock.mock.calls[0][1]).toMatchObject({ username: 'deploy', privileged: true })
    const bar = w.find('[data-test="manage-done"]')
    expect(bar.text()).toContain('deploy')
    await w.find('[data-test="manage-back"]').trigger('click')
    expect(w.emitted('back-to-inventory')).toHaveLength(1)
  })

  it('非從盤點進來的新增成功：沒有成功條', async () => {
    createMock.mockResolvedValue({})
    const w = await mountRows(null)
    await w.find('[data-test="account-add"]').trigger('click')
    await flushPromises()
    const row = w.findComponent({ name: 'AssetAccountAddRow' })
    row.vm.model.credential_mode = 'dedicated'
    row.vm.model.username = 'x'
    await row.vm.submit()
    await flushPromises()
    expect(w.find('[data-test="manage-done"]').exists()).toBe(false)
  })
})
