import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Assets from '../Assets.vue'
import { createAsset } from '@/api/assets'

// 新增資產表單的登入憑證區塊與進階選項。
//
// 這一頁最初的毛病是「同一件事有兩個入口」：表單上半段有一組憑證欄位，
// 下半段還有一顆帳號管理按鈕，兩邊寫進去的東西不是同一筆。斷言重心因此是：
//  1. 畫面上只有一個憑證入口，且兩種來源互斥（送出的載荷也二擇一）；
//  2. 不常用的設定預設收合，但「已經有值」與「伺服端說這裡有錯」時必須自己展開
//     ——紅字掛在看不見的欄位上等於沒有紅字。

enableAutoUnmount(afterEach)
vi.setConfig({ testTimeout: 20_000 })

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const getAssetListMock = vi.fn()
vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => getAssetListMock(...a),
  getAsset: vi.fn(),
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn().mockRejectedValue(new Error('no key')),
  resetAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  getAssetTags: vi.fn().mockResolvedValue({ data: [] }),
}))

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: vi.fn().mockResolvedValue({ data: [] }),
}))

vi.mock('@/api/accessRequests', () => ({
  createAccessRequest: vi.fn(),
  breakGlassConnect: vi.fn(),
}))

const listCredentialsMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  listCredentials: (...a) => listCredentialsMock(...a),
  rebindAccountCredential: vi.fn(),
}))

vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: vi.fn().mockResolvedValue({ data: [] }),
  createAssetAccount: vi.fn(),
  updateAssetAccount: vi.fn(),
  deleteAssetAccount: vi.fn(),
  setDefaultAssetAccount: vi.fn(),
}))

vi.mock('@/api/authorizations', () => ({
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
}))

const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}
const treeSelectStub = {
  name: 'ElTreeSelect',
  props: ['modelValue', 'data'],
  template: '<div class="tree-select-stub" />',
}
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  template: '<div class="table-stub"><slot /></div>',
}
const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label'],
  template: '<div class="col-stub"><th>{{ label }}</th></div>',
}

const mountPage = async () => {
  localStorage.setItem('user', JSON.stringify({ id: 1, username: 'admin', roles: ['admin'] }))
  const wrapper = mount(Assets, {
    global: {
      plugins: [ElementPlus],
      stubs: {
        'el-dialog': dialogStub,
        'el-drawer': dialogStub,
        'el-tree-select': treeSelectStub,
        ElTable: tableStub,
        ElTableColumn: tableColumnStub,
        RouterLink: { template: '<a><slot /></a>' },
      },
    },
  })
  await flushPromises()
  return wrapper
}

const advanced = (wrapper) => wrapper.findComponent({ name: 'AssetAdvancedFields' })

beforeEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
  getAssetListMock.mockResolvedValue({ data: [], total: 0, page: 1, page_size: 20 })
  listCredentialsMock.mockResolvedValue({
    data: [
      {
        id: 11,
        name: '正式區 root',
        scope: 'shared',
        username: 'root',
        secret_type: 'password',
        protocol_family: 'ssh',
        binding_count: 12,
      },
    ],
    total: 1,
  })
})

describe('新增資產的登入憑證區塊', () => {
  it('二擇一：畫面上只有一個憑證入口，也沒有第二個帳號管理按鈕', async () => {
    const wrapper = await mountPage()
    wrapper.vm.handleCreate()
    await flushPromises()

    // 出廠值是「這台專用」：全新環境還沒有任何共用憑證可挑
    expect(wrapper.vm.form.credential_mode).toBe('dedicated')
    expect(wrapper.findAll('[data-test="credential-username"]')).toHaveLength(1)
    expect(wrapper.findAll('[data-test="credential-password"]')).toHaveLength(1)
    expect(wrapper.findAllComponents({ name: 'CredentialPicker' })).toHaveLength(0)

    // 換成共用：直填欄位整組收起來，只剩選擇器
    wrapper.vm.form.credential_mode = 'shared'
    await flushPromises()
    expect(wrapper.findAll('[data-test="credential-username"]')).toHaveLength(0)
    expect(wrapper.findAll('[data-test="credential-password"]')).toHaveLength(0)
    expect(wrapper.findAllComponents({ name: 'CredentialPicker' })).toHaveLength(1)

    // 舊的第二入口（帳號管理按鈕）已不存在
    expect(wrapper.text()).not.toContain('帳號管理')
  })

  it('選共用憑證時載荷只帶憑證識別；專用時帶帳號名與秘密', async () => {
    const wrapper = await mountPage()
    wrapper.vm.handleCreate()
    await flushPromises()

    Object.assign(wrapper.vm.form, {
      name: 'web-03',
      protocol: 'ssh',
      host: '10.20.1.13',
      port: 22,
      credential_mode: 'shared',
      credential_id: 11,
    })
    await wrapper.vm.handleSubmit()
    await flushPromises()

    let payload = createAsset.mock.calls.at(-1)[0]
    expect(payload.credential_id).toBe(11)
    expect('username' in payload).toBe(false)
    expect('password' in payload).toBe(false)

    wrapper.vm.handleCreate()
    await flushPromises()
    Object.assign(wrapper.vm.form, {
      name: 'web-04',
      protocol: 'ssh',
      host: '10.20.1.14',
      port: 22,
      credential_mode: 'dedicated',
      username: 'app',
      password: 's3cr3t',
    })
    await wrapper.vm.handleSubmit()
    await flushPromises()

    payload = createAsset.mock.calls.at(-1)[0]
    expect(payload.username).toBe('app')
    expect(payload.password).toBe('s3cr3t')
    expect('credential_id' in payload).toBe(false)
  })

  it('選定共用憑證後說明句當場說出這台會是第幾台（影響面不能等建完才知道）', async () => {
    const wrapper = await mountPage()
    wrapper.vm.handleCreate()
    await flushPromises()

    wrapper.vm.form.credential_mode = 'shared'
    await flushPromises()

    // 還沒選之前不憑空生一個數字
    const before = wrapper.find('[data-test="credential-shared-hint"]').text()
    expect(before).not.toContain('第')
    expect(before).toContain('只列出此協議可用的憑證')

    wrapper.vm.form.credential_id = 11
    await flushPromises()

    // 清單回的 binding_count 是 12：這台建立後是第 13 台
    const after = wrapper.find('[data-test="credential-shared-hint"]').text()
    expect(after).toContain('正式區 root')
    expect(after).toContain('第 13 台')
  })

  it('切到共用即清掉已填的秘密（兩種來源同時帶值會被伺服端整筆拒絕）', async () => {
    const wrapper = await mountPage()
    wrapper.vm.handleCreate()
    await flushPromises()
    Object.assign(wrapper.vm.form, { username: 'app', password: 's3cr3t' })

    wrapper.findComponent({ name: 'AssetCredentialSection' }).vm.onModeChange('shared')
    expect(wrapper.vm.form.username).toBe('')
    expect(wrapper.vm.form.password).toBe('')
  })
})

describe('進階選項', () => {
  it('預設收合，且摘要說得出裡面有什麼', async () => {
    const wrapper = await mountPage()
    wrapper.vm.handleCreate()
    await flushPromises()

    expect(advanced(wrapper).vm.expanded).toBe(false)
    expect(wrapper.find('[data-test="asset-advanced"]').text()).toContain('進階選項')
    expect(wrapper.find('[data-test="asset-advanced"]').text()).toContain('掛載節點')
    expect(wrapper.find('[data-test="asset-advanced-mark"]').exists()).toBe(false)

    // 新增態的收合區沒有「狀態」（那一欄只在編輯態）：摘要不得點名不存在的欄位
    const summary = wrapper.find('[data-test="asset-advanced-summary"]').text()
    expect(summary).toContain('SFTP 帳號')
    expect(summary).not.toContain('狀態')
  })

  it('收合區內任一欄位有值即自動展開並標示', async () => {
    const wrapper = await mountPage()
    wrapper.vm.handleCreate()
    await flushPromises()
    expect(advanced(wrapper).vm.expanded).toBe(false)

    wrapper.vm.form.description = '正式區前台'
    await flushPromises()

    expect(advanced(wrapper).vm.expanded).toBe(true)
    expect(wrapper.find('[data-test="asset-advanced-mark"]').text()).toContain('已設定')
  })

  it('伺服端把驗證錯誤指到收合區內的欄位時自動展開並標示', async () => {
    const wrapper = await mountPage()
    wrapper.vm.handleCreate()
    await flushPromises()
    expect(advanced(wrapper).vm.expanded).toBe(false)

    createAsset.mockRejectedValueOnce({
      response: {
        status: 400,
        data: { code: 'VALIDATION_WINRM_CA_CERT_REQUIRED', params: { field: 'winrm_ca_cert' } },
      },
    })
    Object.assign(wrapper.vm.form, {
      name: 'win-01', protocol: 'rdp', host: '10.20.1.9', port: 3389, username: 'Administrator',
    })
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(advanced(wrapper).vm.expanded).toBe(true)
    expect(wrapper.find('[data-test="asset-advanced-mark"]').text()).toContain('修正')
  })
})
