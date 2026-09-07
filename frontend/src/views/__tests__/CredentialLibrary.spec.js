import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import CredentialLibrary from '@/views/CredentialLibrary.vue'
import CredentialRotateDialog from '@/components/credential/CredentialRotateDialog.vue'

// 帳號憑證庫的主從檢視。
//
// 斷言重心在四件會靜默出錯的事：
//  1. 左表要同時裝得下共用與專用兩種憑證，且專用的顯示名是計算值——
//     少一種就等於「所有登入憑證都在這裡」這句話不成立；
//  2. 點列即切詳情，掛載清單逐台帶就位版本；
//  3. 輪替進行中時四個動作都不可執行，且**每一個都就地說明原因**；
//  4. 篩選送到伺服端（範圍變更即查），不是在前端偷偷過濾一份不完整的清單。

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const listMock = vi.fn()
const getMock = vi.fn()
const getRotationMock = vi.fn()
const convertScopeMock = vi.fn()

vi.mock('@/api/credentials', () => ({
  listCredentials: (...a) => listMock(...a),
  getCredential: (...a) => getMock(...a),
  createCredential: vi.fn(),
  updateCredential: vi.fn(),
  deleteCredential: vi.fn(),
  bindCredential: vi.fn(),
  unbindCredential: vi.fn(),
  detachCredentialBinding: vi.fn(),
  convertCredentialScope: (...a) => convertScopeMock(...a),
  startCredentialRotation: vi.fn(),
  getCredentialRotation: (...a) => getRotationMock(...a),
  retryCredentialRotationMember: vi.fn(),
  abandonCredentialRotation: vi.fn(),
}))

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [], total: 0 }),
}))

const dialogStub = {
  props: ['modelValue'],
  template:
    '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

const credentialFixture = (overrides = {}) => ({
  id: 1,
  name: '正式區 root',
  scope: 'shared',
  username: 'root',
  secret_type: 'password',
  auth_method: 'sql',
  protocol_family: 'ssh',
  note: '',
  has_password: true,
  has_private_key: false,
  binding_count: 12,
  current_version_no: 4,
  rotation_active: false,
  created_at: '2026-07-02T03:00:00Z',
  updated_at: '2026-08-30T03:00:00Z',
  ...overrides,
})

// 七筆：兩筆共用、五筆專用。專用的名稱是「資產名 / 帳號名」的計算值
const listFixture = () => [
  credentialFixture({ id: 1, name: '正式區 root', binding_count: 12 }),
  credentialFixture({
    id: 2, name: 'ops 部署金鑰', username: 'ops',
    secret_type: 'ssh_key', binding_count: 3,
  }),
  credentialFixture({
    id: 11, name: 'web-01 / app', scope: 'dedicated', username: 'app', binding_count: 1,
  }),
  credentialFixture({
    id: 12, name: 'mssql-01 / sa', scope: 'dedicated', username: 'sa',
    protocol_family: 'database', binding_count: 1,
  }),
  credentialFixture({
    id: 13, name: 'k8s-prod / default', scope: 'dedicated', username: 'default',
    protocol_family: 'k8s', binding_count: 1,
  }),
  credentialFixture({
    id: 14, name: 'vnc-01 / operator', scope: 'dedicated', username: 'operator',
    protocol_family: 'vnc', binding_count: 1,
  }),
  credentialFixture({
    id: 15, name: 'win-01 / Administrator', scope: 'dedicated',
    username: 'Administrator', protocol_family: 'windows', binding_count: 1,
  }),
]

const detailFixture = (overrides = {}) => ({
  ...credentialFixture({ binding_count: 3 }),
  bindings: [
    {
      account_id: 101, asset_id: 11, asset_name: 'web-01', username: 'root',
      is_default: true, privileged: false, note: '',
      effective_version_no: 4, up_to_date: true,
    },
    {
      account_id: 102, asset_id: 12, asset_name: 'web-02', username: 'root',
      is_default: false, privileged: true, note: '',
      effective_version_no: 4, up_to_date: true,
    },
    {
      account_id: 103, asset_id: 13, asset_name: 'app-01', username: 'root',
      is_default: false, privileged: false, note: '',
      effective_version_no: 3, up_to_date: false,
    },
  ],
  ...overrides,
})

async function mountPage() {
  const wrapper = mount(CredentialLibrary, {
    global: { plugins: [ElementPlus], stubs: { 'el-dialog': dialogStub } },
  })
  await flushPromises()
  return wrapper
}

async function mountWithSelection(detail = detailFixture()) {
  getMock.mockResolvedValue({ data: detail, aggregate_state: detail.rotation_active ? 'changing' : 'idle' })
  const wrapper = await mountPage()
  await wrapper.vm.selectCredential({ id: detail.id })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  listMock.mockResolvedValue({ data: listFixture(), total: 7 })
  getMock.mockResolvedValue({ data: detailFixture(), aggregate_state: 'idle' })
  getRotationMock.mockResolvedValue({
    data: { id: 7, status: 'running', mode: 'group', aggregate_state: 'changing', members: [] },
  })
  convertScopeMock.mockResolvedValue({ data: credentialFixture({ id: 11, scope: 'shared' }) })
})

// 專用憑證（單一掛載），用於「轉為共用」那一組案例
const dedicatedDetail = (overrides = {}) => detailFixture({
  id: 11,
  name: 'web-01 / app',
  scope: 'dedicated',
  username: 'app',
  binding_count: 1,
  bindings: [
    {
      account_id: 101, asset_id: 11, asset_name: 'web-01', username: 'app',
      is_default: true, privileged: false, note: '',
      effective_version_no: 4, up_to_date: true,
    },
  ],
  ...overrides,
})

describe('左表', () => {
  it('列出七筆（兩共用五專用），專用顯示計算名且掛載數為 1', async () => {
    const wrapper = await mountPage()

    expect(listMock).toHaveBeenCalledTimes(1)
    expect(wrapper.findAll('.el-table__row')).toHaveLength(7)

    // 共用是落庫名稱，專用是「資產名 / 帳號名」
    expect(wrapper.find('[data-test="credential-name-1"]').text()).toBe('正式區 root')
    expect(wrapper.find('[data-test="credential-name-11"]').text()).toBe('web-01 / app')

    expect(wrapper.find('[data-test="credential-scope-1"]').text()).toBe('共用')
    expect(wrapper.find('[data-test="credential-scope-11"]').text()).toBe('專用')

    // 專用憑證恰有一個掛載，這個數字錯了就代表範圍的定義被破壞
    for (const id of [11, 12, 13, 14, 15]) {
      expect(wrapper.find(`[data-test="credential-bindings-${id}"]`).text(), `#${id}`).toBe('1')
    }
    expect(wrapper.find('[data-test="credential-bindings-1"]').text()).toBe('12')
  })

  it('專用憑證的顯示名缺料時補話，不留下一整列空白', async () => {
    listMock.mockResolvedValue({
      data: [
        credentialFixture({ id: 21, scope: 'dedicated', name: 'app', username: 'app' }),
        credentialFixture({ id: 22, scope: 'dedicated', name: 'vnc-test / ', username: '' }),
      ],
      total: 2,
    })
    const wrapper = await mountPage()

    expect(wrapper.find('[data-test="credential-name-21"]').text()).toBe('（資產已移除） / app')
    expect(wrapper.find('[data-test="credential-name-22"]').text()).toBe('vnc-test / （未設定）')
  })

  it('清單載入失敗時就地說出來，不把空表說成「還沒有任何憑證」', async () => {
    listMock.mockRejectedValueOnce(new Error('boom'))
    const wrapper = await mountPage()

    expect(wrapper.find('[data-test="list-error"]').text()).toContain('載入憑證失敗')
    // 失敗與「真的沒有」是兩件事：此時不得出現空狀態那句話
    expect(wrapper.find('[data-test="credential-empty"]').exists()).toBe(false)

    // 重查成功即撤下錯誤
    await wrapper.vm.loadList()
    await flushPromises()
    expect(wrapper.find('[data-test="list-error"]').exists()).toBe(false)
    expect(wrapper.findAll('.el-table__row')).toHaveLength(7)
  })

  it('K8s 的秘密顯示為 Token，而不是一個從來不是密碼的「密碼」', async () => {
    const wrapper = await mountPage()

    const rows = wrapper.findAll('.el-table__row')
    expect(rows.some((r) => r.text().includes('Token'))).toBe(true)
  })
})

describe('篩選', () => {
  it('範圍、型別、輪替狀態變更即查，條件與分頁一併送到伺服端', async () => {
    const wrapper = await mountPage()

    wrapper.vm.filters.scope = 'shared'
    wrapper.vm.filters.secret_type = 'ssh_key'
    wrapper.vm.filters.rotation_state = 'out_of_sync'
    await wrapper.vm.applyFilters()
    await flushPromises()

    expect(listMock).toHaveBeenCalledTimes(2)
    expect(listMock.mock.calls[1][0]).toEqual({
      scope: 'shared',
      secret_type: 'ssh_key',
      rotation_state: 'out_of_sync',
      search: undefined,
      page: 1,
      page_size: 20,
    })
  })

  it('重設清空四個條件並重新查詢', async () => {
    const wrapper = await mountPage()

    wrapper.vm.filters.scope = 'dedicated'
    wrapper.vm.filters.search = 'root'
    wrapper.vm.filters.secret_type = 'password'
    wrapper.vm.filters.rotation_state = 'changing'
    await wrapper.vm.resetFilters()
    await flushPromises()

    expect(wrapper.vm.filters).toEqual({
      scope: '', search: '', secret_type: '', rotation_state: '',
    })
    expect(listMock.mock.calls.at(-1)[0]).toEqual({
      scope: undefined,
      secret_type: undefined,
      rotation_state: undefined,
      search: undefined,
      page: 1,
      page_size: 20,
    })
  })

  it('換頁重新向伺服端要那一頁，總數取自回應', async () => {
    const wrapper = await mountPage()
    expect(wrapper.vm.total).toBe(7)

    await wrapper.vm.changePage(2)
    await flushPromises()
    expect(listMock.mock.calls.at(-1)[0].page).toBe(2)

    // 改每頁筆數要回到第一頁：留在第 3 頁而每頁變大，看到的會是另一批資料
    await wrapper.vm.changePageSize(50)
    await flushPromises()
    expect(listMock.mock.calls.at(-1)[0]).toMatchObject({ page: 1, page_size: 50 })
  })
})

describe('詳情', () => {
  it('點列切詳情，掛載清單列出三台且各標就位版本', async () => {
    const wrapper = await mountWithSelection()

    expect(getMock).toHaveBeenCalledWith(1)
    expect(wrapper.find('[data-test="detail-name"]').text()).toBe('正式區 root')
    expect(wrapper.find('[data-test="detail-version"]').text()).toBe('v4')

    expect(wrapper.findAll('[data-test^="binding-row-"]')).toHaveLength(3)
    expect(wrapper.find('[data-test="binding-version-101"]').text()).toBe('v4')
    expect(wrapper.find('[data-test="binding-version-102"]').text()).toBe('v4')
    expect(wrapper.find('[data-test="binding-version-103"]').text()).toBe('v3')
    expect(wrapper.find('[data-test="binding-state-103"]').text()).toBe('待更新')
  })

  it('未選任何憑證時給的是下一步指引，不是空白面板', async () => {
    const wrapper = await mountPage()

    expect(wrapper.find('[data-test="detail-placeholder"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('選一筆憑證')
  })

  it('輪替進行中：四個動作都不可執行，且就地說明涵蓋這四個動作', async () => {
    const wrapper = await mountWithSelection(detailFixture({ rotation_active: true }))

    for (const action of ['rotate', 'bind', 'to-dedicated']) {
      expect(wrapper.find(`[data-test="action-${action}"]`).classes(), action)
        .toContain('is-disabled')
    }
    expect(wrapper.find('[data-test="detail-delete"]').classes()).toContain('is-disabled')

    // 同一個理由只寫一次，但那一句要記得自己涵蓋哪四個動作
    const reason = wrapper.find('[data-test="blocked-rotate"]')
    expect(reason.exists()).toBe(true)
    expect(reason.text()).toContain('輪替進行中')
    expect(reason.attributes('data-actions').split(' ').sort())
      .toEqual(['bind', 'delete', 'rotate', 'to-dedicated'])

    // 四行一模一樣的字是噪音：只留一行
    expect(wrapper.findAll('.reason')).toHaveLength(1)
  })

  it('仍有掛載的共用憑證不可刪除，就地說明還掛在幾台上', async () => {
    const wrapper = await mountWithSelection()

    expect(wrapper.find('[data-test="detail-delete"]').classes()).toContain('is-disabled')
    const reason = wrapper.find('[data-test="blocked-delete"]')
    expect(reason.text()).toContain('3')
    expect(reason.text()).toContain('卸載')
  })

  it('掛在多台上時不可轉為專用，就地說明先減到一台', async () => {
    const wrapper = await mountWithSelection()

    expect(wrapper.find('[data-test="action-to-dedicated"]').classes()).toContain('is-disabled')
    expect(wrapper.find('[data-test="blocked-to-dedicated"]').text()).toContain('只剩一台')
  })

  it('專用憑證的詳情有「轉為共用」入口（新增資產的說明句指的就是這裡）', async () => {
    const wrapper = await mountWithSelection(dedicatedDetail())

    const toShared = wrapper.find('[data-test="action-to-shared"]')
    expect(toShared.exists()).toBe(true)
    expect(toShared.text()).toBe('轉為共用')
    expect(toShared.classes()).not.toContain('is-disabled')
    // 範圍是二選一：專用憑證上不會同時出現「轉為專用」
    expect(wrapper.find('[data-test="action-to-dedicated"]').exists()).toBe(false)
  })

  it('轉為共用時名稱必填：空白就地說明且不送出，填了才帶名稱送出', async () => {
    const wrapper = await mountWithSelection(dedicatedDetail())

    await wrapper.find('[data-test="action-to-shared"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="to-shared-dialog"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="to-shared-error"]').exists()).toBe(false)

    await wrapper.find('[data-test="to-shared-submit"]').trigger('click')
    await flushPromises()
    expect(convertScopeMock).not.toHaveBeenCalled()
    expect(wrapper.find('[data-test="to-shared-error"]').text()).toContain('請輸入名稱')

    await wrapper.find('[data-test="to-shared-name"]').setValue('  正式區 app  ')
    await wrapper.find('[data-test="to-shared-submit"]').trigger('click')
    await flushPromises()

    expect(convertScopeMock).toHaveBeenCalledTimes(1)
    expect(convertScopeMock).toHaveBeenCalledWith(11, { scope: 'shared', name: '正式區 app' })
    // 送出成功即收起對話框，並讓外層重新載入
    expect(wrapper.find('[data-test="to-shared-dialog"]').exists()).toBe(false)
    expect(getMock.mock.calls.length).toBeGreaterThan(1)
  })

  it('輪替進行中不可轉為共用，且那一句說明記得自己涵蓋這個動作', async () => {
    const wrapper = await mountWithSelection(dedicatedDetail({ rotation_active: true }))

    expect(wrapper.find('[data-test="action-to-shared"]').classes()).toContain('is-disabled')
    const reason = wrapper.find('[data-test="blocked-rotate"]')
    expect(reason.exists()).toBe(true)
    expect(reason.attributes('data-actions').split(' ')).toContain('to-shared')
  })

  it('發起改密後就地顯示進行中面板', async () => {
    const wrapper = await mountWithSelection()
    expect(wrapper.find('[data-test="rotation-progress"]').exists()).toBe(false)

    // 詳情端點回的是聚合態，輪替識別來自發起那一次的回應
    wrapper.findComponent(CredentialRotateDialog).vm.$emit('submitted', { id: 7 })
    await flushPromises()

    expect(wrapper.find('[data-test="rotation-progress"]').exists()).toBe(true)
    expect(getRotationMock).toHaveBeenCalledWith(1, 7)
  })
})
