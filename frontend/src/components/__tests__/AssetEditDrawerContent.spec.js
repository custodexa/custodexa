import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed, reactive } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import AssetEditDrawerContent from '@/components/asset/AssetEditDrawerContent.vue'
import Assets from '@/views/Assets.vue'
import { createAssetAccount, deleteAssetAccount } from '@/api/assetAccounts'

// 編輯資產抽屜的內容。
//
// 原本要疊三層對話框才做得到的事（看帳號、加帳號、換憑證）在這裡是一列，
// 故斷言重心是「一列上讀得出什麼、做得到什麼」：
//  1. 憑證來源看得出是共用（哪一筆、幾台）還是這台專用；
//  2. 四個列動作在同一列可達，不必再往下鑽；
//  3. 新增帳號是表內展開的一列，不是另一層對話框；
//  4. 「移除」與「脫離共用」的後果不同，畫面上必須分得出來
//     ——前者不動主機密碼，後者會登入主機改密；
//  5. 輪替進行中時，擋住的動作要就地說明原因，不是靜默停用。
//
// 抽屜本身（開關、標題列）留在資產頁，故只有深連結那一案掛整頁。

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

const listAssetAccountsMock = vi.fn()
vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: (...a) => listAssetAccountsMock(...a),
  createAssetAccount: vi.fn(),
  updateAssetAccount: vi.fn(),
  deleteAssetAccount: vi.fn(),
  setDefaultAssetAccount: vi.fn(),
}))

const listCredentialsMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  listCredentials: (...a) => listCredentialsMock(...a),
  rebindAccountCredential: vi.fn(),
  detachCredentialBinding: vi.fn(),
  createCredential: vi.fn(),
  updateCredential: vi.fn(),
}))

const getAssetMock = vi.fn()
const getAssetListMock = vi.fn()
vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => getAssetListMock(...a),
  getAsset: (...a) => getAssetMock(...a),
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn().mockResolvedValue({
    algorithm: 'ecdsa-sha2-nistp256',
    fingerprint: 'SHA256:ASWK1NSeksFJUsEstZrqhGHD5FZ',
    created_at: '2026-09-01T00:00:00Z',
  }),
  resetAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  getAssetTags: vi.fn().mockResolvedValue({ data: [] }),
}))

vi.mock('@/api/authorizations', () => ({
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [{ id: 3, paths: [{ via_group_id: 8 }] }] }),
}))

vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: vi.fn().mockResolvedValue({ data: [] }),
}))

vi.mock('@/api/accessRequests', () => ({
  createAccessRequest: vi.fn(),
  breakGlassConnect: vi.fn(),
}))

const replaceMock = vi.fn()
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: replaceMock }),
  useRoute: () => ({ path: '/assets', query: { edit: '2' } }),
}))

// el-table 在 happy-dom 下極慢且與 MutationObserver 不相容：以替身取代，
// 但保留欄位模板執行（每列跑 #default slot 並帶 row），列內渲染的斷言力不變
const STUB_ROWS = Symbol('stubTableRows')
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
  },
  template: `<div class="table-stub">
    <slot />
    <div v-if="!(data || []).length" class="table-empty-stub"><slot name="empty" /></div>
  </div>`,
}
const tableColumnStub = {
  name: 'ElTableColumn',
  // width／minWidth 一併收下：操作欄是否參與 el-table 的彈性分配決定了
  // 第三、四個動作會不會被擠出可視範圍，那是配置而不是樣式
  props: ['label', 'prop', 'width', 'minWidth', 'className'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    rows() {
      const injected = this.stubRows
      if (!injected) return []
      return Array.isArray(injected) ? injected : injected.value || []
    },
  },
  template: `<div class="col-stub">
    <th>{{ label }}</th>
    <div v-for="(row, i) in rows" :key="i" class="cell-stub">
      <slot :row="row" :column="{}" :$index="i">{{ prop ? row[prop] : '' }}</slot>
    </div>
  </div>`,
}
const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}
const treeSelectStub = {
  name: 'ElTreeSelect',
  props: ['modelValue', 'data'],
  template: '<div class="tree-select-stub" />',
}

const formFixture = (over = {}) =>
  reactive({
    id: 2,
    name: 'ssh-multi-test',
    protocol: 'ssh',
    host: '10.20.1.11',
    port: 22,
    credential_mode: 'dedicated',
    credential_id: null,
    username: '',
    password: '',
    private_key: '',
    description: '',
    tags: '',
    tagList: [],
    node_ids: [],
    access_policy: '',
    active: true,
    db_name: '',
    db_tls_mode: '',
    db_ca_cert: '',
    allowed_databases: [],
    rdp_security: '',
    rdp_verify_cert: false,
    k8s_namespace: '',
    k8s_ca_cert: '',
    k8s_insecure_skip_tls: false,
    sftp_enabled: false,
    sftp_port: 22,
    sftp_username: '',
    sftp_password: '',
    has_sftp_password: false,
    rotation_channel: '',
    winrm_scheme: 'https',
    winrm_port: 5986,
    winrm_tls_mode: 'system',
    winrm_ca_cert: '',
    has_winrm_ca_cert: false,
    rotation_ssh_port: 22,
    ...over,
  })

const accountFixture = () => [
  {
    id: 21,
    asset_id: 2,
    username: 'root',
    is_default: false,
    privileged: true,
    note: '',
    has_password: true,
    has_private_key: false,
    shared_credential: true,
    credential_id: 110,
    credential_name: '正式區 root',
    credential_scope: 'shared',
    effective_version_no: 4,
    binding_count: 12,
  },
  {
    id: 22,
    asset_id: 2,
    username: 'app',
    is_default: true,
    privileged: false,
    note: '',
    has_password: true,
    has_private_key: false,
    shared_credential: false,
    credential_id: 111,
    credential_name: 'ssh-multi-test / app',
    credential_scope: 'dedicated',
    effective_version_no: 2,
    binding_count: 1,
  },
]

async function mountContent(props = {}) {
  const wrapper = mount(AssetEditDrawerContent, {
    global: {
      plugins: [ElementPlus],
      stubs: {
        ElTable: tableStub,
        ElTableColumn: tableColumnStub,
        'el-dialog': dialogStub,
        'el-tree-select': treeSelectStub,
      },
    },
    props: { form: formFixture(), ...props },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  listAssetAccountsMock.mockResolvedValue({ data: accountFixture(), total: 2 })
  listCredentialsMock.mockResolvedValue({
    data: [
      {
        id: 110, name: '正式區 root', scope: 'shared', username: 'root',
        secret_type: 'password', protocol_family: 'ssh', binding_count: 12,
        current_version_no: 4, rotation_active: false,
      },
    ],
    total: 1,
  })
})

describe('帳號表的憑證來源', () => {
  it('兩列分別顯示共用憑證名與專用標示，並各自帶就位版本', async () => {
    const wrapper = await mountContent()

    const shared = wrapper.find('[data-test="account-credential-21"]')
    expect(shared.text()).toContain('正式區 root')
    expect(wrapper.find('[data-test="account-shared-21"]').text()).toContain('12')
    expect(wrapper.find('[data-test="account-version-21"]').text()).toContain('v4')

    const dedicated = wrapper.find('[data-test="account-credential-22"]')
    expect(dedicated.text()).toContain('ssh-multi-test / app')
    expect(wrapper.find('[data-test="account-dedicated-22"]').text()).toBe('專用')
    expect(wrapper.find('[data-test="account-shared-22"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="account-version-22"]').text()).toContain('v2')
  })

  it('就位版本落後憑證現行版本時標示待更新（否則看不出這台還沒吃到新密碼）', async () => {
    listCredentialsMock.mockResolvedValue({
      data: [
        {
          id: 110, name: '正式區 root', scope: 'shared', username: 'root',
          secret_type: 'password', protocol_family: 'ssh', binding_count: 12,
          current_version_no: 6, rotation_active: false,
        },
      ],
      total: 1,
    })
    const wrapper = await mountContent()
    expect(wrapper.find('[data-test="account-version-21"]').text()).toContain('待更新')
    expect(wrapper.find('[data-test="account-version-22"]').text()).toContain('就位')
  })
})

describe('列動作', () => {
  it('共用且非預設的一列上四個動作都可達', async () => {
    const wrapper = await mountContent()

    expect(wrapper.find('[data-test="account-set-default-21"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="account-rebind-21"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="account-detach-21"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="account-remove-21"]').exists()).toBe(true)

    // 預設列不再提供「設為預設」，改為標示自己就是預設
    expect(wrapper.find('[data-test="account-is-default-22"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="account-set-default-22"]').exists()).toBe(false)
    // 脫離共用只對共用列成立；專用列改為就地編輯自己的憑證
    expect(wrapper.find('[data-test="account-detach-22"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="account-edit-secret-22"]').exists()).toBe(true)
    // 專用列也要能換憑證：把這台改掛到共用憑證是「跟別台一起管」的唯一入口
    expect(wrapper.find('[data-test="account-rebind-22"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="account-edit-secret-21"]').exists()).toBe(false)
  })

  it('更換憑證的後果依列型分開講：專用列說回收、共用列說其餘主機不受影響', async () => {
    const wrapper = await mountContent()

    await wrapper.find('[data-test="account-rebind-22"]').trigger('click')
    await flushPromises()
    const dedicated = wrapper.find('[data-test="account-rebind-hint-22"]').text()
    expect(dedicated).toContain('原本這台專用的憑證會一併回收')
    expect(dedicated).not.toContain('其餘主機')

    await wrapper.find('[data-test="account-rebind-21"]').trigger('click')
    await flushPromises()
    const shared = wrapper.find('[data-test="account-rebind-hint-21"]').text()
    expect(shared).toContain('其餘主機不受影響')
    expect(shared).not.toContain('回收')
  })

  it('操作欄不參與 el-table 的彈性分配（被擠窄時第三、四個動作會落到可視範圍外）', async () => {
    const wrapper = await mountContent()

    const columns = wrapper.findAllComponents({ name: 'ElTableColumn' })
    const actions = columns.find((col) => col.props('label') === '操作')
    expect(actions).toBeTruthy()
    // 固定寬度＝不會被憑證欄吃掉；min-width 才是會被重新分配的那一種
    expect(actions.props('width')).toBe('216')
    expect(actions.props('minWidth')).toBeUndefined()
    expect(actions.props('className')).toBe('actions-col')
  })

  it('移除與脫離共用的語義在畫面上分得出來（一個不動主機密碼、一個會動）', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    const wrapper = await mountContent()

    // 常駐說明：兩句同時在畫面上，不必點下去才知道差別
    const hint = wrapper.find('[data-test="account-semantics-hint"]').text()
    expect(hint).toContain('移除')
    expect(hint).toContain('主機上的密碼不動')
    expect(hint).toContain('脫離共用')
    expect(hint).toContain('驗證通過才脫離')

    // 移除的確認框把「不動主機密碼」寫進後果
    await wrapper.find('[data-test="account-remove-21"]').trigger('click')
    await flushPromises()
    expect(confirmSpy).toHaveBeenCalled()
    expect(confirmSpy.mock.calls[0][0]).toContain('主機上的密碼不會被更動')
    expect(deleteAssetAccount).not.toHaveBeenCalled()

    // 脫離共用開的是會改遠端的那個對話框（此處不送出）
    await wrapper.find('[data-test="account-detach-21"]').trigger('click')
    await flushPromises()
    const detach = wrapper.findComponent({ name: 'CredentialDetachDialog' })
    expect(detach.props('modelValue')).toBe(true)
    expect(detach.props('accountId')).toBe(21)
    expect(detach.props('credentialName')).toBe('正式區 root')
    confirmSpy.mockRestore()
  })

  it('輪替進行中：就地說明原因，並停用被擋住的兩個動作', async () => {
    listCredentialsMock.mockResolvedValue({
      data: [
        {
          id: 110, name: '正式區 root', scope: 'shared', username: 'root',
          secret_type: 'password', protocol_family: 'ssh', binding_count: 12,
          current_version_no: 4, rotation_active: true, active_rotation_id: 77,
        },
      ],
      total: 1,
    })
    const wrapper = await mountContent()

    const note = wrapper.find('[data-test="account-rotation-note-21"]')
    expect(note.exists()).toBe(true)
    expect(note.text()).toContain('改密')
    expect(wrapper.find('[data-test="account-rebind-21"]').attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-test="account-detach-21"]').attributes('disabled')).toBeDefined()
    // 移除不改遠端，輪替中仍可執行
    expect(wrapper.find('[data-test="account-remove-21"]').attributes('disabled')).toBeUndefined()
    // 專用列不受這筆共用憑證的輪替影響
    expect(wrapper.find('[data-test="account-rotation-note-22"]').exists()).toBe(false)
  })
})

describe('新增帳號', () => {
  it('展開為表內一列（不是另一層對話框），且載荷二擇一', async () => {
    const wrapper = await mountContent()
    expect(wrapper.find('[data-test="account-add-row"]').exists()).toBe(false)

    await wrapper.find('[data-test="account-add"]').trigger('click')
    await flushPromises()

    const row = wrapper.find('[data-test="account-add-row"]')
    expect(row.exists()).toBe(true)
    expect(row.findComponent({ name: 'AssetCredentialSection' }).exists()).toBe(true)
    // 出廠值是共用：這條路取代了原本的「從其他資產帳號複製」
    expect(row.findComponent({ name: 'CredentialPicker' }).exists()).toBe(true)
    expect(row.text()).toContain('尚未掛載的共用憑證')
    // 影響面：新增一個登入身分等於多一個可用身分
    expect(wrapper.find('[data-test="account-add-impact"]').text()).toContain('1')

    const addRow = wrapper.findComponent({ name: 'AssetAccountAddRow' }).vm
    addRow.model.credential_id = 110
    expect(addRow.payload()).toEqual({
      privileged: false,
      is_default: false,
      credential_id: 110,
    })

    addRow.model.credential_mode = 'dedicated'
    addRow.model.username = ' ops '
    addRow.model.password = 'p@ss'
    // ssh 沒有 auth_method 這個語義：載荷不得出現該欄，讓伺服端保持預設值
    expect(addRow.payload()).toEqual({
      privileged: false,
      is_default: false,
      username: 'ops',
      password: 'p@ss',
    })
    expect('auth_method' in addRow.payload()).toBe(false)
  })

  it('auth_method 只在資料庫協定進載荷（ssh 不得出現，mysql 必須出現）', async () => {
    const wrapper = await mountContent({ form: formFixture({ protocol: 'mysql', port: 3306 }) })
    await wrapper.find('[data-test="account-add"]').trigger('click')
    await flushPromises()

    const addRow = wrapper.findComponent({ name: 'AssetAccountAddRow' }).vm
    addRow.model.credential_mode = 'dedicated'
    addRow.model.username = 'dbops'
    addRow.model.password = 'p@ss'
    expect(addRow.payload()).toEqual({
      privileged: false,
      is_default: false,
      username: 'dbops',
      password: 'p@ss',
      auth_method: 'sql',
    })
  })

  it('影響面是 warning 型提示，標題與說明各自成行且標題自己有句末標點', async () => {
    const wrapper = await mountContent()
    await wrapper.find('[data-test="account-add"]').trigger('click')
    await flushPromises()

    const impact = wrapper.find('[data-test="account-add-impact"]')
    expect(impact.find('.el-alert').classes()).toContain('el-alert--warning')
    // 標題與說明是兩個元素：擠成一段時兩句只會用一個空白相接
    const title = impact.find('.el-alert__title').text()
    const desc = impact.find('.el-alert__description').text()
    expect(title).toContain('1')
    expect(title.endsWith('。')).toBe(true)
    expect(desc).toContain('全部帳號')
    expect(title).not.toContain('全部帳號')
  })

  it('共用來源沒選憑證時擋在送出之前', async () => {
    const wrapper = await mountContent()
    await wrapper.find('[data-test="account-add"]').trigger('click')
    await flushPromises()

    await wrapper.findComponent({ name: 'AssetAccountAddRow' }).vm.submit()
    await flushPromises()
    expect(createAssetAccount).not.toHaveBeenCalled()
  })

  it('已掛在這台上的憑證不進選擇器（同一台不會掛兩次同一筆）', async () => {
    const wrapper = await mountContent()
    await wrapper.find('[data-test="account-add"]').trigger('click')
    await flushPromises()

    const picker = wrapper.find('[data-test="account-add-row"]')
      .findComponent({ name: 'CredentialPicker' })
    expect(picker.props('excludeIds')).toEqual([110, 111])
  })
})

describe('退場的帳號管理對話框', () => {
  it('隨它退場的 assetAccounts 文案三語皆已清掉（現行守衛只驗三語相等、驗不到有沒有人用）', () => {
    const retired = [
      'add', 'deleteConfirm', 'deleted', 'editTitle', 'manage', 'password',
      'privateKey', 'sectionHint', 'sectionLabel', 'setAsDefault', 'title',
      'usernamePlaceholder',
    ]
    for (const locale of ['zh-TW', 'en-US', 'ja-JP']) {
      const messages = JSON.parse(
        readFileSync(join(process.cwd(), `src/i18n/locales/${locale}.json`), 'utf8')
      )
      for (const key of retired) {
        expect(messages.assetAccounts[key], `${locale}.assetAccounts.${key}`).toBeUndefined()
      }
      // 還在用的那幾支不得被順手掃掉
      for (const key of ['colUsername', 'setDefault', 'impactTitle', 'impactHint', 'loadFailed']) {
        expect(messages.assetAccounts[key], `${locale}.assetAccounts.${key}`).toBeTruthy()
      }
    }
  })
})

describe('其他（收合區）', () => {
  it('抽屜的摘要報的是抽屜自己的欄位，不是新增資產對話框的那一份', async () => {
    const wrapper = await mountContent()

    const summary = wrapper.find('[data-test="asset-advanced-summary"]').text()
    // 狀態與 Windows OpenSSH 只在編輯態的收合區內，摘要要點得到它們
    expect(summary).toContain('狀態')
    expect(summary).toContain('Windows OpenSSH')
    // SFTP 帳號只在 vnc 資產的收合區內：ssh 資產的摘要不得聲稱裡面有那一欄
    expect(summary).not.toContain('SFTP')
  })
})

describe('主機金鑰與深連結', () => {
  it('SSH 資產的主機金鑰區塊在抽屜內容中，含指紋與重置入口', async () => {
    const wrapper = await mountContent()
    const box = wrapper.find('.host-key-item')
    expect(box.exists()).toBe(true)
    expect(box.text()).toContain('SHA256:ASWK1NSeksFJUsEstZrqhGHD5FZ')
    expect(wrapper.find('[data-test="host-key-reset"]').exists()).toBe(true)
  })

  it('既有的編輯深連結仍解析為開抽屜，且主機金鑰區塊可達', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 1, username: 'admin', roles: ['admin'] }))
    getAssetListMock.mockResolvedValue({ data: [], total: 0, page: 1, page_size: 20 })
    getAssetMock.mockResolvedValue({
      id: 2, name: 'ssh-multi-test', protocol: 'ssh', host: '10.20.1.11', port: 22,
      username: 'root', active: true,
    })

    const wrapper = mount(Assets, {
      global: {
        plugins: [ElementPlus],
        stubs: {
          ElTable: tableStub,
          ElTableColumn: tableColumnStub,
          'el-dialog': dialogStub,
          'el-drawer': dialogStub,
          'el-tree-select': treeSelectStub,
          RouterLink: { template: '<a><slot /></a>' },
        },
      },
    })
    await flushPromises()

    expect(getAssetMock).toHaveBeenCalledWith(2)
    expect(wrapper.vm.drawerVisible).toBe(true)
    expect(wrapper.findComponent({ name: 'AssetEditDrawerContent' }).exists()).toBe(true)
    expect(wrapper.find('.host-key-item').exists()).toBe(true)
    // 深連結參數用完即清，不留在網址上
    expect(replaceMock).toHaveBeenCalled()
    wrapper.unmount()
  })

  // 深連結指向「看不到的資產」：後端對「不存在」與「無可視授權」回同一支
  // NOTFOUND_ASSET／404，前端不得從行為上把兩者分開——抽屜不開、參數照清、
  // 提示只說資產不存在。以 404 與 403 兩種回應各跑一次，比對可觀察結果相同。
  const mountDeepLinkWithError = async (status) => {
    localStorage.setItem('user', JSON.stringify({ id: 1, username: 'admin', roles: ['admin'] }))
    getAssetListMock.mockResolvedValue({ data: [], total: 0, page: 1, page_size: 20 })
    const err = new Error('Request failed')
    err.response = { status, data: { code: 'NOTFOUND_ASSET', error: '資產不存在' } }
    getAssetMock.mockRejectedValue(err)

    const wrapper = mount(Assets, {
      global: {
        plugins: [ElementPlus],
        stubs: {
          ElTable: tableStub,
          ElTableColumn: tableColumnStub,
          'el-dialog': dialogStub,
          'el-drawer': dialogStub,
          'el-tree-select': treeSelectStub,
          RouterLink: { template: '<a><slot /></a>' },
        },
      },
    })
    await flushPromises()
    return wrapper
  }

  it('深連結指向不可視資產（404）：不開抽屜、清掉 edit 參數，且提示不區分不存在與無權限', async () => {
    const wrapper = await mountDeepLinkWithError(404)

    // 現查確實發生過（否則以下三條會是「根本沒跑到」的假綠）
    expect(getAssetMock).toHaveBeenCalledWith(2)
    // THEN 之一：不開抽屜——編輯內容一格都不得渲染
    expect(wrapper.vm.drawerVisible).toBe(false)
    expect(wrapper.findComponent({ name: 'AssetEditDrawerContent' }).exists()).toBe(false)
    expect(wrapper.find('.host-key-item').exists()).toBe(false)
    // THEN 之二：清除參數——replace 的 query 內不得再有 edit
    expect(replaceMock).toHaveBeenCalledTimes(1)
    const replaced = replaceMock.mock.calls[0][0]
    expect(replaced.query).toBeDefined()
    expect('edit' in replaced.query).toBe(false)
    // THEN 之三：畫面上不得出現任何指向該資產的線索（名稱、id、主機）
    expect(wrapper.text()).not.toContain('ssh-multi-test')
    wrapper.unmount()
  })

  it('深連結遇 403 與遇 404 的可觀察結果相同（不從行為反推資產存在性）', async () => {
    const wrapper403 = await mountDeepLinkWithError(403)
    const observed403 = {
      drawer: wrapper403.vm.drawerVisible,
      replaceCalls: replaceMock.mock.calls.length,
      query: replaceMock.mock.calls[0][0].query,
    }
    wrapper403.unmount()

    vi.clearAllMocks()
    listAssetAccountsMock.mockResolvedValue({ data: accountFixture(), total: 2 })

    const wrapper404 = await mountDeepLinkWithError(404)
    expect({
      drawer: wrapper404.vm.drawerVisible,
      replaceCalls: replaceMock.mock.calls.length,
      query: replaceMock.mock.calls[0][0].query,
    }).toEqual(observed403)
    wrapper404.unmount()
  })

  it('404 的提示文案三語皆為「資產不存在」語義，不含權限措辭', () => {
    // 提示由全域攔截器以 resolveApiError 解出（元件不自行 toast，避免重複），
    // 故此處驗的是那支碼在三語下的文案本身
    const leaky = ['權限', '授權', '权限', '権限', 'permission', 'forbidden', 'denied', 'unauthorized']
    for (const locale of ['zh-TW', 'en-US', 'ja-JP']) {
      const messages = JSON.parse(
        readFileSync(join(process.cwd(), `src/i18n/locales/${locale}.json`), 'utf8')
      )
      const text = messages.apiError?.NOTFOUND_ASSET
      expect(text, `${locale}.apiError.NOTFOUND_ASSET`).toBeTruthy()
      for (const word of leaky) {
        expect(text.toLowerCase(), `${locale} 洩漏措辭 ${word}`).not.toContain(word.toLowerCase())
      }
    }
  })
})
