import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed, reactive } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AssetEditDrawerContent from '@/components/asset/AssetEditDrawerContent.vue'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'

// 編輯資產抽屜內的測試登入：即時動作，不碰抽屜表單、不通知資產頁，完成後重讀主機金鑰。

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
const getCredentialMock = vi.fn()
vi.mock('@/api/credentials', () => ({
  listCredentials: (...a) => listCredentialsMock(...a),
  getCredential: (...a) => getCredentialMock(...a),
  setCredentialSecret: vi.fn(),
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
  adoptAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  getAssetTags: vi.fn().mockResolvedValue({ data: [] }),
}))

vi.mock('@/api/authorizations', () => ({
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [{ id: 3, paths: [{ via_group_id: 8 }] }] }),
}))

const getExecutorMock = vi.fn()
const getCheckMock = vi.fn()
const runCheckMock = vi.fn()
vi.mock('@/api/assetExecutor', () => ({
  getAssetExecutor: (...a) => getExecutorMock(...a),
  deleteAssetExecutor: vi.fn(),
  putAssetExecutor: vi.fn(),
  exportAssetExecutorPublicKey: vi.fn(),
  getExecutorLoginCheck: (...a) => getCheckMock(...a),
  runExecutorLoginCheck: (...a) => runCheckMock(...a),
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
  setCapabilitiesForTests(['asset:update', 'credential:manage'])
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
import { getAssetHostKey } from '@/api/assets'

afterEach(() => resetCapabilities())

describe('ExecutorLoginCheck 在抽屜內', () => {
  const executorAsset = { id: 2, name: 'ssh-multi-test', protocol: 'ssh', windowsFamily: false }

  beforeEach(() => {
    setCapabilitiesForTests(['asset:update', 'credential:manage', 'asset:executor-manage'])
    getExecutorMock.mockResolvedValue({
      configured: true, account_id: 7, username: 'cx-exec', secret_type: 'ssh_key', source: 'generate',
      credential: { credential_id: 31, credential_name: 'x', shared_credential: false, binding_count: 1 },
      has_public_key: true, fingerprint: 'SHA256:abcd',
    })
    getCheckMock.mockResolvedValue({ tested: false, stale: false, success: false, code: '', method: '', inventory_read: '' })
  })

  it('成功與失敗後抽屜都沒有未存修改：表單值不變、不通知資產頁', async () => {
    const form = formFixture()
    const before = JSON.stringify(form)
    const wrapper = await mountContent({ form, executorAsset })
    const btn = () => wrapper.get('[data-test="login-check-button"]')

    runCheckMock.mockResolvedValueOnce({ success: true, code: '', method: 'executor_sudo_nopasswd', inventory_read: 'ok', checked_at: '2026-11-02T16:58:00', stale: false })
    await btn().trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-test="login-check-box"]').attributes('data-state')).toBe('success')

    runCheckMock.mockResolvedValueOnce({ success: false, code: 'RULE_EXECUTOR_CHECK_LOGIN_FAILED', method: '', inventory_read: 'not_checked', checked_at: '2026-11-02T17:00:00', stale: false })
    await btn().trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-test="login-check-box"]').attributes('data-state')).toBe('failed')

    expect(JSON.stringify(form)).toBe(before)
    expect(wrapper.emitted('changed')).toBeUndefined()
    expect(wrapper.emitted('update:form')).toBeUndefined()
  })

  it('測試登入完成後重讀主機金鑰（第一次登入會記下指紋）', async () => {
    const wrapper = await mountContent({ form: formFixture(), executorAsset })
    const before = getAssetHostKey.mock.calls.length
    runCheckMock.mockResolvedValueOnce({ success: true, code: '', method: 'executor_root', inventory_read: 'not_needed', checked_at: '2026-11-02T16:58:00', stale: false })
    await wrapper.get('[data-test="login-check-button"]').trigger('click')
    await flushPromises()
    expect(getAssetHostKey.mock.calls.length).toBe(before + 1)
  })

  it('指紋提示的判斷來源是主機金鑰載入結果：尚無記錄時顯示，記錄就位後消失', async () => {
    getAssetHostKey.mockRejectedValueOnce({ response: { status: 404 } })
    const wrapper = await mountContent({ form: formFixture(), executorAsset })
    expect(wrapper.find('[data-test="login-check-hostkey-note"]').exists()).toBe(true)
    runCheckMock.mockResolvedValueOnce({ success: true, code: '', method: 'executor_root', inventory_read: 'not_needed', checked_at: '2026-11-02T16:58:00', stale: false })
    await wrapper.get('[data-test="login-check-button"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-test="login-check-hostkey-note"]').exists()).toBe(false)
  })
})
