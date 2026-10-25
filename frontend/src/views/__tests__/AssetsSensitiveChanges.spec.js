import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed, reactive } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Assets from '../Assets.vue'
import AssetEditDrawerContent from '@/components/asset/AssetEditDrawerContent.vue'
import { securityChangeFields, pickSecurityBaseline } from '@/utils/assetSecurityChange'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import { grantFor } from '@/composables/__tests__/capabilityFixtures'
import { getAssetHostKey } from '@/api/assets'

// 位址與傳輸放寬的儲存前提示、標籤管理與主機金鑰重置的超管限定呈現、沿用指紋標示

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

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [], total: 0, page: 1, page_size: 20 }),
  getAsset: vi.fn(),
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn(),
  resetAssetHostKey: vi.fn(),
  adoptAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  getAssetTags: vi.fn().mockResolvedValue({ data: [] }),
}))
vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  createAssetAccount: vi.fn(),
  updateAssetAccount: vi.fn(),
  deleteAssetAccount: vi.fn(),
  setDefaultAssetAccount: vi.fn(),
}))
vi.mock('@/api/credentials', () => ({
  listCredentials: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getCredential: vi.fn(),
  setCredentialSecret: vi.fn(),
  rebindAccountCredential: vi.fn(),
  detachCredentialBinding: vi.fn(),
  createCredential: vi.fn(),
  updateCredential: vi.fn(),
}))
vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: vi.fn().mockResolvedValue({ data: [] }),
}))
vi.mock('@/api/accessRequests', () => ({
  createAccessRequest: vi.fn(),
  breakGlassConnect: vi.fn(),
}))
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useRoute: () => ({ path: '/assets', query: {} }),
}))

const STUB_ROWS = Symbol('rows')
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
  },
  template: '<div class="table-stub"><slot /></div>',
}
const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label', 'prop'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  template: '<div class="col-stub" />',
}
const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

const baseForm = () => ({
  host: '10.0.0.1', port: 22, protocol: 'ssh', rotation_channel: '', winrm_scheme: 'https', winrm_port: 5986,
  rotation_ssh_port: 22, sftp_port: 22, sftp_enabled: false, rdp_verify_cert: false, rdp_security: '',
  db_tls_mode: '', k8s_insecure_skip_tls: false, winrm_tls_mode: 'system', db_ca_cert: '',
  k8s_ca_cert: '', winrm_ca_cert: '',
})

describe('securityChangeFields：提示的命中判定', () => {
  const hit = (base, over) => securityChangeFields(pickSecurityBaseline(base), { ...base, ...over })

  it.each([
    ['host', { host: '10.0.0.2' }, 'host'],
    ['port', { port: 2222 }, 'port'],
    ['protocol', { protocol: 'rdp' }, 'protocol'],
    ['k8s 跳過驗證 關到開', { k8s_insecure_skip_tls: true }, 'k8s_insecure_skip_tls'],
    ['CA 新貼上', { k8s_ca_cert: 'PEM' }, 'k8s_ca_cert'],
  ])('%s 出現提示', (_n, over, field) => {
    expect(hit(baseForm(), over)).toContain(field)
  })

  it('RDP 驗證由開改關出現提示，由關改開不出現', () => {
    expect(hit({ ...baseForm(), rdp_verify_cert: true }, { rdp_verify_cert: false })).toContain('rdp_verify_cert')
    expect(hit(baseForm(), { rdp_verify_cert: true })).toEqual([])
  })

  it('只改描述、名稱、標籤不出現', () => {
    expect(hit(baseForm(), { description: 'x', name: 'y', tags: 'z' })).toEqual([])
  })

  it('收緊方向不出現', () => {
    expect(hit({ ...baseForm(), rdp_security: 'tls' }, { rdp_security: 'nla' })).toEqual([])
  })
})

async function mountContent(props = {}) {
  const wrapper = mount(AssetEditDrawerContent, {
    global: {
      plugins: [ElementPlus],
      stubs: { ElTable: tableStub, ElTableColumn: tableColumnStub, 'el-dialog': dialogStub },
    },
    props: {
      form: reactive({
        id: 2, name: 'a', protocol: 'ssh', host: '10.0.0.1', port: 22, username: '', password: '', private_key: '',
        description: '', tags: '', tagList: [], node_ids: [], access_policy: '', active: true, db_name: '',
        db_tls_mode: '', db_ca_cert: '', allowed_databases: [], rdp_security: '', rdp_verify_cert: false,
        k8s_namespace: '', k8s_ca_cert: '', k8s_insecure_skip_tls: false, sftp_enabled: false, sftp_port: 22,
        sftp_username: '', sftp_password: '', has_sftp_password: false, rotation_channel: '',
        winrm_scheme: 'https', winrm_port: 5986, winrm_tls_mode: 'system', winrm_ca_cert: '',
        has_winrm_ca_cert: false, rotation_ssh_port: 22,
      }),
      ...props,
    },
  })
  await flushPromises()
  return wrapper
}

describe('抽屜：提示、重置鈕與沿用標示', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getAssetHostKey.mockResolvedValue({
      algorithm: 'ssh-ed25519', fingerprint: 'SHA256:abc', created_at: '2026-09-01T00:00:00Z',
    })
  })

  it('有命中欄位時出現儲存後通知安全人員的提示，無命中則不出現', async () => {
    const hot = await mountContent({ securityChangeFields: ['host', 'port'] })
    const note = hot.find('[data-test="security-change-notice"]')
    expect(note.exists()).toBe(true)
    expect(note.text()).toContain('host, port')
    const cold = await mountContent({ securityChangeFields: [] })
    expect(cold.find('[data-test="security-change-notice"]').exists()).toBe(false)
  })

  it('非超管：重置鈕 disabled 且有說明文字', async () => {
    const w = await mountContent({ canResetHostKey: false })
    expect(w.find('[data-test="host-key-reset"]').attributes('disabled')).toBeDefined()
    expect(w.find('[data-test="host-key-reset-note"]').text()).toContain('超級管理員')
  })

  it('超管：重置鈕可用且無說明', async () => {
    const w = await mountContent({ canResetHostKey: true })
    expect(w.find('[data-test="host-key-reset"]').attributes('disabled')).toBeUndefined()
    expect(w.find('[data-test="host-key-reset-note"]').exists()).toBe(false)
  })

  it('inherited 回應顯示沿用標示而非記錄時間', async () => {
    getAssetHostKey.mockResolvedValue({
      asset_id: 2, algorithm: 'ssh-ed25519', fingerprint: 'SHA256:abc', inherited: true,
    })
    const w = await mountContent({ canResetHostKey: true })
    expect(w.find('[data-test="host-key-inherited"]').exists()).toBe(true)
    expect(w.text()).not.toContain('Invalid')
  })
})

describe('資產頁：標籤管理鈕的超管限定', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    resetCapabilities()
  })

  const mountPage = async () => {
    const w = mount(Assets, {
      global: {
        plugins: [ElementPlus],
        stubs: { ElTable: tableStub, ElTableColumn: tableColumnStub, 'el-dialog': dialogStub, 'el-drawer': dialogStub },
      },
    })
    await flushPromises()
    return w
  }

  it('持有 asset:update 的非超管：鈕 disabled 且有說明', async () => {
    setCapabilitiesForTests(['asset:view', 'asset:update', 'ui:assets-global'])
    const w = await mountPage()
    const btn = w.find('[data-test="tag-manager-entry"]')
    expect(btn.exists()).toBe(true)
    expect(btn.attributes('disabled')).toBeDefined()
    expect(btn.attributes('title')).toContain('超級管理員')
  })

  it('超管：鈕可用', async () => {
    grantFor(['admin'])
    const w = await mountPage()
    const btn = w.find('[data-test="tag-manager-entry"]')
    expect(btn.attributes('disabled')).toBeUndefined()
  })
})
