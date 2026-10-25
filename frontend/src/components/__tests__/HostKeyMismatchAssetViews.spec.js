// 資產抽屜的待確認指紋清單與「採用這個指紋」，以及資產頁連線測試成功但主機金鑰不符的警示。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed, reactive } from 'vue'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessage, ElMessageBox, ElNotification } from 'element-plus'
import AssetEditDrawerContent from '@/components/asset/AssetEditDrawerContent.vue'
import Assets from '@/views/Assets.vue'
import { getAsset, getAssetHostKey, adoptAssetHostKey, testAssetConnection } from '@/api/assets'
import { setCapabilitiesForTests, resetCapabilities } from '@/composables/useCapabilities'
import { grantFor } from '@/composables/__tests__/capabilityFixtures'
import { setLanguage, t } from '@/i18n'

enableAutoUnmount(afterEach)
vi.setConfig({ testTimeout: 20_000 })

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

// ElNotification 包一層 spy：照常渲染到 body（斷言卡片內容），同時取得呼叫參數（斷言 duration 0）
vi.mock('element-plus', async (importOriginal) => {
  const mod = await importOriginal()
  const real = mod.ElNotification
  const spy = vi.fn((...args) => real(...args))
  Object.assign(spy, real)
  return { ...mod, ElNotification: spy }
})

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
const getAssetListMock = vi.fn()
vi.mock('@/api/assets', () => ({
  getAssetList: (...a) => getAssetListMock(...a),
  getAsset: vi.fn(),
  createAsset: vi.fn(),
  updateAsset: vi.fn(),
  deleteAsset: vi.fn(),
  getAssetHostKey: vi.fn(),
  resetAssetHostKey: vi.fn(),
  adoptAssetHostKey: vi.fn(),
  testAssetConnection: vi.fn(),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  deleteAssetGroup: vi.fn(),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  getAssetTags: vi.fn().mockResolvedValue({ data: [] }),
  renameAssetTag: vi.fn(),
  deleteAssetTag: vi.fn(),
}))
vi.mock('@/api/authorizations', () => ({
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
  // 節點樹在持授權能力時載入可授權節點候選
  getAuthorizationTargetOptions: vi.fn().mockResolvedValue({ data: [], total: 0 }),
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

const STUB_ROWS = Symbol('stubTableRows')
const tableStub = {
  name: 'ElTable',
  props: ['data'],
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
  },
  template: `<div class="table-stub"><slot /></div>`,
}
const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label', 'prop', 'width', 'minWidth', 'className'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    rows() {
      const injected = this.stubRows
      if (!injected) return []
      return Array.isArray(injected) ? injected : injected.value || []
    },
  },
  template: `<div class="col-stub"><div v-for="(row, i) in rows" :key="i" class="cell-stub"><slot :row="row" :column="{}" :$index="i" /></div></div>`,
}
const dialogStub = {
  props: ['modelValue'],
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}
const treeSelectStub = { name: 'ElTreeSelect', props: ['modelValue', 'data'], template: '<div class="tree-select-stub" />' }

const formFixture = () =>
  reactive({
    id: 2, name: 'ssh-multi-test', protocol: 'ssh', host: '10.20.1.11', port: 22,
    credential_mode: 'dedicated', credential_id: null, username: '', password: '', private_key: '',
    description: '', tags: '', tagList: [], node_ids: [], access_policy: '', active: true,
    db_name: '', db_tls_mode: '', db_ca_cert: '', allowed_databases: [],
    rdp_security: '', rdp_verify_cert: false, k8s_namespace: '', k8s_ca_cert: '', k8s_insecure_skip_tls: false,
    sftp_enabled: false, sftp_port: 22, sftp_username: '', sftp_password: '', has_sftp_password: false,
    rotation_channel: '', winrm_scheme: 'https', winrm_port: 5986, winrm_tls_mode: 'system', winrm_ca_cert: '',
    has_winrm_ca_cert: false, rotation_ssh_port: 22,
  })

const recordView = (over = {}) => ({
  id: 9, asset_id: 2, algorithm: 'ssh-ed25519', fingerprint: 'SHA256:recorded',
  created_at: '2026-09-01T00:00:00Z', updated_at: '2026-09-01T00:00:00Z', ...over,
})
const mismatches = () => [
  { algorithm: 'ssh-ed25519', fingerprint: 'SHA256:newer', first_seen_at: '2026-10-17T01:00:00Z', last_seen_at: '2026-10-18T02:00:00Z', seen_count: 4 },
  { algorithm: 'ecdsa-sha2-nistp256', fingerprint: 'SHA256:older', first_seen_at: '2026-10-10T01:00:00Z', last_seen_at: '2026-10-11T02:00:00Z', seen_count: 1 },
]

async function mountContent(props = {}) {
  const wrapper = mount(AssetEditDrawerContent, {
    global: {
      plugins: [ElementPlus],
      stubs: { ElTable: tableStub, ElTableColumn: tableColumnStub, 'el-dialog': dialogStub, 'el-tree-select': treeSelectStub },
    },
    props: { form: formFixture(), canResetHostKey: true, ...props },
  })
  await flushPromises()
  return wrapper
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  resetCapabilities()
  setLanguage('zh-TW')
  setCapabilitiesForTests(['asset:update', 'credential:manage', 'hostkey:reset'])
  getAssetHostKey.mockResolvedValue(recordView({ mismatches: mismatches() }))
})

describe('資產抽屜：待確認指紋與採用', () => {
  it('有 mismatches 時列出指紋、時間、次數與採用按鈕；無時區塊與現況相同', async () => {
    const w = await mountContent()
    const box = w.find('[data-test="host-key-mismatches"]')
    expect(box.exists()).toBe(true)
    expect(box.text()).toContain('待確認的指紋（2）')
    const rows = w.findAll('[data-test="host-key-mismatch-row"]')
    expect(rows).toHaveLength(2)
    expect(rows[0].text()).toContain('SHA256:newer')
    expect(rows[0].text()).toContain('共 4 次')
    expect(rows[0].text()).toContain('首次')
    expect(w.findAll('[data-test="host-key-adopt"]')).toHaveLength(2)
    expect(w.find('[data-test="host-key-adopt-note"]').exists()).toBe(false)
    // 記錄本身仍照舊顯示
    expect(w.text()).toContain('SHA256:recorded')

    getAssetHostKey.mockResolvedValue(recordView())
    const plain = await mountContent()
    expect(plain.find('[data-test="host-key-mismatches"]').exists()).toBe(false)
    expect(plain.find('.host-key-item').exists()).toBe(true)
    expect(plain.find('[data-test="host-key-reset"]').exists()).toBe(true)
  })

  it('超管確認後送出採用（body 只有該筆指紋），成功後重新取檢視；取消不送請求', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const okSpy = vi.spyOn(ElMessage, 'success').mockImplementation(() => {})
    adoptAssetHostKey.mockResolvedValue(recordView({ fingerprint: 'SHA256:newer' }))
    const w = await mountContent()
    getAssetHostKey.mockResolvedValue(recordView({ fingerprint: 'SHA256:newer' }))
    await w.findAll('[data-test="host-key-adopt"]')[0].trigger('click')
    await flushPromises()
    expect(confirmSpy.mock.calls[0][0]).toContain('先向主機管理者確認')
    expect(confirmSpy.mock.calls[0][0]).toContain('此操作會記錄並建立系統告警')
    expect(adoptAssetHostKey).toHaveBeenCalledTimes(1)
    expect(adoptAssetHostKey).toHaveBeenCalledWith(2, 'SHA256:newer')
    expect(getAssetHostKey).toHaveBeenCalledTimes(2)
    expect(okSpy).toHaveBeenCalledWith(t('assets.hostKeyAdoptSuccess'))
    expect(w.find('[data-test="host-key-mismatches"]').exists()).toBe(false)
    expect(w.text()).toContain('SHA256:newer')

    confirmSpy.mockRejectedValue('cancel')
    getAssetHostKey.mockResolvedValue(recordView({ mismatches: mismatches() }))
    const w2 = await mountContent()
    await w2.findAll('[data-test="host-key-adopt"]')[1].trigger('click')
    await flushPromises()
    expect(adoptAssetHostKey).toHaveBeenCalledTimes(1)
  })

  it('非超管：按鈕停用且顯示只有超級管理者能採用', async () => {
    setCapabilitiesForTests(['asset:update'])
    const w = await mountContent({ canResetHostKey: false })
    const btn = w.find('[data-test="host-key-adopt"]')
    expect(btn.attributes('disabled')).toBeDefined()
    expect(w.find('[data-test="host-key-adopt-note"]').text()).toBe(t('assets.hostKeyAdoptSuperAdminOnly'))
  })

  it('後端回 NOTFOUND_HOST_KEY_OBSERVATION 時以當前語言顯示並重新取檢視', async () => {
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const errSpy = vi.spyOn(ElMessage, 'error').mockImplementation(() => {})
    const err = new Error('Request failed')
    err.response = { status: 404, data: { code: 'NOTFOUND_HOST_KEY_OBSERVATION', error: '這個指紋不在待確認清單中' } }
    adoptAssetHostKey.mockRejectedValue(err)
    setLanguage('en-US')
    const w = await mountContent()
    getAssetHostKey.mockResolvedValue(recordView())
    await w.findAll('[data-test="host-key-adopt"]')[0].trigger('click')
    await flushPromises()
    expect(errSpy).toHaveBeenCalledWith(t('apiError.NOTFOUND_HOST_KEY_OBSERVATION'))
    expect(errSpy.mock.calls[0][0]).toContain('not in the list')
    expect(getAssetHostKey).toHaveBeenCalledTimes(2)
    expect(w.find('[data-test="host-key-mismatches"]').exists()).toBe(false)
    setLanguage('zh-TW')
  })

  it('重置確認文案不含「中間人攻擊防護」且建議改用採用', async () => {
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')
    const w = await mountContent()
    await w.find('[data-test="host-key-reset"]').trigger('click')
    await flushPromises()
    const text = confirmSpy.mock.calls[0][0]
    expect(text).not.toContain('中間人攻擊防護')
    expect(text).toContain('採用這個指紋')
    expect(w.text()).not.toContain('指紋不符時連線將被拒絕')
    expect(w.text()).toContain('改密與輪替則停止')
  })
})

describe('資產頁：連線測試成功但主機金鑰不符', () => {
  const mountView = () =>
    mount(Assets, {
      global: {
        plugins: [ElementPlus],
        stubs: { ElTable: tableStub, ElTableColumn: tableColumnStub, 'el-dialog': dialogStub, 'el-drawer': dialogStub, 'el-tree-select': treeSelectStub },
      },
    })

  beforeEach(() => {
    localStorage.setItem('user', JSON.stringify({ id: 7, username: 'tester', roles: ['admin'] }))
    grantFor(['admin'])
    getAssetListMock.mockResolvedValue({
      data: [{ id: 1, name: 'ssh-server', protocol: 'ssh', host: 'h', port: 22, active: true, permission: 'connect' }],
      total: 1, page: 1, page_size: 20,
    })
  })

  beforeEach(() => {
    ElNotification.mockClear()
  })

  afterEach(() => {
    ElNotification.closeAll()
    vi.restoreAllMocks()
  })

  // closeAll 後前一個案例的卡片仍在離場動畫中、留在 DOM：一律取最新的一張
  const card = () => [...document.body.querySelectorAll('[data-test="host-key-test-card"]')].at(-1) ?? null

  it('帶 warning_code 時以不自動消失的通知卡顯示主機身分不符，不帶時仍為 testSuccess', async () => {
    const warnSpy = vi.spyOn(ElMessage, 'warning').mockImplementation(() => {})
    const okSpy = vi.spyOn(ElMessage, 'success').mockImplementation(() => {})
    const wrapper = mountView()
    await flushPromises()

    testAssetConnection.mockResolvedValueOnce({ success: true, latency_ms: 12, warning_code: 'RULE_SSH_HOST_KEY_CHANGED' })
    await wrapper.vm.handleTest({ id: 1 })
    await flushPromises()
    expect(ElNotification).toHaveBeenCalledTimes(1)
    const opts = ElNotification.mock.calls[0][0]
    expect(opts.duration).toBe(0)
    expect(opts.title).toBe(t('assets.testSuccess', { ms: 12 }))
    expect(card()).not.toBeNull()
    expect(card().textContent).toContain('主機身分與記錄不符：')
    expect(card().textContent).toContain('平台已把登入憑證送給它')
    expect(card().textContent).toContain('請先不要使用')
    expect(card().textContent).toContain('此事已記錄')
    expect(okSpy).not.toHaveBeenCalled()
    expect(warnSpy).not.toHaveBeenCalled()

    // 不符放行後才失敗：失敗原因之外仍保留不符與憑證可能已送出的警示（核可稿未涵蓋，維持訊息）
    testAssetConnection.mockResolvedValueOnce({ success: false, code: 'RULE_SSH_AUTH_FAILED', error_code: 'auth_failed', warning_code: 'RULE_SSH_HOST_KEY_CHANGED' })
    await wrapper.vm.handleTest({ id: 1 })
    await flushPromises()
    expect(warnSpy.mock.calls[0][0]).toContain('密碼可能已送出')
    expect(warnSpy.mock.calls[0][0]).toContain(t('apiError.RULE_SSH_AUTH_FAILED'))

    testAssetConnection.mockResolvedValueOnce({ success: true, latency_ms: 12 })
    await wrapper.vm.handleTest({ id: 1 })
    await flushPromises()
    expect(okSpy).toHaveBeenCalledWith(t('assets.testSuccess', { ms: 12 }))
    expect(warnSpy).toHaveBeenCalledTimes(1)
    expect(ElNotification).toHaveBeenCalledTimes(1)
  })

  it('超管：通知卡有「前往資產設定採用或重置主機金鑰」，點擊關卡並開該資產編輯框；詳細說明預設收合、展開含列表狀態說明', async () => {
    getAsset.mockResolvedValue({ id: 1, name: 'ssh-server', protocol: 'ssh', host: 'h', port: 22, active: true })
    const wrapper = mountView()
    await flushPromises()
    testAssetConnection.mockResolvedValueOnce({ success: true, latency_ms: 12, warning_code: 'RULE_SSH_HOST_KEY_CHANGED' })
    await wrapper.vm.handleTest({ id: 1 })
    await flushPromises()

    expect(card().querySelector('[data-test="host-key-test-contact"]')).toBeNull()
    expect(card().querySelector('[data-test="host-key-mismatch-details"]')).toBeNull()
    const toggle = card().querySelector('[data-test="host-key-mismatch-details-toggle"]')
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    expect(toggle.textContent).toContain('詳細說明')
    toggle.click()
    await flushPromises()
    const items = card().querySelectorAll('[data-test="host-key-mismatch-details"] li')
    expect(items).toHaveLength(4)
    expect(items[3].textContent).toContain(t('assets.testHostKeyReachabilityNote'))

    const go = card().querySelector('[data-test="host-key-test-go"]')
    expect(go.textContent.trim()).toBe('前往資產設定採用或重置主機金鑰')
    go.click()
    await flushPromises()
    expect(getAsset).toHaveBeenCalledWith(1)
    expect(wrapper.vm.drawerVisible).toBe(true)
  })

  it('非超管：通知卡只有聯絡管理員的提示；同一資產重測先關掉前一張卡', async () => {
    grantFor(['user'])
    const wrapper = mountView()
    await flushPromises()
    testAssetConnection.mockResolvedValueOnce({ success: true, latency_ms: 12, warning_code: 'RULE_SSH_HOST_KEY_CHANGED' })
    await wrapper.vm.handleTest({ id: 1 })
    await flushPromises()
    expect(card().querySelector('[data-test="host-key-test-go"]')).toBeNull()
    expect(card().querySelector('[data-test="host-key-test-contact"]').textContent.trim()).toBe('請聯絡管理員確認後採用新指紋或重置主機金鑰')

    const first = ElNotification.mock.results[0].value
    const closeFirst = vi.spyOn(first, 'close')
    testAssetConnection.mockResolvedValueOnce({ success: true, latency_ms: 12, warning_code: 'RULE_SSH_HOST_KEY_CHANGED' })
    await wrapper.vm.handleTest({ id: 1 })
    await flushPromises()
    expect(closeFirst).toHaveBeenCalledTimes(1)
    expect(ElNotification).toHaveBeenCalledTimes(2)
  })
})
