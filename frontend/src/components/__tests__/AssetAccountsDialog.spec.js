// 資產帳號管理（asset-multi-account 階段 5）：CRUD、預設切換、跨資產複製建號、
// 新增前明示授權影響面。憑證只進不出——編輯不回填、空值不送（沿用既有語義）。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { computed } from 'vue'
import ElementPlus, { ElMessage, ElMessageBox } from 'element-plus'
import AssetAccountsDialog from '../AssetAccountsDialog.vue'
import {
  listAssetAccounts,
  createAssetAccount,
  updateAssetAccount,
  deleteAssetAccount,
  setDefaultAssetAccount,
} from '@/api/assetAccounts'
import { getAssetList } from '@/api/assets'
import { getEffectiveUsers } from '@/api/authorizations'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

vi.mock('@/api/assetAccounts', () => ({
  listAssetAccounts: vi.fn(),
  createAssetAccount: vi.fn(),
  updateAssetAccount: vi.fn(),
  deleteAssetAccount: vi.fn(),
  setDefaultAssetAccount: vi.fn(),
}))
vi.mock('@/api/assets', () => ({ getAssetList: vi.fn() }))
vi.mock('@/api/authorizations', () => ({ getEffectiveUsers: vi.fn() }))

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
  props: ['label', 'prop'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    rows() {
      const injected = this.stubRows
      if (!injected) return []
      return Array.isArray(injected) ? injected : injected.value || []
    },
  },
  template: `<div class="col-stub">
    <span class="col-label">{{ label }}</span>
    <div v-for="(row, i) in rows" :key="i" class="cell-stub">
      <slot :row="row" :$index="i">{{ prop ? row[prop] : '' }}</slot>
    </div>
  </div>`,
}

const dialogStub = {
  props: ['modelValue'],
  emits: ['open', 'update:modelValue'],
  mounted() {
    if (this.modelValue) this.$emit('open')
  },
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

const ACCOUNTS = [
  { id: 11, username: 'root', is_default: true, privileged: true, note: '', has_password: true },
  { id: 12, username: 'app', is_default: false, privileged: false, note: '應用', has_private_key: true },
]

const mountDialog = (props = {}) =>
  mount(AssetAccountsDialog, {
    props: { modelValue: true, assetId: 7, assetName: 'web-01', protocol: 'ssh', ...props },
    global: {
      plugins: [ElementPlus],
      stubs: { 'el-dialog': dialogStub, ElTable: tableStub, ElTableColumn: tableColumnStub },
    },
  })

describe('AssetAccountsDialog 資產帳號管理', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    listAssetAccounts.mockResolvedValue({ data: ACCOUNTS, total: 2 })
    getAssetList.mockResolvedValue({ data: [{ id: 7, name: 'web-01' }, { id: 9, name: 'db-01' }] })
    getEffectiveUsers.mockResolvedValue({ users: [] })
  })

  it('開啟即載入帳號並列出憑證型別與特權標記', async () => {
    const wrapper = mountDialog()
    await flushPromises()

    expect(listAssetAccounts).toHaveBeenCalledWith(7, { skipErrorToast: true })
    const text = wrapper.text()
    expect(text).toContain('root')
    expect(text).toContain('app')
    expect(text).toContain('特權')
    expect(text).toContain('密碼')
    expect(text).toContain('私鑰')
  })

  it('載入失敗誠實呈現錯誤，不以空狀態偽裝', async () => {
    listAssetAccounts.mockRejectedValueOnce({
      response: { status: 500, data: { code: 'INTERNAL_ASSET_ACCOUNT_LIST' } },
    })
    const wrapper = mountDialog()
    await flushPromises()

    expect(wrapper.vm.loadError).toBeTruthy()
    expect(wrapper.text()).toContain('查詢資產帳號失敗')
  })

  it('新增帳號送出 username/privileged/note，空憑證不進 payload', async () => {
    createAssetAccount.mockResolvedValue({ id: 13 })
    const wrapper = mountDialog()
    await flushPromises()

    wrapper.vm.openCreate()
    await flushPromises()
    wrapper.vm.form.username = 'deploy'
    wrapper.vm.form.privileged = true
    wrapper.vm.form.note = '部署帳號'
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(createAssetAccount).toHaveBeenCalledWith(7, {
      username: 'deploy',
      privileged: true,
      is_default: false,
      note: '部署帳號',
    })
    expect(wrapper.emitted('changed')).toBeTruthy()
  })

  it('新增前明示影響面：N 位使用者與經群組授權的 M 個群組', async () => {
    getEffectiveUsers.mockResolvedValue({
      users: [
        { user_id: 1, paths: [{ kind: 'direct_user' }] },
        { user_id: 2, paths: [{ kind: 'user_group', via_group_id: 5 }] },
        { user_id: 3, paths: [{ kind: 'user_group', via_group_id: 5 }, { via_group_id: 6 }] },
      ],
    })
    const wrapper = mountDialog()
    await flushPromises()

    wrapper.vm.openCreate()
    await flushPromises()

    expect(getEffectiveUsers).toHaveBeenCalledWith(7)
    expect(wrapper.vm.impactUsers).toBe(3)
    expect(wrapper.vm.impactGroups).toBe(2)
    expect(wrapper.text()).toContain('此資產已授權 3 位使用者、2 個群組')
  })

  it('影響面併呈 role_override_note（admin/auditor 不逐人列舉，漏了就低估）', async () => {
    getEffectiveUsers.mockResolvedValue({
      users: [{ user_id: 1, paths: [{ kind: 'direct_user' }] }],
      role_override_note: '另有 2 個 admin/auditor 角色帳號隱含可及本資產',
    })
    const wrapper = mountDialog()
    await flushPromises()

    wrapper.vm.openCreate()
    await flushPromises()

    expect(wrapper.vm.impactNote).toContain('admin/auditor')
    expect(wrapper.text()).toContain('另有 2 個 admin/auditor 角色帳號隱含可及本資產')
  })

  it('快速切換複製來源資產：後發者為準（latest-request-wins）', async () => {
    const wrapper = mountDialog()
    await flushPromises()
    wrapper.vm.openCreate()
    await flushPromises()

    let resolveFirst
    listAssetAccounts
      .mockImplementationOnce(() => new Promise((r) => { resolveFirst = r }))
      .mockResolvedValueOnce({ data: [{ id: 92, username: 'second' }] })

    const first = wrapper.vm.onCopyAssetChange(9)
    const second = wrapper.vm.onCopyAssetChange(10)
    await second
    resolveFirst({ data: [{ id: 91, username: 'first' }] })
    await first
    await flushPromises()

    expect(wrapper.vm.copySourceAccounts.map((a) => a.username)).toEqual(['second'])
  })

  it('影響面查不到時不擋新增（提示而非閘門）', async () => {
    getEffectiveUsers.mockRejectedValue(new Error('forbidden'))
    const wrapper = mountDialog()
    await flushPromises()

    wrapper.vm.openCreate()
    await flushPromises()

    expect(wrapper.vm.impactLoaded).toBe(false)
    expect(wrapper.vm.formVisible).toBe(true)
  })

  it('複製建號：帶 copy_from_account_id 且不送憑證欄位', async () => {
    createAssetAccount.mockResolvedValue({ id: 14 })
    const wrapper = mountDialog()
    await flushPromises()

    wrapper.vm.openCreate()
    await flushPromises()

    listAssetAccounts.mockResolvedValueOnce({ data: [{ id: 90, username: 'ops' }] })
    await wrapper.vm.onCopyAssetChange(9)
    wrapper.vm.form.copy_from_account_id = 90
    wrapper.vm.onCopySourceChange(90)
    // 來源 username 自動帶出，免得使用者重打一次
    expect(wrapper.vm.form.username).toBe('ops')

    wrapper.vm.form.password = 'ignored'
    await wrapper.vm.handleSubmit()
    await flushPromises()

    const payload = createAssetAccount.mock.calls[0][1]
    expect(payload.copy_from_account_id).toBe(90)
    expect(payload.password).toBeUndefined()
    expect(payload.private_key).toBeUndefined()
  })

  it('可複製資產清單排除自己（複製自身帳號無意義）', async () => {
    const wrapper = mountDialog()
    await flushPromises()
    wrapper.vm.openCreate()
    await flushPromises()

    expect(wrapper.vm.copyAssetOptions.map((a) => a.id)).toEqual([9])
  })

  it('編輯不回填憑證；未輸入時不送出憑證欄位（沿用既有）', async () => {
    updateAssetAccount.mockResolvedValue({ id: 12 })
    const wrapper = mountDialog()
    await flushPromises()

    wrapper.vm.openEdit(ACCOUNTS[1])
    await flushPromises()
    expect(wrapper.vm.form.password).toBe('')
    expect(wrapper.vm.form.private_key).toBe('')

    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(updateAssetAccount).toHaveBeenCalledWith(7, 12, {
      username: 'app',
      privileged: false,
      note: '應用',
    })
  })

  it('刪除需二次確認；取消不打 API', async () => {
    deleteAssetAccount.mockResolvedValue({})
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountDialog()
    await flushPromises()

    await wrapper.vm.handleDelete(ACCOUNTS[1])
    expect(confirmSpy).toHaveBeenCalled()
    expect(deleteAssetAccount).toHaveBeenCalledWith(7, 12)

    deleteAssetAccount.mockClear()
    confirmSpy.mockRejectedValue('cancel')
    await wrapper.vm.handleDelete(ACCOUNTS[0])
    expect(deleteAssetAccount).not.toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('設為預設後重載清單並通知父層', async () => {
    setDefaultAssetAccount.mockResolvedValue({ id: 12, is_default: true })
    const wrapper = mountDialog()
    await flushPromises()

    await wrapper.vm.handleSetDefault(ACCOUNTS[1])
    await flushPromises()

    expect(setDefaultAssetAccount).toHaveBeenCalledWith(7, 12)
    expect(listAssetAccounts).toHaveBeenCalledTimes(2)
    expect(wrapper.emitted('changed')).toBeTruthy()
  })

  it('K8s 資產明示單帳號限制，且已有帳號時真的停用新增鈕', async () => {
    const wrapper = mountDialog({ protocol: 'k8s' })
    await flushPromises()

    expect(wrapper.text()).toContain('K8s 資產固定使用單一預設帳號')
    const addBtn = wrapper
      .findAllComponents({ name: 'ElButton' })
      .find((b) => b.text().includes('新增帳號'))
    expect(addBtn.props('disabled')).toBe(true)

    // 零帳號的 K8s 資產仍可建第一個（預設）帳號
    listAssetAccounts.mockResolvedValue({ data: [], total: 0 })
    const empty = mountDialog({ protocol: 'k8s' })
    await flushPromises()
    const emptyAddBtn = empty
      .findAllComponents({ name: 'ElButton' })
      .find((b) => b.text().includes('新增帳號'))
    expect(emptyAddBtn.props('disabled')).toBe(false)
  })

  // 認證類型（mssql-web-cli D3）：欄位只在 DB 協議出現，1.0 只送 sql
  it('DB 協議帶 auth_method 送出，非 DB 協議完全不帶該欄', async () => {
    createAssetAccount.mockResolvedValue({ id: 30 })
    const dbWrapper = mountDialog({ protocol: 'mssql' })
    await flushPromises()

    dbWrapper.vm.openCreate()
    await flushPromises()
    dbWrapper.vm.form.username = 'sa'
    await dbWrapper.vm.handleSubmit()
    await flushPromises()

    expect(createAssetAccount).toHaveBeenCalledWith(
      7,
      expect.objectContaining({ username: 'sa', auth_method: 'sql' })
    )

    // ssh：payload 不得出現 auth_method（後端無此語義）
    createAssetAccount.mockClear()
    const sshWrapper = mountDialog({ protocol: 'ssh' })
    await flushPromises()
    sshWrapper.vm.openCreate()
    await flushPromises()
    sshWrapper.vm.form.username = 'deploy'
    await sshWrapper.vm.handleSubmit()
    await flushPromises()

    expect(createAssetAccount.mock.calls[0][1]).not.toHaveProperty('auth_method')
  })

  // domain 後端明確 400（不靜默降級），故 UI 讓它可見但不可選
  it('網域認證選項存在但停用（尚未支援，且不可誤送）', async () => {
    const wrapper = mountDialog({ protocol: 'mssql' })
    await flushPromises()
    wrapper.vm.openCreate()
    await flushPromises()

    const options = wrapper.findAllComponents({ name: 'ElOption' })
    const domain = options.find((o) => String(o.props('value')) === 'domain')
    expect(domain, '網域認證選項應存在').toBeTruthy()
    expect(domain.props('disabled')).toBe(true)
    const sql = options.find((o) => String(o.props('value')) === 'sql')
    expect(sql.props('disabled')).toBeFalsy()
    expect(wrapper.vm.form.auth_method).toBe('sql')
  })

  // 對抗審查 MED-3：只隱藏對話框會讓明文續留 reactive state，DevTools 可讀
  it('關閉表單即清空明文密碼與私鑰（取消、成功、切換帳號三路徑）', async () => {
    createAssetAccount.mockResolvedValue({ id: 20 })
    const wrapper = mountDialog()
    await flushPromises()

    // 取消路徑
    wrapper.vm.openCreate()
    await flushPromises()
    wrapper.vm.form.password = 'hunter2'
    wrapper.vm.form.private_key = 'KEY'
    wrapper.vm.closeForm()
    expect(wrapper.vm.form.password).toBe('')
    expect(wrapper.vm.form.private_key).toBe('')

    // 成功送出路徑
    wrapper.vm.openCreate()
    await flushPromises()
    wrapper.vm.form.username = 'deploy'
    wrapper.vm.form.password = 'hunter2'
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(wrapper.vm.form.password).toBe('')

    // 切換到編輯另一個帳號：不得殘留前一次輸入
    wrapper.vm.form.password = 'leftover'
    wrapper.vm.openEdit(ACCOUNTS[0])
    expect(wrapper.vm.form.password).toBe('')
  })

  it('寫入失敗時 console 不得印出含明文的錯誤本體', async () => {
    const err = new Error('conflict')
    err.response = {
      status: 409,
      data: { code: 'CONFLICT_ACCOUNT_USERNAME' },
      config: { data: JSON.stringify({ password: 'hunter2' }) },
    }
    err.config = { data: JSON.stringify({ password: 'hunter2' }) }
    createAssetAccount.mockRejectedValueOnce(err)
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const wrapper = mountDialog()
    await flushPromises()
    wrapper.vm.openCreate()
    await flushPromises()
    wrapper.vm.form.username = 'deploy'
    wrapper.vm.form.password = 'hunter2'
    await wrapper.vm.handleSubmit()
    await flushPromises()

    const logged = JSON.stringify(consoleSpy.mock.calls)
    expect(logged).not.toContain('hunter2')
    expect(logged).toContain('CONFLICT_ACCOUNT_USERNAME')
    // 失敗時對話框保持開啟供修正（明文留著讓使用者不必重打）
    expect(wrapper.vm.formVisible).toBe(true)
    consoleSpy.mockRestore()
  })

  // UI 走查 F6：走查未觀察到成功 toast，此處鎖住四條寫入路徑都有回饋
  it('新增／編輯／刪除／設為預設皆給成功回饋', async () => {
    const successSpy = vi.spyOn(ElMessage, 'success').mockImplementation(() => {})
    createAssetAccount.mockResolvedValue({ id: 21 })
    updateAssetAccount.mockResolvedValue({ id: 12 })
    deleteAssetAccount.mockResolvedValue({})
    setDefaultAssetAccount.mockResolvedValue({ id: 12 })
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')

    const wrapper = mountDialog()
    await flushPromises()

    wrapper.vm.openCreate()
    await flushPromises()
    wrapper.vm.form.username = 'deploy'
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(successSpy).toHaveBeenCalledWith('已新增帳號')

    wrapper.vm.openEdit(ACCOUNTS[1])
    await flushPromises()
    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(successSpy).toHaveBeenCalledWith('已更新帳號')

    await wrapper.vm.handleSetDefault(ACCOUNTS[1])
    await flushPromises()
    expect(successSpy).toHaveBeenCalledWith('已設為預設帳號')

    await wrapper.vm.handleDelete(ACCOUNTS[1])
    await flushPromises()
    expect(successSpy).toHaveBeenCalledWith('已刪除帳號')

    successSpy.mockRestore()
  })
})
