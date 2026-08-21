import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Users from '../Users.vue'
import ApproverScopeForm from '../../components/ApproverScopeForm.vue'

// 本檔掛載 19 次且從不卸載，殘留元件在 document 上累積使單測耗時隨測試序上升
// ——全量並行時末幾格逼近 5s 上限而轉紅（單跑全綠）。與 Assets／AuditLogs／
// MainLayout 同型根因，治法相同：逐測卸載使成本不隨測試序遞增。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容（同 MyConnections）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getUserListMock = vi.fn()
const updateUserStatusMock = vi.fn()
const getRoleListMock = vi.fn()
const getApproverScopesMock = vi.fn()
const createApproverScopeMock = vi.fn()
const deleteApproverScopeMock = vi.fn()
const getExternalIdentitiesMock = vi.fn().mockResolvedValue({ data: [], total: 0 })

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [{ id: 1, name: '測試 SSH 伺服器' }] }),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [{ id: 9, name: 'Prod' }] }),
}))

vi.mock('@/api/accessRequests', () => ({
  getApproverScopes: (...a) => getApproverScopesMock(...a),
  createApproverScope: (...a) => createApproverScopeMock(...a),
  deleteApproverScope: (...a) => deleteApproverScopeMock(...a),
}))

vi.mock('@/api/userGroups', () => ({
  getUserGroups: vi.fn().mockResolvedValue({ data: [{ id: 3, name: 'SRE' }] }),
}))

vi.mock('@/api/user', () => ({
  getUserList: (...a) => getUserListMock(...a),
  getRoleList: (...a) => getRoleListMock(...a),
  createUser: vi.fn(),
  updateUser: vi.fn(),
  deleteUser: vi.fn(),
  assignRoles: vi.fn(),
  addUserRole: vi.fn(),
  updateUserStatus: (...a) => updateUserStatusMock(...a),
  changePassword: vi.fn(),
  adminDisableMFA: vi.fn(),
  unlockUser: vi.fn(),
  setInactivityExempt: vi.fn(),
  // 外部身分面板（idp-oidc-integration 5.5）同源於 @/api/user，
  // 缺這幾個 export 會讓抽屜內的元件在載入期就取到 undefined
  getExternalIdentities: (...a) => getExternalIdentitiesMock(...a),
  bindExternalIdentity: vi.fn(),
  unbindExternalIdentity: vi.fn(),
  unbindExternalIdentityAndDisable: vi.fn(),
}))

vi.mock('@/api/oidc', () => ({
  getOIDCProviders: vi.fn().mockResolvedValue({ data: [] }),
}))

const sampleUsers = {
  data: [
    {
      id: 7,
      username: 'carol',
      email: 'carol@example.com',
      active: true,
      roles: [{ name: 'user' }],
      created_at: '2026-07-01T10:00:00+08:00',
    },
  ],
  total: 1,
}

const mountView = () =>
  mount(Users, {
    global: { plugins: [ElementPlus] },
  })

describe('Users 用戶管理：啟停開關欄位契約（ui-quick-fixes）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getUserListMock.mockResolvedValue(sampleUsers)
    getRoleListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'admin' },
        { id: 2, name: 'user' },
        { id: 3, name: 'auditor' },
        { id: 4, name: 'approver' },
      ],
    })
  })

  it('啟停切換以 row.active 呼叫 API（switch v-model 已翻新值後 @change 觸發）', async () => {
    updateUserStatusMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    // 模擬 switch 已把 v-model 翻為停用後觸發 change handler
    const row = { id: 7, active: false, _statusLoading: false }
    await wrapper.vm.handleStatusChange(row)
    await flushPromises()

    expect(updateUserStatusMock).toHaveBeenCalledWith(7, false)
    expect(row.active).toBe(false)
  })

  it('更新失敗時回滾 row.active，switch 顯示還原', async () => {
    updateUserStatusMock.mockRejectedValue(new Error('boom'))
    const wrapper = mountView()
    await flushPromises()

    const row = { id: 7, active: false, _statusLoading: false }
    await wrapper.vm.handleStatusChange(row)
    await flushPromises()

    expect(updateUserStatusMock).toHaveBeenCalledWith(7, false)
    // 失敗回滾：切換前為啟用（true）
    expect(row.active).toBe(true)
    expect(row._statusLoading).toBe(false)
  })
})

describe('Users 分配角色對話框（role-enum-metadata-sync）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getUserListMock.mockResolvedValue(sampleUsers)
    getRoleListMock.mockResolvedValue({
      data: [
        { id: 1, name: 'admin' },
        { id: 2, name: 'user' },
        { id: 3, name: 'auditor' },
        { id: 4, name: 'approver' },
      ],
    })
  })

  it('開窗時由 /roles API 拉可指派清單，approver 以中文標籤呈現', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleAssignRoles({ id: 7, username: 'carol', roles: [{ name: 'user' }] })
    await flushPromises()

    expect(getRoleListMock).toHaveBeenCalled()
    expect(wrapper.vm.assignableRoles.map((r) => r.name)).toEqual([
      'admin', 'user', 'auditor', 'approver',
    ])
    const text = wrapper.text()
    expect(text).toContain('審核人員')
    expect(text).toContain('稽核人員')
    expect(text).toContain('一般使用者')
    expect(wrapper.vm.selectedRoles).toEqual(['user'])
  })
})

// 帳號來源欄與外部憑證鎖定（idp-oidc-integration D14.1/D14.5）。
// 兩個都是「靜默錯了也看不出來」的欄位：來源若由 is_ldap 推導，OIDC 帳號會被
// 顯示成本地帳號；修改密碼若不鎖，管理員會按下一個必被後端擋的按鈕
describe('Users 帳號來源與外部憑證鎖定（idp-oidc-integration）', () => {
  const externalUsers = {
    data: [
      {
        id: 1,
        username: 'local-admin',
        active: true,
        roles: [{ name: 'admin' }],
        provisioning_origin: 'local',
        external_credential: false,
        is_ldap: false,
        created_at: '2026-07-01T10:00:00+08:00',
      },
      {
        id: 2,
        username: 'ldap-user',
        active: true,
        roles: [{ name: 'user' }],
        provisioning_origin: 'ldap',
        external_credential: true,
        is_ldap: true,
        created_at: '2026-07-01T10:00:00+08:00',
      },
      {
        id: 3,
        username: 'oidc-user',
        active: true,
        roles: [{ name: 'user' }],
        // OIDC 供應帳號的 is_ldap 為 false——只認該欄即誤判為本地
        provisioning_origin: 'oidc',
        external_credential: true,
        is_ldap: false,
        created_at: '2026-07-01T10:00:00+08:00',
      },
    ],
    total: 3,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    getUserListMock.mockResolvedValue(externalUsers)
    getRoleListMock.mockResolvedValue({ data: [{ id: 1, name: 'admin' }, { id: 2, name: 'user' }] })
  })

  it('來源欄以 provisioning_origin 為準（OIDC 不因 is_ldap=false 被顯示成本地）', async () => {
    const wrapper = mountView()
    await flushPromises()

    const rows = wrapper.findAll('.el-table__row')
    expect(rows[0].text()).toContain('本地')
    expect(rows[1].text()).toContain('LDAP')
    expect(rows[2].text()).toContain('OIDC')
  })

  it('未知來源值原樣顯示，不吞成「本地」', async () => {
    const wrapper = mountView()
    await flushPromises()
    // 未知值不吞成「本地」，但也不輸出裸機器碼（i18n 規範）
    expect(wrapper.vm.sourceLabel({ provisioning_origin: 'saml' })).toBe('其他（saml）')
    // 舊後端未回該欄時退回 is_ldap 推導
    expect(wrapper.vm.sourceLabel({ is_ldap: true })).toBe('LDAP')
    expect(wrapper.vm.sourceLabel({})).toBe('本地')
  })

  it('外部憑證帳號的「修改密碼」停用並就地說明原因；本地帳號可按', async () => {
    // 入口自輪 2 欄寬重排起收進「更多」選單（操作欄改為不 fixed、總寬守在
    // 1280 可視寬內），故改為比對各列選單內該項目的停用狀態
    document.body.innerHTML = ''
    mountView()
    await flushPromises()

    const items = Array.from(document.querySelectorAll('.el-dropdown__popper')).map((menu) =>
      Array.from(menu.querySelectorAll('.el-dropdown-menu__item')).find((li) =>
        li.textContent.includes('修改密碼')
      )
    )
    expect(items).toHaveLength(3)
    expect(items.every(Boolean)).toBe(true)
    expect(items[0].classList.contains('is-disabled')).toBe(false)
    expect(items[1].classList.contains('is-disabled')).toBe(true)
    expect(items[2].classList.contains('is-disabled')).toBe(true)
    // 停用項在 EP 下不觸發 tooltip，原因必須寫在項目裡
    expect(items[1].textContent).toContain('由外部身分提供者管理')
  })

  it('external_credential 為權威旗標，缺欄時退回 is_ldap', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.vm.isExternalAccount({ external_credential: true })).toBe(true)
    expect(wrapper.vm.isExternalAccount({ external_credential: false, is_ldap: true })).toBe(false)
    expect(wrapper.vm.isExternalAccount({ is_ldap: true })).toBe(true)
    expect(wrapper.vm.isExternalAccount({})).toBe(false)
  })
})

describe('Users 審核範圍對話框（role-enum-metadata-sync H4）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getUserListMock.mockResolvedValue(sampleUsers)
    getRoleListMock.mockResolvedValue({ data: [{ id: 4, name: 'approver' }] })
    getApproverScopesMock.mockResolvedValue({
      data: [
        { id: 11, approver_id: 8, asset_id: 1, asset: { name: '測試 SSH 伺服器' } },
        { id: 12, approver_id: 99, asset_group_id: 9, asset_group: { name: 'Prod' } },
      ],
      total: 2,
    })
  })

  it('開窗載入並僅顯示該使用者的範圍；掛載共用 ApproverScopeForm', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleManageScopes({ id: 8, username: 'appr', roles: [{ name: 'approver' }] })
    await flushPromises()

    expect(getApproverScopesMock).toHaveBeenCalled()
    // 全量回應過濾出 approver_id=8 的範圍
    expect(wrapper.vm.userScopes.map((sc) => sc.id)).toEqual([11])

    // 新增表單收斂至共用組件（approval-routing-quorum：payload 契約測試在
    // ApproverScopeForm.spec.js，本頁只驗掛載與預選審核方傳遞）
    const form = wrapper.findComponent(ApproverScopeForm)
    expect(form.exists()).toBe(true)
    expect(form.props('presetActor')).toEqual({ type: 'user', id: 8 })
  })

  it('移除範圍：確認後呼叫 delete 並重載', async () => {
    const { ElMessageBox } = await import('element-plus')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    deleteApproverScopeMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleManageScopes({ id: 8, username: 'appr', roles: [{ name: 'approver' }] })
    await flushPromises()
    getApproverScopesMock.mockClear()

    await wrapper.vm.handleRemoveScope({ id: 11, asset: { name: '測試 SSH 伺服器' } })
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    expect(deleteApproverScopeMock).toHaveBeenCalledWith(11)
    expect(getApproverScopesMock).toHaveBeenCalled()
    confirmSpy.mockRestore()
  })

  it('僅 approver 列顯示審核範圍入口', async () => {
    getUserListMock.mockResolvedValue({
      data: [
        { id: 8, username: 'appr', active: true, roles: [{ name: 'user' }, { name: 'approver' }], created_at: '2026-07-01T10:00:00+08:00' },
        { id: 7, username: 'carol', active: true, roles: [{ name: 'user' }], created_at: '2026-07-01T10:00:00+08:00' },
      ],
      total: 2,
    })
    // 同檔前面的測試會在 body 留下已 teleport 的選單節點，先清乾淨
    document.body.innerHTML = ''
    const wrapper = mountView()
    await flushPromises()

    // 入口自 UI 審查 MEDIUM-1 起收進「更多」選單（操作欄 470→280，避免 fixed
    // 欄蓋住來源／Email），故改為比對兩列的選單內容：兩列各一個選單，
    // 只有 approver 那一列帶「審核範圍」
    const menus = Array.from(document.querySelectorAll('.el-dropdown__popper')).map(
      (el) => el.textContent
    )
    expect(menus).toHaveLength(2)
    expect(menus.filter((m) => m.includes('審核範圍'))).toHaveLength(1)
    expect(menus.every((m) => m.includes('分配角色') && m.includes('刪除'))).toBe(true)

    // 選單命令仍直達原 handler
    wrapper.vm.handleRowCommand('scopes', { id: 8, username: 'appr' })
    await flushPromises()
    expect(wrapper.vm.scopeDialogVisible).toBe(true)
  })
})

describe('Users 帳號來源欄與篩選（idp-oidc-integration D14.1）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getRoleListMock.mockResolvedValue({ data: [{ id: 2, name: 'user' }] })
  })

  it('來源欄列出全部 provider 實例名，不只第一個', async () => {
    // 只顯示第一個會讓管理者誤以為「解綁這一個就切斷了此人的全部 SSO 途徑」
    getUserListMock.mockResolvedValue({
      data: [
        {
          id: 11,
          username: 'sso-both',
          active: true,
          roles: [{ name: 'user' }],
          provisioning_origin: 'oidc',
          external_credential: true,
          auth_provider_names: ['Azure AD', 'Okta'],
        },
      ],
      total: 1,
    })
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('Azure AD')
    expect(text).toContain('Okta')
  })

  it('本地帳號不顯示任何 provider 實例名', async () => {
    getUserListMock.mockResolvedValue({
      data: [
        {
          id: 12,
          username: 'local-user',
          active: true,
          roles: [{ name: 'user' }],
          provisioning_origin: 'local',
        },
      ],
      total: 1,
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).not.toContain('Azure AD')
  })

  it('來源篩選走伺服端參數 provisioning_origin，重設後不再帶', async () => {
    // 列表是分頁的：在前端篩當頁會讓使用者看到「第 2 頁明明有 oidc 帳號，
    // 篩選後卻說沒有」，故必須是伺服端參數
    getUserListMock.mockResolvedValue({ data: [], total: 0 })
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.filterForm.provisioningOrigin = 'oidc'
    await wrapper.vm.handleFilter()
    await flushPromises()
    expect(getUserListMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ provisioning_origin: 'oidc' })
    )

    await wrapper.vm.handleResetFilter()
    await flushPromises()
    expect(getUserListMock).toHaveBeenLastCalledWith(
      expect.objectContaining({ provisioning_origin: undefined })
    )
  })
})

// 外部身分管理入口（idp-oidc-integration 5.5）：後端四端點齊備但前端零表面，
// 使 UA-1 的「admin SHALL 可檢視／綁定／解除」與純 UI 的 scenario 全數無從成立。
// 入口必須對**每個**帳號開放——本地帳號亦可由 admin 綁定外部身分
describe('Users 外部身分管理入口（idp-oidc-integration 5.5）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getRoleListMock.mockResolvedValue({ data: [{ id: 2, name: 'user' }] })
    getUserListMock.mockResolvedValue({
      data: [
        {
          id: 7,
          username: 'carol',
          active: true,
          roles: [{ name: 'user' }],
          provisioning_origin: 'local',
          external_credential: false,
        },
      ],
      total: 1,
    })
  })

  it('每一列都有外部身分入口（本地帳號亦可由 admin 綁定）', async () => {
    const wrapper = mountView()
    await flushPromises()

    const rows = wrapper.findAll('.el-table__row')
    expect(rows[0].findAll('button').map((b) => b.text())).toContain('外部身分')
  })

  it('開啟入口時把整列傳給面板（username 與外部憑證旗標是後果文案的依據）', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleManageIdentities({
      id: 7,
      username: 'carol',
      external_credential: false,
    })
    await flushPromises()

    expect(wrapper.vm.identityDrawerVisible).toBe(true)
    expect(wrapper.vm.identityUser).toMatchObject({
      id: 7,
      username: 'carol',
      external_credential: false,
    })
  })

  it('面板操作後列表刷新失敗時標記狀態過期，不以舊列表回填抽屜（輪 2 codex MEDIUM-3）', async () => {
    // fetchUserList 吞掉錯誤並保留舊列表；把它當成一定成功，
    // external-only 轉換成功後畫面仍會顯示「具本地密碼、可轉換」
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleManageIdentities({
      id: 7,
      username: 'carol',
      external_credential: false,
    })
    await flushPromises()
    expect(wrapper.vm.identityRefreshFailed).toBe(false)

    getUserListMock.mockRejectedValueOnce(new Error('network down'))
    await wrapper.vm.handleIdentitiesChanged()
    await flushPromises()

    expect(wrapper.vm.identityRefreshFailed).toBe(true)
    // 舊列表的那一列不得被拿去回填（回填即宣稱「這是操作後的現況」）
    expect(wrapper.vm.identityUser.external_credential).toBe(false)

    // 刷新成功後旗標清除並以新資料回填
    getUserListMock.mockResolvedValueOnce({
      data: [{ id: 7, username: 'carol', active: true, external_credential: true }],
      total: 1,
    })
    await wrapper.vm.handleIdentitiesChanged()
    await flushPromises()
    expect(wrapper.vm.identityRefreshFailed).toBe(false)
    expect(wrapper.vm.identityUser.external_credential).toBe(true)
  })

  it('其他使用者（stale 面板）的 changed 事件一律忽略，不刷新目前抽屜（輪 3 codex MEDIUM）', async () => {
    // 面板可在確認框開著期間被換人／卸載，舊實例的成功事件仍會抵達；
    // 拿它去刷新目前抽屜等於用別人的操作驅動這個帳號的狀態
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleManageIdentities({ id: 7, username: 'carol', external_credential: false })
    await flushPromises()
    getUserListMock.mockClear()

    await wrapper.vm.handleIdentitiesChanged(999)
    await flushPromises()

    expect(getUserListMock).not.toHaveBeenCalled()
    expect(wrapper.vm.identityRefreshFailed).toBe(false)
  })

  it('較舊的刷新結果不得覆蓋較新的（父層序號防護，輪 3 codex MEDIUM）', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleManageIdentities({ id: 7, username: 'carol', external_credential: false })
    await flushPromises()

    // 第一次刷新緩慢且最終失敗；第二次刷新先成功落地
    let rejectSlow
    getUserListMock.mockImplementationOnce(
      () => new Promise((_, reject) => { rejectSlow = reject })
    )
    const stale = wrapper.vm.handleIdentitiesChanged(7)
    getUserListMock.mockResolvedValueOnce({
      data: [{ id: 7, username: 'carol', active: true, external_credential: true }],
      total: 1,
    })
    await wrapper.vm.handleIdentitiesChanged(7)
    await flushPromises()
    expect(wrapper.vm.identityRefreshFailed).toBe(false)
    expect(wrapper.vm.identityUser.external_credential).toBe(true)

    rejectSlow(new Error('network down'))
    await stale
    await flushPromises()

    // 舊刷新的失敗不得把新刷新的成功結論改寫成「狀態過期」
    expect(wrapper.vm.identityRefreshFailed).toBe(false)
    expect(wrapper.vm.identityUser.external_credential).toBe(true)
  })

  it('刷新成功但目標使用者不在結果集時維持過期旗標（輪 3 codex MEDIUM）', async () => {
    // 篩選條件、分頁或操作本身（例如帳號被停用而退出 active 篩選）都會讓目標
    // 缺席；此時抽屜上的帳號狀態同樣是舊值，清掉旗標等於重新開放不可逆入口
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleManageIdentities({ id: 7, username: 'carol', external_credential: false })
    await flushPromises()

    getUserListMock.mockResolvedValueOnce({
      data: [{ id: 99, username: 'dave', active: true, external_credential: false }],
      total: 1,
    })
    await wrapper.vm.handleIdentitiesChanged(7)
    await flushPromises()

    expect(wrapper.vm.identityRefreshFailed).toBe(true)
    expect(wrapper.vm.identityUser.external_credential).toBe(false)
  })
})
