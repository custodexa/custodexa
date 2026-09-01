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
const checkSourcePolicyMock = vi.fn()
const updateUserMock = vi.fn()
const createUserMock = vi.fn()
const getCurrentUserMock = vi.fn()

// 允許來源網段的「你目前的來源」走 /auth/me（僅供顯示，不參與判定）
vi.mock('@/api/auth', () => ({
  getCurrentUser: (...a) => getCurrentUserMock(...a),
}))

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
  createUser: (...a) => createUserMock(...a),
  updateUser: (...a) => updateUserMock(...a),
  deleteUser: vi.fn(),
  assignRoles: vi.fn(),
  addUserRole: vi.fn(),
  updateUserStatus: (...a) => updateUserStatusMock(...a),
  changePassword: vi.fn(),
  adminDisableMFA: vi.fn(),
  unlockUser: vi.fn(),
  setInactivityExempt: vi.fn(),
  checkSourcePolicy: (...a) => checkSourcePolicyMock(...a),
  // 外部身分面板同源於 @/api/user，
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

describe('Users 用戶管理：啟停開關欄位契約', () => {
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

describe('Users 分配角色對話框', () => {
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

// 帳號來源欄與外部憑證鎖定。
// 兩個都是「靜默錯了也看不出來」的欄位：來源若由 is_ldap 推導，OIDC 帳號會被
// 顯示成本地帳號；修改密碼若不鎖，管理員會按下一個必被後端擋的按鈕
describe('Users 帳號來源與外部憑證鎖定', () => {
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
    // 入口自欄寬重排起收進「更多」選單（操作欄改為不 fixed、總寬守在
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

describe('Users 審核範圍對話框', () => {
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

    // 新增表單收斂至共用組件（payload 契約測試在
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

    // 入口收進「更多」選單（操作欄 470→280，避免 fixed
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

describe('Users 帳號來源欄與篩選', () => {
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

// 外部身分管理入口：後端四端點齊備但前端零表面，
// 使 UA-1 的「admin SHALL 可檢視／綁定／解除」與純 UI 的 scenario 全數無從成立。
// 入口必須對**每個**帳號開放——本地帳號亦可由 admin 綁定外部身分
describe('Users 外部身分管理入口', () => {
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

  it('面板操作後列表刷新失敗時標記狀態過期，不以舊列表回填抽屜', async () => {
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

  it('其他使用者（stale 面板）的 changed 事件一律忽略，不刷新目前抽屜', async () => {
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

  it('較舊的刷新結果不得覆蓋較新的（父層序號防護）', async () => {
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

  it('刷新成功但目標使用者不在結果集時維持過期旗標', async () => {
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

// —— 允許來源網段（來源限定功能）——
//
// 這一組守的是三件「錯了就把管理者鎖在門外、或把限制靜默清空」的事：
// 1) 更新請求的 presence 語義——沒動過清單就**不送**該欄位；
// 2) 落入判定一律來自端點回覆，前端不自算（自算與強制點分歧＝警告說謊）；
// 3) 警告是 warning 級，**不阻擋儲存**（管理者可能刻意設一個尚未切過去的網段）。
describe('Users：允許來源網段', () => {
  const withPolicy = (over = {}) => ({
    data: [
      {
        id: 7,
        username: 'carol',
        email: 'carol@example.com',
        active: true,
        roles: [{ name: 'user' }],
        created_at: '2026-07-01T10:00:00+08:00',
        allowed_cidrs: [],
        allowed_cidrs_status: 'unrestricted',
        ...over,
      },
    ],
    total: 1,
  })

  const okCheck = (over = {}) => ({
    valid: true,
    items: [],
    normalized: [],
    status: 'restricted',
    source: { address: '203.0.113.9', reason: 'request' },
    allowed: true,
    ...over,
  })

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getUserListMock.mockResolvedValue(withPolicy())
    getRoleListMock.mockResolvedValue({ data: [{ name: 'user' }, { name: 'admin' }] })
    getApproverScopesMock.mockResolvedValue({ data: [] })
    getCurrentUserMock.mockResolvedValue({ id: 7, source_ip: '203.0.113.9' })
    checkSourcePolicyMock.mockResolvedValue(okCheck())
    updateUserMock.mockResolvedValue({})
    createUserMock.mockResolvedValue({})
  })

  // 三態消費伺服端衍生的 allowed_cidrs_status。**不以陣列非空推算**：
  // 清單含 0.0.0.0/0 時實際全部放行，標成「已限定」是把放行呈為受限
  it('列表三態：不限不標、已限定標 info、等同不限標 warning', async () => {
    getUserListMock.mockResolvedValue(withPolicy())
    let wrapper = mountView()
    await flushPromises()
    expect(wrapper.find('[data-test="source-restricted-tag"]').exists()).toBe(false)
    expect(wrapper.find('[data-test="source-effective-tag"]').exists()).toBe(false)
    wrapper.unmount()

    getUserListMock.mockResolvedValue(
      withPolicy({ allowed_cidrs: ['10.0.0.0/8'], allowed_cidrs_status: 'restricted' })
    )
    wrapper = mountView()
    await flushPromises()
    expect(wrapper.find('[data-test="source-restricted-tag"]').text()).toContain(
      '已限定來源'
    )
    // 內容不展開（清單本身不進列表）
    expect(wrapper.find('[data-test="source-restricted-tag"]').text()).not.toContain(
      '10.0.0.0/8'
    )
    wrapper.unmount()

    getUserListMock.mockResolvedValue(
      withPolicy({
        allowed_cidrs: ['0.0.0.0/0'],
        allowed_cidrs_status: 'effectively_unrestricted',
        // User 物件的家族欄是 allowed_cidrs_families；判定端點回應才叫 families
        allowed_cidrs_families: ['v4'],
      })
    )
    wrapper = mountView()
    await flushPromises()
    const tag = wrapper.find('[data-test="source-effective-tag"]')
    expect(tag.exists()).toBe(true)
    expect(tag.text()).toContain('等同不限')
    // tooltip 取的是 User 列上的 allowed_cidrs_families，不是端點回應的 families
    expect(tag.attributes('title') ?? '').not.toContain('undefined')
    expect(wrapper.vm.userList[0].allowed_cidrs_families).toEqual(['v4'])
    expect(
      wrapper.vm.effectiveUnrestrictedText(wrapper.vm.userList[0].allowed_cidrs_families)
    ).toContain('IPv4')
    // 錯欄名（families）在 User 列上恆為 undefined → 文案會空掉，守住這一點
    expect(wrapper.vm.effectiveUnrestrictedText(wrapper.vm.userList[0].families)).toBe('')
  })

  it('編輯時沒動清單 → 更新請求不帶 allowed_cidrs（缺欄＝保留現值）', async () => {
    getUserListMock.mockResolvedValue(
      withPolicy({ allowed_cidrs: ['10.0.0.0/8'], allowed_cidrs_status: 'restricted' })
    )
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0])
    await flushPromises()
    wrapper.vm.form.email = 'carol2@example.com'
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(updateUserMock).toHaveBeenCalledTimes(1)
    const body = updateUserMock.mock.calls[0][1]
    expect(body.email).toBe('carol2@example.com')
    expect('allowed_cidrs' in body).toBe(false)
    // 沒動過就不必打判定端點
    expect(checkSourcePolicyMock).not.toHaveBeenCalled()
  })

  it('把清單清空 → 送空陣列（`[]` 才是「清除為不限」）', async () => {
    getUserListMock.mockResolvedValue(
      withPolicy({ allowed_cidrs: ['10.0.0.0/8'], allowed_cidrs_status: 'restricted' })
    )
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0])
    await flushPromises()
    wrapper.vm.removeCidr(0)
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(updateUserMock.mock.calls[0][1].allowed_cidrs).toEqual([])
  })

  it('格式層就近紅字：明顯不是位址的輸入不進清單', async () => {
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.handleCreate()
    await flushPromises()

    wrapper.vm.cidrDraft = 'gateway.example'
    wrapper.vm.addCidr()
    await flushPromises()
    expect(wrapper.vm.cidrDraftError).toContain('gateway.example')
    expect(wrapper.vm.form.allowed_cidrs).toEqual([])

    // 後端才拒的邊界不預先擋（判定權在後端）
    wrapper.vm.cidrDraft = '10.0.0.999/24'
    wrapper.vm.addCidr()
    await flushPromises()
    expect(wrapper.vm.form.allowed_cidrs).toEqual(['10.0.0.999/24'])
  })

  it('逐項錯誤與正規化預覽都來自端點回覆', async () => {
    checkSourcePolicyMock.mockResolvedValue(
      okCheck({
        valid: false,
        items: [{ input: '10.0.0.999/24', error_code: 'invalid' }],
        normalized: [],
      })
    )
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.handleCreate()
    wrapper.vm.form.allowed_cidrs = ['10.0.0.999/24']
    await wrapper.vm.runSourcePolicyCheck()
    await flushPromises()

    expect(wrapper.vm.itemErrors).toHaveLength(1)
    expect(wrapper.vm.itemErrors[0].text).toContain('10.0.0.999/24')

    checkSourcePolicyMock.mockResolvedValue(
      okCheck({ normalized: ['10.0.0.0/8'], items: [{ input: '10.1.2.3/8' }] })
    )
    wrapper.vm.form.allowed_cidrs = ['10.1.2.3/8']
    await wrapper.vm.runSourcePolicyCheck()
    await flushPromises()
    expect(wrapper.vm.itemErrors).toHaveLength(0)
    expect(wrapper.vm.normalizedPreview).toBe('10.0.0.0/8')
  })

  it('正規化結果與輸入一致時不顯示預覽（一模一樣時那行是噪音）', async () => {
    checkSourcePolicyMock.mockResolvedValue(okCheck({ normalized: ['10.0.0.0/8'] }))
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.handleCreate()
    wrapper.vm.form.allowed_cidrs = ['10.0.0.0/8']
    await wrapper.vm.runSourcePolicyCheck()
    await flushPromises()
    expect(wrapper.vm.normalizedPreview).toBe('')
  })

  it('端點回 effectively_unrestricted → 顯示「等同不限」並指出家族', async () => {
    checkSourcePolicyMock.mockResolvedValue(
      okCheck({ status: 'effectively_unrestricted', families: ['v4'] })
    )
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.handleCreate()
    wrapper.vm.form.allowed_cidrs = ['0.0.0.0/0']
    await wrapper.vm.runSourcePolicyCheck()
    await flushPromises()
    expect(wrapper.vm.effectiveUnrestrictedLine).toContain('等同不限')
    expect(wrapper.vm.effectiveUnrestrictedLine).toContain('IPv4')
  })

  it('自鎖警告：編輯本人且端點回 allowed=false 才出現，且帶本次來源', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 7, roles: ['admin'] }))
    checkSourcePolicyMock.mockResolvedValue(okCheck({ allowed: false }))
    getUserListMock.mockResolvedValue(withPolicy())
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0])
    wrapper.vm.form.allowed_cidrs = ['10.0.0.0/8']
    wrapper.vm.cidrTouched = true
    await wrapper.vm.runSourcePolicyCheck()
    await flushPromises()
    expect(wrapper.vm.selfLockLine).toContain('203.0.113.9')
    expect(wrapper.vm.selfLockLine).toContain('無法登入')
  })

  it('編輯他人時不出現自鎖警告（那不是他的來源）', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 1, roles: ['admin'] }))
    checkSourcePolicyMock.mockResolvedValue(okCheck({ allowed: false }))
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0])
    wrapper.vm.form.allowed_cidrs = ['10.0.0.0/8']
    await wrapper.vm.runSourcePolicyCheck()
    await flushPromises()
    expect(wrapper.vm.selfLockLine).toBe('')
  })

  it('來源取不到時自鎖警告改說「取不到來源」，不假裝有位址', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 7, roles: ['admin'] }))
    checkSourcePolicyMock.mockResolvedValue(
      okCheck({ allowed: false, source: { address: null, reason: 'unresolvable' } })
    )
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0])
    wrapper.vm.form.allowed_cidrs = ['10.0.0.0/8']
    await wrapper.vm.runSourcePolicyCheck()
    await flushPromises()
    expect(wrapper.vm.selfLockLine).toContain('取不到')
    expect(wrapper.vm.selfLockLine).not.toContain('null')
  })

  it('警告不阻擋儲存：自鎖狀態下仍送出，且儲存前再判定一次', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 7, roles: ['admin'] }))
    checkSourcePolicyMock.mockResolvedValue(okCheck({ allowed: false }))
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0])
    wrapper.vm.cidrDraft = '10.0.0.0/8'
    wrapper.vm.addCidr()
    await flushPromises()
    const before = checkSourcePolicyMock.mock.calls.length

    await wrapper.vm.handleSubmit()
    await flushPromises()
    expect(checkSourcePolicyMock.mock.calls.length).toBeGreaterThan(before)
    expect(updateUserMock).toHaveBeenCalledTimes(1)
    expect(updateUserMock.mock.calls[0][1].allowed_cidrs).toEqual(['10.0.0.0/8'])
  })

  it('判定端點失敗只說「無法確認」，不得渲染成允許', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 7, roles: ['admin'] }))
    checkSourcePolicyMock.mockRejectedValue(new Error('boom'))
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0])
    wrapper.vm.form.allowed_cidrs = ['10.0.0.0/8']
    await wrapper.vm.runSourcePolicyCheck()
    await flushPromises()
    expect(wrapper.vm.cidrCheckFailed).toBe(true)
    // 三種端點驅動的提示一律不出現——取不到結果不是「沒問題」
    expect(wrapper.vm.selfLockLine).toBe('')
    expect(wrapper.vm.effectiveUnrestrictedLine).toBe('')
    expect(wrapper.vm.normalizedPreview).toBe('')
  })

  it('「你目前的來源」取自 /auth/me，取不到時整行不出現', async () => {
    getCurrentUserMock.mockResolvedValue({ id: 7 })
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.handleCreate()
    await flushPromises()
    expect(wrapper.vm.currentSourceIp).toBe('')
    expect(wrapper.vm.currentSourceLine).toBe('')
  })

  // 那個位址是**管理者自己**的。擺在別人的允許清單旁邊，會被讀成
  // 「這個帳號的來源」而照著填——與自鎖警告同一道把關
  it('「你目前的來源」只在編輯自己的帳號時出現', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 7, roles: ['admin'] }))
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0]) // 對象 id 7＝自己
    await flushPromises()
    expect(wrapper.vm.currentSourceLine).toContain('203.0.113.9')
  })

  it('編輯他人與新增帳號時都不顯示管理者自己的來源位址', async () => {
    localStorage.setItem('user', JSON.stringify({ id: 1, roles: ['admin'] }))
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0]) // 對象 id 7≠自己（id 1）
    await flushPromises()
    expect(wrapper.vm.currentSourceIp).toBe('203.0.113.9') // 取得到，但不該渲染
    expect(wrapper.vm.currentSourceLine).toBe('')

    wrapper.vm.handleCreate()
    await flushPromises()
    expect(wrapper.vm.currentSourceLine).toBe('')
  })

  // 打完網段直接點「確定」，第一次點不會送出（實測三次全重現）：
  // 按下按鈕使輸入框失焦 → 就地觸發判定 → 「檢查中」那行插進對話框內容裡，
  // 把整個頁尾往下推一行 → 放開時按鈕已離開游標 → 瀏覽器不產生 click。
  // 對使用者而言是主要儲存路徑「按了沒反應」且零回饋。
  //
  // 兩件事一起守，少一件就會復發：
  // (1) 頁尾按下時不奪走輸入框的焦點（mousedown 被 preventDefault）＝不重排；
  // (2) 送出自己收攏還停在輸入框裡的那一項，不倚賴失焦的副作用。
  // 判定端點仍要被呼叫（自鎖警告與「等同不限」靠它），且**只呼叫一次**
  // ——收攏時排的 debounce 必須被送出前的那次吃掉，不得變成兩次請求。
  it('輸入後直接點「確定」：一次點擊即送出，且不因按下而失焦', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleEdit(wrapper.vm.userList[0])
    await flushPromises()

    await wrapper.find('[data-test="cidr-input"]').setValue('10.0.0.0/8')
    await flushPromises()
    expect(wrapper.vm.cidrDraft).toBe('10.0.0.0/8')
    expect(wrapper.vm.form.allowed_cidrs).toEqual([]) // 還沒按 Enter，仍停在輸入框裡

    const submit = wrapper.find('[data-test="user-dialog-submit"]').element
    const down = new MouseEvent('mousedown', { bubbles: true, cancelable: true })
    submit.dispatchEvent(down)
    expect(down.defaultPrevented).toBe(true)

    submit.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }))
    await flushPromises()
    await flushPromises()

    expect(updateUserMock).toHaveBeenCalledTimes(1)
    expect(updateUserMock.mock.calls[0][1].allowed_cidrs).toEqual(['10.0.0.0/8'])
    expect(checkSourcePolicyMock).toHaveBeenCalledTimes(1)
    expect(checkSourcePolicyMock.mock.calls[0][0].allowed_cidrs).toEqual(['10.0.0.0/8'])
  })
})
