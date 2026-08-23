import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Authorizations from '../Authorizations.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
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

// 全量高負載下偶發單測 5s 逾時（單跑穩綠）——負載型 flake 治標，非本檔測試不穩
// （慣例同 SessionDetail/AuditLogs/Alerts.spec.js）
vi.setConfig({ testTimeout: 20_000 })

const getAuthorizationsMock = vi.fn()
const deleteAuthorizationMock = vi.fn()
const revokeAccessRequestMock = vi.fn()

vi.mock('@/api/authorizations', () => ({
  getAuthorizations: (...a) => getAuthorizationsMock(...a),
  deleteAuthorization: (...a) => deleteAuthorizationMock(...a),
  batchCreateAuthorizations: vi.fn(),
  getEffectiveAssets: vi.fn().mockResolvedValue({ assets: [] }),
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
}))

vi.mock('@/api/accessRequests', () => ({
  revokeAccessRequest: (...a) => revokeAccessRequestMock(...a),
}))

vi.mock('@/api/assets', () => ({
  getAssetGroups: vi.fn().mockResolvedValue({ data: [{ id: 4, name: 'prod-ag', assets: [] }] }),
  getAssetList: vi.fn().mockResolvedValue({ data: [{ id: 1, name: 'srv', host: 'h', protocol: 'ssh' }] }),
}))

vi.mock('@/api/auth', () => ({
  getUsers: vi.fn().mockResolvedValue({ data: [{ id: 2, username: 'alice', roles: [] }] }),
}))

vi.mock('@/api/userGroups', () => ({
  getUserGroups: vi.fn().mockResolvedValue({ data: [{ id: 5, name: 'ops', users: [] }] }),
}))

const setAdmin = () => {
  localStorage.setItem('user', JSON.stringify({ id: 1, username: 'admin', roles: ['admin'] }))
}

const mountView = () =>
  mount(Authorizations, {
    global: { plugins: [ElementPlus] },
  })

describe('Authorizations 授權管理', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    setAdmin()
    getAuthorizationsMock.mockResolvedValue({ data: [], total: 0 })
  })

  it('初載即全量請求（帶分頁參數、無篩選維度）', async () => {
    mountView()
    await flushPromises()

    expect(getAuthorizationsMock).toHaveBeenCalledWith(
      expect.objectContaining({
        page: 1,
        page_size: 20,
        user_id: undefined,
        user_group_id: undefined,
        asset_id: undefined,
      })
    )
  })

  it('列表主體/客體標籤對稱：使用者與群組各有 tag、節點客體用「節點」術語', async () => {
    getAuthorizationsMock.mockResolvedValue({
      data: [
        {
          id: 1,
          user_group_id: 5,
          user_group_name: 'ops',
          asset_id: 1,
          asset_name: 'srv',
          permission: 'connect',
          source: 'manual',
          validity_state: 'active',
          created_at: '2026-07-17T00:00:00Z',
        },
        {
          id: 2,
          user_id: 2,
          username: 'alice',
          asset_group_id: 4,
          asset_group_name: 'prod-ag',
          permission: 'view',
          source: 'manual',
          validity_state: 'active',
          created_at: '2026-07-17T00:00:00Z',
        },
      ],
      total: 2,
    })

    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('ops')
    expect(text).toContain('alice')
    expect(text).toContain('群組')
    expect(text).toContain('使用者')
    // 節點客體術語（不再用「分組」）
    expect(text).toContain('節點')
    expect(text).not.toContain('分組')
  })

  it('快速篩選送伺服端參數且重設頁碼', async () => {
    const wrapper = mountView()
    await flushPromises()
    getAuthorizationsMock.mockClear()

    wrapper.vm.pagination.page = 5
    wrapper.vm.quickFilter = 'expired'
    wrapper.vm.handleQuickFilterChange()
    await flushPromises()

    expect(wrapper.vm.pagination.page).toBe(1)
    expect(getAuthorizationsMock).toHaveBeenCalledWith(
      expect.objectContaining({ validity: 'expired', page: 1 })
    )

    getAuthorizationsMock.mockClear()
    wrapper.vm.quickFilter = 'ticket'
    wrapper.vm.handleQuickFilterChange()
    await flushPromises()
    expect(getAuthorizationsMock).toHaveBeenCalledWith(
      expect.objectContaining({ source: 'ticket', page: 1 })
    )
  })

  it('ticket 列動作三態分流：可撤→撤銷、過期→已到期唯讀、manual→刪除', async () => {
    getAuthorizationsMock.mockResolvedValue({
      data: [
        {
          id: 120,
          user_id: 2,
          username: 'alice',
          asset_id: 1,
          asset_name: 'srv',
          permission: 'connect',
          source: 'ticket',
          validity_state: 'active',
          revocable: true,
          request_id: 31,
          date_expired: '2099-01-01T00:00:00Z',
          created_at: '2026-07-17T00:00:00Z',
        },
        {
          id: 108,
          user_id: 2,
          username: 'alice',
          asset_id: 1,
          asset_name: 'srv',
          permission: 'connect',
          source: 'ticket',
          validity_state: 'expired',
          revocable: false,
          request_id: 28,
          date_expired: '2026-07-17T00:00:00Z',
          created_at: '2026-07-16T00:00:00Z',
        },
        {
          id: 54,
          user_id: 2,
          username: 'alice',
          asset_id: 1,
          asset_name: 'srv',
          permission: 'connect',
          source: 'manual',
          validity_state: 'active',
          created_at: '2026-07-16T00:00:00Z',
        },
      ],
      total: 3,
    })

    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('撤銷')
    expect(text).toContain('已到期')
    expect(text).toContain('刪除')
    expect(text).toContain('臨時')
    expect(text).toContain('常設')
  })

  it('撤銷走申請單 API（帶 request_id 與事由）', async () => {
    revokeAccessRequestMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.handleRevoke({ id: 120, request_id: 31, revocable: true })
    wrapper.vm.revokeNote = '維護窗結束提前收回'
    await wrapper.vm.submitRevoke()
    await flushPromises()

    expect(revokeAccessRequestMock).toHaveBeenCalledWith(31, '維護窗結束提前收回')
  })

  it('載入失敗顯錯不偽裝空狀態', async () => {
    getAuthorizationsMock.mockRejectedValue({
      response: { status: 500, data: { error: 'boom' } },
    })

    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('授權列表載入失敗')
    expect(text).not.toContain('尚無授權記錄')
  })

  it('主體/客體過濾至多一個互斥（選群組清掉使用者與資產）且重設頁碼', async () => {
    const wrapper = mountView()
    await flushPromises()
    getAuthorizationsMock.mockClear()

    wrapper.vm.pagination.page = 3
    wrapper.vm.filterForm.user_id = 2
    wrapper.vm.filterForm.asset_id = 1
    wrapper.vm.filterForm.user_group_id = 5
    wrapper.vm.handleSubjectFilterChange('user_group_id')
    await flushPromises()

    expect(wrapper.vm.filterForm.user_id).toBe('')
    expect(wrapper.vm.filterForm.asset_id).toBe('')
    expect(wrapper.vm.pagination.page).toBe(1)
    expect(getAuthorizationsMock).toHaveBeenCalledWith(
      expect.objectContaining({ user_group_id: 5, user_id: undefined, asset_id: undefined, page: 1 })
    )
  })

  it('授權頁不承載複審職能（已遷出至審計區）', async () => {
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).not.toContain('發起存取複審')
    expect(text).not.toContain('上次存取複審')
  })

  it('每頁筆數變更重設頁碼', async () => {
    const wrapper = mountView()
    await flushPromises()
    getAuthorizationsMock.mockClear()

    wrapper.vm.pagination.page = 4
    wrapper.vm.handleSizeChange()
    await flushPromises()

    expect(wrapper.vm.pagination.page).toBe(1)
  })
})

describe('Authorizations 節點涵蓋盤點篩選', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.setItem('user', JSON.stringify({ id: 1, username: 'admin', roles: ['admin'] }))
    getAuthorizationsMock.mockResolvedValue({ data: [], total: 0 })
  })

  it('選節點：node_id 進參數、頁碼重設 1', async () => {
    const wrapper = mountView()
    await flushPromises()
    getAuthorizationsMock.mockClear()

    wrapper.vm.pagination.page = 5
    wrapper.vm.filterForm.node_id = 4
    wrapper.vm.handleSubjectFilterChange('node_id')
    await flushPromises()

    expect(wrapper.vm.pagination.page).toBe(1)
    expect(getAuthorizationsMock).toHaveBeenCalledWith(
      expect.objectContaining({ node_id: 4, page: 1 })
    )
  })

  it('第四維互斥：選節點清空其他三維', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.filterForm.asset_id = 10
    wrapper.vm.filterForm.node_id = 4
    wrapper.vm.handleSubjectFilterChange('node_id')
    await flushPromises()

    expect(wrapper.vm.filterForm.asset_id).toBe('')
    expect(wrapper.vm.filterForm.user_id).toBe('')
    const lastCall = getAuthorizationsMock.mock.calls.at(-1)[0]
    expect(lastCall.node_id).toBe(4)
    expect(lastCall.asset_id).toBeUndefined()
  })

  it('重置清空節點條件', async () => {
    const wrapper = mountView()
    await flushPromises()

    wrapper.vm.filterForm.node_id = 4
    wrapper.vm.handleResetFilter()
    await flushPromises()

    expect(wrapper.vm.filterForm.node_id).toBe('')
  })
})
