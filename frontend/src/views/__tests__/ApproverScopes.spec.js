import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ApproverScopes from '../ApproverScopes.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容（同 Users）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getApproverScopesMock = vi.fn()
const deleteApproverScopeMock = vi.fn()
const getUserListMock = vi.fn()
const getSecurityPoliciesMock = vi.fn()

vi.mock('@/api/accessRequests', () => ({
  getApproverScopes: (...a) => getApproverScopesMock(...a),
  createApproverScope: vi.fn().mockResolvedValue({ id: 99 }),
  deleteApproverScope: (...a) => deleteApproverScopeMock(...a),
}))
vi.mock('@/api/user', () => ({
  getUserList: (...a) => getUserListMock(...a),
  addUserRole: vi.fn().mockResolvedValue({}),
}))
vi.mock('@/api/userGroups', () => ({
  getUserGroups: vi.fn().mockResolvedValue({
    data: [
      { id: 3, name: 'SRE', users: [{ id: 7 }, { id: 8 }] },
      { id: 4, name: 'DBA', users: [{ id: 8 }, { id: 9 }] },
    ],
  }),
}))
vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [{ id: 1, name: 'web-1' }] }),
  getAssetGroups: vi.fn().mockResolvedValue({
    data: [
      { id: 1, name: 'prod' },
      { id: 2, name: 'db', parent_id: 1 },
      { id: 5, name: 'web', parent_id: 1 },
    ],
  }),
}))
vi.mock('@/api/securityPolicies', () => ({
  getSecurityPolicies: (...a) => getSecurityPoliciesMock(...a),
}))

const mountView = () =>
  mount(ApproverScopes, {
    global: { plugins: [ElementPlus] },
  })

describe('ApproverScopes 審核範圍雙視角', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getSecurityPoliciesMock.mockResolvedValue({
      data: [{ key: 'access_request_min_approvals', value: '2' }],
    })
    getUserListMock.mockResolvedValue({
      data: [
        { id: 8, username: 'appr', full_name: '審核甲', roles: [{ name: 'user' }, { name: 'approver' }] },
        { id: 7, username: 'carol', roles: [{ name: 'user' }] },
        { id: 9, username: 'dave', roles: [{ name: 'user' }] },
      ],
      total: 3,
    })
    getApproverScopesMock.mockResolvedValue({
      data: [
        // 個人 appr(8)×節點 db(2)；群組 DBA(4)×節點 db(2)；個人 appr×資產 web-1；
        // 申請人群組 SRE(3) → appr
        { id: 11, approver_id: 8, approver: { username: 'appr' }, asset_group_id: 2, asset_group: { name: 'db' } },
        { id: 12, approver_group_id: 4, approver_group: { name: 'DBA' }, asset_group_id: 2, asset_group: { name: 'db' } },
        { id: 13, approver_id: 8, approver: { username: 'appr' }, asset_id: 1, asset: { name: 'web-1' } },
        { id: 14, approver_id: 8, approver: { username: 'appr' }, subject_group_id: 3, subject_group: { name: 'SRE' } },
      ],
      total: 4,
    })
  })

  it('預設客體中心：節點樹含繼承池與門檻警告', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.vm.activeView).toBe('objects')
    const tree = wrapper.vm.nodeTreeRows
    const prod = tree.find((n) => n.name === 'prod')
    expect(prod).toBeTruthy()
    // prod 自身無範圍 → 池 0、顯示不足門檻警示（門檻 2）
    expect(prod.poolCount).toBe(0)
    // db 節點：個人 appr(8) ＋ DBA 群組成員 {8,9} → 去重 {8,9} = 2，達門檻
    const db = prod.children.find((n) => n.name === 'db')
    expect(db.poolCount).toBe(2)
    // web 節點：僅繼承 prod（無）→ 0
    const web = prod.children.find((n) => n.name === 'web')
    expect(web.poolCount).toBe(0)
  })

  it('直配資產與申請人側路由各自成區塊', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.vm.assetScopeRows.map((r) => r.assetName)).toEqual(['web-1'])
    expect(wrapper.vm.subjectScopeRows.map((s) => s.id)).toEqual([14])
  })

  it('按審核人員視角：個人與群組皆成列、零範圍者也列出', async () => {
    const wrapper = mountView()
    await flushPromises()

    const rows = wrapper.vm.actorRows
    const names = rows.map((r) => `${r.type}:${r.name}`)
    expect(names).toContain('user:appr')
    expect(names).toContain('group:DBA')
    const appr = rows.find((r) => r.name === 'appr')
    expect(appr.fullName).toBe('審核甲')
    expect(appr.byType.asset_group.map((s) => s.id)).toEqual([11])
    expect(appr.byType.asset.map((s) => s.id)).toEqual([13])
    expect(appr.byType.subject_group.map((s) => s.id)).toEqual([14])
    const dba = rows.find((r) => r.name === 'DBA')
    expect(dba.byType.asset_group.map((s) => s.id)).toEqual([12])
  })

  it('頁面明示範圍語義（含群組即資格與自審禁止）', async () => {
    const wrapper = mountView()
    await flushPromises()
    const text = wrapper.text()
    expect(text).toContain('群組成員自動具審核資格')
    expect(text).toContain('申請人不得核准自己的申請')
    expect(text).toContain('節點範圍含整棵子樹')
  })

  it('新增成功後關窗並重載（結果在矩陣上可見）', async () => {
    const wrapper = mountView()
    await flushPromises()
    wrapper.vm.openAdd()
    expect(wrapper.vm.addVisible).toBe(true)
    getApproverScopesMock.mockClear()
    wrapper.vm.handleCreated()
    await flushPromises()
    expect(wrapper.vm.addVisible).toBe(false)
    expect(getApproverScopesMock).toHaveBeenCalled()
  })

  it('移除：確認三件套後呼叫 delete 並重載', async () => {
    const { ElMessageBox } = await import('element-plus')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    deleteApproverScopeMock.mockResolvedValue({})
    const wrapper = mountView()
    await flushPromises()
    getApproverScopesMock.mockClear()

    const dba = wrapper.vm.actorRows.find((r) => r.name === 'DBA')
    await wrapper.vm.handleRemove(dba.byType.asset_group[0])
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    expect(String(confirmSpy.mock.calls[0][0])).toContain('無法復原')
    expect(String(confirmSpy.mock.calls[0][0])).toContain('DBA')
    expect(deleteApproverScopeMock).toHaveBeenCalledWith(12)
    expect(getApproverScopesMock).toHaveBeenCalled()
    confirmSpy.mockRestore()
  })
})
