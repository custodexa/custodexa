import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AuthzBatchWizard from '../AuthzBatchWizard.vue'

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

const batchCreateAuthorizationsMock = vi.fn()

vi.mock('@/api/authorizations', () => ({
  batchCreateAuthorizations: (...a) => batchCreateAuthorizationsMock(...a),
}))

vi.mock('@/api/assets', () => ({
  getAssetGroups: vi.fn().mockResolvedValue({ data: [{ id: 4, name: 'prod-ag', path: 'prod-ag' }] }),
  getAssetList: vi.fn().mockResolvedValue({
    data: [{ id: 1, name: 'srv', host: 'h', port: 22, protocol: 'mysql' }],
    total: 1,
  }),
  getAssetTags: vi.fn().mockResolvedValue({
    data: [
      { name: '生產', count: 2 },
      { name: '資料庫', count: 1 },
    ],
  }),
}))

vi.mock('@/api/auth', () => ({
  getUsers: vi.fn().mockResolvedValue({
    data: [
      {
        id: 2,
        username: 'alice',
        email: 'a@t.local',
        active: true,
        roles: [{ id: 2, name: 'user', description: '一般使用者' }],
      },
      { id: 3, username: 'bob', email: 'b@t.local', active: false, roles: [] },
    ],
  }),
}))

vi.mock('@/api/userGroups', () => ({
  getUserGroups: vi.fn().mockResolvedValue({ data: [{ id: 5, name: 'ops', users: [] }] }),
}))

const mountWizard = (props = {}) =>
  mount(AuthzBatchWizard, {
    props: { modelValue: true, ...props },
    global: { plugins: [ElementPlus] },
  })

describe('AuthzBatchWizard 批次授權精靈', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('第一步角色欄取 role.name、狀態欄讀 active（修錯：原噴 JSON/全員停用）', async () => {
    const wrapper = mountWizard()
    await flushPromises()

    const text = wrapper.text()
    // 角色顯示名稱而非物件 JSON
    expect(text).toContain('user')
    expect(text).not.toContain('created_at')
    expect(text).not.toContain('{')
    // active=true 顯啟用、false 顯停用（原全員誤標停用）
    expect(text).toContain('啟用')
    expect(text).toContain('停用')
  })

  it('批次授權送伺服端展開 payload（多主體×多客體）', async () => {
    batchCreateAuthorizationsMock.mockResolvedValue({ created: 3, skipped: 1 })
    const wrapper = mountWizard()
    await flushPromises()

    wrapper.vm.selectedUsers = [{ id: 2, username: 'alice' }]
    wrapper.vm.selectedUserGroups = [{ id: 5, name: 'ops' }]
    wrapper.vm.selectedAssets = [{ id: 1, name: 'srv' }]
    wrapper.vm.selectedGroups = [{ id: 4, name: 'prod-ag' }]
    wrapper.vm.selectedPermission = 'connect'

    await wrapper.vm.handleBatchSubmit()
    await flushPromises()

    expect(batchCreateAuthorizationsMock).toHaveBeenCalledWith({
      user_ids: [2],
      user_group_ids: [5],
      asset_ids: [1],
      asset_group_ids: [4],
      permission: 'connect',
    })
  })

  it('客體節點樹：平面節點組樹、確認步驟帶含子樹語義', async () => {
    const wrapper = mountWizard()
    await flushPromises()

    wrapper.vm.targetMode = 'groups'
    await flushPromises()

    const opts = wrapper.vm.nodeTreeOptions
    expect(opts.length).toBe(1)
    expect(opts[0].id).toBe(4)

    wrapper.vm.selectedGroups = [{ id: 4, name: 'prod-ag', path: 'prod-ag' }]
    wrapper.vm.currentStep = 3
    await flushPromises()
    expect(wrapper.text()).toContain('含子樹，新資產掛入自動生效')
  })

  it('第一步：主體聯集非空才能下一步', async () => {
    const wrapper = mountWizard()
    await flushPromises()

    expect(wrapper.vm.canProceedToNextStep).toBe(false)
    wrapper.vm.selectedUserGroups = [{ id: 5, name: 'ops' }]
    await flushPromises()
    expect(wrapper.vm.canProceedToNextStep).toBe(true)
  })

  it('node_id 深連結預填：開啟即切節點模式並預選該節點（Assets.vue 跳轉契約）', async () => {
    const wrapper = mountWizard({ prefillNodeId: 4 })
    await flushPromises()
    await flushPromises()

    expect(wrapper.vm.targetMode).toBe('groups')
    expect(wrapper.vm.selectedGroups.map((g) => g.id)).toContain(4)
  })

  it('協議 tag 對 DB/K8s 類協議不產生空 type（修 invalid prop 警告）', async () => {
    const warnSpy = vi.spyOn(console, 'warn')
    const wrapper = mountWizard()
    await flushPromises()

    wrapper.vm.currentStep = 1
    await flushPromises()

    const invalidPropWarnings = warnSpy.mock.calls.filter((c) =>
      String(c[0]).includes('Invalid prop')
    )
    expect(invalidPropWarnings.length).toBe(0)
    expect(wrapper.text()).toContain('MYSQL')
    warnSpy.mockRestore()
  })
})

describe('AuthzBatchWizard 挑選輔助', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('節點/標籤/搜尋以伺服端參數重抓（含子樹預設）', async () => {
    const { getAssetList } = await import('@/api/assets')
    const wrapper = mountWizard()
    await flushPromises()
    getAssetList.mockClear()

    wrapper.vm.assetNodeFilter = 4
    wrapper.vm.assetTagFilter = ['生產', '資料庫']
    await wrapper.vm.reloadAssetList()

    expect(getAssetList).toHaveBeenCalledWith({
      page_size: 1000,
      node_id: 4,
      tags: '生產,資料庫',
    })
  })

  it('total 超過已載入數顯示誠實截斷警示', async () => {
    const { getAssetList } = await import('@/api/assets')
    const wrapper = mountWizard()
    await flushPromises()

    getAssetList.mockResolvedValueOnce({
      data: [{ id: 1, name: 'srv', host: 'h', port: 22, protocol: 'ssh' }],
      total: 1500,
    })
    await wrapper.vm.reloadAssetList()
    await flushPromises()

    expect(wrapper.vm.assetListTruncated).toBe(true)
    expect(wrapper.text()).toContain('僅載入前 1 筆（共 1500 筆）')
  })

  it('latest-request-wins：舊回應晚到不得覆蓋新結果', async () => {
    const { getAssetList } = await import('@/api/assets')
    const wrapper = mountWizard()
    await flushPromises()

    let resolveOld
    const oldPromise = new Promise((resolve) => {
      resolveOld = resolve
    })
    getAssetList
      .mockImplementationOnce(() => oldPromise)
      .mockResolvedValueOnce({
        data: [{ id: 22, name: 'new-result', host: 'h', port: 22, protocol: 'ssh' }],
        total: 1,
      })

    const oldCall = wrapper.vm.reloadAssetList() // 舊請求（懸置）
    await wrapper.vm.reloadAssetList() // 新請求先完成
    resolveOld({
      data: [{ id: 11, name: 'stale-result', host: 'h', port: 22, protocol: 'ssh' }],
      total: 1,
    })
    await oldCall
    await flushPromises()

    expect(wrapper.vm.assetList.map((a) => a.name)).toEqual(['new-result'])
  })

  it('跨篩選保勾選：已選但不在目前列表仍計入送出 payload', async () => {
    batchCreateAuthorizationsMock.mockResolvedValue({ created: 1, skipped: 0 })
    const wrapper = mountWizard()
    await flushPromises()

    wrapper.vm.selectedUsers = [{ id: 2, username: 'alice' }]
    // 勾選了一台後續被篩掉的資產（reserve-selection 全集語義）
    wrapper.vm.selectedAssets = [{ id: 9, name: 'off-list', host: 'h', port: 22, protocol: 'ssh' }]
    wrapper.vm.selectedPermission = 'connect'
    await wrapper.vm.reloadAssetList() // 換資料集
    await wrapper.vm.handleBatchSubmit()

    expect(wrapper.vm.selectedAssets.map((a) => a.id)).toEqual([9])
    expect(batchCreateAuthorizationsMock).toHaveBeenCalledWith(
      expect.objectContaining({ asset_ids: [9], user_ids: [2] })
    )
  })

  it('重開精靈清空勾選與篩選（殘留勾選＝溢授）', async () => {
    const wrapper = mountWizard()
    await flushPromises()

    wrapper.vm.selectedAssets = [{ id: 9, name: 'x', host: 'h', port: 22, protocol: 'ssh' }]
    wrapper.vm.assetNodeFilter = 4
    wrapper.vm.assetTagFilter = ['生產']

    await wrapper.setProps({ modelValue: false })
    await wrapper.setProps({ modelValue: true })
    await flushPromises()

    expect(wrapper.vm.selectedAssets).toEqual([])
    expect(wrapper.vm.assetNodeFilter).toBe(null)
    expect(wrapper.vm.assetTagFilter).toEqual([])
  })
})
