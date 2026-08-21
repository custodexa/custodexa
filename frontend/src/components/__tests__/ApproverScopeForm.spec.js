import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import ApproverScopeForm from '../ApproverScopeForm.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

const createApproverScopeMock = vi.fn()
const addUserRoleMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [{ id: 1, name: 'web-1' }] }),
  getAssetGroups: vi.fn().mockResolvedValue({
    data: [
      { id: 1, name: 'prod' },
      { id: 2, name: 'db', parent_id: 1 },
    ],
  }),
}))
vi.mock('@/api/user', () => ({
  getUserList: vi.fn().mockResolvedValue({
    data: [
      { id: 7, username: 'alice', roles: [{ name: 'user' }] },
      { id: 8, username: 'appr', roles: [{ name: 'user' }, { name: 'approver' }] },
      { id: 9, username: 'root', roles: [{ name: 'admin' }] },
      { id: 10, username: 'aud', roles: [{ name: 'auditor' }] },
    ],
  }),
  addUserRole: (...a) => addUserRoleMock(...a),
}))
vi.mock('@/api/userGroups', () => ({
  getUserGroups: vi.fn().mockResolvedValue({ data: [{ id: 3, name: 'SRE' }, { id: 4, name: 'DBA' }] }),
}))
vi.mock('@/api/accessRequests', () => ({
  createApproverScope: (...a) => createApproverScopeMock(...a),
}))

const mountForm = (props = {}) =>
  mount(ApproverScopeForm, {
    props,
    global: { plugins: [ElementPlus] },
  })

describe('ApproverScopeForm 共用範圍表單（approval-routing-quorum）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    createApproverScopeMock.mockResolvedValue({ id: 99 })
    addUserRoleMock.mockResolvedValue({})
  })

  it('預選審核方（列內捷徑）：四維各送對應 payload 欄位（XOR 契約）', async () => {
    const wrapper = mountForm({ presetActor: { type: 'user', id: 8 } })
    await flushPromises()

    const cases = [
      ['asset', 1, { approver_id: 8, asset_id: 1 }],
      ['asset_group', 2, { approver_id: 8, asset_group_id: 2 }],
      ['subject_user', 7, { approver_id: 8, subject_user_id: 7 }],
      ['subject_group', 3, { approver_id: 8, subject_group_id: 3 }],
    ]
    for (const [type, id, payload] of cases) {
      wrapper.vm.form.type = type
      await flushPromises()
      wrapper.vm.form.targetId = id
      await wrapper.vm.handleSubmit()
      await flushPromises()
      expect(createApproverScopeMock).toHaveBeenLastCalledWith(payload)
    }
    expect(wrapper.emitted('created')).toHaveLength(4)
  })

  it('審核方群組：送 approver_group_id 且零代配', async () => {
    const wrapper = mountForm()
    await flushPromises()
    wrapper.vm.form.actorType = 'group'
    await flushPromises()
    wrapper.vm.form.actorId = 4
    wrapper.vm.form.type = 'asset_group'
    await flushPromises()
    wrapper.vm.form.targetId = 2
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(createApproverScopeMock).toHaveBeenLastCalledWith({
      approver_group_id: 4,
      asset_group_id: 2,
    })
    expect(addUserRoleMock).not.toHaveBeenCalled()
  })

  it('一站式代配：非 approver 個人經確認後先配角色再建範圍（兩步順序）', async () => {
    const { ElMessageBox } = await import('element-plus')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const wrapper = mountForm()
    await flushPromises()

    // alice（user 7）無 approver 角色——選項帶代配標註
    const alice = wrapper.vm.options.actor_user.find((o) => o.id === 7)
    expect(alice.label).toContain('將加上審核人員角色')

    wrapper.vm.form.actorId = 7
    wrapper.vm.form.targetId = 1
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    expect(String(confirmSpy.mock.calls[0][0])).toContain('尚未具備審核人員角色')
    // 冪等追加端點（codex #1）：只送單一角色，不整包覆蓋
    expect(addUserRoleMock).toHaveBeenCalledWith(7, 'approver')
    expect(createApproverScopeMock).toHaveBeenCalledWith({ approver_id: 7, asset_id: 1 })
    // 代配後選項標註消除（避免重複代配）
    expect(alice.needsRole).toBe(false)
    confirmSpy.mockRestore()
  })

  it('代配後範圍建立失敗：誠實提示且不回滾角色', async () => {
    const { ElMessageBox, ElMessage } = await import('element-plus')
    const confirmSpy = vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    const warnSpy = vi.spyOn(ElMessage, 'warning')
    createApproverScopeMock.mockRejectedValue(new Error('boom'))
    const wrapper = mountForm()
    await flushPromises()

    wrapper.vm.form.actorId = 7
    wrapper.vm.form.targetId = 1
    await wrapper.vm.handleSubmit()
    await flushPromises()

    expect(addUserRoleMock).toHaveBeenCalled()
    expect(warnSpy).toHaveBeenCalled()
    expect(String(warnSpy.mock.calls[0][0])).toContain('角色已分配')
    expect(wrapper.emitted('created')).toBeUndefined()
    confirmSpy.mockRestore()
    warnSpy.mockRestore()
  })

  it('審核方個人清單排除 admin 與 auditor', async () => {
    const wrapper = mountForm()
    await flushPromises()
    const ids = wrapper.vm.options.actor_user.map((o) => o.id)
    expect(ids).toContain(7)
    expect(ids).toContain(8)
    expect(ids).not.toContain(9)
    expect(ids).not.toContain(10)
  })

  it('節點選項帶全路徑；表單用「範圍類型」label 與「新增」按鈕（D6 去三連發）', async () => {
    const wrapper = mountForm({ presetActor: { type: 'user', id: 8 } })
    await flushPromises()
    const labels = wrapper.vm.options.asset_group.map((o) => o.label)
    expect(labels).toContain('prod / db')
    expect(wrapper.text()).toContain('範圍類型')
    const submit = wrapper.findAll('button').find((b) => b.text() === '新增')
    expect(submit).toBeTruthy()
  })

  it('語義說明預設顯示、showHelp=false 隱藏（雙入口同文案）', async () => {
    const withHelp = mountForm({ presetActor: { type: 'user', id: 8 } })
    await flushPromises()
    expect(withHelp.text()).toContain('節點範圍含整棵子樹')
    expect(withHelp.text()).toContain('申請人側範圍不帶任何資產可視')

    const noHelp = mountForm({ presetActor: { type: 'user', id: 8 }, showHelp: false })
    await flushPromises()
    expect(noHelp.text()).not.toContain('節點範圍含整棵子樹')
  })
})
