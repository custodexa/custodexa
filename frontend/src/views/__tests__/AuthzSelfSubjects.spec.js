import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AuthzBatchWizard from '@/components/AuthzBatchWizard.vue'
import Authorizations from '../Authorizations.vue'
import zhTW from '@/i18n/locales/zh-TW.json'

// 本人範圍的介面預先停用：
// 精靈把本人、本人擁有的 agent、本人所屬群組列為不可勾選並說明原因；
// 授權列表對主體屬本人範圍的列停用帳號範圍動作、保留刪除。
// applies=false 或端點失敗時不預先停用（後端守衛照常拒絕）。

enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
vi.setConfig({ testTimeout: 20_000 })

const getSelfSubjectsMock = vi.fn()
const getAuthorizationsMock = vi.fn()
const deleteAuthorizationMock = vi.fn()

vi.mock('@/api/authorizations', () => ({
  getSelfSubjects: (...a) => getSelfSubjectsMock(...a),
  getAuthorizations: (...a) => getAuthorizationsMock(...a),
  deleteAuthorization: (...a) => deleteAuthorizationMock(...a),
  batchCreateAuthorizations: vi.fn(),
  // 選項改由授權選擇器供應（欄位同伺服器回應契約）
  getAuthorizationSubjectOptions: ({ kind }) => Promise.resolve(
    kind === 'user'
      ? {
          total: 3,
          data: [
            { id: 2, username: 'alice', display_name: 'alice', kind: 'human', active: true, roles: [] },
            { id: 3, username: 'bob', display_name: 'bob', kind: 'human', active: true, roles: [] },
            { id: 9, username: 'report-bot', display_name: 'report-bot', kind: 'agent', active: true, roles: [] },
          ],
        }
      : {
          total: 2,
          data: [
            { id: 5, name: 'ops', description: '', member_count: 0 },
            { id: 6, name: 'dba', description: '', member_count: 0 },
          ],
        }
  ),
  getAuthorizationTargetOptions: ({ kind }) => Promise.resolve(
    kind === 'asset'
      ? { total: 1, data: [{ id: 1, name: 'srv', protocol: 'ssh', host: 'h', nodes: [] }] }
      : kind === 'node'
        ? { total: 1, data: [{ id: 4, name: 'prod-ag', path: 'prod-ag', selectable: true }] }
        : { total: 0, data: [] }
  ),
  getEffectiveAssets: vi.fn().mockResolvedValue({ assets: [] }),
  getEffectiveUsers: vi.fn().mockResolvedValue({ users: [] }),
}))

vi.mock('@/api/accessRequests', () => ({
  revokeAccessRequest: vi.fn(),
}))

vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [], total: 0 }),
}))

const selfApplies = { applies: true, user_id: 2, user_group_ids: [5], agent_ids: [9] }

const mountWizard = () =>
  mount(AuthzBatchWizard, {
    props: { modelValue: true },
    global: { plugins: [ElementPlus] },
  })

const mountList = () => {
  localStorage.setItem('user', JSON.stringify({ id: 2, username: 'alice', roles: ['admin'] }))
  return mount(Authorizations, { global: { plugins: [ElementPlus] } })
}

const rowByText = (wrapper, text) =>
  wrapper.findAll('.el-table__body tr').find(tr => tr.text().includes(text))

const checkboxDisabled = tr => tr.find('.el-checkbox').classes().includes('is-disabled')

describe('AuthzSelfSubjects 本人範圍的介面預先停用', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    getAuthorizationsMock.mockResolvedValue({ data: [], total: 0 })
  })

  it('applies=true：精靈的本人列與自有 agent 列不可勾選並顯示原因，他人可勾', async () => {
    getSelfSubjectsMock.mockResolvedValue(selfApplies)
    const wrapper = mountWizard()
    await flushPromises()

    const me = rowByText(wrapper, 'alice')
    expect(me).toBeTruthy()
    expect(checkboxDisabled(me)).toBe(true)
    expect(me.text()).toContain(zhTW.authzWizard.selfSubjectUser)

    const bot = rowByText(wrapper, 'report-bot')
    expect(checkboxDisabled(bot)).toBe(true)
    expect(bot.text()).toContain(zhTW.authzWizard.selfSubjectAgent)

    const bob = rowByText(wrapper, 'bob')
    expect(checkboxDisabled(bob)).toBe(false)
    expect(bob.text()).not.toContain(zhTW.authzWizard.selfSubjectUser)
  })

  it('applies=true：群組分頁本人所屬群組不可勾選並顯示底部說明', async () => {
    getSelfSubjectsMock.mockResolvedValue(selfApplies)
    const wrapper = mountWizard()
    await flushPromises()
    const groupRadio = wrapper.findAll('.el-radio-button').find(r => r.text().includes(zhTW.authzWizard.subjectGroup))
    await groupRadio.find('input').setValue(true)
    await flushPromises()

    const ops = rowByText(wrapper, 'ops')
    expect(ops).toBeTruthy()
    expect(checkboxDisabled(ops)).toBe(true)
    const dba = rowByText(wrapper, 'dba')
    expect(checkboxDisabled(dba)).toBe(false)
    expect(wrapper.text()).toContain(zhTW.authzWizard.selfGroupNotice)
  })

  it('applies=false 或端點失敗時精靈無任何停用', async () => {
    for (const setup of [
      () => getSelfSubjectsMock.mockResolvedValue({ ...selfApplies, applies: false }),
      () => getSelfSubjectsMock.mockRejectedValue(new Error('network')),
    ]) {
      setup()
      const wrapper = mountWizard()
      await flushPromises()
      expect(checkboxDisabled(rowByText(wrapper, 'alice'))).toBe(false)
      expect(checkboxDisabled(rowByText(wrapper, 'report-bot'))).toBe(false)
      expect(wrapper.text()).not.toContain(zhTW.authzWizard.selfSubjectUser)
      wrapper.unmount()
    }
  })

  it('列表中本人所屬群組列的帳號範圍動作停用並有提示、刪除可按；他人列照常', async () => {
    getSelfSubjectsMock.mockResolvedValue(selfApplies)
    getAuthorizationsMock.mockResolvedValue({
      data: [
        { id: 11, user_group_id: 5, user_group_name: 'ops', asset_id: 1, asset_name: 'srv', permission: 'connect', source: 'manual', accounts: ['@ALL'], validity_state: 'active' },
        { id: 12, user_id: 3, username: 'bob', asset_id: 1, asset_name: 'srv', permission: 'connect', source: 'manual', accounts: ['@ALL'], validity_state: 'active' },
      ],
      total: 2,
    })
    const wrapper = mountList()
    await flushPromises()

    const opsRow = rowByText(wrapper, 'ops')
    expect(opsRow).toBeTruthy()
    const scopeBtn = opsRow.findAll('button').find(b => b.text().includes(zhTW.authorizations.accountScopeAction))
    expect(scopeBtn.attributes('disabled')).toBeDefined()
    const deleteBtn = opsRow.findAll('button').find(b => b.text().includes(zhTW.common.delete))
    expect(deleteBtn).toBeTruthy()
    expect(deleteBtn.attributes('disabled')).toBeUndefined()
    // 提示文案掛在 tooltip：以元件 props 驗證停用列帶 accountScopeSelfLocked
    const tooltip = opsRow.findComponent({ name: 'ElTooltip' })
    expect(tooltip.props('content')).toBe(zhTW.authorizations.accountScopeSelfLocked)
    expect(tooltip.props('disabled')).toBe(false)

    const bobRow = rowByText(wrapper, 'bob')
    const bobScope = bobRow.findAll('button').find(b => b.text().includes(zhTW.authorizations.accountScopeAction))
    expect(bobScope.attributes('disabled')).toBeUndefined()
    expect(bobRow.findComponent({ name: 'ElTooltip' }).props('disabled')).toBe(true)
  })

  it('applies=false 或端點失敗時列表無任何停用', async () => {
    getAuthorizationsMock.mockResolvedValue({
      data: [{ id: 11, user_group_id: 5, user_group_name: 'ops', asset_id: 1, asset_name: 'srv', permission: 'connect', source: 'manual', accounts: ['@ALL'], validity_state: 'active' }],
      total: 1,
    })
    for (const setup of [
      () => getSelfSubjectsMock.mockResolvedValue({ ...selfApplies, applies: false }),
      () => getSelfSubjectsMock.mockRejectedValue(new Error('network')),
    ]) {
      setup()
      const wrapper = mountList()
      await flushPromises()
      const opsRow = rowByText(wrapper, 'ops')
      const scopeBtn = opsRow.findAll('button').find(b => b.text().includes(zhTW.authorizations.accountScopeAction))
      expect(scopeBtn.attributes('disabled')).toBeUndefined()
      wrapper.unmount()
    }
  })
})
