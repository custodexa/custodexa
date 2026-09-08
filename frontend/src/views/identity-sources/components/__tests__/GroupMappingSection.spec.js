import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import GroupMappingSection from '../GroupMappingSection.vue'

enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getSourceMappingsMock = vi.fn()
const getRoleListMock = vi.fn()

vi.mock('@/api/identitySources', () => ({
  getSourceMappings: (...a) => getSourceMappingsMock(...a),
  createSourceMapping: vi.fn(),
  updateSourceMapping: vi.fn(),
  deleteSourceMapping: vi.fn(),
  isNotImplemented: () => false,
}))

vi.mock('@/api/user', () => ({
  getRoleList: (...a) => getRoleListMock(...a),
}))

const rules = [
  { id: 1, match_value: 'cn=ops,ou=groups,dc=example,dc=org', role: 'admin', enabled: true, created_by: 'admin' },
  { id: 2, match_value: 'cn=inner,ou=groups,dc=example,dc=org', role: 'auditor', enabled: true, created_by: 'admin' },
  { id: 3, match_value: 'cn=devs,ou=groups,dc=example,dc=org', role: 'user', enabled: true, created_by: 'admin' },
]

const mountSection = () =>
  mount(GroupMappingSection, {
    props: { type: 'ldap', sourceId: 19, attrSet: true },
    global: { plugins: [ElementPlus] },
  })

// 「哪些外部群組取得了管理員角色」是稽核者的實際問法。規則多的來源上逐列目視
// 不可行，故規格把依角色篩選寫成 SHALL——這裡守的是它沒有退回紙上承諾
describe('GroupMappingSection 依目標角色篩選', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getSourceMappingsMock.mockResolvedValue({ data: rules })
    getRoleListMock.mockResolvedValue({
      data: [{ name: 'admin' }, { name: 'user' }, { name: 'auditor' }, { name: 'approver' }],
    })
  })

  it('選定角色後只留該角色的規則，全部則不過濾，且規則條數不隨篩選變動', async () => {
    const wrapper = mountSection()
    await flushPromises()

    expect(wrapper.find('[data-test="mapping-role-filter"]').exists()).toBe(true)
    expect(wrapper.vm.visibleRules).toHaveLength(3)

    wrapper.vm.roleFilter = 'admin'
    await flushPromises()
    expect(wrapper.vm.visibleRules.map((r) => r.match_value)).toEqual([
      'cn=ops,ou=groups,dc=example,dc=org',
    ])

    // 回報給來源列表的規則條數是這個來源的實際條數，不是畫面上看得到的列數
    const emitted = wrapper.emitted('count-change')
    expect(emitted[emitted.length - 1]).toEqual([3])

    wrapper.vm.roleFilter = ''
    await flushPromises()
    expect(wrapper.vm.visibleRules).toHaveLength(3)
  })
})
