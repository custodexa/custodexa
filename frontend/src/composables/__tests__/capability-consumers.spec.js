import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import BreakerReleaseForm from '@/components/agent/BreakerReleaseForm.vue'
import ToolCallLedgerTable from '@/components/agent/ToolCallLedgerTable.vue'
import AssetNodeTree from '@/components/AssetNodeTree.vue'
import MyConnections from '@/views/MyConnections.vue'
import MyRequests from '@/views/MyRequests.vue'
import { grantFor } from '@/composables/__tests__/capabilityFixtures'
import { useRoles } from '@/composables/useRoles'
import { resetCapabilities, setCapabilitiesForTests } from '@/composables/useCapabilities'
import { t } from '@/i18n'

// 操作者能力消費者：有能力／無能力各一列；本人（ownership）路徑與角色資料用途不被能力替代。
// 能力集合直接指定，不經角色夾具，以免測試自己把角色翻成能力。
vi.mock('@/api/myConnections', () => ({
  getMyConnections: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  terminateMyConnection: vi.fn(),
}))
vi.mock('@/api/accessRequests', () => ({
  getMyAccessRequests: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getMyActiveTickets: vi.fn().mockResolvedValue({ data: [] }),
  cancelAccessRequest: vi.fn(),
}))
vi.mock('@/api/agents', () => ({ releaseAgentBreaker: vi.fn() }))
vi.mock('@/api/agentTasks', () => ({ getAgentToolCallArguments: vi.fn() }))
vi.mock('@/api/assets', () => ({
  getAssetList: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  moveAssetGroup: vi.fn(),
  deleteAssetGroup: vi.fn(),
}))
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() { return [] }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)
enableAutoUnmount(afterEach)

beforeEach(() => {
  resetCapabilities()
  localStorage.clear()
})
afterEach(() => {
  resetCapabilities()
  localStorage.clear()
})

const plugins = { global: { plugins: [ElementPlus] } }

describe('BreakerReleaseForm 解除斷路資格', () => {
  const agent = { id: 9, kind: 'agent', owner_user_id: 4 }
  const mountForm = (actor, principal = agent) =>
    mount(BreakerReleaseForm, { props: { principal, actor }, ...plugins })

  it.each([
    ['持有 user:manage（管理任一 agent）', ['user:manage'], { id: 1, kind: 'human' }, true],
    ['無 user:manage 且不是負責人', ['asset:view'], { id: 1, kind: 'human' }, false],
    ['無 user:manage 但是該 agent 的負責人（ownership 路徑）', ['asset:view'], { id: 4, kind: 'human' }, true],
    ['持有 user:manage 但操作者本身是 agent', ['user:manage'], { id: 1, kind: 'agent' }, false],
  ])('%s', (_name, perms, actor, shown) => {
    setCapabilitiesForTests(perms)
    expect(mountForm(actor).find('[data-test="breaker-release"]').exists()).toBe(shown)
  })

  it('能力尚未載入時不以快取的角色頂替', () => {
    localStorage.setItem('user', JSON.stringify({ id: 1, roles: ['admin'] }))
    expect(mountForm({ id: 1, kind: 'human' }).find('[data-test="breaker-release"]').exists()).toBe(false)
  })
})

describe('ToolCallLedgerTable 還原遮罩參數', () => {
  const row = {
    id: 5, seq: 3, session_id: 118, tool: 'run_command', decision: 'denied',
    denial_code: 'RULE_COMMAND_BLOCKED', masked_count: 1, args_retained: true,
    args_redacted: { command: '[REDACTED]' }, created_at: '2026-09-23T03:00:00Z', duration_ms: 1,
  }
  it.each([
    ['持有 audit:view', ['audit:view'], true],
    ['無 audit:view（即使持有其他管理能力）', ['user:manage', 'session:view'], false],
  ])('%s', (_name, perms, shown) => {
    setCapabilitiesForTests(perms)
    const wrapper = mount(ToolCallLedgerTable, { props: { rows: [row] }, ...plugins })
    expect(wrapper.find('[data-test="reveal-arguments"]').exists()).toBe(shown)
  })
})

describe('AssetNodeTree 節點管理', () => {
  const rootLabel = () => t('nodeTree.rootNode')
  const mountTree = async () => {
    const wrapper = mount(AssetNodeTree, plugins)
    await flushPromises()
    return wrapper
  }
  it.each([
    ['持有 assetgroup:manage', ['assetgroup:manage'], true],
    ['只有 authorization:manage（不得管理節點）', ['authorization:manage'], false],
    ['沒有任何節點能力', ['asset:view'], false],
  ])('%s 時新增根節點入口', async (_name, perms, shown) => {
    setCapabilitiesForTests(perms)
    const wrapper = await mountTree()
    expect(wrapper.text().includes(rootLabel())).toBe(shown)
  })
})

describe('角色資料用途不提供授權旗標', () => {
  it('useRoles 只回角色顯示資料與本人 ID', () => {
    localStorage.setItem('user', JSON.stringify({ id: 7, roles: [{ name: 'admin' }] }))
    const api = useRoles()
    expect(Object.keys(api).sort()).toEqual(['currentUserId', 'roles'])
    expect(api.currentUserId.value).toBe(7)
  })
})

describe('自助頁的不適用說明', () => {
  const note = '[data-test="self-service-not-applicable"]'
  it.each([
    ['MyConnections', MyConnections, 'myConnections'],
    ['MyRequests', MyRequests, 'myRequests'],
  ])('%s：admin／auditor 看見本人資料頁與說明，原可送件者不顯示說明', async (_n, comp, key) => {
    for (const roles of [['admin'], ['auditor']]) {
      grantFor(roles)
      const wrapper = mount(comp, plugins)
      await flushPromises()
      expect(wrapper.find(note).exists()).toBe(true)
      expect(wrapper.text()).toContain(t(`${key}.notApplicable`))
      wrapper.unmount()
    }
    for (const roles of [['user'], ['approver']]) {
      grantFor(roles)
      const wrapper = mount(comp, plugins)
      await flushPromises()
      expect(wrapper.find(note).exists()).toBe(false)
      wrapper.unmount()
    }
  })

  it('能力尚未載入時不先閃出說明', async () => {
    const wrapper = mount(MyConnections, plugins)
    await flushPromises()
    expect(wrapper.find(note).exists()).toBe(false)
  })
})
