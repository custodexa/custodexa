import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import Commands from '../Commands.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容，
// 以 no-op stub 取代（不影響渲染結果驗證）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const searchCommandsMock = vi.fn()
const routerPushMock = vi.fn()

vi.mock('@/api/commands', () => ({
  searchCommands: (...args) => searchCommandsMock(...args),
}))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: routerPushMock }),
}))

const sampleCommands = [
  {
    id: 1,
    session_id: 'sess-001',
    user_id: 7,
    asset_id: 3,
    command: 'ls -la /etc',
    seq: 1,
    executed_at: '2026-06-12T08:00:00Z',
  },
  {
    id: 2,
    session_id: 'sess-002',
    user_id: 8,
    asset_id: 4,
    command: 'cat /var/log/syslog',
    seq: 2,
    executed_at: '2026-06-12T08:01:00Z',
  },
]

const mountCommands = () =>
  mount(Commands, {
    global: {
      plugins: [ElementPlus],
    },
  })

describe('Commands', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('fetches commands on mount with default pagination params', async () => {
    searchCommandsMock.mockResolvedValue({ data: sampleCommands, total: 2 })

    const wrapper = mountCommands()
    await flushPromises()

    expect(searchCommandsMock).toHaveBeenCalledWith({
      page: 1,
      page_size: 20,
    })
    expect(wrapper.text()).toContain('指令稽核')
    expect(wrapper.text()).toContain('ls -la /etc')
    expect(wrapper.text()).toContain('cat /var/log/syslog')
  })

  it('sends keyword filter when searching', async () => {
    searchCommandsMock.mockResolvedValue({ data: [], total: 0 })

    const wrapper = mountCommands()
    await flushPromises()
    searchCommandsMock.mockClear()

    wrapper.vm.filters.keyword = 'rm'
    wrapper.vm.handleSearch()
    await flushPromises()

    expect(searchCommandsMock).toHaveBeenCalledWith({
      page: 1,
      page_size: 20,
      keyword: 'rm',
    })
  })

  it('navigates to session detail when clicking 檢視連線', async () => {
    searchCommandsMock.mockResolvedValue({ data: sampleCommands, total: 2 })

    const wrapper = mountCommands()
    await flushPromises()

    const detailButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('檢視連線'))
    expect(detailButton).toBeTruthy()

    await detailButton.trigger('click')
    expect(routerPushMock).toHaveBeenCalledWith('/sessions/sess-001')
  })

  it('survives API failure without crashing and stops loading', async () => {
    searchCommandsMock.mockRejectedValue(new Error('network down'))

    const wrapper = mountCommands()
    await flushPromises()

    expect(wrapper.text()).toContain('指令稽核')
    expect(wrapper.vm.loading).toBe(false)
  })

  it('shows empty state when no commands exist', async () => {
    searchCommandsMock.mockResolvedValue({ data: [], total: 0 })

    const wrapper = mountCommands()
    await flushPromises()

    expect(wrapper.text()).toContain('尚無指令記錄')
  })
})
