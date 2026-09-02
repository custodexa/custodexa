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

// 結果事實篩選（查詢主控台）：稽核員要能問「哪些語句被擋下」「哪些結果未知」，
// 這幾個問題全靠 result_status 多選，靜默失效即等於查不到
describe('Commands 結果事實篩選', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    searchCommandsMock.mockResolvedValue({ data: [], total: 0, page: 1, page_size: 20 })
  })

  const mountPage = () => mount(Commands, { global: { plugins: [ElementPlus] } })

  it('四個篩選各自進 params，多選狀態以陣列送出', async () => {
    const wrapper = mountPage()
    await flushPromises()

    wrapper.vm.filters.source = 'console'
    wrapper.vm.filters.target_database = 'app'
    wrapper.vm.filters.result_status = ['blocked', 'partial', 'effect_unknown']
    wrapper.vm.filters.error_code = '42000'
    wrapper.vm.handleSearch()
    await flushPromises()

    const params = searchCommandsMock.mock.calls.at(-1)[0]
    expect(params.source).toBe('console')
    expect(params.target_database).toBe('app')
    expect(params.result_status).toEqual(['blocked', 'partial', 'effect_unknown'])
    expect(params.error_code).toBe('42000')
    expect(params.page).toBe(1)
  })

  it('未設定的篩選不進 params（空字串不得當成過濾條件）', async () => {
    const wrapper = mountPage()
    await flushPromises()

    const params = searchCommandsMock.mock.calls.at(-1)[0]
    expect(params.source).toBeUndefined()
    expect(params.target_database).toBeUndefined()
    expect(params.result_status).toBeUndefined()
    expect(params.error_code).toBeUndefined()
    expect(wrapper.vm.filters.result_status).toEqual([])
  })

  it('重置清空全部篩選，不留殘值', async () => {
    const wrapper = mountPage()
    await flushPromises()

    wrapper.vm.filters.source = 'cli'
    wrapper.vm.filters.target_database = 'app'
    wrapper.vm.filters.result_status = ['ok']
    wrapper.vm.filters.error_code = '1064'
    wrapper.vm.filters.keyword = 'drop'
    wrapper.vm.handleReset()
    await flushPromises()

    expect(wrapper.vm.filters).toEqual({
      keyword: '',
      source: '',
      target_database: '',
      result_status: [],
      error_code: '',
    })
    const params = searchCommandsMock.mock.calls.at(-1)[0]
    expect(Object.keys(params).sort()).toEqual(['page', 'page_size'])
  })

  it('狀態選項取自枚舉事實源，八值齊備且以譯文顯示', async () => {
    const wrapper = mountPage()
    await flushPromises()

    const select = wrapper.findAllComponents({ name: 'ElSelect' })
      .find((c) => c.attributes('data-test') === 'result-status-filter')
    expect(select).toBeTruthy()
    const labels = select.findAllComponents({ name: 'ElOption' }).map((o) => o.props('label'))
    expect(labels).toHaveLength(8)
    expect(labels).toContain('已阻斷')
    expect(labels).toContain('部分生效')
    expect(labels).toContain('結果未知')
  })

  // 篩得到卻看不到，等於要人憑記憶核對自己篩了什麼
  it('可篩的三項結果事實在表格上看得見；命令列列留白不冒充值', async () => {
    searchCommandsMock.mockResolvedValue({
      data: [
        {
          id: 1, command: 'SELECT 1', executed_at: '2026-06-12T08:00:00Z',
          target_database: 'app', result_status: 'blocked', error_code: '42000',
        },
        { id: 2, command: 'ls -la', executed_at: '2026-06-12T08:01:00Z' },
      ],
      total: 2,
    })
    const wrapper = mountPage()
    await flushPromises()

    const labels = wrapper.findAllComponents({ name: 'ElTableColumn' })
      .map((c) => c.props('label'))
    expect(labels).toContain('目標資料庫')
    expect(labels).toContain('結果狀態')
    expect(labels).toContain('錯誤碼')

    const text = wrapper.text()
    expect(text).toContain('app')
    expect(text).toContain('42000')
    expect(text).toContain('已阻斷')
  })

  it('連發查詢時慢的先發者不覆寫後發者的結果（latest-request-wins）', async () => {
    let resolveFirst
    searchCommandsMock
      .mockImplementationOnce(() => new Promise((r) => { resolveFirst = r }))
      .mockResolvedValue({ data: [{ id: 9, command: 'x', executed_at: '2026-06-12T08:00:00Z' }], total: 1 })

    const wrapper = mountPage()
    // 首次掛載的查詢被卡住，其後改篩選再查一次
    wrapper.vm.filters.source = 'console'
    wrapper.vm.handleSearch()
    await flushPromises()
    expect(wrapper.vm.commands).toHaveLength(1)

    resolveFirst({ data: [], total: 0 })
    await flushPromises()
    // 過期回應不得把畫面清空
    expect(wrapper.vm.commands).toHaveLength(1)
  })
})
