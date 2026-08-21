import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus, { ElMessageBox } from 'element-plus'
import MyConnections from '../MyConnections.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 el-table key-render-helper 不相容，
// 以 no-op stub 取代（不影響渲染結果驗證，與 Commands.spec.js 同法）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getMyConnectionsMock = vi.fn()
const terminateMyConnectionMock = vi.fn()

vi.mock('@/api/myConnections', () => ({
  getMyConnections: (...args) => getMyConnectionsMock(...args),
  terminateMyConnection: (...args) => terminateMyConnectionMock(...args),
}))

const sampleConnections = {
  data: [
    {
      id: 11,
      asset_name: 'web-server',
      protocol: 'ssh',
      connected_at: '2026-07-16T10:00:00Z',
      duration_seconds: 3665,
      status: 'active',
    },
    {
      id: 22,
      asset_name: 'db-server',
      protocol: 'rdp',
      connected_at: '2026-07-15T08:00:00Z',
      duration_seconds: 120,
      status: 'ended',
    },
  ],
  total: 2,
  page: 1,
  page_size: 20,
}

const mountView = () =>
  mount(MyConnections, {
    global: { plugins: [ElementPlus] },
  })

describe('MyConnections', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getMyConnectionsMock.mockResolvedValue(sampleConnections)
  })

  it('renders the minimal contract fields per row', async () => {
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('web-server')
    expect(text).toContain('SSH')
    expect(text).toContain('進行中')
    expect(text).toContain('db-server')
    expect(text).toContain('RDP')
    expect(text).toContain('已結束')
    // 時長格式化（3665s = 1 時 1 分 5 秒；120s = 2 分）
    expect(text).toContain('1 時 1 分 5 秒')
    expect(text).toContain('2 分')
  })

  it('has no command or recording elements (self-service scope)', async () => {
    const wrapper = mountView()
    await flushPromises()

    const text = wrapper.text()
    expect(text).not.toContain('指令')
    expect(text).not.toContain('錄製')
    expect(text).not.toContain('錄影')
    expect(text).not.toContain('播放')
    expect(text).not.toContain('監看')
    // 列操作僅有 active 列的「終止」（無其他入口）
    const rowButtons = wrapper.findAll('.el-table button')
    expect(rowButtons).toHaveLength(1)
    expect(rowButtons[0].text()).toContain('終止')
  })

  it('shows terminate button only on active rows', async () => {
    const wrapper = mountView()
    await flushPromises()

    const rows = wrapper.findAll('.el-table__body tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0].text()).toContain('終止') // active 列
    expect(rows[1].text()).not.toContain('終止') // ended 列
  })

  it('terminates after confirm and refreshes the list', async () => {
    const confirmSpy = vi
      .spyOn(ElMessageBox, 'confirm')
      .mockResolvedValue('confirm')
    terminateMyConnectionMock.mockResolvedValue({ message: '連線已終止' })

    const wrapper = mountView()
    await flushPromises()

    await wrapper.findAll('.el-table button')[0].trigger('click')
    await flushPromises()

    expect(confirmSpy).toHaveBeenCalled()
    expect(terminateMyConnectionMock).toHaveBeenCalledWith(11)
    // 初載＋終止後刷新
    expect(getMyConnectionsMock).toHaveBeenCalledTimes(2)
  })

  it('does not call the API when confirm is cancelled', async () => {
    vi.spyOn(ElMessageBox, 'confirm').mockRejectedValue('cancel')

    const wrapper = mountView()
    await flushPromises()

    await wrapper.findAll('.el-table button')[0].trigger('click')
    await flushPromises()

    expect(terminateMyConnectionMock).not.toHaveBeenCalled()
    expect(getMyConnectionsMock).toHaveBeenCalledTimes(1)
  })

  it('handles racing 400 (already ended) by refreshing without crashing', async () => {
    vi.spyOn(ElMessageBox, 'confirm').mockResolvedValue('confirm')
    terminateMyConnectionMock.mockRejectedValue({
      response: { status: 400, data: { error: '連線已結束' } },
    })

    const wrapper = mountView()
    await flushPromises()

    await wrapper.findAll('.el-table button')[0].trigger('click')
    await flushPromises()

    // 競態當「已結束」處理：刷新收斂、不拋未處理錯誤
    expect(getMyConnectionsMock).toHaveBeenCalledTimes(2)
    expect(wrapper.vm.loading).toBe(false)
  })

  it('requests with pagination params and renders total', async () => {
    const wrapper = mountView()
    await flushPromises()

    expect(getMyConnectionsMock).toHaveBeenCalledWith({ page: 1, page_size: 20 })
    expect(wrapper.vm.pagination.total).toBe(2)
  })

  it('falls back to manual-connection label when asset_name empty', async () => {
    getMyConnectionsMock.mockResolvedValue({
      data: [
        {
          id: 33,
          asset_name: '',
          protocol: 'ssh',
          connected_at: '2026-07-16T10:00:00Z',
          duration_seconds: 5,
          status: 'ended',
        },
      ],
      total: 1,
    })

    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('手動連線')
  })

  it('survives API failure without crashing', async () => {
    getMyConnectionsMock.mockRejectedValue(new Error('network down'))

    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('我的連線')
    expect(wrapper.vm.loading).toBe(false)
  })
})
