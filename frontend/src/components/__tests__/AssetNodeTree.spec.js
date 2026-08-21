import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import AssetNodeTree from '../AssetNodeTree.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 的 MutationObserver 與 EP 內部觀察器不相容，no-op stub（與 Assets.spec.js 同法）
class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const getAssetListMock = vi.fn()

vi.mock('@/api/assets', () => ({
  getAssetList: (...args) => getAssetListMock(...args),
  getAssetNodeTree: vi.fn().mockResolvedValue({ data: [] }),
  getAssetGroups: vi.fn().mockResolvedValue({ data: [], total: 0 }),
  createAssetGroup: vi.fn(),
  updateAssetGroup: vi.fn(),
  moveAssetGroup: vi.fn(),
  deleteAssetGroup: vi.fn(),
}))

const mountTree = () =>
  mount(AssetNodeTree, {
    global: { plugins: [ElementPlus] },
  })

describe('AssetNodeTree 虛擬項顯著化（未分組區塊＋計數）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // 計數查詢：ungrouped=true 回未分組數，否則回全部可視數
    getAssetListMock.mockImplementation((params) =>
      Promise.resolve(params?.ungrouped ? { data: [], total: 3 } : { data: [], total: 7 })
    )
  })

  it('全部資產帶總計數；未分組入「其他」區塊帶計數', async () => {
    const wrapper = mountTree()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('全部資產')
    expect(text).toContain('其他')
    expect(text).toContain('未分組')
    expect(wrapper.find('.all-assets .node-count').text()).toBe('7')
    expect(wrapper.find('.ungrouped-item .node-count').text()).toBe('3')
    // 區塊以分隔線＋小節標題呈現
    expect(wrapper.find('.tree-section .tree-section-title').text()).toBe('其他')
  })

  it('計數走 page_size=1 輕量查詢（全部與未分組各一次）', async () => {
    mountTree()
    await flushPromises()

    const calls = getAssetListMock.mock.calls.map(([p]) => p)
    expect(calls).toContainEqual({ page: 1, page_size: 1 })
    expect(calls).toContainEqual({ page: 1, page_size: 1, ungrouped: true })
  })

  it('計數查詢失敗時不渲染計數徽章（不阻斷樹本體）', async () => {
    getAssetListMock.mockRejectedValue(new Error('network'))
    const wrapper = mountTree()
    await flushPromises()

    expect(wrapper.text()).toContain('全部資產')
    expect(wrapper.text()).toContain('未分組')
    expect(wrapper.find('.all-assets .node-count').exists()).toBe(false)
    expect(wrapper.find('.ungrouped-item .node-count').exists()).toBe(false)
  })

  it('點未分組發出 select ungrouped；reloadTree 重抓計數', async () => {
    const wrapper = mountTree()
    await flushPromises()

    await wrapper.find('.ungrouped-item').trigger('click')
    expect(wrapper.emitted('select').at(-1)).toEqual(['ungrouped'])

    getAssetListMock.mockClear()
    wrapper.vm.reloadTree()
    await flushPromises()
    expect(getAssetListMock.mock.calls.map(([p]) => p)).toContainEqual({
      page: 1,
      page_size: 1,
      ungrouped: true,
    })
  })
})
