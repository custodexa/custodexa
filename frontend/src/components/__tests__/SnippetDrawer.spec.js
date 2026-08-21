import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

// happy-dom 與 el-drawer 不相容（既知炸點）：以渲染 default slot 的 stub 取代
const ElDrawerStub = {
  name: 'ElDrawer',
  props: ['modelValue', 'title'],
  emits: ['update:modelValue', 'open'],
  template: '<div class="stub-drawer"><slot /></div>',
}

const { mockGetSnippets, mockCreateSnippet, mockDeleteSnippet } = vi.hoisted(() => ({
  mockGetSnippets: vi.fn(),
  mockCreateSnippet: vi.fn(),
  mockDeleteSnippet: vi.fn(),
}))

vi.mock('@/api/snippets', () => ({
  getSnippets: mockGetSnippets,
  createSnippet: mockCreateSnippet,
  updateSnippet: vi.fn(),
  deleteSnippet: mockDeleteSnippet,
}))

vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    ElMessage: { success: vi.fn(), error: vi.fn() },
  }
})

import SnippetDrawer from '../SnippetDrawer.vue'

function mountDrawer() {
  return mount(SnippetDrawer, {
    props: { modelValue: true },
    global: {
      stubs: { 'el-drawer': ElDrawerStub },
    },
  })
}

describe('SnippetDrawer', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetSnippets.mockResolvedValue({
      data: [
        { id: 1, name: '檢視磁碟', content: 'df -h' },
        { id: 2, name: '查行程', content: 'ps aux' },
      ],
      total: 2,
    })
  })

  it('載入並渲染片段列表', async () => {
    const wrapper = mountDrawer()
    await wrapper.vm.load()
    await wrapper.vm.$nextTick()

    expect(wrapper.findAll('.snippet-card')).toHaveLength(2)
    expect(wrapper.text()).toContain('檢視磁碟')
    expect(wrapper.text()).toContain('df -h')
  })

  it('點擊使用 emit use 事件帶 content', async () => {
    const wrapper = mountDrawer()
    await wrapper.vm.load()
    await wrapper.vm.$nextTick()

    const useBtn = wrapper.findAll('el-button').find((b) => b.text() === '使用')
    await useBtn.trigger('click')

    expect(wrapper.emitted('use')[0]).toEqual(['df -h'])
  })

  it('搜尋過濾名稱', async () => {
    const wrapper = mountDrawer()
    await wrapper.vm.load()
    wrapper.vm.keyword = '磁碟'
    await wrapper.vm.$nextTick()

    expect(wrapper.findAll('.snippet-card')).toHaveLength(1)
    expect(wrapper.text()).toContain('檢視磁碟')
  })

  it('新增片段後重新載入', async () => {
    mockCreateSnippet.mockResolvedValue({ id: 3 })
    const wrapper = mountDrawer()
    await wrapper.vm.load()

    wrapper.vm.form = { name: 'top', content: 'top -c' }
    await wrapper.vm.create()

    expect(mockCreateSnippet).toHaveBeenCalledWith({ name: 'top', content: 'top -c' })
    expect(mockGetSnippets).toHaveBeenCalledTimes(2)
  })

  it('刪除片段自列表移除', async () => {
    mockDeleteSnippet.mockResolvedValue({})
    const wrapper = mountDrawer()
    await wrapper.vm.load()

    await wrapper.vm.remove({ id: 1 })
    await wrapper.vm.$nextTick()

    expect(mockDeleteSnippet).toHaveBeenCalledWith(1)
    expect(wrapper.findAll('.snippet-card')).toHaveLength(1)
  })
})
