import { describe, it, expect, afterEach } from 'vitest'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import PageHeader from '../PageHeader.vue'
import EmptyState from '../EmptyState.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

const globalOpts = { plugins: [ElementPlus] }

describe('PageHeader', () => {
  it('renders title and description', () => {
    const wrapper = mount(PageHeader, {
      props: { title: '資產管理', description: '管理遠端主機資產' },
      global: globalOpts,
    })
    expect(wrapper.find('.page-title').text()).toBe('資產管理')
    expect(wrapper.find('.page-description').text()).toBe('管理遠端主機資產')
  })

  it('omits description element when not provided', () => {
    const wrapper = mount(PageHeader, {
      props: { title: '儀表板' },
      global: globalOpts,
    })
    expect(wrapper.find('.page-description').exists()).toBe(false)
  })

  it('projects actions slot content', () => {
    const wrapper = mount(PageHeader, {
      props: { title: 'T' },
      slots: { actions: '<button class="my-action">新增</button>' },
      global: globalOpts,
    })
    expect(wrapper.find('.page-actions .my-action').text()).toBe('新增')
  })
})

describe('EmptyState', () => {
  it('renders default title', () => {
    const wrapper = mount(EmptyState, { global: globalOpts })
    expect(wrapper.find('.empty-title').text()).toBe('目前沒有資料')
  })

  it('renders custom title and hint', () => {
    const wrapper = mount(EmptyState, {
      props: { title: '尚無授權記錄', hint: '點擊批次授權新增' },
      global: globalOpts,
    })
    expect(wrapper.find('.empty-title').text()).toBe('尚無授權記錄')
    expect(wrapper.find('.empty-hint').text()).toBe('點擊批次授權新增')
  })

  it('projects action slot content', () => {
    const wrapper = mount(EmptyState, {
      slots: { action: '<button class="retry">重試</button>' },
      global: globalOpts,
    })
    expect(wrapper.find('.empty-action .retry').exists()).toBe(true)
  })
})
