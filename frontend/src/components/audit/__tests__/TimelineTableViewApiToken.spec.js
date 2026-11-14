import { describe, it, expect, afterEach, vi } from 'vitest'
import { mount, enableAutoUnmount, flushPromises, RouterLinkStub } from '@vue/test-utils'
import ElementPlus from 'element-plus'
import TimelineTableView from '../TimelineTableView.vue'

// 純文字檢視與時間軸檢視對「經由 API token」的歸因要說同一句：
// 表格常被複製進調查報告，少了這一句就讀不出是工具代為操作

enableAutoUnmount(afterEach)

class ObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', ObserverStub)
vi.stubGlobal('ResizeObserver', ObserverStub)

const event = (over = {}) => ({
  id: 'audit:1',
  ts: '2026-11-13T05:58:04Z',
  type: 'audit_log',
  summary_code: 'timeline.audit_log.create',
  params: { resource: 'asset' },
  refs: {},
  ...over,
})

const mountTable = async (events, props = {}) => {
  const w = mount(TimelineTableView, {
    props: { events, spans: [], ...props },
    global: { plugins: [ElementPlus], stubs: { RouterLink: RouterLinkStub } },
  })
  await flushPromises()
  return w
}

describe('TimelineTableView API token 歸因', () => {
  it('人樞紐：經由 token 的列註明操作者（調查對象）與 token 名', async () => {
    const w = await mountTable([event({ api_token_name: 'tf-plan' })], {
      subject: 'user',
      subjectName: 'operator-a',
    })
    const via = w.find('[data-test="table-via"]')
    expect(via.exists()).toBe(true)
    expect(via.text()).toContain('operator-a')
    expect(via.text()).toContain('tf-plan')
  })

  it('本人親自操作的列不加註記', async () => {
    const w = await mountTable([event()], { subject: 'user', subjectName: 'operator-a' })
    expect(w.find('[data-test="table-via"]').exists()).toBe(false)
  })

  it('位址樞紐：註記併進操作者欄，不在摘要重複', async () => {
    const w = await mountTable(
      [event({ api_token_name: 'tf-plan', actor: { id: 84, name: 'operator-a' } })],
      { subject: 'ip' }
    )
    expect(w.find('[data-test="table-via"]').exists()).toBe(false)
    const text = w.text()
    expect(text).toContain('operator-a')
    expect(text).toContain('tf-plan')
  })
})
