import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, enableAutoUnmount, flushPromises } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

import DbConsoleTree from '../DbConsole/DbConsoleTree.vue'
import { t } from '@/i18n'

const DATABASES = [
  { name: 'app', connectable: true },
  { name: 'reporting', connectable: true },
  { name: 'offline_db', connectable: false },
]

const mountTree = (props = {}) => {
  const fetchChildren = props.fetchChildren || vi.fn().mockResolvedValue({ tables: [] })
  const wrapper = mount(DbConsoleTree, {
    props: {
      databases: DATABASES,
      currentDatabase: 'app',
      fetchChildren,
      ...props,
    },
    global: { plugins: [ElementPlus] },
    attachTo: document.body,
  })
  return { wrapper, fetchChildren }
}

describe('DbConsoleTree', () => {
  it('空態 A：目錄回空且資產無允許清單', () => {
    const { wrapper } = mountTree({ databases: [] })
    expect(wrapper.text()).toContain(t('dbConsole.tree.emptyCatalogTitle'))
    expect(wrapper.text()).toContain(t('dbConsole.tree.emptyCatalogHint'))
  })

  it('空態 B：資產設了允許清單卻與目標端無交集', () => {
    const { wrapper } = mountTree({ databases: [], allowedDatabases: ['payments'] })
    expect(wrapper.text()).toContain(t('dbConsole.tree.emptyAllowListTitle'))
    expect(wrapper.text()).toContain(t('dbConsole.tree.emptyAllowListHint'))
  })

  it('不可連線的節點標鎖定圖示並附說明，切換鈕停用', async () => {
    const { wrapper } = mountTree()
    await flushPromises()

    const tips = wrapper.findAllComponents({ name: 'ElTooltip' })
    expect(tips.length).toBe(1)
    expect(tips[0].props('content')).toBe(t('dbConsole.tree.unconnectableTip'))

    const offline = wrapper
      .findAll('.tree-node')
      .find((n) => n.text().includes('offline_db'))
    expect(offline.find('button').attributes('disabled')).toBeDefined()
  })

  it('非當前庫才有切換鈕，點擊發出切換事件', async () => {
    const { wrapper } = mountTree()
    await flushPromises()

    const nodes = wrapper.findAll('.tree-node')
    const current = nodes.find((n) => n.text().includes('app'))
    expect(current.find('button').exists()).toBe(false)

    const reporting = nodes.find((n) => n.text().includes('reporting'))
    await reporting.find('button').trigger('click')
    expect(wrapper.emitted('switch')).toEqual([['reporting']])
  })

  it('樹頂篩選只過濾已載入節點，不發任何請求', async () => {
    const { wrapper, fetchChildren } = mountTree()
    await flushPromises()
    fetchChildren.mockClear()

    await wrapper.find('.tree-toolbar input').setValue('report')
    await flushPromises()

    expect(fetchChildren).not.toHaveBeenCalled()
    const visible = wrapper
      .findAll('.el-tree-node')
      .filter((n) => n.element.style.display !== 'none')
      .map((n) => n.text())
    expect(visible.join('|')).toContain('reporting')
    expect(visible.join('|')).not.toContain('offline_db')
  })

  it('展開當前庫載入表，再展開表載入欄位', async () => {
    const fetchChildren = vi.fn(async ({ level }) => {
      if (level === 'tables') {
        return { tables: [{ schema: 'public', name: 'orders', kind: 'table' }] }
      }
      return { columns: [{ name: 'id', type_name: 'int8', nullable: false }] }
    })
    const { wrapper } = mountTree({ fetchChildren })
    await flushPromises()

    // 以節點自身的 content 選取：`.el-tree-node` 含子樹，父節點的文字會涵蓋子節點
    const current = wrapper
      .findAll('.el-tree-node__content')
      .find((n) => n.text().includes('app'))
    await current.find('.el-tree-node__expand-icon').trigger('click')
    await flushPromises()
    expect(fetchChildren).toHaveBeenCalledWith({ level: 'tables' })
    expect(wrapper.text()).toContain('public.orders')

    const table = wrapper
      .findAll('.el-tree-node__content')
      .find((n) => n.text().includes('public.orders'))
    await table.find('.el-tree-node__expand-icon').trigger('click')
    await flushPromises()
    expect(fetchChildren).toHaveBeenCalledWith({
      level: 'columns',
      schema: 'public',
      table: 'orders',
    })
    expect(wrapper.text()).toContain('int8')
  })

  it('表節點不重複資料庫名，長名以 title 給出完整限定名', async () => {
    // MySQL 的 schema 就是資料庫名，父節點已經是它
    const longName = 'transaction_settlement_reconciliation_daily_snapshot_2026'
    const fetchChildren = vi.fn(async ({ level }) => {
      if (level === 'tables') {
        return { tables: [{ schema: 'app', name: longName, kind: 'table' }] }
      }
      return { columns: [{ name: 'id', type_name: 'bigint', nullable: false }] }
    })
    const { wrapper } = mountTree({ fetchChildren })
    await flushPromises()

    const current = wrapper
      .findAll('.el-tree-node__content')
      .find((n) => n.text().includes('app'))
    await current.find('.el-tree-node__expand-icon').trigger('click')
    await flushPromises()

    const label = wrapper
      .findAll('.node-label')
      .find((n) => n.text().includes(longName))
    expect(label.text()).toBe(longName)
    expect(label.text()).not.toContain('app.')
    expect(label.attributes('title')).toBe(`app.${longName}`)
  })

  it('schema 與資料庫不同名時保留 schema 段，title 為三段全名', async () => {
    const fetchChildren = vi.fn(async ({ level }) => {
      if (level === 'tables') {
        return { tables: [{ schema: 'public', name: 'orders', kind: 'table' }] }
      }
      return { columns: [{ name: 'id', type_name: 'int8', nullable: false }] }
    })
    const { wrapper } = mountTree({ fetchChildren })
    await flushPromises()

    const current = wrapper
      .findAll('.el-tree-node__content')
      .find((n) => n.text().includes('app'))
    await current.find('.el-tree-node__expand-icon').trigger('click')
    await flushPromises()

    const table = wrapper
      .findAll('.node-label')
      .find((n) => n.text() === 'public.orders')
    expect(table.attributes('title')).toBe('app.public.orders')

    const tableNode = wrapper
      .findAll('.el-tree-node__content')
      .find((n) => n.text().includes('public.orders'))
    await tableNode.find('.el-tree-node__expand-icon').trigger('click')
    await flushPromises()

    const column = wrapper.findAll('.node-label').find((n) => n.text() === 'id')
    expect(column.attributes('title')).toBe('app.public.orders.id')
  })

  it('節點截斷提示帶出上限數字；重新整理發出事件', async () => {
    const { wrapper } = mountTree({ truncated: true, nodeLimit: 2000 })
    expect(wrapper.find('.tree-truncated').text()).toContain('2000')

    await wrapper.find('.tree-toolbar button').trigger('click')
    expect(wrapper.emitted('refresh')).toHaveLength(1)
  })
})
