import { describe, it, expect, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, enableAutoUnmount } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

// el-table 的 key-render-helper 會在 happy-dom 上以 MutationObserver 觀察節點而爆錯，
// 全庫慣例是以結構等價的 stub 取代（同 Assets.spec.js）
const STUB_ROWS = Symbol('stubTableRows')

const tableStub = {
  name: 'ElTable',
  // 型別要宣告：布林屬性以裸屬性寫入時值為空字串，未宣告型別就不會被轉成 true
  props: {
    data: Array,
    stripe: Boolean,
    showOverflowTooltip: Boolean,
    scrollbarAlwaysOn: Boolean,
  },
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
  },
  template: `<div class="table-stub"><slot /></div>`,
}

const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label', 'prop', 'minWidth'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    rows() {
      const injected = this.stubRows
      if (!injected) return []
      return Array.isArray(injected) ? injected : injected.value || []
    },
  },
  template: `<div class="col-stub">
    <span class="col-label"><slot name="header" :column="{ label }">{{ label }}</slot></span>
    <div v-for="(row, i) in rows" :key="i" class="cell-stub">
      <slot :row="row" :column="{}" :$index="i" />
    </div>
  </div>`,
}

import DbConsoleResults from '../DbConsole/DbConsoleResults.vue'
import { t } from '@/i18n'

const RouterLinkStub = {
  name: 'RouterLink',
  props: ['to'],
  template: '<a class="router-link"><slot /></a>',
}

const makeSet = (rowCount, setIndex = 0) => ({
  set_index: setIndex,
  columns: [
    { name: 'id', type_name: 'int8', kind: 'integer' },
    { name: 'note', type_name: 'text', kind: 'text' },
  ],
  rows: Array.from({ length: rowCount }, (_, i) => [String(i), i === 0 ? null : `n${i}`]),
  row_count: rowCount,
  truncated: false,
})

const makeUnit = (over = {}) => ({
  eventId: 'EV1',
  seq: 1,
  sql: 'SELECT 1',
  submission: 1,
  status: 'ok',
  reason: '',
  sets: [makeSet(3)],
  rowsAffected: 0,
  durationMs: 8,
  truncated: false,
  txState: 'none',
  dbError: null,
  resultUnknown: false,
  ...over,
})

const mountResults = (props = {}) =>
  mount(DbConsoleResults, {
    props: {
      units: [makeUnit()],
      selection: { eventId: 'EV1', setIndex: 0 },
      limits: { rows_per_unit: 1000 },
      ...props,
    },
    global: {
      plugins: [ElementPlus],
      stubs: {
        RouterLink: RouterLinkStub,
        ElTable: tableStub,
        ElTableColumn: tableColumnStub,
      },
    },
    attachTo: document.body,
  })

describe('DbConsoleResults', () => {
  it('尚未執行時走共用空狀態並給下一步指引', () => {
    const wrapper = mountResults({ units: [], selection: { eventId: '', setIndex: 0 } })
    expect(wrapper.text()).toContain(t('dbConsole.results.emptyTitle'))
    expect(wrapper.text()).toContain(t('dbConsole.results.emptyHint'))
  })

  it('零列態走空狀態而非空白表格', () => {
    const unit = makeUnit({ sets: [{ ...makeSet(0), columns: [] }] })
    const wrapper = mountResults({ units: [unit] })
    expect(wrapper.text()).toContain(t('dbConsole.results.noRowsTitle'))
  })

  it('狀態列含狀態、耗時與可複製的事件識別', () => {
    const wrapper = mountResults()
    const status = wrapper.find('.unit-status').text()
    expect(status).toContain(t('enum.resultStatus.ok'))
    expect(status).toContain('EV1')
    expect(status).toContain(t('dbConsole.results.copyEventId'))
  })

  it('分頁列常駐且以 .pagination 收容', async () => {
    const wrapper = mountResults({ units: [makeUnit({ sets: [makeSet(120)] })] })
    expect(wrapper.find('.pagination').exists()).toBe(true)
    const pagination = wrapper.findComponent({ name: 'ElPagination' })
    expect(pagination.props('total')).toBe(120)
    expect(pagination.props('layout')).toBe('total, sizes, prev, pager, next, jumper')
  })

  it('NULL 與空字串分開呈現；表格沿用條紋與溢位提示慣例', () => {
    const wrapper = mountResults()
    expect(wrapper.find('.cell-null').exists()).toBe(true)
    expect(wrapper.find('.cell-null').text()).toBe('NULL')
    const table = wrapper.findComponent({ name: 'ElTable' })
    expect(table.props('stripe')).toBe(true)
    expect(table.props('showOverflowTooltip')).toBe(true)
  })

  // 欄數多時全部欄擠進一個視寬，每欄只剩幾個字元、長欄名折行成兩三列，
  // 而末幾欄根本無從抵達——寬度要有下限、溢位要由常駐橫向捲軸承接
  it('欄數多時每欄保有最小寬度，溢位交給常駐橫向捲軸，欄名全文走 title', () => {
    const columns = Array.from({ length: 30 }, (_, i) => ({
      name: `CHARACTER_MAXIMUM_LENGTH_${i}`,
      type_name: 'text',
      kind: 'text',
    }))
    const wideSet = {
      set_index: 0,
      columns,
      rows: [columns.map((_, i) => `v${i}`)],
      row_count: 1,
      truncated: false,
    }
    const wrapper = mountResults({ units: [makeUnit({ sets: [wideSet] })] })

    const cols = wrapper.findAllComponents({ name: 'ElTableColumn' })
    expect(cols).toHaveLength(30)
    cols.forEach((col) => {
      expect(Number(col.props('minWidth'))).toBeGreaterThanOrEqual(140)
    })

    const table = wrapper.findComponent({ name: 'ElTable' })
    expect(table.props('scrollbarAlwaysOn')).toBe(true)
    // 表格的捲動區由它自己承接：外層若另設 overflow 就會把捲軸與末欄一起藏掉
    expect(wrapper.find('.table-wrap').exists()).toBe(true)

    const names = wrapper.findAll('.column-name')
    expect(names).toHaveLength(30)
    expect(names[29].attributes('title')).toBe('CHARACTER_MAXIMUM_LENGTH_29')
    expect(names[29].text()).toBe('CHARACTER_MAXIMUM_LENGTH_29')
  })

  it('截斷橫幅說明那是回傳上限並給出可照做的縮小範圍指引', () => {
    const wrapper = mountResults({
      units: [makeUnit({ truncated: true, reason: 'cell_truncated' })],
    })
    const text = wrapper.text()
    expect(text).toContain('1000')
    expect(text).toContain('LIMIT')
    expect(text).toContain('OFFSET')
    expect(text).toContain(t('dbConsole.results.cellTruncatedHint'))
  })

  it('部分生效以警示呈現，不標成成功或失敗', () => {
    const wrapper = mountResults({
      units: [makeUnit({ status: 'partial', reason: 'error_after_results' })],
    })
    expect(wrapper.text()).toContain(t('dbConsole.results.alert.partial'))
    expect(wrapper.text()).toContain(t('enum.resultReason.error_after_results'))
    const tag = wrapper.findComponent({ name: 'ElTag' })
    expect(tag.props('type')).toBe('warning')
  })

  it('結果未知橫幅附事件識別與稽核紀錄連結（有稽核權限時）', () => {
    const wrapper = mountResults({
      units: [makeUnit({ status: 'running', resultUnknown: true })],
      auditLinkTo: { name: 'SessionDetail', params: { id: '91' }, hash: '#cmd-EV1' },
    })
    expect(wrapper.text()).toContain(t('dbConsole.results.unknownTitle'))
    expect(wrapper.text()).toContain(t('dbConsole.results.unknownHint'))
    const link = wrapper.findComponent(RouterLinkStub)
    expect(link.props('to')).toEqual({
      name: 'SessionDetail',
      params: { id: '91' },
      hash: '#cmd-EV1',
    })
    // 結果未知的單位不得顯示為「進行中」
    expect(wrapper.find('.unit-status').text()).toContain(
      t('enum.resultStatus.effect_unknown')
    )
  })

  it('無稽核權限時不給連結，仍以事件識別轉交', () => {
    const wrapper = mountResults({
      units: [makeUnit({ status: 'running', resultUnknown: true })],
      auditLinkTo: null,
    })
    expect(wrapper.findComponent(RouterLinkStub).exists()).toBe(false)
    expect(wrapper.text()).toContain('EV1')
  })

  // 失敗與進行中的單位都沒有結果集，但「請確認查詢條件」是在說語句跑成功了、
  // 只是沒命中——那是與事實相反的一句話
  it('失敗與進行中不得沿用零列態文案；失敗指回錯誤原文的所在', () => {
    const failed = mountResults({
      units: [makeUnit({ status: 'error', sets: [], rowsAffected: -1 })],
    })
    expect(failed.text()).not.toContain(t('dbConsole.results.noRowsHint'))
    expect(failed.text()).toContain(t('dbConsole.results.failedTitle'))
    expect(failed.text()).toContain(t('dbConsole.results.failedHint'))
    // 驅動程式對查詢類語句回的 -1 不是列數，不得直出
    expect(failed.find('.unit-status').text()).not.toContain('-1')

    const running = mountResults({ units: [makeUnit({ status: 'running', sets: [] })] })
    expect(running.text()).not.toContain(t('dbConsole.results.noRowsHint'))
    expect(running.text()).toContain(t('dbConsole.results.runningTitle'))
  })

  // 重連自報的佔位列沒有伺服端序號：0 不是它的序號
  it('無伺服端序號的未收束單位不冒充「第 0 筆」', () => {
    const wrapper = mountResults({
      units: [makeUnit({ seq: 0, status: 'running', resultUnknown: true, sets: [] })],
    })
    const label = wrapper.find('.unit-label').text()
    expect(label).toContain(t('dbConsole.results.unitLabelPending'))
    expect(label).not.toContain(t('dbConsole.results.unitLabel', { seq: 0 }))
  })

  it('多結果集以分頁切換並回報目前檢視的定址', async () => {
    const unit = makeUnit({ sets: [makeSet(2, 0), makeSet(2, 1)] })
    const wrapper = mountResults({ units: [unit] })
    const setTabs = wrapper.find('.set-tabs')
    expect(setTabs.exists()).toBe(true)

    await wrapper.findComponent({ name: 'ElTabs' }).vm.$emit('update:modelValue', 'EV1')
    expect(wrapper.emitted('update:selection').at(-1)).toEqual([
      { eventId: 'EV1', setIndex: 0 },
    ])
  })
})
