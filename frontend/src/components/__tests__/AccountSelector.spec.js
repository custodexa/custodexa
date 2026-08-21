// 連線選帳號（asset-multi-account D2）：預選預設帳號、privileged 明示、確認即帶回帳號。
// 清單由呼叫端（Workspace）傳入——後端已依有效授權帳號範圍過濾，元件不再自行判定可見性。
import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises, enableAutoUnmount } from '@vue/test-utils'
import { computed } from 'vue'
import ElementPlus from 'element-plus'
import AccountSelector from '../AccountSelector.vue'

// 逐測卸載：本檔掛載元件後不卸載，殘留元件在 document 上累積使單測耗時隨測試序
// 上升，全量並行時末幾格逼近逾時上限而間歇轉紅。治法同 fca615b（Assets／
// AuditLogs／Users／MainLayout）：enableAutoUnmount(afterEach)。
enableAutoUnmount(afterEach)

class MutationObserverStub {
  observe() {}
  disconnect() {}
  takeRecords() {
    return []
  }
}
vi.stubGlobal('MutationObserver', MutationObserverStub)

const STUB_ROWS = Symbol('stubTableRows')

const tableStub = {
  name: 'ElTable',
  props: ['data'],
  // 記錄 setCurrentRow：預選是否套到表格選取態（UI 走查 F1）只能由此驗證
  data() {
    return { currentRow: null }
  },
  methods: {
    setCurrentRow(row) {
      this.currentRow = row
    },
  },
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
  },
  template: `<div class="table-stub">
    <slot />
    <div v-if="!(data || []).length" class="table-empty-stub"><slot name="empty" /></div>
  </div>`,
}

const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label', 'prop'],
  inject: { stubRows: { from: STUB_ROWS, default: null } },
  computed: {
    rows() {
      const injected = this.stubRows
      if (!injected) return []
      return Array.isArray(injected) ? injected : injected.value || []
    },
  },
  template: `<div class="col-stub">
    <span class="col-label">{{ label }}</span>
    <div v-for="(row, i) in rows" :key="i" class="cell-stub">
      <slot :row="row" :$index="i">{{ prop ? row[prop] : '' }}</slot>
    </div>
  </div>`,
}

const dialogStub = {
  props: ['modelValue'],
  emits: ['open'],
  mounted() {
    if (this.modelValue) this.$emit('open')
  },
  template: '<div v-if="modelValue" class="dialog-stub"><slot /><slot name="footer" /></div>',
}

const accounts = [
  { id: 1, username: 'app', is_default: false, privileged: false, has_password: true, note: '應用帳號' },
  { id: 2, username: 'root', is_default: true, privileged: true, has_private_key: true, note: '' },
]

const mountSelector = (props = {}) =>
  mount(AccountSelector, {
    props: { modelValue: true, assetName: 'web-01', accounts, ...props },
    global: {
      plugins: [ElementPlus],
      stubs: { 'el-dialog': dialogStub, ElTable: tableStub, ElTableColumn: tableColumnStub },
    },
  })

describe('AccountSelector 連線選帳號', () => {
  it('開啟時預選預設帳號（非首筆亦然）', async () => {
    const wrapper = mountSelector()
    await flushPromises()
    expect(wrapper.vm.selected.username).toBe('root')
  })

  it('無預設帳號時退回首筆', async () => {
    const wrapper = mountSelector({
      accounts: [
        { id: 5, username: 'a', is_default: false },
        { id: 6, username: 'b', is_default: false },
      ],
    })
    await flushPromises()
    expect(wrapper.vm.selected.id).toBe(5)
  })

  it('privileged 標記只掛在特權帳號那一列（非全表都顯示）', async () => {
    const wrapper = mountSelector()
    await flushPromises()

    // 每列一個 cell-stub：root 為 privileged、app 不是
    const rows = wrapper.findAll('.col-stub')[0].findAll('.cell-stub')
    const appRow = rows.find((r) => r.text().includes('app'))
    const rootRow = rows.find((r) => r.text().includes('root'))
    expect(appRow.text()).not.toContain('特權')
    expect(rootRow.text()).toContain('特權')

    // 憑證型別逐列導出，不是同一個常數
    const credCells = wrapper.findAll('.col-stub')[1].findAll('.cell-stub')
    expect(credCells.map((c) => c.text())).toEqual(['密碼', '私鑰'])
  })

  it('預選同時套用 current-row（只設 selected 會讓表格看起來沒選中）', async () => {
    const wrapper = mountSelector()
    await flushPromises()

    const table = wrapper.findComponent({ name: 'ElTable' })
    expect(table.vm.currentRow).toEqual(accounts[1])
  })

  it('確認帶回 id 與 username 並關閉對話框', async () => {
    const wrapper = mountSelector()
    await flushPromises()
    wrapper.vm.onSelect(accounts[0])
    wrapper.vm.confirm()
    await flushPromises()

    expect(wrapper.emitted('confirm')[0][0]).toEqual({ id: 1, username: 'app' })
    expect(wrapper.emitted('update:modelValue')[0]).toEqual([false])
  })

  it('雙擊該列＝直接以該帳號連線', async () => {
    const wrapper = mountSelector()
    await flushPromises()
    wrapper.vm.onRowDblClick(accounts[0])
    await flushPromises()
    expect(wrapper.emitted('confirm')[0][0]).toEqual({ id: 1, username: 'app' })
  })

  it('current-change 傳 null 時保留既有選取（不讓連線鈕忽然變 disabled）', async () => {
    const wrapper = mountSelector()
    await flushPromises()
    wrapper.vm.onSelect(null)
    expect(wrapper.vm.selected.username).toBe('root')
  })

  it('未選帳號時 confirm 不發事件', async () => {
    const wrapper = mountSelector({ accounts: [] })
    await flushPromises()
    wrapper.vm.confirm()
    expect(wrapper.emitted('confirm')).toBeFalsy()
  })
})
