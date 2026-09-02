import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { computed } from 'vue'
import { mount, enableAutoUnmount, flushPromises } from '@vue/test-utils'
import ElementPlus from 'element-plus'

enableAutoUnmount(afterEach)

const tokenMock = vi.fn().mockResolvedValue({ connect_token: 'ct-console' })
vi.mock('@/api/connect', () => ({
  createConnectTokenWithConsent: (...args) => tokenMock(...args),
}))

const downloadCsvMock = vi.fn()
const capabilityMock = vi.fn()
vi.mock('@/api/dbConsole', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    downloadResultCsv: (...args) => downloadCsvMock(...args),
    fetchExportCapability: (...args) => capabilityMock(...args),
  }
})

const downloadBlobMock = vi.fn()
vi.mock('@/utils/download', () => ({
  downloadBlob: (...args) => downloadBlobMock(...args),
  timestampSuffix: () => '20260902-000000',
}))

const confirmMock = vi.fn()
vi.mock('element-plus', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    ElMessageBox: { ...actual.ElMessageBox, confirm: (...args) => confirmMock(...args) },
  }
})

// el-table 在 happy-dom 上以 MutationObserver 觀察節點會爆錯，沿全庫慣例改用 stub
const STUB_ROWS = Symbol('stubTableRows')
const tableStub = {
  name: 'ElTable',
  props: { data: Array },
  provide() {
    return { [STUB_ROWS]: computed(() => this.data || []) }
  },
  template: '<div class="table-stub"><slot /></div>',
}
const tableColumnStub = {
  name: 'ElTableColumn',
  props: ['label'],
  template: '<div class="col-stub">{{ label }}</div>',
}

class WebSocketMock {
  static instances = []
  static OPEN = 1

  constructor(url) {
    this.url = url
    this.readyState = WebSocketMock.OPEN
    this.sent = []
    WebSocketMock.instances.push(this)
  }

  send(payload) {
    this.sent.push(JSON.parse(payload))
  }

  close() {}

  receive(msg) {
    this.onmessage?.({ data: JSON.stringify(msg) })
  }
}

import DbConsole from '../DbConsole/DbConsole.vue'
import { t } from '@/i18n'

const READY = {
  type: 'ready',
  session_id: 91,
  dialect: 'postgres',
  database: 'app',
  database_allowed: true,
  databases: [
    { name: 'app', connectable: true },
    { name: 'sales', connectable: true },
  ],
  capabilities: { file_download: true },
  tx_state: 'none',
  limits: { rows_per_unit: 1000, tree_nodes_per_level: 2000 },
}

const RESULT = {
  type: 'result',
  event_id: 'EV1',
  seq: 1,
  status: 'ok',
  sets: [
    {
      set_index: 0,
      columns: [{ name: 'id', type_name: 'int8', kind: 'integer' }],
      rows: [['1']],
      row_count: 1,
      truncated: false,
    },
  ],
  rows_affected: 0,
  duration_ms: 5,
  truncated: false,
  tx_state: 'none',
}

const mountConsole = (props = {}) =>
  mount(DbConsole, {
    props: { assetId: 7, assetName: 'prod-pg', ...props },
    global: {
      plugins: [ElementPlus],
      stubs: {
        RouterLink: { props: ['to'], template: '<a><slot /></a>' },
        ElTable: tableStub,
        ElTableColumn: tableColumnStub,
      },
    },
    attachTo: document.body,
  })

// 掛載後完成握手，回傳 wrapper 與 socket
const ready = async (props = {}, readyMsg = READY) => {
  const wrapper = mountConsole(props)
  await flushPromises()
  const ws = WebSocketMock.instances.at(-1)
  ws.onopen?.()
  ws.receive(readyMsg)
  await flushPromises()
  return { wrapper, ws }
}

// 走完整送出路徑（編輯器 → sendQuery → unit_started → result），
// 送出批號才會遞增——匯出的「最近一次送出」判準靠的就是它
const runUnit = async (wrapper, ws, eventId, seq) => {
  wrapper.findComponent({ name: 'DbConsoleEditor' }).vm.$emit('execute', `SELECT ${seq}`)
  await flushPromises()
  ws.receive({
    type: 'unit_started',
    event_id: eventId,
    seq,
    batch_index: 0,
    batch_count: 1,
  })
  ws.receive({ ...RESULT, event_id: eventId, seq })
  await flushPromises()
}

describe('DbConsole', () => {
  beforeEach(() => {
    vi.stubGlobal('WebSocket', WebSocketMock)
    WebSocketMock.instances = []
    tokenMock.mockClear().mockResolvedValue({ connect_token: 'ct-console' })
    downloadCsvMock.mockClear().mockResolvedValue(new Blob(['a,b']))
    capabilityMock.mockClear().mockResolvedValue(true)
    downloadBlobMock.mockClear()
    confirmMock.mockClear().mockResolvedValue(true)
    localStorage.setItem('user', JSON.stringify({ id: 1, roles: ['auditor'] }))
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    localStorage.removeItem('user')
  })

  it('連線就緒後三欄齊備，狀態外發為分頁詞彙', async () => {
    const { wrapper } = await ready()
    expect(wrapper.find('.pane-tree').exists()).toBe(true)
    expect(wrapper.find('.pane-editor').exists()).toBe(true)
    expect(wrapper.find('.pane-results').exists()).toBe(true)
    expect(wrapper.emitted('status-change').at(-1)).toEqual(['connected'])
    expect(wrapper.emitted('session-id').at(-1)).toEqual([91])
  })

  it('匯出停用態一：目前沒有結果', async () => {
    const { wrapper } = await ready()
    expect(exportTooltip(wrapper)).toBe(t('dbConsole.exportDisabled.noResult'))
    expect(wrapper.find('.export-wrap button').attributes('disabled')).toBeDefined()
  })

  it('匯出停用態二：非最近一次送出的結果分頁', async () => {
    const { wrapper, ws } = await ready()
    await runUnit(wrapper, ws, 'EV1', 1)
    await runUnit(wrapper, ws, 'EV2', 2)
    expect(wrapper.find('.export-wrap button').attributes('disabled')).toBeUndefined()

    // 切回上一次送出的結果：伺服端快取只留最近一次，故不發請求而先停用
    wrapper.findComponent({ name: 'DbConsoleResults' }).vm.$emit('update:selection', {
      eventId: 'EV1',
      setIndex: 0,
    })
    await flushPromises()
    expect(wrapper.find('.export-wrap button').attributes('disabled')).toBeDefined()
    expect(exportTooltip(wrapper)).toBe(t('dbConsole.exportDisabled.notLatest'))
    expect(downloadCsvMock).not.toHaveBeenCalled()
  })

  it('匯出停用態三：連線已結束', async () => {
    const { wrapper, ws } = await ready()
    await runUnit(wrapper, ws, 'EV1', 1)
    expect(wrapper.find('.export-wrap button').attributes('disabled')).toBeUndefined()

    ws.receive({ type: 'closed', reason: 'idle_timeout' })
    await flushPromises()
    expect(wrapper.find('.export-wrap button').attributes('disabled')).toBeDefined()
    expect(exportTooltip(wrapper)).toBe(t('dbConsole.exportDisabled.sessionEnded'))
    expect(wrapper.emitted('status-change').at(-1)).toEqual(['closed'])
  })

  it('傳輸政策停用匯出時鈕不可按，且不發任何匯出請求', async () => {
    const { wrapper, ws } = await ready({}, {
      ...READY,
      capabilities: { file_download: false },
    })
    await runUnit(wrapper, ws, 'EV1', 1)
    expect(exportTooltip(wrapper)).toBe(t('dbConsole.exportDisabled.policy'))
    await wrapper.find('.export-wrap button').trigger('click')
    expect(downloadCsvMock).not.toHaveBeenCalled()
  })

  it('匯出以 (event_id, set_index) 定址並交給另存', async () => {
    const { wrapper, ws } = await ready()
    await runUnit(wrapper, ws, 'EV1', 1)
    await wrapper.find('.export-wrap button').trigger('click')
    await flushPromises()
    expect(downloadCsvMock).toHaveBeenCalledWith(91, 'EV1', 0)
    expect(downloadBlobMock).toHaveBeenCalled()
  })

  it('視窗重獲焦點時重抓能力投影，false→true 即解除停用', async () => {
    const { wrapper, ws } = await ready({}, {
      ...READY,
      capabilities: { file_download: false },
    })
    await runUnit(wrapper, ws, 'EV1', 1)
    expect(wrapper.find('.export-wrap button').attributes('disabled')).toBeDefined()

    capabilityMock.mockResolvedValueOnce(true)
    document.dispatchEvent(new Event('visibilitychange'))
    await flushPromises()
    expect(capabilityMock).toHaveBeenCalledWith(7)
    expect(wrapper.find('.export-wrap button').attributes('disabled')).toBeUndefined()
  })

  it('PostgreSQL 切庫先確認再送出；取消則不送', async () => {
    const { wrapper, ws } = await ready()
    confirmMock.mockRejectedValueOnce(new Error('cancel'))
    await wrapper.findComponent({ name: 'DbConsoleTree' }).vm.$emit('switch', 'sales')
    await flushPromises()
    expect(ws.sent.some((m) => m.type === 'switch')).toBe(false)

    confirmMock.mockResolvedValueOnce(true)
    await wrapper.findComponent({ name: 'DbConsoleTree' }).vm.$emit('switch', 'sales')
    await flushPromises()
    expect(confirmMock).toHaveBeenCalledTimes(2)
    expect(ws.sent.at(-1)).toEqual({ type: 'switch', database: 'sales' })
  })

  it('目標受限：下拉呈錯誤態、常駐提示、編輯器停用', async () => {
    const { wrapper, ws } = await ready()
    ws.receive({
      type: 'notice',
      code: 'database_drift_denied',
      params: { database: 'mysql', previous: 'app' },
    })
    await flushPromises()

    expect(wrapper.find('.database-select').classes()).toContain('is-restricted')
    expect(wrapper.text()).toContain(t('dbConsole.restricted.database_drift_denied'))
    expect(wrapper.text()).toContain(t('dbConsole.restrictedHint'))
    expect(wrapper.findComponent({ name: 'DbConsoleEditor' }).props('disabled')).toBe(true)
  })

  it('交易失敗態常駐橫幅並指引 ROLLBACK；進行中只給小標', async () => {
    const { wrapper, ws } = await ready()
    ws.receive({ ...RESULT, tx_state: 'active' })
    await flushPromises()
    expect(wrapper.find('.tx-badge').text()).toBe(t('dbConsole.tx.active'))

    ws.receive({ ...RESULT, event_id: 'EV2', tx_state: 'failed' })
    await flushPromises()
    expect(wrapper.text()).toContain(t('dbConsole.tx.failed'))
    expect(wrapper.text()).toContain('ROLLBACK')
  })

  it('重送與未收束單位位元組相同的原文前先確認', async () => {
    const { wrapper, ws } = await ready()
    const editor = wrapper.findComponent({ name: 'DbConsoleEditor' })
    editor.vm.$emit('execute', 'UPDATE t SET a=1')
    await flushPromises()
    ws.receive({
      type: 'unit_started',
      event_id: 'EV9',
      seq: 1,
      batch_index: 0,
      batch_count: 1,
    })
    await flushPromises()
    expect(confirmMock).not.toHaveBeenCalled()

    // 送出後斷線：該單位結果未知，原文與識別都保留給下一場
    ws.receive({ type: 'closed', reason: 'target_closed' })
    await flushPromises()
    expect(wrapper.emitted('pending-change').at(-1)[0]).toEqual({
      eventId: 'EV9',
      sql: 'UPDATE t SET a=1',
    })
    expect(wrapper.emitted('unsettled-change').at(-1)).toEqual([true])

    // 重連後送出位元組相同的原文：先出確認框，取消即不送
    await wrapper.find('.status-overlay button').trigger('click')
    await flushPromises()
    const ws2 = WebSocketMock.instances.at(-1)
    ws2.onopen?.()
    ws2.receive(READY)
    await flushPromises()

    confirmMock.mockRejectedValueOnce(new Error('cancel'))
    editor.vm.$emit('execute', 'UPDATE t SET a=1')
    await flushPromises()
    expect(confirmMock).toHaveBeenCalledTimes(1)
    expect(ws2.sent.some((m) => m.type === 'query')).toBe(false)

    // 確認後才送出
    editor.vm.$emit('execute', 'UPDATE t SET a=1')
    await flushPromises()
    expect(ws2.sent.at(-1)).toEqual({ type: 'query', sql: 'UPDATE t SET a=1' })
  })

  it('斷線後可頁內重連：以新票新會話，編輯器文字保留', async () => {
    const { wrapper, ws } = await ready()
    wrapper.findComponent({ name: 'DbConsoleEditor' }).vm.$emit('update:modelValue', 'SELECT 1')
    await flushPromises()
    ws.receive({ type: 'closed', reason: 'idle_timeout' })
    await flushPromises()

    expect(wrapper.text()).toContain(t('dbConsole.closed.idle_timeout'))
    await wrapper.find('.status-overlay button').trigger('click')
    await flushPromises()
    expect(tokenMock).toHaveBeenCalledTimes(2)
    expect(WebSocketMock.instances).toHaveLength(2)
    expect(wrapper.findComponent({ name: 'DbConsoleEditor' }).props('modelValue')).toBe(
      'SELECT 1'
    )
  })

  it('使用前說明面板列出連線者版五條', async () => {
    const { wrapper } = await ready()
    expect(wrapper.text()).toContain(t('dbConsole.boundary.title'))
    const items = wrapper.findAll('.console-boundary .boundary-list li')
    expect(items).toHaveLength(5)
    expect(items[0].text()).toBe(t('dbConsole.boundary.item1'))
    expect(items[4].text()).toBe(t('dbConsole.boundary.item5'))
    // 稽核與管理視角的邊界（阻斷為文字比對、畫面可複製、驅動程式保留材料）
    // 不呈現給連線者，只列於文件與管理者可見面
    const panelText = wrapper.find('.console-boundary').text()
    expect(panelText).not.toContain('開發者工具')
    expect(panelText).not.toContain('文字比對')
    expect(panelText).not.toContain('認證材料')
  })

  it('匯出鈕提示揭露公式注入轉義', async () => {
    const { wrapper, ws } = await ready()
    await runUnit(wrapper, ws, 'EV1', 1)
    expect(exportTooltip(wrapper)).toContain(t('dbConsole.exportEscapeNote'))
  })

  it('重連成功後明示為新會話，提示可關閉', async () => {
    const { wrapper, ws } = await ready()
    await runUnit(wrapper, ws, 'EV1', 1)
    expect(wrapper.text()).not.toContain(t('dbConsole.reconnectedTitle'))

    ws.receive({ type: 'closed', reason: 'idle_timeout' })
    await flushPromises()
    // 斷線當下還不算重連成功：新會話未建立前不得出現提示
    await wrapper.find('.status-overlay button').trigger('click')
    await flushPromises()
    expect(wrapper.text()).not.toContain(t('dbConsole.reconnectedTitle'))

    const ws2 = WebSocketMock.instances.at(-1)
    ws2.onopen?.()
    ws2.receive(READY)
    await flushPromises()
    expect(wrapper.text()).toContain(t('dbConsole.reconnectedTitle'))
    expect(wrapper.text()).toContain(t('dbConsole.reconnectedHint'))
    // 明示的對象就是這件事：結果區已清空
    expect(wrapper.findComponent({ name: 'DbConsoleResults' }).props('units')).toEqual([])

    // 可關閉：關閉鈕在，且關閉事件確實把提示收掉
    // （EP 的關閉走延時計時器，此處只測本元件的接線，不測 EP 內部）
    expect(wrapper.find('.session-notice .el-alert__close-btn').exists()).toBe(true)
    wrapper
      .findAllComponents({ name: 'ElAlert' })
      .find((c) => c.props('title') === t('dbConsole.reconnectedTitle'))
      .vm.$emit('close')
    await flushPromises()
    expect(wrapper.text()).not.toContain(t('dbConsole.reconnectedTitle'))
  })

  it('簽發被拒即進錯誤態，不建立連線', async () => {
    tokenMock.mockRejectedValueOnce({
      response: { status: 403, data: { code: 'RULE_ACCESS_DENIED', error: '沒有連線授權' } },
    })
    const wrapper = mountConsole()
    await flushPromises()
    expect(WebSocketMock.instances).toHaveLength(0)
    expect(wrapper.emitted('status-change').at(-1)).toEqual(['error'])
    expect(wrapper.text()).toContain('沒有連線授權')
  })
})

// 匯出鈕的 tooltip：以就近的 tooltip 元件讀 content，避免依賴 teleport 後的 DOM
function exportTooltip(wrapper) {
  const tip = wrapper
    .findAllComponents({ name: 'ElTooltip' })
    .find((c) => c.find('.export-wrap').exists())
  return tip?.props('content')
}
