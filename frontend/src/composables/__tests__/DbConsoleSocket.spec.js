import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const tokenMock = vi.fn().mockResolvedValue({ connect_token: 'ct-console' })
vi.mock('@/api/connect', () => ({
  createConnectTokenWithConsent: (...args) => tokenMock(...args),
}))

import { useDbConsoleSocket, DB_CONSOLE_STATUS } from '../useDbConsoleSocket'

// WebSocket mock：記錄建構 URL 與送出的訊息，可手動觸發事件
class WebSocketMock {
  static instances = []
  static OPEN = 1

  constructor(url) {
    this.url = url
    this.readyState = WebSocketMock.OPEN
    this.sent = []
    this.closed = false
    WebSocketMock.instances.push(this)
  }

  send(payload) {
    this.sent.push(JSON.parse(payload))
  }

  close() {
    this.closed = true
  }

  open() {
    this.onopen?.()
  }

  receive(msg) {
    this.onmessage?.({ data: JSON.stringify(msg) })
  }
}

const READY = {
  type: 'ready',
  session_id: 91,
  dialect: 'postgres',
  database: 'app',
  database_allowed: true,
  databases: [{ name: 'app', connectable: true }],
  capabilities: { file_download: true },
  tx_state: 'none',
  limits: { rows_per_unit: 1000 },
}

// 連線並完成握手；回傳 socket 實例
const connectReady = async (console_, ready = READY) => {
  await console_.connect()
  const ws = WebSocketMock.instances.at(-1)
  ws.open()
  if (ready) ws.receive(ready)
  return ws
}

describe('useDbConsoleSocket', () => {
  beforeEach(() => {
    vi.stubGlobal('WebSocket', WebSocketMock)
    WebSocketMock.instances = []
    tokenMock.mockClear()
    tokenMock.mockResolvedValue({ connect_token: 'ct-console' })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('WS URL 只帶一次性連線票，不含 JWT、密碼或帳號欄位', async () => {
    const c = useDbConsoleSocket({ assetId: 7, accountId: 3 })
    await c.connect()

    const url = new URL(WebSocketMock.instances[0].url)
    expect(url.pathname).toBe('/api/v1/db-console')
    expect(url.searchParams.get('connect_token')).toBe('ct-console')
    expect(url.searchParams.has('token')).toBe(false)
    expect(url.searchParams.has('password')).toBe(false)
    expect(url.searchParams.has('username')).toBe(false)
    expect(url.searchParams.has('account_id')).toBe(false)
    expect(url.searchParams.has('asset_id')).toBe(false)
    // 帳號綁定封在票內：只進簽發 body，不進 WS query
    expect(tokenMock).toHaveBeenCalledWith(7, 3)
    c.dispose()
  })

  it('首則送出 hello 自報上一場會話與未收束單位', async () => {
    const c = useDbConsoleSocket({
      assetId: 7,
      previousSessionId: 12,
      pendingEventId: 'EV-PENDING',
      pendingSql: 'UPDATE t SET a=1',
    })
    await c.connect()
    const ws = WebSocketMock.instances[0]
    ws.open()

    expect(ws.sent[0]).toEqual({
      type: 'hello',
      previous_session_id: 12,
      pending_event_id: 'EV-PENDING',
    })
    // 未收束單位在 ready 之前就以「結果未知」呈現
    expect(c.units.value).toHaveLength(1)
    expect(c.units.value[0]).toMatchObject({
      eventId: 'EV-PENDING',
      resultUnknown: true,
      sql: 'UPDATE t SET a=1',
    })
    c.dispose()
  })

  it('ready 後轉 connected 並帶入方言、當前庫、能力投影與上限', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    expect(c.status.value).toBe(DB_CONSOLE_STATUS.CONNECTING)
    await connectReady(c)

    expect(c.status.value).toBe(DB_CONSOLE_STATUS.CONNECTED)
    expect(c.tabStatus.value).toBe('connected')
    expect(c.sessionId.value).toBe(91)
    expect(c.dialect.value).toBe('postgres')
    expect(c.currentDatabase.value).toBe('app')
    expect(c.exportAllowed.value).toBe(true)
    expect(c.limits.value).toEqual({ rows_per_unit: 1000 })
    c.dispose()
  })

  it('ready 帶 database_allowed=false 即進受限態；切庫成功後解除', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c, { ...READY, database_allowed: false })
    ws.receive({ type: 'notice', code: 'database_not_allowed', params: { database: 'app' } })

    expect(c.status.value).toBe(DB_CONSOLE_STATUS.RESTRICTED)
    expect(c.restrictedCode.value).toBe('database_not_allowed')
    // 受限態不標灰：會話還活著，切庫即可救回
    expect(c.tabStatus.value).toBe('connected')

    ws.receive({ type: 'notice', code: 'database_switched', params: { database: 'sales' } })
    expect(c.status.value).toBe(DB_CONSOLE_STATUS.CONNECTED)
    expect(c.currentDatabase.value).toBe('sales')
    expect(c.databaseAllowed.value).toBe(true)
    c.dispose()
  })

  it('漂移通知進受限態並更新當前庫顯示', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c)
    ws.receive({
      type: 'notice',
      code: 'database_drift_denied',
      params: { database: 'mysql', previous: 'app' },
    })
    expect(c.status.value).toBe(DB_CONSOLE_STATUS.RESTRICTED)
    expect(c.restrictedCode.value).toBe('database_drift_denied')
    expect(c.currentDatabase.value).toBe('mysql')
    c.dispose()
  })

  it('單進行中送出：unit_started 後不再送第二筆，result 收束後才放行', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c)

    expect(c.sendQuery('SELECT 1')).toBe(true)
    ws.receive({ type: 'unit_started', event_id: 'E1', seq: 1, batch_index: 0, batch_count: 1 })
    expect(c.busy.value).toBe(true)
    expect(c.sendQuery('SELECT 2')).toBe(false)

    ws.receive({
      type: 'result',
      event_id: 'E1',
      seq: 1,
      status: 'ok',
      sets: [{ set_index: 0, columns: [], rows: [], row_count: 0, truncated: false }],
      rows_affected: 0,
      duration_ms: 12,
      truncated: false,
      tx_state: 'active',
    })
    expect(c.busy.value).toBe(false)
    expect(c.txState.value).toBe('active')
    expect(c.units.value[0]).toMatchObject({ eventId: 'E1', status: 'ok', durationMs: 12 })
    expect(c.sendQuery('SELECT 2')).toBe(true)
    expect(c.submissionSeq.value).toBe(2)
    c.dispose()
  })

  it('未經 unit_started 的 result（未送出的批次）也建立單位', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c)
    ws.receive({
      type: 'result',
      event_id: 'E9',
      seq: 4,
      status: 'cancelled',
      result_reason: 'batch_stopped',
      sets: [],
    })
    expect(c.units.value).toHaveLength(1)
    expect(c.units.value[0]).toMatchObject({
      eventId: 'E9',
      status: 'cancelled',
      reason: 'batch_stopped',
    })
    c.dispose()
  })

  it('error 訊息把目標端原文原樣暴露，且不動連線狀態', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c)
    ws.receive({
      type: 'error',
      event_id: 'E2',
      code: 'RULE_DB_CONSOLE_STATEMENT_BLOCKED',
      params: { rule: 'no-drop' },
      db_error: { code: '42601', message: 'syntax error at or near "slect"' },
    })

    expect(c.status.value).toBe(DB_CONSOLE_STATUS.CONNECTED)
    expect(c.lastError.value).toMatchObject({
      eventId: 'E2',
      code: 'RULE_DB_CONSOLE_STATEMENT_BLOCKED',
      dbError: { code: '42601', message: 'syntax error at or near "slect"' },
    })
    expect(c.lastError.value.params).toEqual({ rule: 'no-drop' })
    c.dispose()
  })

  it('closed{target_closed} 轉 disconnected 並保留未收束單位的識別與原文', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c)
    c.sendQuery('UPDATE t SET a=1')
    ws.receive({ type: 'unit_started', event_id: 'E3', seq: 1, batch_index: 0, batch_count: 1 })
    ws.receive({ type: 'closed', reason: 'target_closed' })

    expect(c.status.value).toBe(DB_CONSOLE_STATUS.DISCONNECTED)
    expect(c.tabStatus.value).toBe('closed')
    expect(c.closedReason.value).toBe('target_closed')
    expect(c.pendingEventId.value).toBe('E3')
    expect(c.pendingSql.value).toBe('UPDATE t SET a=1')
    expect(c.units.value[0].resultUnknown).toBe(true)
    c.dispose()
  })

  it('重連的 ready.pending_result 把「結果未知」更新為終態', async () => {
    const c = useDbConsoleSocket({
      assetId: 7,
      previousSessionId: 12,
      pendingEventId: 'E3',
      pendingSql: 'UPDATE t SET a=1',
    })
    await connectReady(c, {
      ...READY,
      pending_result: { event_id: 'E3', status: 'ok', result_reason: '' },
    })

    expect(c.units.value[0]).toMatchObject({
      eventId: 'E3',
      status: 'ok',
      resultUnknown: false,
    })
    expect(c.pendingEventId.value).toBe('')
    c.dispose()
  })

  it('取消只對進行中的單位送出，切庫送出目錄名', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c)
    expect(c.cancel()).toBe(false)

    c.sendQuery('SELECT pg_sleep(30)')
    ws.receive({ type: 'unit_started', event_id: 'E4', seq: 1, batch_index: 0, batch_count: 1 })
    expect(c.cancel()).toBe(true)
    expect(ws.sent.at(-1)).toEqual({ type: 'cancel', event_id: 'E4' })

    expect(c.switchDatabase('app')).toBe(false) // 已是當前庫
    expect(c.switchDatabase('sales')).toBe(true)
    expect(ws.sent.at(-1)).toEqual({ type: 'switch', database: 'sales' })
    c.dispose()
  })

  it('樹請求以層級對應回應兌現，連線關閉時 reject 未兌現的請求', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c)

    const pending = c.requestTree({ level: 'tables' })
    expect(ws.sent.at(-1)).toEqual({ type: 'tree', level: 'tables', schema: '', table: '' })
    ws.receive({
      type: 'tree_result',
      level: 'tables',
      database: 'app',
      tables: [{ schema: 'public', name: 't1', kind: 'table' }],
      truncated: false,
    })
    await expect(pending).resolves.toMatchObject({ level: 'tables' })

    const orphan = c.requestTree({ level: 'columns', schema: 'public', table: 't1' })
    ws.receive({ type: 'closed', reason: 'idle_timeout' })
    await expect(orphan).rejects.toThrow('closed')
    c.dispose()
  })

  it('簽發失敗即進錯誤態，不建立 WebSocket', async () => {
    tokenMock.mockRejectedValueOnce({
      response: { status: 403, data: { code: 'RULE_ACCESS_DENIED' } },
    })
    const c = useDbConsoleSocket({ assetId: 7 })
    await c.connect()

    expect(c.status.value).toBe(DB_CONSOLE_STATUS.ERROR)
    expect(c.tabStatus.value).toBe('error')
    expect(c.errorCode.value).toBe('RULE_ACCESS_DENIED')
    expect(WebSocketMock.instances).toHaveLength(0)
    c.dispose()
  })

  it('能力投影可就地更新；查詢失敗（null）保留上一次已知值', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    await connectReady(c, { ...READY, capabilities: { file_download: false } })
    expect(c.exportAllowed.value).toBe(false)

    c.setExportCapability(null)
    expect(c.exportAllowed.value).toBe(false)
    c.setExportCapability(true)
    expect(c.exportAllowed.value).toBe(true)
    c.dispose()
  })

  // 語句失敗的原文只掛在 result 上：漏接這條路徑，打錯 SQL 的人只會看到一個
  // 「失敗」標籤，畫面說不出目標端到底講了什麼
  it('result 的 db_error 進錯誤面板：錯誤碼與目標端原文都拿得到', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c)
    c.sendQuery('SELECT * FROM nope WHERE')
    ws.receive({ type: 'unit_started', event_id: 'E1', seq: 1 })
    ws.receive({
      type: 'result',
      event_id: 'E1',
      seq: 1,
      status: 'error',
      sets: [],
      duration_ms: 6,
      db_error: { code: '1064', message: "syntax error near '' at line 1" },
    })

    expect(c.lastError.value).toBeTruthy()
    expect(c.lastError.value.dbError).toEqual({
      code: '1064',
      message: "syntax error near '' at line 1",
    })
    expect(c.lastError.value.message).not.toBe('')
    expect(c.units.value[0].status).toBe('error')
    c.dispose()
  })

  // 使用者在語句卡住時最自然的動作就是重新連線；那一筆的識別必須跟著 hello 走，
  // 否則它連同下場一起從畫面上消失
  it('重新連線時未收束的單位轉為結果未知，hello 帶著它的事件識別去問下場', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const first = await connectReady(c)
    c.sendQuery('SELECT pg_sleep(45)')
    first.receive({ type: 'unit_started', event_id: 'E9', seq: 1 })
    expect(c.busy.value).toBe(true)

    await c.reconnect()

    expect(c.pendingEventId.value).toBe('E9')
    expect(c.units.value).toHaveLength(1)
    expect(c.units.value[0].resultUnknown).toBe(true)

    const second = WebSocketMock.instances.at(-1)
    expect(second).not.toBe(first)
    second.open()
    expect(second.sent[0]).toMatchObject({
      type: 'hello',
      previous_session_id: 91,
      pending_event_id: 'E9',
    })
    c.dispose()
  })

  // 目標端關掉連線後，畫面必須當下就進斷線態：晚一步就會再送出一句
  // 從未執行的語句，並為它留下一列稽核紀錄
  it('closed（目標端關閉）即進斷線態，後續送出一律不出手', async () => {
    const c = useDbConsoleSocket({ assetId: 7 })
    const ws = await connectReady(c)
    ws.receive({ type: 'closed', reason: 'target_closed' })

    expect(c.connected.value).toBe(false)
    expect(c.status.value).toBe(DB_CONSOLE_STATUS.DISCONNECTED)
    expect(c.statusDetail.value).not.toBe('')
    const before = ws.sent.length
    expect(c.sendQuery('SELECT 1')).toBe(false)
    expect(ws.sent).toHaveLength(before)
    c.dispose()
  })
})
