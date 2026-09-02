// 查詢主控台的 WebSocket 通道與會話狀態。
//
// 為什麼是 composable 而不是寫在元件裡：協議狀態（連線、當前庫、執行單位、
// 交易態、待回填的單位）與畫面佈局是兩件會各自變動的事，混在同一個 .vue 裡
// 會讓「送出後斷線」這類跨訊息的規則散進模板。
//
// 連線收口：本檔唯一取得的機密是一次性連線票，且票只進 query string 一次；
// 帳號綁定封在票內，前端自始至終不經手憑證。

import { ref, shallowRef, computed, toValue } from 'vue'
import { createConnectTokenWithConsent } from '@/api/connect'
import { dbConsoleSocketUrl, allowsExport } from '@/api/dbConsole'
import { resolveApiError } from '@/api/error'
import { t } from '@/i18n'
import { pendingUnit, upsertUnit, markRunningUnknown } from './dbConsoleUnits'
import { createTreeChannel } from './dbConsoleTreeChannel'
import { DB_CONSOLE_STATUS, TREE_LEVELS, toTabStatus } from './dbConsoleStatus'
import {
  sessionFacts,
  resultPatch,
  pendingResultPatch,
  noticeEffect,
} from './dbConsoleMessages'

/**
 * @param {object} options
 * @param {number|string|import('vue').Ref} options.assetId 資產 ID
 * @param {number|string|import('vue').Ref} [options.accountId] 所選資產帳號
 * @param {number|string|import('vue').Ref} [options.previousSessionId] 重連時的上一場會話
 * @param {string|import('vue').Ref} [options.pendingEventId] 重連時未收束的執行單位
 * @param {string|import('vue').Ref} [options.pendingSql] 該單位的原文（重送前比對用）
 */
export function useDbConsoleSocket(options = {}) {
  const status = ref(DB_CONSOLE_STATUS.CONNECTING)
  const statusDetail = ref('')
  const errorCode = ref('')

  const sessionId = ref(null)
  const dialect = ref('')
  const currentDatabase = ref('')
  const databaseAllowed = ref(true)
  const databases = ref([])
  const capabilities = ref(null)
  const txState = ref('')
  const limits = ref({})
  // 目標受限的成因碼（database_not_allowed／database_drift_denied），供提示分文案
  const restrictedCode = ref('')

  // 執行單位。shallowRef＋整體換陣列：單一結果集可達千列，逐列做深層響應式
  // 只是把時間花在代理物件上
  const units = shallowRef([])
  // 進行中的單位（單進行中送出）
  const activeEventId = ref('')
  // 未收束的單位：斷線時保留，重連以 hello 自報，伺服端回填後轉為真相
  const pendingEventId = ref(toValue(options.pendingEventId) || '')
  const pendingSql = ref(toValue(options.pendingSql) || '')
  // 最近一次送出的批號：只有這一批的結果還在伺服端快取內，可匯出
  const submissionSeq = ref(0)
  // 編輯器下方錯誤面板的內容（不走全域 toast）
  const lastError = ref(null)
  const closedReason = ref('')

  let socket = null
  let disposed = false
  // 頁內重連時自報的上一場會話（優先於外部傳入的值）
  let lastSessionId = null
  const tree = createTreeChannel((payload) => send(payload))

  const tabStatus = computed(() => toTabStatus(status.value))
  const connected = computed(
    () =>
      status.value === DB_CONSOLE_STATUS.CONNECTED ||
      status.value === DB_CONSOLE_STATUS.RESTRICTED
  )
  const sessionEnded = computed(
    () =>
      status.value === DB_CONSOLE_STATUS.DISCONNECTED ||
      status.value === DB_CONSOLE_STATUS.ERROR
  )
  const busy = computed(() => activeEventId.value !== '')
  const exportAllowed = computed(() => allowsExport(capabilities.value))

  function putUnit(eventId, patch, seed = {}) {
    units.value = upsertUnit(units.value, eventId, { ...patch }, {
      submission: submissionSeq.value,
      ...seed,
    })
  }

  // 重連自報的未收束單位先以佔位列呈現，使「結果未知」在 ready 之前就看得到
  if (pendingEventId.value) {
    units.value = [pendingUnit(pendingEventId.value, pendingSql.value)]
  }

  async function connect() {
    disposed = false
    status.value = DB_CONSOLE_STATUS.CONNECTING
    statusDetail.value = ''
    errorCode.value = ''
    closedReason.value = ''

    let connectToken
    try {
      const resp = await createConnectTokenWithConsent(
        toValue(options.assetId),
        toValue(options.accountId)
      )
      connectToken = resp.connect_token
    } catch (err) {
      status.value = DB_CONSOLE_STATUS.ERROR
      errorCode.value = err?.response?.data?.code || ''
      statusDetail.value = resolveApiError(
        err?.response?.data,
        err?.response?.status,
        t('dbConsole.tokenFailed')
      )
      return
    }
    if (disposed) return

    socket = new WebSocket(dbConsoleSocketUrl(connectToken))
    socket.onopen = () => {
      // 首則自報：伺服端只記錄不信任，僅用來查本人的既有列
      send({
        type: 'hello',
        previous_session_id:
          Number(lastSessionId ?? toValue(options.previousSessionId)) || undefined,
        pending_event_id: pendingEventId.value || undefined,
      })
    }
    socket.onmessage = (event) => {
      let msg
      try {
        msg = JSON.parse(event.data)
      } catch {
        return
      }
      handleMessage(msg)
    }
    socket.onclose = () => {
      if (disposed || sessionEnded.value) return
      markDisconnected(closedReason.value || 'client_gone')
    }
    socket.onerror = () => {
      if (disposed || status.value !== DB_CONSOLE_STATUS.CONNECTING) return
      status.value = DB_CONSOLE_STATUS.ERROR
      statusDetail.value = t('dbConsole.connectFailed')
    }
  }

  function handleMessage(msg) {
    switch (msg.type) {
      case 'ready':
        applyReady(msg)
        break
      case 'unit_started':
        activeEventId.value = msg.event_id
        putUnit(
          msg.event_id,
          {
            seq: msg.seq ?? 0,
            batchIndex: msg.batch_index ?? 0,
            batchCount: msg.batch_count ?? 1,
            submission: submissionSeq.value,
            status: 'running',
          },
          { sql: pendingSql.value }
        )
        break
      case 'result':
        applyResult(msg)
        break
      case 'error':
        applyError(msg)
        break
      case 'notice':
        applyNotice(msg)
        break
      case 'closed':
        closedReason.value = msg.reason || ''
        markDisconnected(msg.reason || '')
        break
      case 'tree_result':
        resolveTree(msg)
        break
      default:
        break
    }
  }

  function applyReady(msg) {
    const facts = sessionFacts(msg)
    sessionId.value = facts.sessionId
    dialect.value = facts.dialect
    currentDatabase.value = facts.database
    databaseAllowed.value = facts.databaseAllowed
    databases.value = facts.databases
    capabilities.value = facts.capabilities
    txState.value = facts.txState
    limits.value = facts.limits
    status.value = facts.databaseAllowed
      ? DB_CONSOLE_STATUS.CONNECTED
      : DB_CONSOLE_STATUS.RESTRICTED

    const pending = pendingResultPatch(msg)
    if (pending) {
      putUnit(pending.eventId, pending.patch)
      if (pending.eventId === pendingEventId.value) pendingEventId.value = ''
    }
  }

  function applyResult(msg) {
    if (msg.event_id === activeEventId.value) activeEventId.value = ''
    if (msg.event_id === pendingEventId.value) pendingEventId.value = ''
    if (msg.tx_state) txState.value = msg.tx_state
    putUnit(msg.event_id, resultPatch(msg), { sql: pendingSql.value })
    // 語句層失敗的原文只掛在 result 上（阻斷與切庫失敗走 error）。少了這一段，
    // 打錯 SQL 的人拿不到目標端說了什麼，畫面只剩一個「失敗」的標籤
    if (msg.status === 'error') {
      lastError.value = {
        eventId: msg.event_id || '',
        code: '',
        params: null,
        dbError: msg.db_error || null,
        message: t('dbConsole.editor.statementFailed'),
      }
    }
  }

  function applyError(msg) {
    // 語句層的錯誤就近呈現，不動連線狀態；db_error 原樣暴露（那是使用者自己的
    // 產品內容，泛化只會讓他無從修正）
    lastError.value = {
      eventId: msg.event_id || '',
      code: msg.code || '',
      params: msg.params || null,
      dbError: msg.db_error || null,
      message: resolveApiError(
        { code: msg.code, params: msg.params },
        undefined,
        t('common.unknownError')
      ),
    }
    if (msg.event_id && msg.event_id === activeEventId.value) activeEventId.value = ''
    tree.rejectAll(msg.code || 'error')
  }

  function applyNotice(msg) {
    const effect = noticeEffect(msg)
    if (!effect) return
    if (effect.database) currentDatabase.value = effect.database
    databaseAllowed.value = effect.allowed
    restrictedCode.value = effect.code
    if (effect.allowed) {
      if (connected.value) status.value = DB_CONSOLE_STATUS.CONNECTED
      return
    }
    status.value = DB_CONSOLE_STATUS.RESTRICTED
  }

  /**
   * 更新匯出能力投影（政策中途放寬時，視窗重獲焦點即重抓，毋須重連）。
   * 傳入 null＝查詢失敗，保留上一次已知值。
   * @param {boolean|null} allowed
   */
  function setExportCapability(allowed) {
    if (allowed === null || allowed === undefined) return
    capabilities.value = { ...(capabilities.value || {}), file_download: allowed }
  }

  function markDisconnected(reason) {
    // 沒收到終態就斷線的單位＝結果未知；保留識別與原文，重連後以伺服端回報更新
    const { units: next, pending } = markRunningUnknown(units.value)
    if (pending) {
      pendingEventId.value = pending.eventId
      pendingSql.value = pending.sql
      units.value = next
    }
    activeEventId.value = ''
    closedReason.value = reason || closedReason.value
    status.value = DB_CONSOLE_STATUS.DISCONNECTED
    statusDetail.value = reason ? t(`dbConsole.closed.${reason}`) : t('dbConsole.disconnected')
    tree.rejectAll('closed')
  }

  function send(payload) {
    if (!socket || socket.readyState !== WebSocket.OPEN) return false
    socket.send(JSON.stringify(payload))
    return true
  }

  /**
   * 送出一個執行單位。單進行中：前一筆未回終態前不再送
   * （伺服端同樣以 BUSY 擋，此處只是不讓使用者白按）。
   * @param {string} sql 原文
   * @returns {boolean} 是否送出
   */
  function sendQuery(sql) {
    if (!sql || busy.value || !connected.value) return false
    submissionSeq.value += 1
    pendingSql.value = sql
    lastError.value = null
    return send({ type: 'query', sql })
  }

  function cancel() {
    if (!activeEventId.value) return false
    return send({ type: 'cancel', event_id: activeEventId.value })
  }

  function switchDatabase(database) {
    if (!database || database === currentDatabase.value) return false
    lastError.value = null
    return send({ type: 'switch', database })
  }

  // 根層的回應同時更新資料庫下拉：那是同一份目錄事實
  function resolveTree(msg) {
    if (msg.level === TREE_LEVELS.DATABASES && Array.isArray(msg.databases)) {
      databases.value = msg.databases
    }
    tree.settle(msg)
  }

  /**
   * 頁內重連：新票、新會話。編輯器文字由元件保留，結果區清空——
   * 舊會話的結果快取已隨會話釋放，留著會讓人以為還能匯出。
   * 未收束的單位保留為佔位列並於 hello 自報，伺服端回填後轉為真相。
   */
  function reconnect() {
    lastSessionId = sessionId.value
    dispose()
    disposed = false
    sessionId.value = null
    currentDatabase.value = ''
    databases.value = []
    databaseAllowed.value = true
    restrictedCode.value = ''
    txState.value = ''
    lastError.value = null
    activeEventId.value = ''
    submissionSeq.value = 0
    units.value = pendingEventId.value
      ? [pendingUnit(pendingEventId.value, pendingSql.value)]
      : []
    return connect()
  }

  function dispose() {
    // 先收束再拆線：下面會拔掉 onclose，之後沒有人會再把進行中的單位標成
    // 「結果未知」，那一筆會連同它的事件識別一起從畫面上消失
    if (!sessionEnded.value) markDisconnected(closedReason.value || 'client_gone')
    disposed = true
    tree.rejectAll('disposed')
    if (socket) {
      socket.onopen = null
      socket.onmessage = null
      socket.onclose = null
      socket.onerror = null
      try {
        socket.close()
      } catch {
        // 已關閉的 socket 再關一次不是錯誤
      }
      socket = null
    }
  }

  return {
    // 狀態
    status,
    tabStatus,
    statusDetail,
    errorCode,
    connected,
    sessionEnded,
    busy,
    closedReason,
    // 會話事實
    sessionId,
    dialect,
    currentDatabase,
    databaseAllowed,
    restrictedCode,
    databases,
    capabilities,
    exportAllowed,
    txState,
    limits,
    // 執行單位
    units,
    activeEventId,
    pendingEventId,
    pendingSql,
    submissionSeq,
    lastError,
    // 動作
    connect,
    reconnect,
    dispose,
    setExportCapability,
    sendQuery,
    cancel,
    switchDatabase,
    requestTree: tree.request,
  }
}

export { DB_CONSOLE_STATUS, TREE_LEVELS }
