/**
 * 資產批次新增的列模型（線上填寫與 CSV 匯入共用同一張表）。
 *
 * 規則的事實來源在伺服端（預檢與寫入共用同一個驗證函式）；此處只做三件事：
 *   1. 表格列 ↔ 端點列 JSON 的轉換；
 *   2. 協定連動（哪些欄不適用、協定改變時清掉哪些值）；
 *   3. JSON 承載不了的輸入（非數字的埠、非整數的憑證編號）在送出前就地標錯——
 *      這些值若直接轉成 null 送出，會被伺服端解讀成「用預設埠」「稍後指定憑證」，
 *      使用者填錯的值就這樣悄悄變成另一個意思。
 */
import { isDatabaseProtocol, PROTOCOL_DEFAULT_PORTS } from '@/utils/protocol'

/** 範本與欄位說明的 13 欄（順序即範本欄序，design §2.2） */
export const BULK_FIELDS = [
  'name',
  'protocol',
  'host',
  'port',
  'credential_id',
  'tags',
  'nodes',
  'description',
  'access_policy',
  'db_name',
  'k8s_namespace',
  'rdp_security',
  'db_tls_mode',
]

/** 必填欄（k8s_namespace 另為 k8s 協定必填） */
export const REQUIRED_FIELDS = ['name', 'protocol', 'host']

export const BULK_PROTOCOLS = Object.keys(PROTOCOL_DEFAULT_PORTS)

/** 只對特定協定有意義的欄 */
export const PROTOCOL_SPECIFIC_FIELDS = ['db_name', 'db_tls_mode', 'rdp_security', 'k8s_namespace']

export const DB_TLS_VERIFY_MODES = ['verify-ca', 'verify-full']

// 埠超過這個位數一定不在 1–65535：直接本地標錯，免得超大整數在 JSON 解碼端溢位、
// 讓整批以格式錯誤被拒而指不出是哪一格
const PORT_MAX_DIGITS = 5

/**
 * 欄位是否適用該協定。協定不合法時無從判定，一律視為適用（讓使用者看得到並改得到值）
 */
export function fieldApplies(field, protocol) {
  if (!BULK_PROTOCOLS.includes(protocol)) return true
  switch (field) {
    case 'db_name':
    case 'db_tls_mode':
      return isDatabaseProtocol(protocol)
    case 'rdp_security':
      return protocol === 'rdp'
    case 'k8s_namespace':
      return protocol === 'k8s'
    default:
      return true
  }
}

let seq = 0

/** 新的一列（預設 ssh：最常見的協定，空白列不因此被當成「有填」） */
export function newRow(protocol = 'ssh') {
  seq += 1
  return {
    key: seq,
    line: null,
    name: '',
    protocol,
    host: '',
    port: '',
    credential_id: null,
    // 伺服端回顯的憑證（名稱、帳號名）：該憑證不在相容清單時仍要顯示得出來
    credential_ref: null,
    tags: '',
    node_ids: [],
    // CSV 以路徑指定節點：路徑為準，改了節點選擇即清空、改以 node_ids 送出
    node_paths: [],
    description: '',
    access_policy: '',
    db_name: '',
    k8s_namespace: '',
    rdp_security: '',
    db_tls_mode: '',
    // CSV 中無法轉型的原文（埠、憑證編號）：保留給使用者看、並阻擋送出
    raw: {},
    // 格內提示（協定改變時清掉的欄）
    hints: {},
  }
}

/** 複製一列：內容全帶，列號與提示不帶（新列不是檔案裡的那一列） */
export function duplicateRow(row) {
  const copy = newRow(row.protocol)
  return {
    ...copy,
    name: row.name,
    host: row.host,
    port: row.port,
    credential_id: row.credential_id,
    credential_ref: row.credential_ref,
    tags: row.tags,
    node_ids: [...row.node_ids],
    node_paths: [...row.node_paths],
    description: row.description,
    access_policy: row.access_policy,
    db_name: row.db_name,
    k8s_namespace: row.k8s_namespace,
    rdp_security: row.rdp_security,
    db_tls_mode: row.db_tls_mode,
    raw: { ...row.raw },
  }
}

const TEXT_FIELDS = [
  'name',
  'host',
  'port',
  'tags',
  'description',
  'access_policy',
  'db_name',
  'k8s_namespace',
  'rdp_security',
  'db_tls_mode',
]

/** 全空白列（協定有預設值，不算「有填」）：檢查時略過、不計台數 */
export function isBlankRow(row) {
  return (
    TEXT_FIELDS.every((f) => String(row[f] ?? '').trim() === '') &&
    row.credential_id == null &&
    !row.node_ids.length &&
    !row.node_paths.length &&
    !Object.keys(row.raw).length
  )
}

/** 該列「未指定登入憑證」（填了無法辨識的編號不算：那是要改的錯，不是稍後再配） */
export function isCredentialPendingRow(row) {
  return row.credential_id == null && !row.raw.credential_id
}

/**
 * 協定改變：不適用的已填值清空並留提示；回傳被清掉的欄名
 */
export function applyProtocolChange(row, protocol) {
  row.protocol = protocol
  row.hints = {}
  const cleared = []
  for (const field of PROTOCOL_SPECIFIC_FIELDS) {
    if (row[field] !== '' && !fieldApplies(field, protocol)) {
      row[field] = ''
      row.hints = { ...row.hints, [field]: 'fieldCleared' }
      cleared.push(field)
    }
  }
  return cleared
}

/**
 * 憑證不在新協定的相容清單內即清空並留提示。清單尚未取得（null）時不動
 */
export function clearIncompatibleCredential(row, compatibleIds) {
  if (row.credential_id == null || !compatibleIds) return false
  if (compatibleIds.includes(row.credential_id)) return false
  row.credential_id = null
  row.credential_ref = null
  row.hints = { ...row.hints, credential_id: 'credentialCleared' }
  return true
}

function portPayload(port) {
  const v = String(port ?? '').trim()
  if (v === '') return { value: null }
  if (!/^\d+$/.test(v) || v.length > PORT_MAX_DIGITS) {
    return { value: null, error: { field: 'port', code: 'VALIDATION_ASSET_IMPORT_PORT', params: {} } }
  }
  return { value: Number(v) }
}

/**
 * 表格列 → 端點列 JSON，連同送出前就地發現的錯誤（JSON 承載不了的輸入）
 * @returns {{ row: object, localErrors: object[] }}
 */
export function rowToPayload(row) {
  const localErrors = []
  const port = portPayload(row.port)
  if (port.error) localErrors.push(port.error)
  if (row.credential_id == null && row.raw.credential_id) {
    localErrors.push({ field: 'credential_id', code: 'VALIDATION_ASSET_IMPORT_FIELD_FORMAT', params: {} })
  }
  const payload = {
    line: row.line,
    name: row.name,
    protocol: row.protocol,
    host: row.host,
    port: port.value,
    credential_id: row.credential_id,
    tags: row.tags,
    node_ids: [...row.node_ids],
    description: row.description,
    access_policy: row.access_policy,
    db_name: row.db_name,
    k8s_namespace: row.k8s_namespace,
    rdp_security: row.rdp_security,
    db_tls_mode: row.db_tls_mode,
  }
  if (row.node_paths.length) payload.node_paths = [...row.node_paths]
  return { row: payload, localErrors }
}

/** 預檢回應的一列 → 表格列（CSV 載入時用） */
export function rowFromReport(report) {
  const v = report.values || {}
  const raw = report.raw || {}
  const row = newRow(v.protocol || '')
  row.line = report.line ?? null
  row.name = v.name || ''
  row.host = v.host || ''
  // 預設埠是伺服端代填的，不是使用者填的：表格維持空白、以 placeholder 呈現
  if (report.resolved?.port_defaulted) row.port = ''
  else if (v.port != null) row.port = String(v.port)
  else row.port = raw.port ?? ''
  row.credential_id = v.credential_id ?? null
  row.credential_ref = report.resolved?.credential || null
  if (v.credential_id == null && raw.credential_id) row.raw = { credential_id: raw.credential_id }
  row.tags = v.tags || ''
  row.node_ids = [...(v.node_ids || [])]
  row.node_paths = [...(v.node_paths || [])]
  row.description = v.description || ''
  row.access_policy = v.access_policy || ''
  row.db_name = v.db_name || ''
  row.k8s_namespace = v.k8s_namespace || ''
  row.rdp_security = v.rdp_security || ''
  row.db_tls_mode = v.db_tls_mode || ''
  return row
}

/**
 * 預檢通過後的寫入本文：每列的 values 原樣帶回，節點同時帶 node_ids 與 node_paths——
 * 伺服端在交易內以路徑重算比對，預檢後節點被改名或搬移即整批不建立。
 * 以節點選擇器選的列（values 無路徑）帶回預檢解析出的路徑，同受此保護
 */
export function importPayloadFromPreview(source, preview) {
  return {
    source,
    rows: preview.rows.map((r) => {
      const values = { ...r.values }
      const paths = values.node_paths?.length ? values.node_paths : r.resolved?.node_paths || []
      values.node_ids = [...(values.node_ids || [])]
      values.node_paths = [...paths]
      return values
    }),
  }
}

/** 驗證檔位但未提供 CA 的台數（完成畫面提示；CSV 不收 CA，故凡驗證檔位皆算） */
export function countVerifyWithoutCa(rows) {
  return rows.filter((r) => isDatabaseProtocol(r.protocol) && DB_TLS_VERIFY_MODES.includes(r.db_tls_mode)).length
}

/** CSV 範本：UTF-8 BOM＋13 欄機器欄名（必填以 * 標示）、只有表頭 */
export function templateCsv() {
  const header = BULK_FIELDS.map((f) => (REQUIRED_FIELDS.includes(f) ? `*${f}` : f)).join(',')
  return `\uFEFF${header}\r\n`
}
