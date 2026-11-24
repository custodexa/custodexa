import { t, te } from '@/i18n'
import { alertRuleText } from '@/constants/command-degrade'
import { BATCH_STATE } from '@/composables/useBatchReview'

/**
 * 告警的一次送出批次：共用的類型分組、列上的觸發者與對象文字、查回比對。
 *
 * 規則（本人觸發可否納入、單次上限、理由必填）一律由伺服端判定；這裡只負責呈現。
 */

/** 批次審閱端點一次請求的上限（伺服端回應的 limit 為準，這只是回應前的預設） */
export const ALERT_BULK_LIMIT = 500

/** 伺服端批次交易的逾時上限：送出未滿這段時間時，查回的「仍未審閱」不能斷定沒有生效 */
export const SERVER_TX_TIMEOUT_MS = 30_000

/** 批次審閱請求的用戶端逾時（長於伺服端交易逾時，避免伺服端還在處理時就先放棄） */
export const BULK_REQUEST_TIMEOUT_MS = 45_000

/** 以 id 清單查回告警時每段的個數（告警列表查詢的上限） */
export const RECONCILE_CHUNK = 50

/** 結果值的原因（沒有生效的那幾筆） */
export const NOT_APPLIED_REASON = Object.freeze({
  BY_YOU: 'byYou',
  YOU_DIFFERENT: 'youDifferent',
  BY_OTHER: 'byOther',
  NOT_FOUND: 'notFound',
  NOT_DELIVERED: 'notDelivered',
})

const SEVERITIES = ['high', 'medium', 'low']
const SEVERITY_RANK = { high: 0, medium: 1, low: 2 }
const DISPOSITIONS = ['benign', 'escalated']

export const severityLabel = (severity) =>
  SEVERITIES.includes(severity) ? t(`enum.alertLevel.${severity}`) : severity || ''

export const dispositionText = (disposition) =>
  disposition === 'escalated' ? t('alerts.dispositionEscalated') : t('alerts.dispositionBenign')

/** 系統告警（管理動作觸發） */
export const isSystemAlert = (row) => row?.kind === 'system_security'

/** 連線中的指令比對規則觸發的告警 */
export const isCommandRuleAlert = (row) => row?.kind === 'rule'

/**
 * 類型鍵：系統告警以 rule_name（類型鍵）為主、reason_code 為輔；規則類以規則名；
 * 其餘非規則類以種類
 */
export const alertTypeKey = (row) => {
  if (isSystemAlert(row)) return `system:${row.rule_name || row.reason_code || ''}`
  if (isCommandRuleAlert(row)) return `rule:${row.rule_name || ''}`
  return `kind:${row?.kind || ''}`
}

/** 類型名稱：系統告警查類型譯名（rule_name 優先），不認得時退回泛稱；其餘沿用告警頁的散文 */
export const alertTypeName = (row) => {
  if (isSystemAlert(row)) {
    for (const key of [row.rule_name, row.reason_code]) {
      if (key && te(`systemAlerts.types.${key}.name`)) return t(`systemAlerts.types.${key}.name`)
    }
    return t('systemAlerts.detail.title')
  }
  return alertRuleText(row)
}

export const isSelfTriggered = (row, me) => me != null && row?.user_id === me

/** 觸發者名稱；使用者列已不存在時以編號代稱 */
export const triggerName = (row) => {
  if (row?.username) return row.username
  if (row?.user_id) return t('alerts.bulk.unknownUser', { id: row.user_id })
  return t('alerts.bulk.systemUser')
}

/** 列上的觸發者：本人加註「（你）」 */
export const userLabel = (row, me) =>
  isSelfTriggered(row, me) ? t('alerts.bulk.userSelf', { user: triggerName(row) }) : triggerName(row)

const TARGET_KINDS = ['asset', 'credential', 'user', 'user_group', 'role_mapping', 'role', 'identity_source', 'notification_channel', 'session', 'system_setting']

// 對象名稱：各類型宣告的參數裡可讀的名稱（依序取第一個有值的）
const TARGET_NAME_PARAMS = ['recipient', 'target_username', 'owner_username', 'channel_name', 'asset_name', 'credential_name', 'session_username']

/** 系統告警的對象：「名稱（種類 #編號）」；不知道名稱時只寫種類與編號；沒有對象時回空字串 */
export const alertTargetText = (row) => {
  if (!row?.target_kind) return ''
  const kind = TARGET_KINDS.includes(row.target_kind) ? t(`systemAlerts.targetKinds.${row.target_kind}`) : row.target_kind
  const params = row.params || {}
  const name = TARGET_NAME_PARAMS.map((key) => params[key]).find((v) => typeof v === 'string' && v)
  const id = row.target_id && row.target_id !== '0' ? row.target_id : ''
  if (name && id) return t('systemAlerts.detail.targetNamed', { name, kind, id })
  if (name) return `${name}（${kind}）`
  return id ? `${kind} #${id}` : kind
}

/**
 * 依類型分組：組的順序依各組最早一筆出現的順序（清單已依時間排序），組內維持原順序。
 * 每組帶等級（組內最高）、筆數、各觸發者筆數（本人在前）與時間範圍。
 */
export function groupAlerts(rows, me) {
  const groups = new Map()
  for (const row of rows) {
    const key = alertTypeKey(row)
    let group = groups.get(key)
    if (!group) {
      group = { key, name: alertTypeName(row), severity: row.severity, isRule: isCommandRuleAlert(row), isSystem: isSystemAlert(row), rows: [], selfCount: 0, users: new Map(), from: row.triggered_at, to: row.triggered_at }
      groups.set(key, group)
    }
    group.rows.push(row)
    if ((SEVERITY_RANK[row.severity] ?? 9) < (SEVERITY_RANK[group.severity] ?? 9)) group.severity = row.severity
    const self = isSelfTriggered(row, me)
    if (self) group.selfCount += 1
    const userKey = self ? '__self__' : String(row.user_id ?? '')
    const entry = group.users.get(userKey) || { name: self ? t('alerts.bulk.you') : triggerName(row), count: 0, self }
    entry.count += 1
    group.users.set(userKey, entry)
    if (row.triggered_at < group.from) group.from = row.triggered_at
    if (row.triggered_at > group.to) group.to = row.triggered_at
  }
  return [...groups.values()].map((group) => {
    const users = [...group.users.values()].sort((a, b) => Number(b.self) - Number(a.self) || b.count - a.count)
    return { ...group, users }
  })
}

/** 依類型彙整（對話框的類型表、結果的成功彙整共用）：每類筆數、本人筆數、各天筆數 */
export function summarizeByType(rows, { me = null, dayOf = null } = {}) {
  return groupAlerts(rows, me).map((group) => {
    const days = []
    if (dayOf) {
      const counts = new Map()
      for (const row of group.rows) {
        const day = dayOf(row)
        counts.set(day, (counts.get(day) || 0) + 1)
      }
      for (const [day, count] of [...counts.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) days.push({ day, count })
    }
    return { key: group.key, name: group.name, severity: group.severity, count: group.rows.length, selfCount: group.selfCount, days }
  })
}

/**
 * 伺服端明說整批沒有生效的錯誤：只有本文帶 INTERNAL_ALERT_REVIEW 的 500（交易已回滾）。
 * 其他 5xx（含提交階段結果不明時的一般內部錯誤）、代理層錯誤與逾時都無法斷定，歸待確認
 */
export const isDefiniteBulkFailure = (error) =>
  error?.response?.status === 500 && error?.response?.data?.code === 'INTERNAL_ALERT_REVIEW'

/** 批次審閱回應的一筆結果 → 列的狀態 */
export function itemPatch(item, disposition) {
  switch (item?.result) {
    case 'reviewed':
      return { state: BATCH_STATE.SUCCESS }
    case 'already_reviewed': {
      const existing = DISPOSITIONS.includes(item.existing_disposition) ? item.existing_disposition : ''
      if (item.reviewed_by_you !== true) return { state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.BY_OTHER, existing }
      // 本人先前的處置與這次不同：如實寫出先前的處置，不說成照這次處置
      if (existing && existing !== disposition) {
        return { state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.YOU_DIFFERENT, existing }
      }
      return { state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.BY_YOU, existing }
    }
    case 'not_found':
      return { state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.NOT_FOUND }
    default:
      return null
  }
}

/** 沒有生效的原因句 */
export function notAppliedText(item) {
  switch (item?.reason) {
    // 寫出先前的處置分類（不寫處置者名稱）；回應沒帶分類時退回不帶分類的說法
    case NOT_APPLIED_REASON.BY_YOU:
      return item.existing
        ? t('alerts.bulk.reason.byYou', { prev: dispositionText(item.existing) })
        : t('alerts.bulk.reason.byYouPlain')
    case NOT_APPLIED_REASON.YOU_DIFFERENT:
      return t('alerts.bulk.reason.youDifferent', { prev: dispositionText(item.existing) })
    case NOT_APPLIED_REASON.BY_OTHER:
      return item.existing
        ? t('alerts.bulk.reason.byOther', { prev: dispositionText(item.existing) })
        : t('alerts.bulk.reason.byOtherPlain')
    case NOT_APPLIED_REASON.NOT_FOUND:
      return t('alerts.bulk.reason.notFound')
    case NOT_APPLIED_REASON.NOT_DELIVERED:
      return t('alerts.bulk.reason.notDelivered')
    default:
      return ''
  }
}

/**
 * 沒有收到回應時的查回：以 id 清單分段查詢（每段至多 50 個），逐筆比對。
 * - 已審閱且審閱者是本人、處置分類與理由都是這一次的 → 成功
 * - 已審閱且審閱者是本人但處置不同 → 沒有生效（先前的處置不變）
 * - 已審閱但審閱者是別人 → 沒有生效（送出前已有人處置）
 * - 仍未審閱：送出至今未滿伺服端交易逾時上限 → 維持待確認；超過 → 沒有生效（這一次沒有送達）
 * - 查不到 → 維持待確認
 */
export async function reconcileAlertBulk(entry, { search, now = () => Date.now() }) {
  const ids = entry.items.filter((item) => item.state === BATCH_STATE.UNCONFIRMED).map((item) => item.id)
  const rows = new Map()
  for (let i = 0; i < ids.length; i += RECONCILE_CHUNK) {
    const chunk = ids.slice(i, i + RECONCILE_CHUNK)
    const res = await search({ ids: chunk.join(','), page: 1, page_size: chunk.length }, { skipErrorToast: true })
    for (const row of res?.data || []) rows.set(row.id, row)
  }
  const elapsed = now() - Date.parse(entry.startedAt || '')
  const withinServerWindow = !(elapsed >= SERVER_TX_TIMEOUT_MS)
  const { disposition, note } = entry.params || {}
  const updates = {}
  for (const id of ids) {
    const row = rows.get(id)
    if (!row) continue
    if (!row.reviewed_at) {
      updates[id] = withinServerWindow
        ? { state: BATCH_STATE.UNCONFIRMED, stillProcessing: true }
        : { state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.NOT_DELIVERED }
      continue
    }
    if (row.reviewed_by !== entry.userId) {
      updates[id] = { state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.BY_OTHER, existing: row.disposition }
    } else if (row.disposition !== disposition) {
      updates[id] = { state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.YOU_DIFFERENT, existing: row.disposition }
    } else if ((row.note || '') === (note || '')) {
      updates[id] = { state: BATCH_STATE.SUCCESS, rechecked: true }
    } else {
      updates[id] = { state: BATCH_STATE.NOT_APPLIED, reason: NOT_APPLIED_REASON.BY_YOU, existing: row.disposition }
    }
  }
  return updates
}
