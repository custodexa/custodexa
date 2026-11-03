// 主機帳號盤點的呈現對應：值域逐一對應到三語鍵與視覺類別；未知值走退路並保留原碼。
// 值域與後端 docs/API_SPEC.md「主機帳號盤點 API」一致；對照由單測讀同一份常數比對。

export const SCAN_STATUSES = ['queued', 'running', 'succeeded', 'partial', 'failed', 'interrupted']

/** 進行中的狀態（需要輪詢） */
export const ACTIVE_STATUSES = ['queued', 'running']

export const FAILURE_REASONS = [
  'INVENTORY_HOST_KEY_MISMATCH',
  'INVENTORY_HOST_KEY_CHECK_FAILED',
  'INVENTORY_LOGIN_FAILED',
  'INVENTORY_CONNECTION_FAILED',
  'INVENTORY_TIMEOUT',
  'INVENTORY_COMMAND_FAILED',
  'INVENTORY_OUTPUT_LIMIT',
  'INVENTORY_OUTPUT_MALFORMED',
  'INVENTORY_NO_ACCOUNT',
  'INVENTORY_NO_SECRET',
  'INVENTORY_ASSET_CHANGED',
  'INVENTORY_PERSIST_FAILED',
  'INVENTORY_INTERRUPTED',
  'INVENTORY_EXECUTOR_CHANGED',
  'INVENTORY_EXECUTOR_BUSY',
  'INVENTORY_EXECUTOR_UNAVAILABLE',
]

export const COVERAGE_CHECKS = [
  'accounts',
  'groups',
  'sudoers_main',
  'sudoers_dir',
  'sudoers_unresolved',
]
// undetermined：前提項目讀不到而無從判斷（主規則檔讀不到時的「無法解析的項目」）
export const COVERAGE_STATES = ['checked', 'partial', 'unreadable', 'absent', 'failed', 'undetermined']
export const COVERAGE_REASONS = [
  'permission_denied',
  'nondefault_location',
  'not_included',
  'invalid_rows',
  'command_failed',
  'via_escalation',
  'escalation_denied',
]
export const FIXED_NOTES = [
  'other_escalation_tools',
  'unenumerated_directory_accounts',
  'replaced_noninteractive_shell',
]

/** 特權理由碼（不含名稱的前綴）；second 表示理由來自 sudo 規則判斷 */
export const REASON_KINDS = {
  uid0: { named: false, bySudoRules: false },
  group: { named: true, bySudoRules: false },
  group_primary: { named: true, bySudoRules: false },
  sudoers_user: { named: false, bySudoRules: true },
  sudoers_group: { named: true, bySudoRules: true },
  sudoers_alias: { named: true, bySudoRules: true },
  sudoers_all: { named: false, bySudoRules: true },
  sudoers_all_targetpw: { named: false, bySudoRules: true, muted: true },
}

/** 失敗原因碼的下一步型別：goHostKey、goAccounts、goExecutor（持專用帳號管理權者才有鈕）、retry、none */
export const FAILURE_NEXT = {
  INVENTORY_HOST_KEY_MISMATCH: 'goHostKey',
  INVENTORY_HOST_KEY_CHECK_FAILED: 'retry',
  INVENTORY_LOGIN_FAILED: 'goAccounts',
  INVENTORY_CONNECTION_FAILED: 'retry',
  INVENTORY_TIMEOUT: 'retry',
  INVENTORY_COMMAND_FAILED: 'retry',
  INVENTORY_OUTPUT_LIMIT: 'none',
  INVENTORY_OUTPUT_MALFORMED: 'retry',
  INVENTORY_NO_ACCOUNT: 'goAccounts',
  INVENTORY_NO_SECRET: 'goAccounts',
  INVENTORY_ASSET_CHANGED: 'none',
  INVENTORY_PERSIST_FAILED: 'retry',
  INVENTORY_INTERRUPTED: 'retry',
  INVENTORY_EXECUTOR_CHANGED: 'goExecutor',
  INVENTORY_EXECUTOR_BUSY: 'retry',
  INVENTORY_EXECUTOR_UNAVAILABLE: 'goExecutor',
}

export function isActiveStatus(status) {
  return ACTIVE_STATUSES.includes(status)
}

/** 狀態的視覺類別（對應 --ot-* 色彩語意） */
export function statusTone(status) {
  switch (status) {
    case 'succeeded':
      return 'success'
    case 'partial':
      return 'warning'
    case 'failed':
      return 'danger'
    case 'running':
      return 'primary'
    default:
      return 'info'
  }
}

/** 狀態徽章鍵；未知值回 null，由呼叫端顯示原值 */
export function statusKey(status) {
  return SCAN_STATUSES.includes(status) ? status : null
}

/** 失敗原因碼：已知回 { known: true, key, next }，未知回 { known: false, code } */
export function failureInfo(code) {
  if (FAILURE_REASONS.includes(code)) {
    return { known: true, code, key: code, next: FAILURE_NEXT[code] }
  }
  return { known: false, code: code || '', key: null, next: 'retry' }
}

/** 特權理由字串（"碼" 或 "碼:名稱"）拆成結構；未知碼 known=false 保留原字串 */
export function parseReason(raw) {
  const text = typeof raw === 'string' ? raw : ''
  const i = text.indexOf(':')
  const kind = i === -1 ? text : text.slice(0, i)
  const name = i === -1 ? '' : text.slice(i + 1)
  const meta = REASON_KINDS[kind]
  if (!meta) return { known: false, raw: text, kind, name }
  return { known: true, raw: text, kind, name, ...meta }
}

/** 檢查範圍狀態的視覺類別 */
export function coverageTone(state) {
  switch (state) {
    case 'checked':
      return 'success'
    case 'partial':
    case 'unreadable':
      return 'warning'
    case 'failed':
      return 'danger'
    default:
      return 'info'
  }
}

/**
 * 檢查範圍項目是否算「缺項」（警示帶列出）：不是已檢查、也不是主機上沒有；
 * 無從判斷的項目是另一項缺漏的後果，警示帶已列出其原因，不重複列。
 */
export function isCoverageGap(item) {
  return !!item && !['checked', 'absent', 'undetermined'].includes(item.state)
}

/** 檢查項的檔案路徑（回應未帶 path 時的預設位置） */
export const COVERAGE_PATHS = {
  sudoers_main: '/etc/sudoers',
  sudoers_dir: '/etc/sudoers.d',
}

/** 檢查項的路徑：回應有 path 用回應值，否則用預設位置；沒有路徑的項目回空字串 */
export function coveragePath(item) {
  if (!item) return ''
  if (typeof item.path === 'string' && item.path.trim()) return item.path
  return COVERAGE_PATHS[item.check] || ''
}

/** 已有結果的狀態（數字與表格屬於這一次） */
export const RESULT_STATUSES = ['succeeded', 'partial']
export function isResultStatus(status) {
  return RESULT_STATUSES.includes(status)
}

/** 結果列的排序：特權在前，同組內未納管在前，再依帳號名 */
export function sortFindings(list) {
  return [...(list || [])].sort((a, b) => {
    if (!!a.privileged !== !!b.privileged) return a.privileged ? -1 : 1
    if (!!a.managed !== !!b.managed) return a.managed ? 1 : -1
    return String(a.username).localeCompare(String(b.username))
  })
}

/** 篩選鍵 → 單台讀取的查詢參數 */
export const FILTERS = ['needs', 'privileged', 'all', 'ignored', 'gone']
export function filterParams(filter) {
  switch (filter) {
    case 'needs':
      // actionable：排除不可登入、唯一特權理由為主要群組 root 的系統預設帳號
      return { privileged: true, managed: false, present: true, status: 'open', actionable: true }
    case 'privileged':
      return { privileged: true, present: true }
    case 'ignored':
      return { status: 'ignored' }
    case 'gone':
      return { present: false }
    default:
      return {}
  }
}

/** 主機金鑰端點「尚無記錄」的錯誤碼（後端回 404） */
export const HOST_KEY_NOT_FOUND = 'NOTFOUND_HOST_KEY'

/**
 * 讀主機指紋記錄失敗時的判讀：只有 404 且為「尚無記錄」碼才算確定沒有記錄（'none'），
 * 其他失敗（權限、網路、伺服器錯誤）一律是讀不到、無法判斷（'unknown'）。
 */
export function hostKeyState(err) {
  const status = err?.response?.status
  const code = err?.response?.data?.code
  return status === 404 && code === HOST_KEY_NOT_FOUND ? 'none' : 'unknown'
}
