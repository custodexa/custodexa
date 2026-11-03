/**
 * 堡壘機專用帳號畫面的共用常數。
 */

/** 可設定專用帳號的協定。 */
export const EXECUTOR_PROTOCOLS = ['ssh', 'rdp']

/** 設定來源。 */
export const EXECUTOR_SOURCES = ['generate', 'inline', 'shared', 'convert']

/**
 * 是否為 Windows 族主機：rdp，或 ssh 且改密通道為 windows_ssh。
 * 與伺服器端判定同形；用「已儲存的資產列」判斷，不用編輯中的表單值。
 */
export function isWindowsFamily(row) {
  if (!row) return false
  if (row.protocol === 'rdp') return true
  return row.protocol === 'ssh' && row.rotation_channel === 'windows_ssh'
}

/** 協定是否可設定專用帳號。 */
export function isExecutorProtocol(protocol) {
  return EXECUTOR_PROTOCOLS.includes(protocol)
}

/**
 * 秘密來源字樣的 i18n 鍵（相對於 assetExecutor.sourceLabel）。
 * 依 source；欄位缺席（升級前設定的列）時退回推斷：共用看投影，專用時有公鑰視為平台產生，
 * 其餘視為只給這台的秘密。
 * @param {Object} executor - GET 回應
 * @returns {'generate'|'inline'|'inlineKey'|'convert'|'shared'|'sharedOutOfScope'|'dedicated'}
 */
export function executorSourceKey(executor) {
  if (!executor) return 'dedicated'
  const cred = executor.credential || {}
  if (cred.credential_out_of_scope) return 'sharedOutOfScope'
  if (cred.shared_credential || executor.source === 'shared') return 'shared'
  switch (executor.source) {
    case 'generate':
      return 'generate'
    case 'convert':
      return 'convert'
    case 'inline':
      return executor.secret_type === 'ssh_key' ? 'inlineKey' : 'inline'
    default:
      return executor.has_public_key ? 'generate' : 'dedicated'
  }
}

/**
 * 編輯深連結的落點表（?edit=<id>&focus=<鍵>）。鍵為 focus 的值；未帶或查無時沿用主機金鑰。
 * scroll（必填）為落點選擇器；focus（選填）為捲動後要聚焦的選擇器。
 */
export const EDIT_FOCUS_TARGETS = {
  'host-key': { scroll: '.host-key-item' },
  // 捲到區塊後聚焦區塊標題（可聚焦的 h3），鍵盤使用者從這一區開始
  executor: { scroll: '[data-focus="executor"]', focus: '[data-focus="executor"] [data-test="executor-title"]' },
  // 測試登入：捲到區塊並聚焦「測試登入」鈕（按鈕在區塊讀取完成後才出現，落點流程會等它）
  'executor-test-login': { scroll: '[data-focus="executor"]', focus: '[data-focus="executor-test-login"]' },
}

/**
 * 測試登入結果碼 → 畫面文案鍵（相對於 assetExecutor.loginCheck.result）與下一步。
 * fix：keyPublic＝取得公鑰（沒有平台公鑰時退回更換）、replace＝更換、setup＝設定方式、
 * hostKey＝捲到主機金鑰區、credential＝前往憑證庫；null 只留「再測一次」。
 * 登入被拒另依秘密型別分金鑰與密碼兩種文案，見 loginCheckResultView。
 */
export const LOGIN_CHECK_RESULTS = {
  RULE_EXECUTOR_CHECK_CONNECTION_FAILED: { key: 'connection', fix: null },
  RULE_EXECUTOR_CHECK_LOGIN_FAILED: { key: 'loginKey', fix: 'keyPublic' },
  RULE_EXECUTOR_CHECK_HOST_KEY_MISMATCH: { key: 'hostKeyMismatch', fix: 'hostKey' },
  RULE_EXECUTOR_CHECK_HOST_KEY_CHECK_FAILED: { key: 'hostKeyCheck', fix: null },
  RULE_EXECUTOR_CHECK_ESCALATION_DENIED: { key: 'escalationDenied', fix: null, setupLink: true },
  RULE_EXECUTOR_CHECK_ESCALATION_NEEDS_NOPASSWD: { key: 'escalationNopasswd', fix: null, setupLink: true },
  RULE_EXECUTOR_CHECK_UNAVAILABLE: { key: 'unavailable', fix: 'replace' },
  RULE_EXECUTOR_CHECK_ROTATION_PENDING: { key: 'rotation', fix: 'credential' },
  RULE_EXECUTOR_CHECK_TIMEOUT: { key: 'timeout', fix: null },
}

/**
 * 依結果碼與專用帳號決定失敗列的文案與下一步；未知碼回 null。
 * 密碼型的登入被拒改寫成「拒絕了密碼」，修正動作改為更換。
 * @param {string} code
 * @param {Object} executor - GET /assets/:id/executor 回應
 * @returns {{key: string, fix: string|null, setupLink?: boolean}|null}
 */
export function loginCheckResultView(code, executor) {
  const row = LOGIN_CHECK_RESULTS[code]
  if (!row) return null
  if (code === 'RULE_EXECUTOR_CHECK_LOGIN_FAILED') {
    if (executor?.secret_type !== 'ssh_key') return { key: 'loginPassword', fix: 'replace' }
    return { ...row, fix: executor?.has_public_key ? 'keyPublic' : 'replace' }
  }
  return row
}

/**
 * 錯誤碼 → 落點、文案鍵與修正動作。表格驅動，同一個碼在不同情境分列。
 * messageKey 為 'apiError' 時以通用錯誤句（resolveApiError）顯示。
 * placement：field-username、field-credential、field-secret-type、field-account（欄位下方）、
 * confirm-count（確認勾選列下方）、block（區塊內靠近動作）、reload（關閉後重新讀取）、button（主要鈕上方）。
 */
export const EXECUTOR_ERROR_TABLE = [
  { code: 'CONFLICT_ACCOUNT_USERNAME', context: 'set', placement: 'field-username', messageKey: 'assetExecutor.error.usernameTaken', fixAction: 'useConvert' },
  { code: 'RULE_EXECUTOR_SHARED_HOST_COUNT', context: 'set', placement: 'confirm-count', messageKey: 'assetExecutor.error.hostCountChanged', fixAction: 'confirmCount' },
  { code: 'RULE_CREDENTIAL_PURPOSE_MISMATCH', context: 'set', placement: 'field-credential', messageKey: 'assetExecutor.error.purposeMismatch', fixAction: 'useGenerate' },
  { code: 'RULE_EXECUTOR_SECRET_TYPE_UNSUPPORTED', context: 'set', placement: 'field-secret-type', messageKey: 'apiError', fixAction: null },
  { code: 'RULE_EXECUTOR_CONVERT_CANDIDATE_PENDING', context: 'convert', placement: 'field-account', messageKey: 'assetExecutor.error.convertPending', fixAction: 'openPlans' },
  { code: 'RULE_CREDENTIAL_ROTATION_ACTIVE', context: 'convert', placement: 'field-account', messageKey: 'assetExecutor.error.convertRotationActive', fixAction: 'openRotation' },
  { code: 'RULE_CREDENTIAL_OUT_OF_SYNC', context: 'convert', placement: 'field-account', messageKey: 'assetExecutor.error.convertOutOfSync', fixAction: 'openCredentials' },
  { code: 'RULE_CREDENTIAL_ROTATION_ACTIVE', context: 'replace', placement: 'block', messageKey: 'assetExecutor.error.replaceRotationActive', fixAction: 'openRotation' },
  { code: 'RULE_CREDENTIAL_ROTATION_ACTIVE', context: 'clear', placement: 'block', messageKey: 'assetExecutor.error.clearRotationActive', fixAction: 'openRotation' },
  { code: 'RULE_EXECUTOR_STATE_CHANGED', context: 'any', placement: 'reload', messageKey: 'assetExecutor.stateChanged', fixAction: null },
  { code: 'RULE_EXECUTOR_PROTOCOL_UNSUPPORTED', context: 'any', placement: 'reload', messageKey: 'assetExecutor.protocolUnsupported', fixAction: null },
  { code: 'VALIDATION_EXECUTOR_SOURCE_INVALID', context: 'any', placement: 'button', messageKey: 'apiError', fixAction: null },
  { code: 'INTERNAL_ASSET_EXECUTOR_WRITE', context: 'any', placement: 'button', messageKey: 'apiError', fixAction: null },
]

/** 查表：同時比對碼與情境；情境為 any 的列對所有情境成立。 */
export function findExecutorError(code, context) {
  return (
    EXECUTOR_ERROR_TABLE.find((r) => r.code === code && r.context === context) ||
    EXECUTOR_ERROR_TABLE.find((r) => r.code === code && r.context === 'any') ||
    null
  )
}
