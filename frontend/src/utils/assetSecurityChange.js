// 編輯資產時，哪些欄位的變更會在儲存後通知安全人員。
// 判定與後端的位址與傳輸放寬分類一致（只供提示；是否通知的權威在伺服器）。

const RDP_RANK = { nla: 3, tls: 2 }
const DB_TLS_RANK = { 'verify-full': 5, 'verify-ca': 4, require: 3, disable: 1 }

const rdpRank = (v) => RDP_RANK[v] ?? 1
const dbTlsRank = (v) => DB_TLS_RANK[v] ?? 2

/**
 * @param {object} base 開啟編輯當下的欄位快照
 * @param {object} cur 目前表單
 * @returns {string[]} 命中的欄位 JSON 名稱
 */
export function securityChangeFields(base, cur) {
  if (!base || !cur) return []
  const out = []
  for (const f of ['host', 'port', 'protocol', 'rotation_channel', 'winrm_scheme', 'winrm_port', 'rotation_ssh_port', 'sftp_port']) {
    if ((base[f] ?? '') !== (cur[f] ?? '')) out.push(f)
  }
  if (!base.sftp_enabled && cur.sftp_enabled) out.push('sftp_enabled')
  if (base.rdp_verify_cert && !cur.rdp_verify_cert) out.push('rdp_verify_cert')
  if (rdpRank(cur.rdp_security) < rdpRank(base.rdp_security)) out.push('rdp_security')
  if (dbTlsRank(cur.db_tls_mode) < dbTlsRank(base.db_tls_mode)) out.push('db_tls_mode')
  if (!base.k8s_insecure_skip_tls && cur.k8s_insecure_skip_tls) out.push('k8s_insecure_skip_tls')
  if (base.winrm_tls_mode !== 'insecure' && cur.winrm_tls_mode === 'insecure') out.push('winrm_tls_mode')
  // CA：留空＝維持既有（k8s、winrm 不回顯本體）；db 回顯本體，改動即算
  if ((base.db_ca_cert ?? '') !== (cur.db_ca_cert ?? '')) out.push('db_ca_cert')
  if (cur.k8s_ca_cert) out.push('k8s_ca_cert')
  if (cur.winrm_ca_cert) out.push('winrm_ca_cert')
  return out
}

export const SECURITY_BASELINE_FIELDS = [
  'host', 'port', 'protocol', 'rotation_channel', 'winrm_scheme', 'winrm_port', 'rotation_ssh_port',
  'sftp_port', 'sftp_enabled', 'rdp_verify_cert', 'rdp_security', 'db_tls_mode',
  'k8s_insecure_skip_tls', 'winrm_tls_mode', 'db_ca_cert',
]

export function pickSecurityBaseline(form) {
  const out = {}
  for (const f of SECURITY_BASELINE_FIELDS) out[f] = form[f]
  return out
}
