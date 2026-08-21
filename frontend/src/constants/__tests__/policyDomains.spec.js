import { describe, it, expect } from 'vitest'
import { POLICY_DOMAINS, sectionKeys } from '../policyDomains'

// 後端全鍵集對照組（backend/internal/service/security_policy_service.go:19-64）。
// 一致性守護（settings-domain-restructure D5）：四域鍵集互斥且聯集＝後端全鍵集——
// 後端新增政策鍵時必須在 policyDomains.js 歸域並同步本清單，否則此測試紅燈提醒。
const BACKEND_POLICY_KEYS = [
  'lockout_max_attempts',
  'lockout_duration_minutes',
  'password_min_length',
  'password_require_alnum',
  'password_history_count',
  'password_max_age_days',
  'force_change_on_reset',
  'mfa_required',
  'web_idle_minutes',
  'web_max_session_hours',
  'session_idle_minutes',
  'session_max_minutes',
  'inactive_disable_days',
  'retention_audit_log_days',
  'retention_session_command_days',
  'retention_alert_days',
  'retention_recording_days',
  'retention_checkpoint_days',
  'audit_checkpoint_interval_seconds',
  'audit_checkpoint_row_threshold',
  // 鏈自動驗證三鍵（audit-chain-scheduled-verification）
  'audit_chain_recent_verify_days',
  'audit_chain_verify_interval_seconds',
  'audit_chain_verify_rows_per_hour',
  'retention_max_per_run',
  'daily_review_enabled',
  'failure_alert_enabled',
  'recording_failclose_enabled',
  'key_cryptoperiod_reminder_days',
  'key_rotation_max_per_run',
  'k8s_list_timeout_seconds',
  'transport_rdp_level',
  'transport_vnc_level',
  'transport_db_level',
  'transport_ldap_level',
  'transport_syslog_level',
  'transport_notify_level',
  'transport_consent_ttl_days',
  'access_policy_default',
  'access_request_max_duration_minutes',
  'access_request_pending_timeout_hours',
  'access_request_min_approvals',
  'break_glass_enabled',
  'break_glass_duration_minutes',
  'break_glass_review_timeout_hours',
  'access_revoke_disconnect',
  // 資料傳輸管控（data-transfer-control D1）
  'clipboard_send_enabled',
  'clipboard_recv_enabled',
  'file_upload_enabled',
  'file_download_enabled',
  'file_delete_enabled',
]

describe('policyDomains 鍵歸屬一致性', () => {
  it('四域鍵集互斥（單一鍵不得重複歸域）', () => {
    const seen = new Map()
    POLICY_DOMAINS.forEach((domain) => {
      sectionKeys(domain.sections).forEach((key) => {
        expect(
          seen.has(key),
          `鍵 ${key} 同時歸屬 ${seen.get(key)} 與 ${domain.id}`
        ).toBe(false)
        seen.set(key, domain.id)
      })
    })
  })

  it('四域聯集＝後端全鍵集（新增鍵必須歸域）', () => {
    const union = POLICY_DOMAINS.flatMap((d) => sectionKeys(d.sections)).sort()
    expect(union).toEqual([...BACKEND_POLICY_KEYS].sort())
  })

  it('域內各區塊鍵不重複', () => {
    POLICY_DOMAINS.forEach((domain) => {
      const keys = sectionKeys(domain.sections)
      expect(new Set(keys).size, `${domain.id} 域內有重複鍵`).toBe(keys.length)
    })
  })
})
