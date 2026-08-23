// 政策鍵域歸屬單一事實源：
// 四個設定頁各吃自己的 sections；一致性單測斷言四域鍵集互斥且聯集＝後端全鍵集。
// 後端新增政策鍵時必須在此歸域，未歸域的鍵只會落到安全政策母頁「其他」區塊。
// title/hint 譯文住 locale 檔 policyDomain.section.<id>.*，
// getter 回 t()——render/computed 期取值被依賴追蹤，切語言自動重繪

import { t } from '@/i18n'

// refresh cookie 的 Secure 屬性。
// 常數化的理由：安全政策頁的明文連線建議（決策 4）要以這個鍵名從政策清單
// 取生效值，鍵名寫兩次就會有漂一次的一天
export const POLICY_REFRESH_COOKIE_SECURE = 'refresh_cookie_secure'

const section = (id, keys) => ({
  id,
  keys,
  get title() {
    return t(`policyDomain.section.${id}.title`)
  },
  get hint() {
    return t(`policyDomain.section.${id}.hint`)
  },
})

export const SECURITY_SECTIONS = [
  section('login_lock', ['lockout_max_attempts', 'lockout_duration_minutes']),
  section('password', [
    'password_min_length',
    'password_require_alnum',
    'password_history_count',
    'password_max_age_days',
    'force_change_on_reset',
  ]),
  section('mfa', ['mfa_required']),
  section('session_account', [
    'web_idle_minutes',
    'web_max_session_hours',
    // 登入狀態僅在 https 連線保存：緊接 Web 會話
    // 兩鍵之後——它決定的正是這段會話能不能續期。走明文的部署關掉它，
    // 否則使用者每 15 分鐘重新登入
    POLICY_REFRESH_COOKIE_SECURE,
    'session_idle_minutes',
    'session_max_minutes',
    'inactive_disable_days',
  ]),
  section('log_retention', [
    'retention_audit_log_days',
    'retention_session_command_days',
    'retention_alert_days',
    'retention_recording_days',
    // 檢查點鏈保留（audit-checkpoint-chain）：受跨鍵約束——不得短於上列
    // 四個資料保留鍵。放在它們之後，讀起來即「資料留多久、證明留多久」
    'retention_checkpoint_days',
    // 封章觸發門檻（audit-checkpoint-chain）：緊接檢查點保留天數之後，
    // 讀起來即「多久封一次、封了留多久」。調整風險寫在 policyNote.<key>
    'audit_checkpoint_interval_seconds',
    'audit_checkpoint_row_threshold',
    // 鏈自動驗證三鍵：緊接封存門檻之後，
    // 整段讀起來即「多久封一次、封了留多久、封完驗多近、多久滾一輪全鏈、掃多快」。
    // 順序＝近期層窗口 → 全鏈層週期 → 內容層速率，與後端 policyDefs 同序；
    // 速率鍵放在週期鍵之後，因為「每輪掃描量＝速率 × 週期」須先讀到週期才成立
    'audit_chain_recent_verify_days',
    'audit_chain_verify_interval_seconds',
    'audit_chain_verify_rows_per_hour',
    // 單輪清理刪除上限：接在上述封存與驗證之後，
    // 整段收在「每輪清得掉多少」。調小才危險（清理追不上新增量＝
    // 保留政策實質失效），下界由後端 Min 承擔
    'retention_max_per_run',
    'daily_review_enabled',
    'failure_alert_enabled',
    'recording_failclose_enabled',
  ]),
  // 叢集存取：K8s 資產列表的逾時預算。
  // 自成一區而非塞進上列任一區——它既不是登入安全也不是日誌保留，
  // 混進去只會讓那些區塊的標題變得不誠實
  section('cluster', ['k8s_list_timeout_seconds']),
]

export const ACCESS_SECTIONS = [
  section('access_policy', ['access_policy_default']),
  section('request_params', [
    'access_request_max_duration_minutes',
    'access_request_pending_timeout_hours',
    'access_request_min_approvals',
  ]),
  section('break_glass', [
    'break_glass_enabled',
    'break_glass_duration_minutes',
    'break_glass_review_timeout_hours',
    'access_revoke_disconnect',
  ]),
  // 資料傳輸管控（data-transfer-control）：剪貼簿雙向需重連才生效，
  // 檔案三鍵即時生效——生效時機差異於區塊 hint 明示
  section('data_transfer', [
    'clipboard_send_enabled',
    'clipboard_recv_enabled',
    'file_upload_enabled',
    'file_download_enabled',
    'file_delete_enabled',
  ]),
]

export const TRANSPORT_SECTIONS = [
  section('transport', [
    'transport_rdp_level',
    'transport_vnc_level',
    'transport_db_level',
    'transport_ldap_level',
    'transport_syslog_level',
    'transport_notify_level',
    'transport_consent_ttl_days',
  ]),
]

export const KEY_SECTIONS = [
  section('key', [
    'key_cryptoperiod_reminder_days',
    // 單輪換鑰重加密上限：調小才危險
    //（換鑰永遠跑不完＝輪替實質失效），下界由後端 Min 承擔
    'key_rotation_max_per_run',
  ]),
]

// 母頁分域偏離列表用：label 顯示名、route 跳轉
const domain = (id, route, sections) => ({
  id,
  route,
  sections,
  get label() {
    return t(`policyDomain.${id}`)
  },
})

export const POLICY_DOMAINS = [
  domain('security', '/security-policies', SECURITY_SECTIONS),
  domain('access', '/access-control', ACCESS_SECTIONS),
  domain('transport', '/transmission-inventory', TRANSPORT_SECTIONS),
  domain('key', '/key-management', KEY_SECTIONS),
]

export const sectionKeys = (sections) => sections.flatMap((s) => s.keys)
