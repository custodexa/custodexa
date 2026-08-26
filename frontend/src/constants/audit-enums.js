/**
 * 審計枚舉顯示中繼資料唯一事實源。
 * 值域硬拷後端：AuditAction/AuditResource＝backend/internal/model/audit_log.go:13-90、
 * 失效機制＝backend/internal/model/audit_failure.go 的 Mechanism* 常數區。
 * 譯文住 locale 檔（enum.auditAction/auditResource/mechanism.*），以 getter 回 t()；
 * 篩選下拉仍由本表 v-for 生成、表格翻譯同步連動，勿手寫選項。
 * 後端新增值時：此處值域補一筆＋三語 locale 補 key——完備性單測
 * （audit-enums.spec.js）對每值 × 每 locale 斷言非空，缺漏即紅燈。
 * resource／mechanism／cause 三族另有「直讀後端原始碼、雙向等同」的守衛，
 * 手抄對照組與值域一起漏補時亦紅（action 族目前僅硬拷對照組）。
 */
import { t } from '@/i18n'

const ACTION_TAG_TYPES = {
  create: 'success',
  read: 'info',
  update: 'warning',
  delete: 'danger',
  execute: 'primary',
  login: 'success',
  logout: 'info',
  unlock: 'warning',
  pw_noncompliant: 'warning',
  recording_failed: 'danger',
  // 帳號自從未見過的來源位址完成 web 登入的標記列（無告警、無推送）
  new_source_ip: 'warning',
  file_list: 'info',
  file_upload: 'warning',
  file_download: 'warning',
  file_mkdir: 'info',
  file_delete: 'danger',
  approve: 'success',
  reject: 'danger',
  cancel: 'info',
  expire: 'info',
  revoke: 'danger',
  review: 'warning',
}

export const AUDIT_ACTION_VALUES = Object.keys(ACTION_TAG_TYPES)

export const AUDIT_RESOURCE_VALUES = [
  'asset',
  'session',
  'recording',
  'user',
  'auth',
  'file',
  'security_policy',
  'command_alert',
  'audit_export',
  'access_review',
  'retention',
  'daily_review',
  'syslog_setting',
  'audit_log',
  'user_group',
  'command',
  'key_management',
  'transmission',
  'access_request',
  'approver_scope',
  // auditor-workbench 訂正的三個獨立分類：原先全落在 `extractResource`
  // 的 default asset 分支（resource_id 卻是計畫／授權列／查詢的 id），
  // 後端已分家，前端值域補齊才不會在介面上顯示機器碼
  'change_secret_plan',
  'authorization',
  'audit_timeline',
  // 取走剪貼簿明文內容的動作，與一般連線讀取
  // 在後端已分屬兩個 resource；此處補值域，介面才不會顯示機器碼
  'clipboard_event',
  // 十族的常數從未存在，整族落
  // `extractResource` 的兜底（舊兜底是 asset，於是帶 :id 的五族把規則／分組／
  // 通道／提供者／片段的 id 灌進 asset_id，在同號資產的時間軸上長出假事件）
  'audit_checkpoint',
  'audit_failure',
  'audit_integrity',
  'alert_rule',
  'notify_channel',
  'oidc_provider',
  'ldap_directory',
  'asset_group',
  'snippet',
  'role',
  // 單實例守衛（single-instance-guard）：系統主體寫入的守衛事件
  //（overridden／lost／regained）與管理者對快照端點的讀取列
  'instance_guard',
  // 兜底哨兵：後端 `extractResource` 對未分類路徑的回傳值。**它會出現在審計列表
  // 與篩選下拉裡，且那是刻意的**——漏分類從此可計數、可篩選、可告警，
  // 而不是靜默冒充資產。此處若不補，介面會對這批列顯示裸機器碼
  'unclassified',
]

// 失效機制值域：與後端 model/audit_failure.go 的 Mechanism* 常數雙向等同
// （audit-enums.spec.js 直讀後端原始碼斷言，缺任一邊即紅）
export const AUDIT_MECHANISM_VALUES = [
  'audit_write',
  'syslog_forward',
  'recording_probe',
  'recording_text',
  'recording_graphics',
  'session_record',
  'kek_retirement',
  // AAD 無 AAD 密文殘餘（顯式遷移的 push 面）
  'aad_residue',
  // audit-checkpoint-chain：檢查點離機錨定失效（與 syslog_forward 分開，
  // 前者的缺口不可回溯，後者恢復即補回）
  'checkpoint_anchor',
  // 鏈驗證異常按攻擊面分三碼（不按驗證層分）。
  // 結構層（檢查點自身被動）與內容層（檢查點覆蓋的審計紀錄被動）不共用碼——失效事件
  // 去重是 per-mechanism 的，合併會使其中一類在另一類未結案期間完全靜默
  'audit_chain_structure',
  'audit_chain_content',
  // 驗證本身無法完成＝機制狀態「未知」，非「無異常」（文案不得寫成後者）
  'audit_chain_verify',
  // 來源網段限定政策不可用：判定點讀不到使用者的允許清單，或儲存的清單字串
  // 無法解析。每個判定點遇此一律拒絕（不當成空清單放行），拒絕對外看起來
  // 與「來源不允許」相同——經本機制上報，營運端才在失效面板上看得見「政策壞了」
  'source_policy',
]

// AUDIT_ACTIONS[v] = { label(getter→t), tagType }；介面與 i18n 前相同
export const AUDIT_ACTIONS = Object.fromEntries(
  AUDIT_ACTION_VALUES.map((value) => [
    value,
    {
      tagType: ACTION_TAG_TYPES[value],
      get label() {
        return t(`enum.auditAction.${value}`)
      },
    },
  ])
)

// AUDIT_RESOURCES[v] = 譯文字串（getter）；v-for 消費端不變
export const AUDIT_RESOURCES = {}
for (const value of AUDIT_RESOURCE_VALUES) {
  Object.defineProperty(AUDIT_RESOURCES, value, {
    enumerable: true,
    get: () => t(`enum.auditResource.${value}`),
  })
}

export const AUDIT_MECHANISMS = {}
for (const value of AUDIT_MECHANISM_VALUES) {
  Object.defineProperty(AUDIT_MECHANISMS, value, {
    enumerable: true,
    get: () => t(`enum.mechanism.${value}`),
  })
}

// 失效原因（cause）值域：與後端 model/audit_failure.go 的 Cause* 常數雙向等同
// （audit-enums.spec.js 直讀後端原始碼斷言，缺任一邊即紅）。
// 同一組碼有兩個消費點：
//   1. audit_failure_events.cause_code（散文 cause 欄降為 fallback）
//   2. sessions.recording_error（存碼不存散文）
// 譯文與後端 notifycat cause 詞庫同文，避免 Slack 與 UI 對同一事實兩種說法。
export const AUDIT_CAUSE_VALUES = [
  'recording_probe_failed',
  'recording_start_failed',
  'recording_flush_failed',
  'recording_write_failed',
  'recording_resize_write_failed',
  'recording_stop_failed',
  'recording_file_stat_failed',
  'recording_rename_failed',
  'recording_metadata_update_failed',
  'recording_file_missing',
  'session_record_create_failed',
  'audit_write_fallback_file',
  'audit_write_batch_dropped',
  // 同步（fail-close）審計寫入失敗：逐筆留痕是交付明文的前置條件
  //（剪貼簿單筆調閱），留痕寫不進去即拒絕交付——證據未損、機制失效須揭露
  'audit_write_sync_refused',
  'syslog_connect_failed',
  'syslog_buffer_overflow',
  'kek_retirement_backlog',
  'aad_residue_impossible_state',
  'checkpoint_anchor_dropped',
  // 鏈驗證異常四碼。同一機制一輪內出現多種
  // 狀態時取較嚴重者（mismatch > extra_rows）；extra_rows 為待人工確認態，非逕判竄改
  'audit_chain_structure_invalid',
  'audit_chain_content_mismatch',
  'audit_chain_content_extra_rows',
  'audit_chain_verify_failed',
  // 來源網段限定政策的兩個成因：讀不到（DB 錯）與解析不了（清單字串損壞）。
  // 兩者對外同樣只回「來源不允許」，歸因只在此處與審計列
  'source_policy_unreadable',
  'source_policy_corrupt',
]

export const AUDIT_CAUSES = {}
for (const value of AUDIT_CAUSE_VALUES) {
  Object.defineProperty(AUDIT_CAUSES, value, {
    enumerable: true,
    get: () => t(`enum.cause.${value}`),
  })
}

export const auditActionLabel = (v) => AUDIT_ACTIONS[v]?.label || v
export const auditActionTagType = (v) => AUDIT_ACTIONS[v]?.tagType || 'info'
export const auditResourceLabel = (v) => AUDIT_RESOURCES[v] || v
export const auditMechanismLabel = (v) => AUDIT_MECHANISMS[v] || v

/**
 * auditCauseLabel 失效原因查譯。
 * 與其他 getter 不同之處在於「未知碼」的降級對象可指定：cause 有一個仍活著的
 * 散文欄（audit_failure_events.cause）與存量未碼化的 sessions.recording_error，
 * 未知碼時顯示那份散文比顯示裸碼有用。
 * @param {string|undefined} code 機器碼（權威表述）
 * @param {string} [fallback] 未知／無碼時的散文降級（省略時回傳 code 原文）
 */
export const auditCauseLabel = (code, fallback = '') =>
  AUDIT_CAUSES[code] || fallback || code || ''
