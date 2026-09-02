import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  AUDIT_ACTIONS,
  AUDIT_RESOURCES,
  AUDIT_RESOURCE_VALUES,
  AUDIT_MECHANISMS,
  AUDIT_MECHANISM_VALUES,
  AUDIT_CAUSES,
  AUDIT_CAUSE_VALUES,
  auditActionLabel,
  auditResourceLabel,
  auditMechanismLabel,
  auditCauseLabel,
} from '../audit-enums'

// 值域硬拷後端（policyDomains 金標準模式）：後端加值此測試即紅燈
// AuditAction: backend/internal/model/audit_log.go:13-42
const BACKEND_ACTIONS = [
  'create', 'read', 'update', 'delete', 'execute', 'login', 'logout',
  'unlock', 'pw_noncompliant', 'recording_failed',
  // 來源限定功能：新來源位址的登入標記（只留審計、不告警）
  'new_source_ip',
  'file_list', 'file_upload', 'file_download', 'file_mkdir', 'file_delete',
  'approve', 'reject', 'cancel', 'expire', 'revoke', 'review',
  // evidence-offsite-storage：離機保管鏈的五個事件（主體恆為系統）
  'offsite_upload', 'offsite_retention', 'offsite_integrity',
  'offsite_profile', 'offsite_cred_revoke',
]
// AuditResource: backend/internal/model/audit_log.go 的 Resource* 常數區
const BACKEND_RESOURCES = [
  'asset', 'session', 'recording', 'user', 'auth', 'file',
  'security_policy', 'command_alert', 'audit_export', 'access_review',
  'retention', 'daily_review', 'syslog_setting', 'audit_log', 'user_group',
  'command', 'key_management', 'transmission', 'access_request', 'approver_scope',
  // auditor-workbench 訂正的三個獨立分類（原落 default asset 分支）
  'change_secret_plan', 'authorization', 'audit_timeline',
  // 取走剪貼簿明文的動作獨立分類
  'clipboard_event',
  // A 類新分類十族＋兜底哨兵
  'audit_checkpoint', 'audit_failure', 'audit_integrity', 'alert_rule',
  'notify_channel', 'oidc_provider', 'ldap_directory', 'asset_group',
  'snippet', 'role',
  // 單實例守衛（single-instance-guard）
  'instance_guard',
  // 離機儲存的保管鏈事件與設定／佇列操作列（evidence-offsite-storage）
  'offsite_storage',
  // 兜底哨兵（`extractResource` 對未分類路徑的回傳值，取代舊兜底 asset）
  'unclassified',
]
// mechanism: backend/internal/model/audit_failure.go 的 Mechanism* 常數
const BACKEND_MECHANISMS = [
  'audit_write', 'syslog_forward',
  'recording_probe', 'recording_text', 'recording_graphics',
  'session_record', 'kek_retirement', 'aad_residue',
  // 指令阻斷比對器不可用（查詢主控台的 fail-close）
  'command_blocking',
  // audit-checkpoint-chain：檢查點離機錨定失效（不與 syslog_forward 合併——
  // 前者的證據缺口不可回溯，後者恢復即補回）
  'checkpoint_anchor',
  // 鏈驗證異常按攻擊面分三碼（結構層／內容層／
  // 驗證本身不可完成），不按驗證層分、亦不彼此合併
  'audit_chain_structure',
  'audit_chain_content',
  'audit_chain_verify',
  // 來源網段限定政策不可用（來源限定功能）
  'source_policy',
  // 離機儲存的上傳與取回完整性（evidence-offsite-storage）
  'offsite_upload',
]

// 後端↔前端雙向完備性守衛：直讀後端原始碼取
// 常數值域，兩側互為全集——舊版單向硬拷守衛放行過 session_record 漏項（Go 有、前端無），
// 本守衛使任一方向缺漏都紅。路徑以 cwd（frontend 根）為錨，對齊 i18n.spec.js／
// websocket-scheme-guard.spec.js 讀磁碟原始檔的慣例。
//
// 環境註記：docker-compose.dev.yml 已為 frontend 掛載
// ./backend/internal/model:/repo/backend/internal/model:ro（整個 model 目錄，
// 故 audit_failure.go 與 audit_log.go 皆可直讀），容器內雙向斷言實跑
// （已以後端假常數探針驗證紅→綠敏感性）。無掛載的環境（如純前端 CI）該案例
// skip（測試清單可見 1 skipped，非靜默通過），僅剩下方硬拷斷言把關。
// resolveBackendSource 逐一試候選路徑；找不到回 undefined（該案例 skip，見上方註記）
const resolveBackendSource = (file) =>
  [
    join(process.cwd(), `../backend/internal/model/${file}`),
    join(process.cwd(), `../../backend/internal/model/${file}`),
    `/repo/backend/internal/model/${file}`,
  ].find((p) => existsSync(p))

const backendSourcePath = resolveBackendSource('audit_failure.go')
const backendAuditLogPath = resolveBackendSource('audit_log.go')

// 抽 `MechanismXxx = "value"` 常數值（含 kek_retirement／session_record）
const parseBackendMechanisms = (src) => [
  ...new Set(
    [...src.matchAll(/^\s*Mechanism\w+\s*=\s*"([a-z0-9_]+)"/gm)].map((m) => m[1])
  ),
]

// 抽 `ResourceXxx AuditResource = "value"` 常數值（audit_log.go）。
//
// **為什麼要有這支**：resource 族原先只有下方硬拷對照組 BACKEND_RESOURCES，
// 而硬拷組與前端值域是同一次手抄——兩邊一起漏補時互相對照仍全綠
//（實際發生過：後端 24 值、兩邊各只有 20 值，介面對四值顯示機器碼）。
// 型別名必須顯式出現在正則裡：`Resource\w+` 單獨比對會誤收 AuditLog 結構的
// `ResourceID` 欄位一類宣告，而要求 `AuditResource =` 使選取只命中常數區
const parseBackendResources = (src) => [
  ...new Set(
    [...src.matchAll(/^\s*Resource\w+\s+AuditResource\s*=\s*"([a-z0-9_]+)"/gm)].map(
      (m) => m[1]
    )
  ),
]

// 抽 `CauseXxx = "value"` 常數值。
// CauseParamDetail 是參數鍵而非原因碼，其值為 "detail" 且宣告為 const 區塊，
// 正則的 `Cause\w+\s*=\s*"..."` 會誤收——顯式排除
const parseBackendCauses = (src) =>
  [
    ...new Set(
      [...src.matchAll(/^\s*Cause\w+\s*=\s*"([a-z0-9_]+)"/gm)].map((m) => m[1])
    ),
  ].filter((v) => v !== 'detail')

const BACKEND_CAUSES = [
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
  'command_audit_write_refused',
  'command_blocker_unavailable',
  'audit_write_fallback_file',
  'audit_write_batch_dropped',
  'audit_write_sync_refused',
  'syslog_connect_failed',
  'syslog_buffer_overflow',
  'kek_retirement_backlog',
  'aad_residue_impossible_state',
  'checkpoint_anchor_dropped',
  'audit_chain_structure_invalid',
  'audit_chain_content_mismatch',
  'audit_chain_content_extra_rows',
  'audit_chain_verify_failed',
  'source_policy_unreadable',
  'source_policy_corrupt',
  'offsite_upload_failed',
  'offsite_upload_stalled',
  'offsite_integrity_mismatch',
]

describe('audit-enums 完備性（前後端值域一致）', () => {
  it('AUDIT_ACTIONS 與後端 27 動作互為全集', () => {
    expect(Object.keys(AUDIT_ACTIONS).sort()).toEqual([...BACKEND_ACTIONS].sort())
    for (const a of BACKEND_ACTIONS) {
      expect(AUDIT_ACTIONS[a]?.label, `${a} 缺 label`).toBeTruthy()
      expect(AUDIT_ACTIONS[a]?.tagType, `${a} 缺 tagType`).toBeTruthy()
    }
  })

  it('AUDIT_RESOURCES 與後端 37 資源互為全集（無殭屍 alert 條目）', () => {
    expect(Object.keys(AUDIT_RESOURCES).sort()).toEqual([...BACKEND_RESOURCES].sort())
    expect(AUDIT_RESOURCES.alert).toBeUndefined()
  })

  it.skipIf(!backendAuditLogPath)(
    'resource 值域與後端原始碼常數雙向等同（直讀 audit_log.go）',
    () => {
      const parsed = parseBackendResources(readFileSync(backendAuditLogPath, 'utf8'))
      // 正則失效（後端改寫法）時集合會空掉而「意外全綠」——先鎖下界
      expect(
        parsed.length,
        '未從後端原始碼抽到 Resource 常數（正則失效？）'
      ).toBeGreaterThanOrEqual(37)
      // 雙向：後端多值（前端漏補）與前端多值（殭屍條目）皆紅
      expect(parsed.sort()).toEqual([...AUDIT_RESOURCE_VALUES].sort())
      // 硬拷對照組亦須與原始碼同步，避免對照組本身漂移（本族的既有缺口正是此點）
      expect(parsed.sort()).toEqual([...BACKEND_RESOURCES].sort())
    }
  )

  it('AUDIT_MECHANISMS 與後端 14 機制互為全集（含錄影三機制族、session_record、kek_retirement、aad_residue、checkpoint_anchor、鏈驗證三機制、source_policy、offsite_upload）', () => {
    expect(Object.keys(AUDIT_MECHANISMS).sort()).toEqual([...BACKEND_MECHANISMS].sort())
  })

  it.skipIf(!backendSourcePath)(
    'mechanism 值域與後端原始碼常數雙向等同（直讀 audit_failure.go）',
    () => {
      const parsed = parseBackendMechanisms(readFileSync(backendSourcePath, 'utf8'))
      // 正則失效（後端改寫法）時集合會空掉而「意外全綠」——先鎖下界
      expect(parsed.length, '未從後端原始碼抽到 Mechanism 常數（正則失效？）').toBeGreaterThanOrEqual(14)
      // 雙向：後端多值（前端漏補）與前端多值（殭屍條目）皆紅
      expect(parsed.sort()).toEqual([...AUDIT_MECHANISM_VALUES].sort())
      // 硬拷對照組亦須與原始碼同步，避免對照組本身漂移
      expect(parsed.sort()).toEqual([...BACKEND_MECHANISMS].sort())
    }
  )

  it('AUDIT_CAUSES 與後端失效原因互為全集', () => {
    expect(Object.keys(AUDIT_CAUSES).sort()).toEqual([...BACKEND_CAUSES].sort())
    expect(AUDIT_CAUSE_VALUES).toHaveLength(30)
  })

  it.skipIf(!backendSourcePath)(
    'cause 值域與後端原始碼常數雙向等同（直讀 audit_failure.go）',
    () => {
      const parsed = parseBackendCauses(readFileSync(backendSourcePath, 'utf8'))
      // 正則失效（後端改寫法）時集合會空掉而「意外全綠」——先鎖下界
      expect(parsed.length, '未從後端原始碼抽到 Cause 常數（正則失效？）').toBeGreaterThanOrEqual(27)
      // 雙向：後端多值（前端漏補）與前端多值（殭屍條目）皆紅
      expect(parsed.sort()).toEqual([...AUDIT_CAUSE_VALUES].sort())
      // 硬拷對照組亦須與原始碼同步，避免對照組本身漂移
      expect(parsed.sort()).toEqual([...BACKEND_CAUSES].sort())
    }
  )

  it('未知值優雅退回原文', () => {
    expect(auditActionLabel('future_action')).toBe('future_action')
    expect(auditResourceLabel('future_resource')).toBe('future_resource')
    expect(auditMechanismLabel('future_mechanism')).toBe('future_mechanism')
  })

  it('auditCauseLabel：已知碼查譯、未知碼優先退回散文 fallback', () => {
    expect(auditCauseLabel('recording_file_missing')).toBe('錄影檔缺失（寫入失敗或錄製未啟動）')
    // 未知碼（存量散文存在 recording_error／cause 欄）→ 顯示散文而非裸碼
    expect(auditCauseLabel('future_cause', '舊版散文原因')).toBe('舊版散文原因')
    // 無碼（audit_failure 存量列）→ 散文
    expect(auditCauseLabel('', '舊版散文原因')).toBe('舊版散文原因')
    expect(auditCauseLabel(undefined, '')).toBe('')
    // 無散文可退時保留碼，不吞資訊
    expect(auditCauseLabel('future_cause')).toBe('future_cause')
  })
})
