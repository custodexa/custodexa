package database

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

// SchemaMigration 追蹤已執行的 migrations
type SchemaMigration struct {
	Version   string    `gorm:"primaryKey;size:50"`
	AppliedAt time.Time `gorm:"not null"`
}

// TableName 指定表名
func (SchemaMigration) TableName() string {
	return "schema_migrations"
}

// Migration 定義單個 migration
type Migration struct {
	Version string
	Name    string
	Up      func(*gorm.DB) error
	Down    func(*gorm.DB) error
}

// migrations 所有可用的 migrations（按版本順序）。
//
// **baseline ＋ 其後的增量**：壓縮前的 49 條增量 migration 已
// 退場，其最終 schema 形狀併入 baseline，其存量回填在全新資料庫上一律零列。
// 「不提供就地升級」的 fail-close 只針對**壓縮前**的資料庫（見 RunMigrations）；
// baseline 之後的新表／新欄回歸標準增量形態，全新庫依序跑 baseline→增量，
// 既有（已套 baseline 的）庫只補增量。
var migrations = []Migration{
	{
		Version: BaselineVersion,
		Name:    "schema_baseline",
		Up:      applyBaseline,
		Down:    refuseBaselineRollback,
	},
	{
		// 證據包非同步匯出 job 表
		Version: "20260824_audit_export_jobs",
		Name:    "audit_export_jobs",
		Up:      applyAuditExportJobs,
		Down:    rollbackAuditExportJobs,
	},
	{
		// 離機儲存：offsite_profiles 設定世代表（含信封加密憑證）、
		// offsite_objects 保管帳冊、兩張擁有表的指標與快取欄。
		// **Down 為資料追蹤不可逆**（見 migration_evidence_offsite.go 檔頭）
		Version: "20260825_evidence_offsite",
		Name:    "evidence_offsite",
		Up:      applyEvidenceOffsite,
		Down:    rollbackEvidenceOffsite,
	},
	{
		// 來源位址追查：users.allowed_cidrs、user_source_ips 基準表、兩條索引、
		// command_alerts kind 值域擴充與冷啟動回填。**Down 銷毀資料、開發庫限定**
		// （見 migration_source_ip_forensics.go 檔頭）
		Version: "20260826_source_ip_forensics",
		Name:    "source_ip_forensics",
		Up:      applySourceIPForensics,
		Down:    rollbackSourceIPForensics,
	},
	{
		// 查詢主控台：assets.allowed_databases、sessions.db_console、
		// session_commands 十一個結果事實欄、三條 CHECK、三個索引。
		// **Down 有損**（刪政策欄與稽核證據欄，生產無回滾入口；
		// 見 migration_db_query_console.go 檔頭的 Down 契約）
		Version: "20260826_db_query_console",
		Name:    "db_query_console",
		Up:      applyDBQueryConsole,
		Down:    rollbackDBQueryConsole,
	},
	{
		// 政策值欄位放寬為 text，容納文字型政策鍵。純型別擴張、無資料回填；
		// Down 收窄回 varchar(128)，存量超長時由資料庫報錯並回滾整個交易
		//（見 migration_security_policies_value_text.go 檔頭的 Down 契約）
		Version: "20260903_security_policies_value_text",
		Name:    "security_policies_value_text",
		Up:      applySecurityPoliciesValueText,
		Down:    rollbackSecurityPoliciesValueText,
	},
	{
		// 輪替證據報告的資料層：asset_accounts.credential_group、
		// change_secret_plans.max_age_days、audit_export_jobs.kind 三個加欄
		// 與新表 rotation_report_schedules。**Down 有損**（刪政策設定、
		// 共用憑證標示與全部排程定義，生產無回滾入口；
		// 見 migration_rotation_evidence_report.go 檔頭的 Down 契約）
		Version: "20260903_rotation_evidence_report",
		Name:    "rotation_evidence_report",
		Up:      applyRotationEvidenceReport,
		Down:    rollbackRotationEvidenceReport,
	},
	{
		// Windows 本機帳號改密的資料層：assets 六個改密通道側車欄
		// （rotation_channel 與 WinRM／SSH 的附屬設定）。全部純加法，
		// rotation_channel 預設空字串＝依協定推導，升級零行為變更。
		// **Down 有損**（刪除全部改密通道設定，生產無回滾入口；
		// 見 migration_windows_local_account_rotation.go 檔頭的 Down 契約）
		Version: "20260904_windows_local_account_rotation",
		Name:    "windows_local_account_rotation",
		Up:      applyWindowsLocalAccountRotation,
		Down:    rollbackWindowsLocalAccountRotation,
	},
	{
		// 以帳號為主軸的批次改密的資料層：新表 change_secret_batches、
		// change_secret_records.batch_id、change_secret_candidates.batch_id／shared_group。
		// 純加法、存量列以 default 回填為「來自計劃」。**Down 有損**（刪批次彙總
		// 與來源辨識，生產無回滾入口；見 migration_account_batch_rotation.go 檔頭的 Down 契約）
		Version: "20260905_account_batch_rotation",
		Name:    "account_batch_rotation",
		Up:      applyAccountBatchRotation,
		Down:    rollbackAccountBatchRotation,
	},
	{
		// 帳號憑證庫的資料層：四張新表（credentials、credential_secret_versions、
		// credential_rotations、credential_rotation_members）、asset_accounts 的
		// 兩個掛載欄與其唯一鍵、三張改密表的目標與快照欄，以及既有帳號轉專用憑證
		// 的存量搬移。**需要金鑰的兩步不在此**（段 1 無 codec）：密文的欄位身分
		// 改綁與隱性共用合併走解封後佇列的 credential_secret_conversion。
		// **Down 有損**（刪除全部共用憑證關係與版本歷史，生產無回滾入口；
		// 見 migration_credential_library.go 檔頭的 Down 契約）
		Version: "20260906_credential_library",
		Name:    "credential_library",
		Up:      applyCredentialLibrary,
		Down:    rollbackCredentialLibrary,
	},
	{
		// 帳號憑證庫的收縮：卸下 asset_accounts 的兩個密文欄、兩張改密表的
		// 群組識別欄與群組索引。**asset_accounts.credential_group 刻意留著**
		// ——它的唯一讀者是解封後的存量轉換，而解封後佇列必然晚於段 1 的全部
		// migration（見 migration_credential_library_contract.go 檔頭）。
		// **Down 有損**（只還原空殼、不還原資料，生產無回滾入口）
		Version: "20260906_credential_library_contract",
		Name:    "credential_library_contract",
		Up:      applyCredentialLibraryContract,
		Down:    rollbackCredentialLibraryContract,
	},
	{
		// 角色指派納入檢查點鏈的資料層：audit_checkpoints 四個可空欄
		// （role_state_hash／role_state_snapshot／role_state_count／
		// role_state_reconciled）。純加欄、無回填、無索引；既有列留空即
		// 「該檢查點不涵蓋角色指派」。**Down 純刪欄**，但須連同產品版本一起
		// 回退（見 migration_role_state_checkpoint.go 檔頭的 Down 契約）
		Version: "20260908_role_state_checkpoint",
		Name:    "role_state_checkpoint",
		Up:      applyRoleStateCheckpoint,
		Down:    rollbackRoleStateCheckpoint,
	},
	{
		// 外部群組對角色映射的資料層：user_roles.source（來源三態）、
		// 新表 group_role_mappings（映射規則）與 user_role_mappings（映射事實）、
		// oidc_providers 的宣告對應三欄。存量列一律落在「管理者指派」，
		// 未設定映射規則的部署行為不變。**Down 有損**（來源標記與映射規則
		// 不可還原，生產無回滾入口；見 migration_group_role_mapping.go 檔頭的 Down 契約）
		Version: "20260908_group_role_mapping",
		Name:    "group_role_mapping",
		Up:      applyGroupRoleMapping,
		Down:    rollbackGroupRoleMapping,
	},
	{
		// 政策組的資料層：四張新表（policy_groups、policy_clauses、
		// policy_clause_controls、policy_clause_annotations）與一條唯一索引。
		// 純加表，既有行為零變更；內建組的內容由啟動種子 upsert。
		// **Down 有損**（機構自建的組、條文、備註與人工確認記錄無第二處存放，
		// 生產無回滾入口；見 migration_policy_groups.go 檔頭的 Down 契約）
		Version: "20260909_policy_groups",
		Name:    "policy_groups",
		Up:      applyPolicyGroups,
		Down:    rollbackPolicyGroups,
	},
	{
		// 委託拓撲的資料層：單列表 kek_topologies（服務商、Vault 位址、
		// Transit 金鑰名、AppRole 角色識別、AWS 服務區域）。全部明文欄位
		// ——**封存狀態下須可讀，不得加密**（見 migration_kek_topology.go 檔頭）。
		// 秘密不入本表。**Down 有損**（拓撲設定無第二處存放，生產無回滾入口）
		Version: "20260913_kek_topology",
		Name:    "kek_topology",
		Up:      applyKEKTopology,
		Down:    rollbackKEKTopology,
	},
	{
		// 輸出敏感資料規則：direction＋CHECK，並插入兩條輸出規則終態種子。
		// Down 有損（方向值無第二處存放；見 migration_alert_rule_direction.go）。
		Version: "20260921_alert_rule_direction",
		Name:    "alert_rule_direction",
		Up:      applyAlertRuleDirection,
		Down:    rollbackAlertRuleDirection,
	},
	{Version: "20260921_agent_audit_actions", Name: "agent_audit_actions", Up: expandAgentAuditActions, Down: rollbackIdentityAgentPrincipal},
	{Version: "20260921_identity_agent_principal", Name: "identity_agent_principal", Up: applyIdentityAgentPrincipal, Down: rollbackIdentityAgentPrincipal},
	{Version: "20260921_principal_integrity", Name: "principal_integrity", Up: applyPrincipalIntegrity, Down: rollbackIdentityAgentPrincipal},
	{Version: "20260921_access_request_items", Name: "access_request_items", Up: applyAccessRequestItems, Down: rollbackAccessRequestItems},
	{Version: "20260921_access_request_item_decisions", Name: "access_request_item_decisions", Up: applyAccessRequestItemDecisions, Down: rollbackAccessRequestItems},
	{Version: "20260921_agent_audit_ledger", Name: "agent_audit_ledger", Up: applyAgentAuditLedger, Down: rollbackAgentAuditLedger},
	{Version: "20260921_agent_breaker_alert", Name: "agent_breaker_alert", Up: applyAgentBreakerAlert, Down: rollbackAgentBreakerAlert},
	{Version: "20260921_agent_visibility_exposures", Name: "agent_visibility_exposures", Up: applyAgentVisibilityExposures, Down: rollbackAgentVisibilityExposures},
	{Version: "20260921_agent_subject_rules", Name: "agent_subject_rules", Up: applyAgentSubjectRules, Down: rollbackAgentSubjectRules},
	{Version: "20260922_agent_session_token_name", Name: "agent_session_token_name", Up: applyAgentSessionTokenName, Down: rollbackAgentSessionTokenName},
	// 純資料 migration（無 schema 變更）：既有站點的出廠橫向移動規則改用指令位置比對。
	{Version: "20260923_agent_lateral_rule_pattern", Name: "agent_lateral_rule_pattern", Up: applyAgentLateralRulePattern, Down: rollbackAgentLateralRulePattern},
	{Version: "20260924_agent_tool_call_args_retained", Name: "agent_tool_call_args_retained", Up: applyAgentToolCallArgsRetained, Down: rollbackAgentToolCallArgsRetained},
	{Version: "20260924_sensitive_reveal_alert", Name: "sensitive_reveal_alert", Up: applySensitiveRevealAlert, Down: rollbackSensitiveRevealAlert},
	{
		// 通知通道推送門檻：min_severity＋CHECK，既有列取 low（行為不變）。
		// Down 有損但方向安全（回到全部推送；見 migration_notification_channel_min_severity.go）
		Version: "20260929_notification_channel_min_severity",
		Name:    "notification_channel_min_severity",
		Up:      applyNotificationChannelMinSeverity,
		Down:    rollbackNotificationChannelMinSeverity,
	},
	{Version: "20260930_identity_group_mappings", Name: "identity_group_mappings", Up: applyIdentityGroupMappings, Down: rollbackIdentityGroupMappings},
	{
		// 每日簽核改版：daily_review_logs 加所屬日與簽核時刻分欄所需的欄位並回填，
		// 新表 security_policy_history 與升級前啟用歷史的重建。
		// **Down 有損**（失去延遲原因、時區、遲簽標示與變更歷史，生產無回滾入口；
		// 見 migration_daily_review_signoff.go 檔頭的 Down 契約）
		Version: "20261012_daily_review_signoff",
		Name:    "daily_review_signoff",
		Up:      applyDailyReviewSignoff,
		Down:    rollbackDailyReviewSignoff,
	},
	{
		// 權限模型：內建範本識別、指派範圍種類、
		// 群組指派、節點範圍、權限狀態。**不提供 Down**：回退只走還原升級前備份。
		Version: "20261016_authz_permission_model",
		Name:    "authz_permission_model",
		Up:      applyAuthzPermissionModel,
		Down:    rollbackAuthzPermissionModel,
	},
	{
		// 權限附證與恢復世代（權限模型調和與還原）：權限狀態事件表、檢查點附證欄、
		// 持久恢復世代與票證簽發世代欄。只加結構、不回填；**不提供 Down**。
		Version: "20261017_permission_state_attestation",
		Name:    "permission_state_attestation",
		Up:      applyPermissionStateAttestation,
		Down:    rollbackPermissionStateAttestation,
	},
	{
		// 權限狀態事件的逐列完整性驗證碼（與審計列同一組完整性密鑰）。只加兩欄、不回填；
		// 既有列保持未蓋章，對帳時視為不可信並告警。**不提供 Down**。
		Version: "20261017_permission_state_event_integrity",
		Name:    "permission_state_event_integrity",
		Up:      applyPermissionEventIntegrity,
		Down:    rollbackPermissionEventIntegrity,
	},
	{
		// 角色定義：定義版本、起手來源、自訂權限集合、
		// 兩個鎖定管理範本。**不提供 Down**：回退只走還原升級前備份。
		Version: "20261017_role_definitions",
		Name:    "role_definitions",
		Up:      applyRoleDefinitions,
		Down:    rollbackRoleDefinitions,
	},
	{
		// 系統安全告警：來源類別 system_security、明細、持久投遞佇列與分級覆寫三張表。
		// 只加結構、不回填；**不提供 Down**（證據不得被回滾刪除）。
		Version: "20261018_system_security_alerts",
		Name:    "system_security_alerts",
		Up:      applySystemSecurityAlerts,
		Down:    rollbackSystemSecurityAlerts,
	},
	{
		// 主機指紋記錄的撥號位址：asset_host_keys 加 host、port、reset_pending 與
		// (host, port) 索引，並回填既有列（含已軟刪資產）。**不提供 Down**：回退只走升級前備份。
		Version: "20261019_asset_host_key_address",
		Name:    "asset_host_key_address",
		Up:      applyHostKeyAddress,
		Down:    rollbackHostKeyAddress,
	},
	{
		// 逐（帳號，通道）最近已知群組觀測時間（外部角色映射用）：
		// 有界重新驗證判定未知觀測是否超時的依據。新增一張表並由既有快照回填該通道；
		// 回填可重入。**不提供 Down**：回退只走還原升級前備份。
		Version: "20261020_mapping_observation_times",
		Name:    "mapping_observation_times",
		Up:      applyMappingObservationTimes,
		Down:    rollbackMappingObservationTimes,
	},
	{
		// 檢查點第四版載荷：權限附證改由檢查點自己的簽章涵蓋。audit_checkpoints 加起點旗標欄、
		// 卸下獨立附證簽章欄並加一條附證痕跡部分索引；修剪錨加載荷版本與累計權限事實三欄。
		// 只改結構、無資料步驟；**不提供 Down**：回退只走還原升級前備份。
		Version: "20261018_checkpoint_v4_attestation",
		Name:    "checkpoint_v4_attestation",
		Up:      applyCheckpointV4Attestation,
		Down:    rollbackCheckpointV4Attestation,
	},
	{
		// 憑證背景工作授權：不可變授權脈絡表、計畫／批次／輪替／候選的授權引用、
		// 輪替成員的 dispatch claim 欄；資料步驟對升級前已啟用的排程計畫回填發起者，
		// 完全查不到可歸屬者的才暫停。**不提供 Down**：回退只走還原升級前備份。
		Version: "20261022_credential_job_authorization",
		Name:    "credential_job_authorization",
		Up:      applyCredentialJobAuthorization,
		Down:    rollbackCredentialJobAuthorization,
	},
	{
		// 失權後有限驗證的告警去重：候選與輪替成員各加 recovery_alerted_at。
		// 只加欄、不回填；**不提供 Down**：回退只走還原升級前備份。
		Version: "20261023_credential_recovery_alert",
		Name:    "credential_recovery_alert",
		Up:      applyCredentialRecoveryAlert,
		Down:    rollbackCredentialRecoveryAlert,
	},
	{
		// 系統安全告警投遞識別：system_alert_outbox 加 delivery_key 與唯一索引，既有列各回填一個隨機值。
		// 送給收端的投遞識別改用它，還原備份後不會與還原前發出的識別重複。**不提供 Down**：回退只走還原升級前備份。
		Version: "20261024_system_alert_delivery_key",
		Name:    "system_alert_delivery_key",
		Up:      applySystemAlertDeliveryKey,
		Down:    rollbackSystemAlertDeliveryKey,
	},
	{
		// 主機金鑰不符觀察紀錄：新表 asset_host_key_mismatches 與（資產、出示指紋）唯一索引。
		// 不回填、不動 asset_host_keys。**不提供 Down**：回退只走還原升級前備份。
		Version: "20261025_host_key_mismatch",
		Name:    "host_key_mismatch",
		Up:      applyHostKeyMismatch,
		Down:    rollbackHostKeyMismatch,
	},
	{
		// 保留下限抬升紀錄：新表 security_policy_floor_raises。只建表、不回填；
		// 保留值的抬升在啟動對帳內做。**不提供 Down**：回退只走還原升級前備份。
		Version: "20261026_security_policy_floor_raises",
		Name:    "security_policy_floor_raises",
		Up:      applySecurityPolicyFloorRaises,
		Down:    rollbackSecurityPolicyFloorRaises,
	},
	{
		// 憑證主機身分：asset_host_keys 加主機信任世代；候選與輪替成員加綁定欄，成員另加派送標記；
		// 新表 credential_host_identity_confirmations（無外鍵）。唯一的資料步驟是對 legacy 成員依既有
		// 證據保守寫入派送標記，快照欄不回填。世代由應用程式推進，不建資料庫觸發器。
		// **不提供 Down**：回退只走還原升級前備份。
		Version: "20261027_credential_host_identity",
		Name:    "credential_host_identity",
		Up:      applyCredentialHostIdentity,
		Down:    rollbackCredentialHostIdentity,
	},
	{
		// 使用者版本說明關閉狀態：新表 user_release_guidance。只建表、不回填，缺列即尚未關閉。
		// **不提供 Down**：回退只走還原升級前備份。
		Version: "20261028_user_release_guidance",
		Name:    "user_release_guidance",
		Up:      applyUserReleaseGuidance,
		Down:    rollbackUserReleaseGuidance,
	},
	{
		// 憑證管理歸屬：credentials 加 owner_kind、owner_node_id 與複合索引；新表 credential_impact_confirmations。
		// 資料步驟只填 owner_kind 為 NULL 的列（共用→global、專用→asset），套用後重算報告不一致即回滾；
		// 報告以固定前綴寫日誌供試跑與正式升級比對。**不提供 Down**：回退只走還原升級前備份。
		Version: "20261029_credential_ownership",
		Name:    "credential_ownership",
		Up:      applyCredentialOwnership,
		Down:    rollbackCredentialOwnership,
	},
	{
		// 改密範圍欄位：change_secret_batches 加共用憑證歸屬兩欄（既有列取 global）、
		// credential_job_authorizations 加計畫掛載上界（既有列為空）。只加欄，不回填。**不提供 Down**。
		Version: "20261031_change_secret_scope_columns",
		Name:    "change_secret_scope_columns",
		Up:      applyChangeSecretScopeColumns,
		Down:    rollbackChangeSecretScopeColumns,
	},
	{
		// 內建識別值域加入兩個範圍化管理範本（roles_builtin_key_check 重建）。只有 DDL，不種任何角色列
		// （列由啟動資料步驟在權限附證來源注入後種入）。**不提供 Down**：回退只走還原升級前備份。
		Version: "20261101_scoped_template_builtin_keys",
		Name:    "scoped_template_builtin_keys",
		Up:      applyScopedTemplateBuiltinKeys,
		Down:    rollbackScopedTemplateBuiltinKeys,
	},
}

// schemaDDLStatements 全部 schema DDL：baseline ＋ baseline 之後的增量建表／加欄／刪欄。
//
// **parity 守衛的解析對象**（schema_parity_test.go 第 1 層；pg 兩層測試以
// applyBaseline＋applyMigrationsAfterBaseline 建出同一形狀）：schema 事實源自
// 增量 migration 出現起即為「baseline＋增量」的串接，守衛只看 baseline 會讓
// 增量表的漂移整張脫離射程。**不供執行**——執行面由 RunMigrations 依已套用
// 集合分別跑，兩者串接執行會在全新庫上重複建表。回填語句不在此列（不是 schema）。
// MigrationVersions 已登記的增量 migration 版本（依登記順序）。
// 供測試與營運檢查核對「某項結構由哪個 migration 建立」，不執行任何 migration。
func MigrationVersions() []string {
	out := make([]string, len(migrations))
	for i, m := range migrations {
		out[i] = m.Version
	}
	return out
}

func schemaDDLStatements() []string {
	out := append(baselineSchemaStatements(), auditExportJobsDDL()...)
	out = append(out, evidenceOffsiteDDL()...)
	out = append(out, sourceIPForensicsDDL()...)
	out = append(out, dbQueryConsoleDDL()...)
	out = append(out, rotationEvidenceReportDDL()...)
	out = append(out, windowsLocalAccountRotationDDL()...)
	out = append(out, accountBatchRotationDDL()...)
	out = append(out, credentialLibraryDDL()...)
	out = append(out, credentialLibraryContractDDL()...)
	out = append(out, roleStateCheckpointDDL()...)
	out = append(out, groupRoleMappingDDL()...)
	out = append(out, policyGroupsDDL()...)
	out = append(out, kekTopologyDDL()...)
	out = append(out, alertRuleDirectionDDL()...)
	out = append(out, identityAgentPrincipalDDL()...)
	out = append(out, principalIntegrityDDL()...)
	out = append(out, accessRequestItemsDDL()...)
	out = append(out, accessRequestItemDecisionsDDL()...)
	out = append(out, agentAuditLedgerDDL()...)
	out = append(out, agentToolCallArgsRetainedDDL()...)
	out = append(out, agentBreakerAlertDDL()...)
	out = append(out, agentVisibilityExposuresDDL()...)
	out = append(out, sensitiveRevealAlertDDL()...)
	out = append(out, agentSessionTokenNameDDL()...)
	out = append(out, notificationChannelMinSeverityDDL()...)
	out = append(out, identityGroupMappingsDDL()...)
	out = append(out, dailyReviewSignoffDDL()...)
	out = append(out, authzPermissionModelDDL()...)
	out = append(out, permissionStateAttestationDDL()...)
	out = append(out, permissionEventIntegrityDDL()...)
	out = append(out, roleDefinitionsDDL()...)
	out = append(out, systemSecurityAlertsDDL()...)
	out = append(out, hostKeyAddressDDL()...)
	out = append(out, mappingObservationTimesDDL()...)
	out = append(out, checkpointV4AttestationDDL()...)
	out = append(out, credentialJobAuthorizationDDL()...)
	out = append(out, credentialRecoveryAlertDDL()...)
	out = append(out, systemAlertDeliveryKeyDDL()...)
	out = append(out, hostKeyMismatchDDL()...)
	out = append(out, securityPolicyFloorRaisesDDL()...)
	out = append(out, credentialHostIdentityDDL()...)
	out = append(out, userReleaseGuidanceDDL()...)
	out = append(out, credentialOwnershipDDL()...)
	return append(out, changeSecretScopeColumnsDDL()...)
}

// applyMigrationsAfterBaseline 依序執行 baseline 之後的全部增量（pg parity
// 測試在 applyBaseline 後補齊終態形狀用；生產路徑一律走 RunMigrations）。
func applyMigrationsAfterBaseline(db *gorm.DB) error {
	for _, m := range migrations[1:] {
		if err := m.Up(db); err != nil {
			return fmt.Errorf("增量 %s 失敗: %w", m.Version, err)
		}
	}
	return nil
}

// LDAPSeedMarkerVersion LDAP env→DB seed 的執行標記（寫入 schema_migrations 的 version）。
//
// **定義於 repository 而非 service**：本標記由 service 的 seed
// 寫入，兩端必須是同一個字串。repository 不得依賴 service（現行相依方向是
// service → repository，反向即循環），故常數落在兩者都可依賴的下層，service 端以
// `ldapSeedMarker = database.LDAPSeedMarkerVersion` 引用，杜絕字面值各寫一份而漂移。
//
// 它**不是** migrations 清單裡的版本項（seed 不是 versioned migration，而是
// post-unseal 佇列項），只是共用 schema_migrations 表做冪等標記。
const LDAPSeedMarkerVersion = "20260804_ldap_env_seeded"

// runtimeMarkerVersions 由執行期寫入 schema_migrations、但**不是** migration 的版本值。
//
// 這些列永遠不會出現在 `migrations` 陣列裡（它們是模組自己的冪等標記，借用
// schema_migrations 當 marker 表）。fail-close 的未知版本判定必須先扣掉它們，
// 否則**每一個跑過 LDAP env seed 的全新安裝，都會在第二次啟動時被自己的
// fail-close 擋住**——marker 是第一次啟動後才寫入的。
//
// 新增執行期 marker 而未登記於此，即為上述形態的復發。守衛：
// `runtime_marker_registry_test.go` 的 TestRuntimeMarkerVersionsCoverAllWriters。
// OffsiteSeedMarkerVersion 離機儲存設定 env→DB seed 的執行標記。
//
// 定義於 repository 的理由同 LDAPSeedMarkerVersion（寫入端在 internal/offsite，
// 而 repository 不得依賴上層，故常數落在兩端都可依賴的下層）。
//
// **語義是「已完成評估」而非「已建立資料」**：實際 seed、env 未設定而跳過、
// 表非空而跳過三種**終局**皆寫入；只有基礎設施失敗與 env 組態矛盾不寫，
// 留待下次啟動重試。marker 隨資料庫備份還原——「marker 在而 offsite_profiles
// 零列」是真實可達的部署狀態，其終局＝未設定，只能經管理介面重新設定
// （營運文件明載；env 不再回灌）。
const OffsiteSeedMarkerVersion = "20260825_offsite_env_seeded"

// ApproverScopeKeyMarkerVersion 申請人型審核範圍管理鍵補鍵資料步驟的執行標記。
//
// 語義是「已完成評估」：補鍵只在升級後的第一次啟動執行一次，之後不再挑候選——否則管理員刻意撤掉某角色的
// 申請人型管理鍵後，下次重啟會被補回。寫入端在 internal/modules/identity（GORM 建立，非原生 INSERT）。
const ApproverScopeKeyMarkerVersion = "20261030_approver_scope_management_key"

var runtimeMarkerVersions = []string{
	LDAPSeedMarkerVersion,
	ApproverScopeKeyMarkerVersion,
	OffsiteSeedMarkerVersion,
	// 憑證密文的欄位身分改綁與既有隱性共用關係的合併：兩者都需要 codec，
	// 故走解封後佇列而非 versioned migration，以本標記記錄「已評估完畢」
	//（見 credential_secret_conversion.go 檔頭）
	CredentialSecretConversionMarkerVersion,
}

// schemaMigrationsBootstrapDDL 追蹤表自身的建立語句。
//
// **這是產品程式碼中唯一的 `IF NOT EXISTS`**：schema_migrations 有雞生蛋問題
// ——必須先於「讀取已套用集合」而存在，故它不能由 baseline 建立（baseline 的執行
// 與否正是要靠讀它來判定）。除此之外，baseline 的 DDL 一律無條件。
//
// 欄位形狀與壓縮前由 GORM 依 SchemaMigration model 自動建出的產物逐欄相同
// （varchar(50) NOT NULL / timestamptz NOT NULL / PK on version），
// 使既有安裝與全新安裝在這張表上不分歧。
const schemaMigrationsBootstrapDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version varchar(50) NOT NULL,
	applied_at timestamp with time zone NOT NULL,
	CONSTRAINT schema_migrations_pkey PRIMARY KEY (version)
)`

// unknownAppliedVersions 已套用集合中，既非本版程式碼宣告、也非執行期 marker 的版本值。
func unknownAppliedVersions(applied map[string]bool) []string {
	known := make(map[string]bool, len(migrations)+len(runtimeMarkerVersions))
	for _, m := range migrations {
		known[m.Version] = true
	}
	for _, v := range runtimeMarkerVersions {
		known[v] = true
	}
	var out []string
	for v := range applied {
		if !known[v] {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// legacySchemaError 既有（壓縮前）資料庫的拒絕啟動訊息。
//
// 形態沿 config.ValidateDatabaseDriver 的既有慣例：陳述現況 → 為什麼擋 →
// 具體怎麼做 → 澄清常見誤解。不含任何連線字串、密碼或主機位址。
func legacySchemaError(unknown []string) error {
	shown := unknown
	const maxShown = 10
	suffix := ""
	if len(shown) > maxShown {
		shown = shown[:maxShown]
		suffix = fmt.Sprintf("（另有 %d 筆未列出）", len(unknown)-maxShown)
	}
	return fmt.Errorf(
		"拒絕啟動：資料庫的 schema_migrations 內有 %d 筆本版程式碼不認得的 migration 版本%s：%s\n"+
			"  本版本以單一 schema baseline（%s）作為 schema 的唯一事實源，"+
			"壓縮前的逐條 migration 已不存在，因此**不提供既有資料庫的就地升級路徑**。\n"+
			"  處置：建立一個全新的空資料庫並讓服務對它啟動（開發環境即重建 dev 資料庫；"+
			"正式環境請依 docs/ops/upgrade-sop.md 評估，該文件明載本版不提供 migration 回滾）。\n"+
			"  這**不是資料庫損毀**：資料仍在原處，只是本版程式碼無法沿用它的 schema。\n"+
			"  **不要手動刪除 schema_migrations 的列來繞過本檢查**："+
			"那會讓 baseline 在既有 schema 上執行，而 baseline 的建表語句是無條件的，"+
			"第一句 CREATE TABLE 就會撞上既有表而中止，留下的是一個既非舊版也非新版的資料庫。",
		len(unknown), suffix, strings.Join(shown, ", "), BaselineVersion)
}

// RunMigrations 執行所有未執行的 migrations
func RunMigrations() error {
	log.Println("開始執行 database migrations...")

	// 1. 確保 schema_migrations 表存在
	if err := DB.Exec(schemaMigrationsBootstrapDDL).Error; err != nil {
		return fmt.Errorf("建立 schema_migrations 表失敗: %w", err)
	}

	// 2. 獲取已執行的 migrations
	var appliedMigrations []SchemaMigration
	if err := DB.Find(&appliedMigrations).Error; err != nil {
		return fmt.Errorf("查詢已執行 migrations 失敗: %w", err)
	}

	appliedVersions := make(map[string]bool)
	for _, m := range appliedMigrations {
		appliedVersions[m.Version] = true
	}

	// 3. fail-close：既有（壓縮前）資料庫一律拒絕啟動。
	//
	// **判定必須在任何 Up 之前**：走到這裡尚未產生任何寫入，故拒絕啟動時資料庫
	// 一個位元都沒動。若讓 baseline 對既有庫跑下去，最好的結果是建表衝突而中止，
	// 最壞的結果是種子重複寫入而告警靜默翻倍。
	//
	// 已套用 baseline 的資料庫不在此列：那時的未知版本屬降版情境，
	// 沿既有的單向比對語義忽略。
	if unknown := unknownAppliedVersions(appliedVersions); len(unknown) > 0 && !appliedVersions[BaselineVersion] {
		return legacySchemaError(unknown)
	}

	// 4. 執行未執行的 migrations
	executedCount := 0
	for _, migration := range migrations {
		if appliedVersions[migration.Version] {
			log.Printf("  跳過已執行的 migration: %s (%s)", migration.Version, migration.Name)
			continue
		}

		log.Printf("  執行 migration: %s (%s)", migration.Version, migration.Name)

		// 在 transaction 中執行 migration
		if err := DB.Transaction(func(tx *gorm.DB) error {
			// 執行 Up 函數
			if err := migration.Up(tx); err != nil {
				return err
			}

			// 記錄到 schema_migrations
			record := SchemaMigration{
				Version:   migration.Version,
				AppliedAt: time.Now(),
			}
			if err := tx.Create(&record).Error; err != nil {
				return fmt.Errorf("記錄 migration 失敗: %w", err)
			}

			return nil
		}); err != nil {
			return fmt.Errorf("執行 migration %s 失敗: %w", migration.Version, err)
		}

		log.Printf("  Migration %s 執行成功", migration.Version)
		executedCount++
	}

	if executedCount == 0 {
		log.Println("所有 migrations 都已執行，無需更新")
	} else {
		log.Printf("成功執行 %d 個 migration(s)", executedCount)
	}

	return nil
}

// RollbackMigration 回滾指定版本的 migration（謹慎使用）。
//
// **本版本沒有任何可回滾的 migration**：唯一的 migration 是 schema baseline，
// 其 Down 一律回拒絕錯誤（見 baseline.go 的 refuseBaselineRollback）。本函式保留
// 供 baseline 之後的增量 migration 使用，屆時仍走同一條「Down 成功才刪版本列」的路徑。
func RollbackMigration(version string) error {
	log.Printf("開始回滾 migration: %s", version)

	// 查找 migration
	var targetMigration *Migration
	for i := range migrations {
		if migrations[i].Version == version {
			targetMigration = &migrations[i]
			break
		}
	}

	if targetMigration == nil {
		return fmt.Errorf("找不到 migration 版本: %s", version)
	}

	// 檢查是否已執行
	var record SchemaMigration
	if err := DB.Where("version = ?", version).First(&record).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return fmt.Errorf("migration %s 尚未執行，無法回滾", version)
		}
		return fmt.Errorf("查詢 migration 記錄失敗: %w", err)
	}

	// 在 transaction 中執行回滾
	if err := DB.Transaction(func(tx *gorm.DB) error {
		// 執行 Down 函數
		if err := targetMigration.Down(tx); err != nil {
			return err
		}

		// 刪除 migration 記錄
		if err := tx.Delete(&record).Error; err != nil {
			return fmt.Errorf("刪除 migration 記錄失敗: %w", err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("回滾 migration 失敗: %w", err)
	}

	log.Printf("Migration %s 回滾成功", version)
	return nil
}
