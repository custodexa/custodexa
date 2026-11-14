// Package auditattribution 守衛：稽核列的每一個產生點都必須登錄它把 API token 標示帶到寫入面的傳遞機制。
//
// 以 API token 認證的請求在處理期間產生的每一筆稽核列都要帶 token 的識別與名稱快照。產生點分散在
// HTTP 稽核中介層、handler 自組的條目與請求欄位、服務層交易內寫入面的事件、資料層依交易 context
// 寫入的列等處，每一處的傳遞方式不同。本守衛掃描正式程式碼中所有帶欄位的稽核條目、稽核事件與
// 稽核資料列字面值，以「檔案#函式」為鍵與下方登錄雙向比對：新產生點未登錄即失敗，登錄了已不存在的
// 產生點也失敗。可由原始碼判讀的機制另做靜態檢查（字面值確實經過歸因函式、請求欄位確實帶標示）；
// 依交易 context 歸因的機制由各模組的行為測試斷言。
package auditattribution

import (
	"sort"
	"strings"
	"testing"
)

type mechanism string

const (
	// classMiddleware HTTP 稽核中介層：條目落地前以 AttributeAuditEntry 補上請求的 token 標示。
	classMiddleware mechanism = "middleware"
	// classHandlerEntry handler 自組的稽核條目：字面值直接作為 AttributeAuditEntry 的引數。
	classHandlerEntry mechanism = "handler-entry"
	// classHandlerMeta handler 自組的寫入面事件：請求欄位經 AttributeAuditMeta 補上標示。
	classHandlerMeta mechanism = "handler-meta"
	// classCarried 操作者或操作者結構帶進服務層：事件的請求欄位由帶標示的組裝函式產生，
	// 或條目以 WithAPIToken 標示。
	classCarried mechanism = "carried"
	// classTxContext 依寫入所在交易的 context 歸因：交易綁上請求 context、操作者組出的稽核脈絡，
	// 或只帶歸因標示的 context，由稽核列入庫匯流點於蓋章之前填入。
	classTxContext mechanism = "tx-context"
	// classSink 寫入面本身的轉換層：把條目或事件上的標示搬到資料列。
	classSink mechanism = "sink"
	// classNotReachable API token 走不到的產生點（登入流程、連線入口、agent 通道、不開放的路由）。
	classNotReachable mechanism = "not-token-reachable"
	// classBackground 排程、背景工作、啟動與系統動作；請求已不存在，執行者是帳號或系統。
	classBackground mechanism = "background"
	// classGap 已知尚未接上的產生點；理由欄寫明走到它的途徑，待補上後改登錄為實際機制。
	classGap mechanism = "gap"
)

type registration struct {
	class  mechanism
	reason string
}

// carriedMarkers 帶標示的請求欄位組裝方式。
var carriedMarkers = []string{"RequestMeta()", "AttributedMeta(", "requestMeta()", "WithAPIToken(", "operatorRequestMeta(", "AttributeAuditMeta("}

// siteLowerBound 產生點數下界：掃描退化成空集合時，兩個空集合比對會假綠。
const siteLowerBound = 120

var registry = map[string]registration{
	"cmd/server/authz_upgrade_warning.go#logAuthzUpgradeWarning":                                                         {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"cmd/server/instance_guard_startup_alert.go#instanceGuardStartupCheck.record":                                        {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"cmd/server/offsite_custody.go#offsiteCustodyJournal.Record":                                                         {classNotReachable, "所在路由不開放 API token"},
	"cmd/server/offsite_custody.go#offsiteCustodyJournal.RecordInTx":                                                     {classNotReachable, "所在路由不開放 API token"},
	"cmd/server/restore_generation.go#restoreSealEnv.reportRestoreSeal":                                                  {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"cmd/server/retention_floor_reconcile.go#retentionFloorAuditor":                                                      {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"cmd/server/sealwire.go#writeSealAudit":                                                                              {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"cmd/server/stage2.go#instanceGuardAuditSink":                                                                        {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"cmd/server/stage2.go#logKEKSwitchAudit":                                                                             {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"cmd/server/stage2.go#runStage2":                                                                                     {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/api/access_review_handler.go#AccessReviewHandler.Create":                                                   {classHandlerEntry, ""},
	"internal/api/asset_handler.go#AssetHandler.auditK8sFile":                                                            {classHandlerMeta, ""},
	"internal/api/asset_handler.go#AssetHandler.auditK8sFileDenied":                                                      {classHandlerMeta, ""},
	"internal/api/audit_export_handler.go#AuditExportHandler.auditExport":                                                {classHandlerEntry, ""},
	"internal/api/audit_export_job_handler.go#AuditExportHandler.auditJob":                                               {classHandlerEntry, ""},
	"internal/api/auth_handler.go#AuthHandler.auditLogin":                                                                {classHandlerEntry, ""},
	"internal/api/auth_handler.go#AuthHandler.auditPasswordChange":                                                       {classHandlerEntry, ""},
	"internal/api/auth_handler.go#AuthHandler.auditPasswordNoncompliant":                                                 {classHandlerEntry, ""},
	"internal/api/auth_handler.go#AuthHandler.auditRefreshEvent":                                                         {classHandlerEntry, ""},
	"internal/api/auth_handler.go#loginAbuseSink.LogAggregatedFailure":                                                   {classNotReachable, "登入、刷新、外部身分登入流程，API token 不經此路"},
	"internal/api/auth_mfa_handler.go#AuthHandler.auditAuthEventFull":                                                    {classHandlerEntry, ""},
	"internal/api/command_alert_handler.go#CommandAlertHandler.Review":                                                   {classHandlerEntry, ""},
	"internal/api/compliance_handler.go#ComplianceHandler.auditReport":                                                   {classHandlerEntry, ""},
	"internal/api/kek_topology_handler.go#KeyManagementHandler.auditTopologyChangeWith":                                  {classHandlerEntry, ""},
	"internal/api/kek_topology_tx.go#KeyManagementHandler.saveTopologyInTx":                                              {classHandlerMeta, ""},
	"internal/api/key_management_handler.go#KeyManagementHandler.CleanupRetired":                                         {classHandlerEntry, ""},
	"internal/api/oidc_handler.go#OIDCHandler.writeOIDCAudit":                                                            {classHandlerEntry, ""},
	"internal/api/policy_group_handler.go#PolicyGroupHandler.writeAudit":                                                 {classHandlerEntry, ""},
	"internal/api/recording_handler.go#RecordingHandler.auditRecordingRetrieval":                                         {classHandlerEntry, ""},
	"internal/api/rotation_report_handler.go#RotationReportHandler.auditReport":                                          {classHandlerEntry, ""},
	"internal/api/security_policy_handler.go#SecurityPolicyHandler.auditPolicyChange":                                    {classHandlerMeta, ""},
	"internal/api/sftp_handler.go#SFTPHandler.audit":                                                                     {classHandlerEntry, ""},
	"internal/api/sftp_handler.go#SFTPHandler.auditDenied":                                                               {classHandlerEntry, ""},
	"internal/api/sftp_handler.go#SFTPHandler.auditSourceDenied":                                                         {classHandlerEntry, ""},
	"internal/api/syslog_setting_handler.go#SyslogSettingHandler.Test":                                                   {classHandlerEntry, ""},
	"internal/api/syslog_setting_handler.go#SyslogSettingHandler.Update":                                                 {classHandlerMeta, ""},
	"internal/api/transmission_inventory_handler.go#TransmissionInventoryHandler.audit":                                  {classHandlerEntry, ""},
	"internal/api/user_handler.go#UserHandler.SetInactivityExempt":                                                       {classHandlerEntry, ""},
	"internal/api/user_handler.go#UserHandler.Unlock":                                                                    {classHandlerEntry, ""},
	"internal/database/credential_secret_conversion.go#markGroupMismatch":                                                {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/database/credential_secret_conversion.go#recordConversionFailure":                                          {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/middleware/anonymous_rejection_audit.go#anonRejectionAuditor.writeRow":                                     {classNotReachable, "未認證拒絕的匿名留痕（認證失敗原因另見匿名留痕）"},
	"internal/middleware/audit_log.go#AuditLogMiddleware":                                                                {classMiddleware, ""},
	"internal/model/asset_audit.go#Asset.AfterCreate":                                                                    {classTxContext, ""},
	"internal/model/asset_audit.go#Asset.AfterDelete":                                                                    {classTxContext, ""},
	"internal/model/asset_audit.go#Asset.AfterUpdate":                                                                    {classTxContext, ""},
	"internal/model/user_role_write.go#recordUserRoleChange":                                                             {classTxContext, ""},
	"internal/modules/asset/asset_audit_events.go#writeAssetAccountAudit":                                                {classTxContext, ""},
	"internal/modules/asset/asset_audit_events.go#writeAssetChangeAudit":                                                 {classTxContext, ""},
	"internal/modules/asset/asset_audit_events.go#writeAssetNodeChangeAudit":                                             {classTxContext, ""},
	"internal/modules/asset/asset_group_service.go#AssetGroupService.Delete":                                             {classTxContext, ""},
	"internal/modules/asset/asset_group_service.go#AssetGroupService.nodeAudit":                                          {classTxContext, ""},
	"internal/modules/asset/change_secret_plan_service.go#ChangeSecretPlanService.writeReauthorizeAudit":                 {classTxContext, ""},
	"internal/modules/asset/change_secret_retry_runner.go#ChangeSecretRetryRunner.auditRestoredStop":                     {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/asset/credential_binding.go#writeCredentialAudit":                                                  {classTxContext, ""},
	"internal/modules/asset/credential_job_authorization.go#ChangeSecretRunner.auditStop":                                {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/asset/credential_job_authorization.go#CredentialRotationService.auditMemberStop":                   {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/asset/credential_job_authorization.go#CredentialRotationService.writeRotationReauthorizationAudit": {classTxContext, ""},
	"internal/modules/asset/credential_recovery.go#writeRecoveryVerifyAudit":                                             {classTxContext, ""},
	"internal/modules/asset/credential_rotation_interrupted.go#CredentialRotationService.writeInterruptedAudit":          {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/asset/executor_login_check.go#ExecutorLoginCheckService.writeEndAudit":                             {classCarried, ""},
	"internal/modules/asset/executor_login_check.go#ExecutorLoginCheckService.writeStartAudit":                           {classCarried, ""},
	"internal/modules/asset/host_inventory_read.go#HostAccountInventoryService.writeFindingAudit":                        {classCarried, ""},
	"internal/modules/asset/host_inventory_service.go#HostAccountInventoryService.writeScanAudit":                        {classCarried, ""},
	"internal/modules/asset/hostkey_identity_stop.go#writeHostIdentityStopAudit":                                         {classTxContext, ""},
	"internal/modules/asset/hostkey_identity_takeover_create.go#HostIdentityTakeoverService.writeConfirmAudit":           {classTxContext, ""},
	"internal/modules/asset/hostkey_service.go#HostKeyService.Adopt":                                                     {classNotReachable, "所在路由不開放 API token"},
	"internal/modules/asset/hostkey_service.go#HostKeyService.RecordCredentialSent":                                      {classGap, "主機金鑰撥接留痕；撥接脈絡未帶 token 標示。現行會撥接的路由皆不開放 API token、其餘為背景工作，日後開放這類路由即成缺口"},
	"internal/modules/asset/hostkey_service.go#HostKeyService.traceMismatch":                                             {classGap, "同上（撥接脈絡尚未帶 token 標示）"},
	"internal/modules/audit/agent_probe_breaker.go#ProbeBreaker.RecordDenied":                                            {classNotReachable, "agent 通道，不開放 API token"},
	"internal/modules/audit/agent_task_reports.go#AgentTaskReports.submit":                                               {classNotReachable, "agent 通道，不開放 API token"},
	"internal/modules/audit/agent_tool_call_arguments.go#ToolCallArgumentsService.ReadArguments":                         {classNotReachable, "agent 通道，不開放 API token"},
	"internal/modules/audit/async_sink.go#entryOf":                                                                       {classSink, ""},
	"internal/modules/audit/audit_export_job_worker.go#AuditExportJobWorker.auditRevokedCancel":                          {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/audit/audit_log_service.go#AuditLogService.logAt":                                                  {classSink, ""},
	"internal/modules/audit/daily_review_service.go#DailyReviewService.Sign":                                             {classNotReachable, "所在路由不開放 API token"},
	"internal/modules/audit/notification_channel_service.go#NotificationChannelService.recordChannelChange":              {classCarried, ""},
	"internal/modules/audit/permission_accept.go#PermissionAcceptService.Accept":                                         {classNotReachable, "所在路由不開放 API token"},
	"internal/modules/audit/retention_service.go#RetentionService.logPurge":                                              {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/audit/seal_replay_sink.go#sealAggregateRow":                                                        {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/audit/seal_replay_sink.go#sealEventRow":                                                            {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/audit/source_ip_baseline.go#SourceIPBaseline.ObserveLogin":                                         {classNotReachable, "登入、刷新、外部身分登入流程，API token 不經此路"},
	"internal/modules/audit/system_alert_catalog_service.go#SystemAlertCatalogService.SetSeverity":                       {classCarried, ""},
	"internal/modules/audit/tx_sink.go#auditRowOf":                                                                       {classSink, ""},
	"internal/modules/authz/access_request_item_lifecycle.go#AccessRequestService.writeRevokeAuditInTx":                  {classNotReachable, "所在路由不開放 API token"},
	"internal/modules/authz/access_request_service.go#AccessRequestService.logAudit":                                     {classNotReachable, "所在路由不開放 API token"},
	"internal/modules/authz/access_request_submit_items.go#AccessRequestService.logAgentRequestRate":                     {classNotReachable, "agent 通道，不開放 API token"},
	"internal/modules/identity/agent_breaker.go#AgentTokenService.ReleaseProbeBreaker":                                   {classNotReachable, "agent 通道，不開放 API token"},
	"internal/modules/identity/agent_self_service.go#agentSelfCreation.audit":                                            {classNotReachable, "agent 通道，不開放 API token"},
	"internal/modules/identity/agent_token_lifecycle.go#AgentTokenService.recordLifecycle":                               {classNotReachable, "agent 通道，不開放 API token"},
	"internal/modules/identity/agent_token_service.go#AgentTokenService.record":                                          {classNotReachable, "agent 通道，不開放 API token"},
	"internal/modules/identity/api_token_events.go#apiTokenEventRecorder.APITokenCreated":                                {classCarried, ""},
	"internal/modules/identity/api_token_events.go#apiTokenEventRecorder.APITokenRevoked":                                {classCarried, ""},
	"internal/modules/identity/approver_scope_management_key.go#backfillApproverScopeKeyForRole":                         {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/identity/auth_service.go#AuthService.auditLDAPResolveFailure":                                      {classNotReachable, "登入、刷新、外部身分登入流程，API token 不經此路"},
	"internal/modules/identity/auth_service.go#AuthService.auditLDAPTransport":                                           {classNotReachable, "登入、刷新、外部身分登入流程，API token 不經此路"},
	"internal/modules/identity/external_identity_service.go#UserService.writeIdentityAudit":                              {classCarried, ""},
	"internal/modules/identity/external_login_attempt_audit.go#writeExternalLoginAttemptAudits":                          {classNotReachable, "登入、刷新、外部身分登入流程，API token 不經此路"},
	"internal/modules/identity/grant_grader.go#grantTracker.writeMarkedAudit":                                            {classCarried, ""},
	"internal/modules/identity/group_role_mapping_service.go#IdentitySourceService.auditMapping":                         {classCarried, ""},
	"internal/modules/identity/inactivity_service.go#InactivityService.auditDisable":                                     {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/identity/ldap_directory_service.go#LDAPDirectoryService.ldapDirectoryAuditLog":                     {classCarried, ""},
	"internal/modules/identity/ldap_seed_migration.go#ldapSeedAudit":                                                     {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/identity/mapping_admin_service.go#IdentitySourceService.UpdateExternalGroupNote":                   {classCarried, ""},
	"internal/modules/identity/oidc_discovery_preview.go#IdentitySourceService.auditDiscoveryPreview":                    {classCarried, ""},
	"internal/modules/identity/oidc_login_service.go#OIDCLoginService.writeAuditFrom":                                    {classNotReachable, "登入、刷新、外部身分登入流程，API token 不經此路"},
	"internal/modules/identity/oidc_provider_service.go#OIDCProviderService.recordSourceChange":                          {classCarried, ""},
	"internal/modules/identity/principal_state_source.go#recordPrincipalState":                                           {classTxContext, ""},
	"internal/modules/identity/protected_account_ops.go#ProtectedAccountOps.Record":                                      {classCarried, ""},
	"internal/modules/identity/release_guidance.go#ReleaseGuidanceService.Dismiss":                                       {classCarried, ""},
	"internal/modules/identity/role_agent_revalidation.go#GrantGrader.detectInNewTx":                                     {classCarried, ""},
	"internal/modules/identity/role_definition_service.go#RoleDefinitionService.write":                                   {classTxContext, ""},
	"internal/modules/identity/role_mapping_recompute.go#writeRoleMappingAudit":                                          {classBackground, "啟動、排程、背景工作或系統動作，無請求"},
	"internal/modules/identity/user_group_mapping_service.go#IdentitySourceService.auditUserGroupMapping":                {classCarried, ""},
	"internal/modules/identity/user_group_role_bindings.go#UserGroupService.writeGroupRoleAuditDetails":                  {classCarried, ""},
	"internal/modules/identity/user_group_service.go#UserGroupService.deleteGroup":                                       {classCarried, ""},
	"internal/modules/identity/user_group_service.go#UserGroupService.replaceMembers":                                    {classCarried, ""},
	"internal/modules/identity/user_group_service.go#UserGroupService.writeMemberAddedAudit":                             {classCarried, ""},
	"internal/modules/identity/user_role_pin.go#UserService.auditPin":                                                    {classCarried, ""},
	"internal/modules/policy/transmission_consent_service.go#TransmissionConsentService.auditConsent":                    {classNotReachable, "所在路由不開放 API token"},
	"internal/modules/policy/transmission_consent_service.go#TransmissionConsentService.auditGateDenied":                 {classNotReachable, "所在路由不開放 API token"},
	"internal/modules/session/agent_actor.go#SessionService.recordRevoked":                                               {classNotReachable, "agent 通道，不開放 API token"},
	"internal/modules/session/clipboard_content_service.go#ClipboardContentService.ReadContent":                          {classTxContext, ""},
	"internal/modules/session/keystroke_view_service.go#KeystrokeViewService.View":                                       {classTxContext, ""},
	"internal/modules/session/recording_delete.go#RecordingService.DeleteRecording":                                      {classCarried, ""},
	"internal/modules/session/recording_failure_report.go#ReportSessionRecordingFailure":                                 {classNotReachable, "連線入口與連線中事件，不開放 API token"},
	"internal/proxy/connect_gates.go#AuditConnectDenied":                                                                 {classNotReachable, "連線入口與連線中事件，不開放 API token"},
	"internal/proxy/file_tap.go#FileTap.submitDetails":                                                                   {classNotReachable, "連線入口與連線中事件，不開放 API token"},
	"internal/proxy/handler.go#ConnectionHandler.HandleConnect":                                                          {classNotReachable, "連線入口與連線中事件，不開放 API token"},
	"internal/sshproxy/dbconsole_audit.go#consoleAuditContext.log":                                                       {classNotReachable, "連線入口與連線中事件，不開放 API token"},
	"internal/sshproxy/dbconsole_export.go#Handler.auditConsoleExport":                                                   {classNotReachable, "連線入口與連線中事件，不開放 API token"},
	"internal/sshproxy/handler.go#Handler.auditObserverJoin":                                                             {classNotReachable, "連線入口與連線中事件，不開放 API token"},
	"internal/sshproxy/sensitive_tap.go#outputScanDisabledAudit":                                                         {classNotReachable, "連線入口與連線中事件，不開放 API token"},
	"internal/sshproxy/transfer_snapshot_audit.go#Handler.auditTextTransferSnapshot":                                     {classNotReachable, "連線入口與連線中事件，不開放 API token"},
}

func hasAny(s string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// checkSite 可由原始碼判讀的機制，檢查字面值確實走該機制。
func checkSite(s site, r registration) string {
	switch r.class {
	case classMiddleware:
		if s.kind != "entry" || !strings.Contains(s.body, "AttributeAuditEntry(") {
			return "中介層條目未經 AttributeAuditEntry"
		}
	case classHandlerEntry:
		if s.kind != "entry" || !s.wrapped {
			return "handler 條目字面值未直接作為 AttributeAuditEntry 的引數"
		}
	case classHandlerMeta:
		if s.kind != "event" {
			return "handler-meta 只登錄寫入面事件"
		}
		if !strings.Contains(s.request, "AttributeAuditMeta(") && !strings.Contains(s.body, "AttributeAuditMeta(") {
			return "事件的請求欄位未經 AttributeAuditMeta"
		}
	case classCarried:
		switch s.kind {
		case "event":
			if !hasAny(s.request, carriedMarkers) {
				return "事件的請求欄位不是帶標示的組裝方式：" + s.request
			}
		case "entry":
			if !strings.Contains(s.body, ".WithAPIToken(") {
				return "條目未以 WithAPIToken 標示"
			}
		default:
			return "carried 不登錄直接組出的資料列"
		}
	case classSink:
		if !strings.Contains(s.body, "APIToken") {
			return "轉換層未搬運 token 標示"
		}
	case classTxContext:
		if s.request != "" && hasAny(s.request, carriedMarkers) {
			return "請求欄位已帶標示，應登錄為 carried"
		}
	case classNotReachable, classBackground, classGap:
		if strings.TrimSpace(r.reason) == "" {
			return "未寫理由"
		}
	default:
		return "未知的機制類別：" + string(r.class)
	}
	return ""
}

func TestAuditAttributionSitesRegistered(t *testing.T) {
	sites := scanSites(t)
	if len(sites) < siteLowerBound {
		t.Fatalf("掃到的稽核產生點只有 %d 個（下界 %d），掃描可能退化", len(sites), siteLowerBound)
	}
	seen := map[string]bool{}
	var problems []string
	for _, s := range sites {
		seen[s.key] = true
		r, ok := registry[s.key]
		if !ok {
			problems = append(problems, "未登錄的稽核產生點："+s.key+"（登錄它把 API token 標示帶到寫入面的機制）")
			continue
		}
		if msg := checkSite(s, r); msg != "" {
			problems = append(problems, s.key+"："+msg)
		}
	}
	for k := range registry {
		if !seen[k] {
			problems = append(problems, "登錄了已不存在的產生點："+k)
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// TestAuditAttributionGapsListed 已知缺口逐筆列出，數量變動時須同步交接紀錄。
func TestAuditAttributionGapsListed(t *testing.T) {
	var gaps []string
	for k, r := range registry {
		if r.class == classGap {
			gaps = append(gaps, k)
		}
	}
	sort.Strings(gaps)
	for _, g := range gaps {
		t.Logf("已知缺口：%s", g)
	}
	if len(gaps) > 2 {
		t.Errorf("已知缺口 %d 筆，多於登錄時的 2 筆：新產生點應接上實際機制", len(gaps))
	}
}
