package database

import (
	"fmt"
	"gorm.io/gorm"
)

// Purely additive. Down disables use by reverting readers; evidence and columns are retained.
func agentAuditLedgerDDL() []string {
	return []string{
		`ALTER TABLE sessions ADD COLUMN actor_kind varchar(16)`,
		`ALTER TABLE sessions ADD COLUMN on_behalf_of_user_id bigint REFERENCES users(id)`,
		`ALTER TABLE sessions ADD COLUMN owner_user_id bigint REFERENCES users(id)`,
		`ALTER TABLE sessions ADD COLUMN revoked_during_session_at timestamptz`,
		`ALTER TABLE sessions ADD CONSTRAINT sessions_actor_kind_check CHECK (actor_kind IN ('human','agent'))`,
		`ALTER TABLE alert_rules ADD COLUMN subject_kind varchar(16) NOT NULL DEFAULT 'all'`,
		`ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_subject_kind_check CHECK (subject_kind IN ('all','human','agent'))`,
		`ALTER TABLE audit_checkpoints ADD COLUMN tool_call_id_from bigint`,
		`ALTER TABLE audit_checkpoints ADD COLUMN tool_call_id_to bigint`,
		`ALTER TABLE audit_checkpoints ADD COLUMN tool_call_row_count bigint`,
		`ALTER TABLE audit_checkpoints ADD COLUMN tool_call_agg_hash varchar(64)`,
		`CREATE TABLE agent_tool_calls (
 id bigserial PRIMARY KEY,
 seq bigint NOT NULL,
 user_id bigint NOT NULL REFERENCES users(id),
 agent_token_id bigint NOT NULL REFERENCES agent_tokens(id),
 access_request_id bigint REFERENCES access_requests(id),
 session_id bigint REFERENCES sessions(id),
 on_behalf_of_user_id bigint REFERENCES users(id),
 owner_user_id bigint NOT NULL REFERENCES users(id),
 tool varchar(64) NOT NULL,
 args_redacted jsonb NOT NULL,
 decision varchar(16) NOT NULL,
 denial_code varchar(100) NOT NULL,
 result_status varchar(32) NOT NULL,
 result_digest varchar(64) NOT NULL,
 result_excerpt text NOT NULL,
 masked_count bigint NOT NULL,
 duration_ms bigint NOT NULL,
 created_at timestamptz NOT NULL,
 integrity_hmac varchar(64) NOT NULL,
 key_version bigint NOT NULL,
 CONSTRAINT agent_tool_calls_seq_check CHECK (seq > 0),
 CONSTRAINT agent_tool_calls_request_check CHECK (access_request_id IS NOT NULL OR tool IN ('list_assets','request_access','check_request')),
 CONSTRAINT agent_tool_calls_decision_check CHECK (decision IN ('pending','allowed','denied','breaker','rate_limited')),
 CONSTRAINT agent_tool_calls_excerpt_check CHECK (octet_length(result_excerpt) <= 2048),
 CONSTRAINT agent_tool_calls_counts_check CHECK (masked_count >= 0 AND duration_ms >= 0)
 )`,
		`CREATE UNIQUE INDEX idx_agent_tool_calls_user_seq ON agent_tool_calls(user_id,seq)`,
		`CREATE INDEX idx_agent_tool_calls_request ON agent_tool_calls(access_request_id)`,
		`CREATE INDEX idx_agent_tool_calls_created_at ON agent_tool_calls(created_at)`,
		`CREATE TABLE agent_task_reports (
 id bigserial PRIMARY KEY,
 access_request_id bigint NOT NULL REFERENCES access_requests(id),
 user_id bigint NOT NULL REFERENCES users(id),
 version bigint NOT NULL,
 body text NOT NULL,
 submitted_at timestamptz NOT NULL,
 CONSTRAINT agent_task_reports_version_check CHECK (version > 0)
 )`,
		`CREATE UNIQUE INDEX idx_agent_task_reports_request_version ON agent_task_reports(access_request_id,version)`,
		`CREATE TABLE agent_probe_events (
 id bigserial PRIMARY KEY,
 user_id bigint NOT NULL REFERENCES users(id),
 agent_token_id bigint NOT NULL REFERENCES agent_tokens(id),
 asset_ref bigint NOT NULL,
 endpoint varchar(255) NOT NULL,
 class varchar(16) NOT NULL,
 created_at timestamptz NOT NULL,
 CONSTRAINT agent_probe_events_class_check CHECK (class IN ('never_visible','revoked','retired'))
 )`,
		`CREATE INDEX idx_agent_probe_events_user_class_created ON agent_probe_events(user_id,class,created_at)`,
	}
}
func applyAgentAuditLedger(db *gorm.DB) error {
	for _, stmt := range agentAuditLedgerDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("agent_audit_ledger DDL: %w", err)
		}
	}
	return nil
}
func rollbackAgentAuditLedger(*gorm.DB) error {
	return fmt.Errorf("agent_audit_ledger retains all evidence; disable readers/writers without deleting data")
}
