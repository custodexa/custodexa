package database

import (
	"fmt"
	"gorm.io/gorm"
)

// Baseline plus this additive migration is the schema source for new and existing installs.
// Down preserves principals and credential history: deploy an older reader without deleting evidence.
func identityAgentPrincipalDDL() []string {
	return []string{
		`ALTER TABLE users ADD COLUMN kind character varying(16) NOT NULL DEFAULT 'human'`,
		`ALTER TABLE users ADD COLUMN owner_user_id bigint`,
		`ALTER TABLE users ADD COLUMN breaker_pending_at timestamp with time zone`,
		`ALTER TABLE users ADD CONSTRAINT users_kind_check CHECK (kind IN ('human','agent'))`,
		`ALTER TABLE users ADD CONSTRAINT users_owner_check CHECK ((kind = 'agent' AND owner_user_id IS NOT NULL) OR (kind = 'human' AND owner_user_id IS NULL))`,
		`ALTER TABLE users ADD CONSTRAINT fk_users_owner FOREIGN KEY (owner_user_id) REFERENCES users(id)`,
		`CREATE TABLE agent_tokens (
   id bigserial,
   user_id bigint NOT NULL,
   name character varying(100) NOT NULL,
   token_hash character varying(64) NOT NULL,
   created_by bigint NOT NULL,
   created_at timestamp with time zone,
   expires_at timestamp with time zone NOT NULL,
   last_used_at timestamp with time zone,
   revoked_at timestamp with time zone,
   revoked_by bigint,
   revoke_note text,
   suspended_at timestamp with time zone,
   suspended_reason text,
   CONSTRAINT agent_tokens_pkey PRIMARY KEY (id),
   CONSTRAINT fk_agent_tokens_user FOREIGN KEY (user_id) REFERENCES users(id),
   CONSTRAINT fk_agent_tokens_creator FOREIGN KEY (created_by) REFERENCES users(id),
   CONSTRAINT fk_agent_tokens_revoker FOREIGN KEY (revoked_by) REFERENCES users(id)
  )`,
		`CREATE UNIQUE INDEX idx_agent_tokens_token_hash ON agent_tokens (token_hash)`,
		`CREATE INDEX idx_agent_tokens_user_id ON agent_tokens (user_id)`,
		`ALTER TABLE sessions ADD COLUMN agent_token_id bigint`,
		`ALTER TABLE sessions ADD COLUMN access_request_id bigint`,
		`ALTER TABLE sessions ADD CONSTRAINT fk_sessions_agent_token FOREIGN KEY (agent_token_id) REFERENCES agent_tokens(id)`,
	}
}
func applyIdentityAgentPrincipal(db *gorm.DB) error {
	for _, stmt := range identityAgentPrincipalDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("identity_agent_principal DDL: %w", err)
		}
	}
	return nil
}
func rollbackIdentityAgentPrincipal(db *gorm.DB) error {
	return fmt.Errorf("identity_agent_principal 保留主體與憑證資料，不支援刪欄回滾")
}

func expandAgentAuditActions(db *gorm.DB) error {
	return db.Exec(`ALTER TABLE audit_logs ALTER COLUMN action TYPE character varying(32)`).Error
}
