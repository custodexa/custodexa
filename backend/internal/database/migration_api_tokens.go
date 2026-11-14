package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 個人 API token 的資料層。
//
// 內容：兩張新表 api_tokens（只存明文摘要、可永不到期）與 api_token_roles（建立時授權的角色，
// 複合主鍵），以及 audit_logs 的兩個可為 NULL 的欄位 api_token_id、api_token_name（經 token
// 認證的操作所寫的列帶值，其他列為 NULL）。純新增，無資料步驟，既有列不變。
//
// 名稱占用的唯一性不以索引表達（是否到期隨時間改變），由建立流程在帳號層級鎖內判定。
//
// # Down 契約
//
// 不提供回滾：回退只走還原升級前備份；舊版忽略新表與新欄。
func apiTokensDDL() []string {
	return []string{
		`CREATE TABLE api_tokens (
		id bigserial,
		user_id bigint NOT NULL,
		name character varying(100) NOT NULL,
		token_hash character varying(64) NOT NULL,
		created_at timestamp with time zone,
		expires_at timestamp with time zone,
		last_used_at timestamp with time zone,
		last_used_ip character varying(50) DEFAULT ''::character varying NOT NULL,
		revoked_at timestamp with time zone,
		revoked_by bigint,
		revoke_note text DEFAULT ''::text NOT NULL,
		restore_generation character varying(64) DEFAULT ''::character varying NOT NULL,
		CONSTRAINT api_tokens_pkey PRIMARY KEY (id),
		CONSTRAINT fk_api_tokens_user FOREIGN KEY (user_id) REFERENCES users(id),
		CONSTRAINT fk_api_tokens_revoker FOREIGN KEY (revoked_by) REFERENCES users(id)
	)`,
		`CREATE UNIQUE INDEX idx_api_tokens_token_hash ON api_tokens USING btree (token_hash)`,
		`CREATE INDEX idx_api_tokens_user_revoked ON api_tokens USING btree (user_id, revoked_at)`,
		`CREATE TABLE api_token_roles (
		api_token_id bigint NOT NULL,
		role_id bigint NOT NULL,
		CONSTRAINT api_token_roles_pkey PRIMARY KEY (api_token_id, role_id),
		CONSTRAINT fk_api_token_roles_token FOREIGN KEY (api_token_id) REFERENCES api_tokens(id) ON DELETE CASCADE,
		CONSTRAINT fk_api_token_roles_role FOREIGN KEY (role_id) REFERENCES roles(id)
	)`,
		`ALTER TABLE audit_logs ADD COLUMN api_token_id bigint`,
		`ALTER TABLE audit_logs ADD COLUMN api_token_name character varying(100)`,
		`CREATE INDEX idx_audit_api_token_created ON audit_logs USING btree (api_token_id, created_at)`,
	}
}

func applyAPITokens(db *gorm.DB) error {
	for _, stmt := range apiTokensDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 api_tokens DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackAPITokens 不提供回滾；見檔頭 Down 契約。
func rollbackAPITokens(_ *gorm.DB) error {
	return fmt.Errorf("api tokens has no down migration; restore the pre-upgrade backup instead")
}
