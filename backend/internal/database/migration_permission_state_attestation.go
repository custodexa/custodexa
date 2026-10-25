package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 權限附證與恢復世代增量（權限模型調和與還原）。
//
// 只新增結構，不回填：
//   - permission_state_events：權限狀態的可重放變更證據（附證啟用後才有列）。
//   - audit_checkpoints.perm_*：權限附證欄（皆可空；啟用界標之前的檢查點為「尚未涵蓋」）。
//   - authz_state.restore_*：持久恢復世代與最近一次恢復交易（預設空＝legacy 世代，
//     一般升級與重啟因此不會讓任何人登出）。
//   - refresh_tokens／agent_tokens／asset_authorizations.restore_generation：持久票證的
//     簽發世代（預設空＝簽發於 legacy 世代；還原後世代非空，舊列即使未撤銷也被拒絕）。
//
// DDL 無條件，不用 IF NOT EXISTS；版本集合負責避免重跑。
//
// # Down 契約
//
// 不提供回滾：與 20261016_authz_permission_model 同一個模型邊界，回退只走升級前備份。
func permissionStateAttestationDDL() []string {
	return []string{
		`CREATE TABLE permission_state_events (id bigserial, seq bigint NOT NULL, version bigint NOT NULL, kind character varying(16) NOT NULL, op_id character varying(64) NOT NULL, prev_digest character varying(64) NOT NULL, before_digest character varying(64) NOT NULL, after_digest character varying(64) NOT NULL, delta text NOT NULL, after_body text NOT NULL, digest character varying(64) NOT NULL, activated_seq bigint, created_at timestamp with time zone NOT NULL, CONSTRAINT permission_state_events_pkey PRIMARY KEY (id), CONSTRAINT permission_state_events_kind_check CHECK (kind IN ('activate','change','restore','untraced','accept')))`,
		`CREATE UNIQUE INDEX uq_permission_state_events_seq ON permission_state_events USING btree (seq)`,
		`ALTER TABLE audit_checkpoints ADD COLUMN perm_state_snapshot text`,
		`ALTER TABLE audit_checkpoints ADD COLUMN perm_format bigint`,
		`ALTER TABLE audit_checkpoints ADD COLUMN perm_event_seq bigint`,
		`ALTER TABLE audit_checkpoints ADD COLUMN perm_event_head character varying(64)`,
		`ALTER TABLE audit_checkpoints ADD COLUMN perm_reconciled boolean`,
		`ALTER TABLE audit_checkpoints ADD COLUMN perm_signature character varying(128)`,
		`ALTER TABLE authz_state ADD COLUMN restore_generation character varying(64) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE authz_state ADD COLUMN restore_op_id character varying(64) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE authz_state ADD COLUMN restore_input_digest character varying(64) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE authz_state ADD COLUMN restore_status character varying(16) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE authz_state ADD COLUMN restored_at timestamp with time zone`,
		`ALTER TABLE refresh_tokens ADD COLUMN restore_generation character varying(64) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE agent_tokens ADD COLUMN restore_generation character varying(64) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE asset_authorizations ADD COLUMN restore_generation character varying(64) DEFAULT ''::character varying NOT NULL`,
	}
}

func applyPermissionStateAttestation(db *gorm.DB) error {
	for _, stmt := range permissionStateAttestationDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 permission_state_attestation DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackPermissionStateAttestation 不提供回滾；見檔頭 Down 契約。
func rollbackPermissionStateAttestation(db *gorm.DB) error {
	return fmt.Errorf("permission state attestation has no rollback; restore the pre-upgrade backup")
}
