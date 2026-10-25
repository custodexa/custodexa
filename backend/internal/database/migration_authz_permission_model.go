package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 權限模型增量：內建範本識別、角色指派範圍種類、
// 使用者群組 × 角色指派、節點範圍表、權限狀態表。
//
// 本增量**只新增結構**；內建角色的標記、前置檢查與遷移報告屬資料步驟，
// 由同一版本的 Up 在 DDL 之後、同一交易內執行（見 applyAuthzPermissionModel）。
// DDL 無條件，不用 IF NOT EXISTS；版本集合負責避免重跑。
//
// # Down 契約
//
// 不提供回滾：套用成功後的回退只走還原升級前備份（舊版看不到群組指派與內建身分，
// 指回上一版不是安全操作）。管理腳本因本版本進入 migration 集合而拒絕指回。
func authzPermissionModelDDL() []string {
	return []string{
		`ALTER TABLE roles ADD COLUMN builtin_key character varying(32)`,
		`CREATE UNIQUE INDEX uq_roles_builtin_key ON roles (builtin_key) WHERE builtin_key IS NOT NULL`,
		`ALTER TABLE roles ADD CONSTRAINT roles_builtin_key_check CHECK (builtin_key IS NULL OR builtin_key IN ('super_admin','auditor','user','approver'))`,
		`ALTER TABLE user_roles ADD COLUMN scope_kind character varying(8) DEFAULT 'global'::character varying NOT NULL`,
		`ALTER TABLE user_roles ADD CONSTRAINT user_roles_scope_kind_check CHECK (scope_kind IN ('global','nodes'))`,
		`CREATE TABLE user_group_roles (
 user_group_id bigint NOT NULL, role_id bigint NOT NULL,
 scope_kind character varying(8) DEFAULT 'global'::character varying NOT NULL,
 created_at timestamp with time zone NOT NULL, created_by bigint,
 CONSTRAINT user_group_roles_pkey PRIMARY KEY (user_group_id, role_id),
 CONSTRAINT user_group_roles_scope_kind_check CHECK (scope_kind IN ('global','nodes')))`,
		`CREATE TABLE role_binding_nodes (
 subject_kind character varying(16) NOT NULL, subject_id bigint NOT NULL,
 role_id bigint NOT NULL, node_id bigint NOT NULL,
 CONSTRAINT role_binding_nodes_pkey PRIMARY KEY (subject_kind, subject_id, role_id, node_id),
 CONSTRAINT role_binding_nodes_subject_kind_check CHECK (subject_kind IN ('user','user_group')))`,
		`CREATE TABLE authz_state (
 id integer DEFAULT 1 NOT NULL, version bigint DEFAULT 0 NOT NULL,
 model_migrated_at timestamp with time zone, model_migration_report text,
 CONSTRAINT authz_state_pkey PRIMARY KEY (id),
 CONSTRAINT authz_state_single_row_check CHECK (id = 1))`,
	}
}

// applyAuthzPermissionModel 前置檢查 → DDL → 資料步驟（補列、標記、前後報告比對、保存報告）。
// RunMigrations 已把本函式與版本記錄包在同一交易內：任一步失敗整筆回滾，資料庫維持原形狀。
func applyAuthzPermissionModel(db *gorm.DB) error {
	return applyAuthzPermissionModelWith(db, planAuthzModelReport)
}

func applyAuthzPermissionModelWith(db *gorm.DB, plan authzReportPlanner) error {
	// 前置檢查先於任何寫入：不通過時連 DDL 都不執行。
	if _, err := checkAuthzBuiltinRoles(db); err != nil {
		return err
	}
	for _, stmt := range authzPermissionModelDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 authz_permission_model DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	// 報告只讀既有欄位，DDL 不影響其計數，故「套用前」報告在 DDL 之後、標記之前計算等價。
	return applyAuthzModelData(db, plan)
}

// rollbackAuthzPermissionModel 不提供回滾；見檔頭 Down 契約。
func rollbackAuthzPermissionModel(db *gorm.DB) error {
	return fmt.Errorf("authz permission model has no rollback; restore the pre-upgrade backup")
}
