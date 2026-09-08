package database

import (
	"fmt"

	"gorm.io/gorm"
)

// 外部群組對角色映射的資料層增量 migration。
// 沿既有增量的紀律：DDL 無條件、不用 IF NOT EXISTS——在已套用的庫上重跑
// 必須大聲失敗，而非靜默 no-op。
//
// # Up 做什麼
//
//  1. `user_roles` 加 `source`：角色列的來源三態（管理者指派／外部群組映射／
//     兩者並存）。**NOT NULL DEFAULT 'manual'**，故存量列與既有五條角色寫入
//     路徑（它們寫的都是兩欄 INSERT）一律落在管理者指派——語義是「認證通過即
//     基本存取，群組只管升權」，基本角色永不受映射控制。
//  2. 新表 `group_role_mappings`：管理者設定的映射規則。來源恰一（目錄 XOR
//     身分提供者）以兩條可空外鍵加 CHECK 表達；同一來源的同一比對值不得重複
//     映射到同一角色，以兩條部分唯一索引（排除軟刪列）擋下。
//  3. 新表 `user_role_mappings`：某條登入途徑於最近一次重算後認定的映射事實。
//     主鍵含通道，兩條途徑各自成列——不含通道的話，同一人交替經兩條途徑登入
//     會互相清除對方的認定，每次都被判為角色縮減而把對方踢下線。
//  4. `ldap_directories` 加 `attr_group`：群組成員資格屬性名。**空值＝本部署不依
//     外部群組決定角色**，登入路徑不向目錄索取該屬性，既有部署升級後行為逐字不變。
//  5. `oidc_providers` 加群組宣告名與宣告對應三欄：群組資訊、帳號名、電郵、
//     顯示名各取自哪個宣告。四欄可空，**空值走現行解析／不依外部群組決定角色**，
//     未設定的部署行為逐字不變。
//  6. `users` 加群組觀測快照三欄：最近一次登入時觀測到的途徑、群組原始值與時間。
//     只供診斷，**不作為任何授權判定的依據**。是欄位不是新表——快照跟著帳號生滅，
//     另立一張指向帳號的表只會在既有的清理路徑上多一次外鍵稅。
//
// # 為什麼映射事實另立一張表而不是在關聯表上加通道欄
//
// 關聯表的主鍵是（角色，帳號）。同一個角色被兩條途徑同時命中時，單一通道欄
// 只表達得了其中一條，另一條的事實在下一次重算即被覆寫或誤刪。
//
// # 索引取捨
//
// `user_role_mappings` 除主鍵外不另建索引：它的兩種讀法是「取某帳號某通道的
// 全部列」（主鍵前綴，走得到）與「取某帳號的全部列」（同前綴）。以角色反查
// 帳號不是本表的用途——那是關聯表的工作。
//
// # Down 契約（讀完再用）
//
// **本 Down 有損，且損失不可還原**：
//
//   - `user_roles.source` 一旦卸下，「哪些角色是管理者指派的、哪些只是外部
//     群組給的」這件事就永久消失。回退後全部角色列一律回到「不分來源」的
//     舊語義，而本地管理員計數會重新把僅由映射取得管理員角色的帳號計入
//     ——那正是本能力要消滅的那個洞。
//   - `user_role_mappings` 的全部列一併消失。它是可重建的（下一次登入重算會
//     重新認定），但重建要等到當事人下一次登入。
//   - `group_role_mappings` 的全部列一併消失，且**不可重建**：那是管理者
//     逐條設定的規則，系統沒有第二個地方存著它們。回退前要自行備份。
//   - 群組宣告名、宣告對應三欄與 `attr_group` 還原為未設定即可，無損
//     （未設定＝走現行解析、不依群組決定角色）。群組觀測快照三欄一併消失，
//     那只是診斷資料，下一次登入即重新寫入。
//
// 生產沒有回滾入口（RollbackMigration 無產品碼呼叫者，回退手段是部署回舊版
// 映像並還原升級前備份，docs/ops/upgrade-sop.md §4）。
func groupRoleMappingDDL() []string {
	return []string{
		`ALTER TABLE user_roles ADD COLUMN source character varying(16) DEFAULT 'manual'::character varying NOT NULL`,
		`CREATE TABLE group_role_mappings (
			id bigserial,
			created_at timestamp with time zone,
			updated_at timestamp with time zone,
			deleted_at timestamp with time zone,
			ldap_directory_id bigint,
			oidc_provider_id bigint,
			match_value character varying(500) NOT NULL,
			role_id bigint NOT NULL,
			enabled boolean DEFAULT true NOT NULL,
			created_by bigint NOT NULL,
			CONSTRAINT chk_group_role_mapping_source CHECK (((((ldap_directory_id IS NOT NULL))::integer + ((oidc_provider_id IS NOT NULL))::integer) = 1)),
			CONSTRAINT group_role_mappings_pkey PRIMARY KEY (id)
		)`,
		`CREATE TABLE user_role_mappings (
			user_id bigint NOT NULL,
			role_id bigint NOT NULL,
			channel character varying(64) NOT NULL,
			matched_at timestamp with time zone NOT NULL,
			CONSTRAINT user_role_mappings_pkey PRIMARY KEY (user_id, role_id, channel)
		)`,
		`ALTER TABLE ldap_directories ADD COLUMN attr_group character varying(100) DEFAULT ''::character varying NOT NULL`,
		`ALTER TABLE users ADD COLUMN group_snapshot_channel character varying(64)`,
		`ALTER TABLE users ADD COLUMN group_snapshot_groups text`,
		`ALTER TABLE users ADD COLUMN group_snapshot_at timestamp with time zone`,
		`ALTER TABLE oidc_providers ADD COLUMN groups_claim character varying(64)`,
		`ALTER TABLE oidc_providers ADD COLUMN username_claim character varying(64)`,
		`ALTER TABLE oidc_providers ADD COLUMN email_claim character varying(64)`,
		`ALTER TABLE oidc_providers ADD COLUMN display_name_claim character varying(64)`,
		`ALTER TABLE group_role_mappings ADD CONSTRAINT fk_group_role_mappings_ldap_directory FOREIGN KEY (ldap_directory_id) REFERENCES ldap_directories(id)`,
		`ALTER TABLE group_role_mappings ADD CONSTRAINT fk_group_role_mappings_oidc_provider FOREIGN KEY (oidc_provider_id) REFERENCES oidc_providers(id)`,
		`ALTER TABLE group_role_mappings ADD CONSTRAINT fk_group_role_mappings_role FOREIGN KEY (role_id) REFERENCES roles(id)`,
		`ALTER TABLE group_role_mappings ADD CONSTRAINT fk_group_role_mappings_created_by_user FOREIGN KEY (created_by) REFERENCES users(id)`,
		`ALTER TABLE user_role_mappings ADD CONSTRAINT fk_user_role_mappings_user FOREIGN KEY (user_id) REFERENCES users(id)`,
		`ALTER TABLE user_role_mappings ADD CONSTRAINT fk_user_role_mappings_role FOREIGN KEY (role_id) REFERENCES roles(id)`,
		`CREATE INDEX idx_group_role_mappings_deleted_at ON group_role_mappings USING btree (deleted_at)`,
		`CREATE UNIQUE INDEX idx_group_role_mappings_ldap ON group_role_mappings USING btree (ldap_directory_id, match_value, role_id) WHERE (deleted_at IS NULL)`,
		`CREATE UNIQUE INDEX idx_group_role_mappings_oidc ON group_role_mappings USING btree (oidc_provider_id, match_value, role_id) WHERE (deleted_at IS NULL)`,
	}
}

func applyGroupRoleMapping(db *gorm.DB) error {
	for _, stmt := range groupRoleMappingDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 group_role_mapping DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackGroupRoleMapping 反序卸下。見本檔檔頭的 Down 契約——**有損**。
func rollbackGroupRoleMapping(db *gorm.DB) error {
	stmts := []string{
		`ALTER TABLE users DROP COLUMN group_snapshot_at`,
		`ALTER TABLE users DROP COLUMN group_snapshot_groups`,
		`ALTER TABLE users DROP COLUMN group_snapshot_channel`,
		`ALTER TABLE oidc_providers DROP COLUMN display_name_claim`,
		`ALTER TABLE oidc_providers DROP COLUMN email_claim`,
		`ALTER TABLE oidc_providers DROP COLUMN username_claim`,
		`ALTER TABLE oidc_providers DROP COLUMN groups_claim`,
		`DROP TABLE user_role_mappings`,
		`DROP TABLE group_role_mappings`,
		`ALTER TABLE ldap_directories DROP COLUMN attr_group`,
		`ALTER TABLE user_roles DROP COLUMN source`,
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("回滾 group_role_mapping 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}
