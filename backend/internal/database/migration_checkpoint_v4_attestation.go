package database

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 檢查點第四版載荷：權限附證改由檢查點自己的簽章涵蓋。
//
// 只改結構、不改資料：
//   - audit_checkpoints.perm_origin：本點是否為可信起點（在第四版簽章內）。
//   - audit_checkpoints.perm_signature 卸下：附證不再另行簽章，改為檢查點載荷的一部分。
//   - audit_checkpoint_trims.format／perm_history／unverified_count：第二版修剪錨帶走
//     被剪段的累計事實（曾有附證、曾有驗不過的點），存量錨維持 format=1、原位元組照驗。
//   - 部分索引 idx_audit_checkpoints_perm_trace：任一附證欄非空的列；述詞與對帳端
//     EXISTS 查詢逐字相同，啟用後判定「是否有附證痕跡」只花一次索引查詢。
//
// 無資料步驟、無回填：存量檢查點的 perm_origin 為 NULL（第四版之前的點不走第四版載荷）。
// DDL 無條件，不用 IF NOT EXISTS；版本集合負責避免重跑。
//
// # Down 契約
//
// 不提供回滾：卸下的欄位無法重建，回退只走升級前備份。
func checkpointV4AttestationDDL() []string {
	return []string{
		`ALTER TABLE audit_checkpoints ADD COLUMN perm_origin boolean`,
		`ALTER TABLE audit_checkpoints DROP COLUMN perm_signature`,
		`ALTER TABLE audit_checkpoint_trims ADD COLUMN format bigint DEFAULT 1 NOT NULL`,
		`ALTER TABLE audit_checkpoint_trims ADD COLUMN perm_history character varying(16)`,
		`ALTER TABLE audit_checkpoint_trims ADD COLUMN unverified_count bigint`,
		`CREATE INDEX idx_audit_checkpoints_perm_trace ON audit_checkpoints (seq) WHERE ` + model.CheckpointPermTracePredicate,
	}
}

func applyCheckpointV4Attestation(db *gorm.DB) error {
	for _, stmt := range checkpointV4AttestationDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 checkpoint_v4_attestation DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	return nil
}

// rollbackCheckpointV4Attestation 不提供回滾；見檔頭 Down 契約。
func rollbackCheckpointV4Attestation(db *gorm.DB) error {
	return fmt.Errorf("checkpoint v4 attestation has no rollback; restore the pre-upgrade backup")
}
