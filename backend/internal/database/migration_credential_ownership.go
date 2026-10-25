package database

import (
	"encoding/json"
	"fmt"
	"log"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
)

// 憑證管理歸屬增量。
//
// 結構：
//   - credentials 加 owner_kind（global｜node｜asset）、owner_node_id 與複合索引 (owner_kind, owner_node_id)。
//   - credential_impact_confirmations：修改共用憑證時的範圍外影響確認（範圍外資產集合只存伺服器）。
//
// # 資料步驟
//
// 既有共用憑證一律設為 global、專用憑證設為 asset（含已軟刪的列，同一規則）。只更新
// owner_kind 為 NULL 的列，預先設定過的列（例如 node）保留不動，故可重入。規劃函式先算報告，
// 套用後以同一函式重算：待設定應為 0、其餘欄與預估一致；不一致即回傳錯誤使整筆交易回滾。
// 報告以固定前綴 credentialOwnershipReportPrefix 寫入後端日誌，供備份試跑與正式升級逐欄比對。
//
// 正常情況專用憑證只有一筆未刪除掛載。不符此形（無掛載或多筆掛載）的列只計入報告、不阻擋升級：
// 多筆時單筆歸屬以最早建立的一筆掛載決定；無掛載的憑證對範圍化主體不可見，只有全域主體可處置。
//
// # Down 契約
//
// 不提供回滾：回退只走升級前備份。
func credentialOwnershipDDL() []string {
	return []string{
		`ALTER TABLE credentials ADD COLUMN owner_kind character varying(16)`,
		`ALTER TABLE credentials ADD COLUMN owner_node_id bigint`,
		`CREATE INDEX idx_credentials_owner ON credentials USING btree (owner_kind, owner_node_id)`,
		`CREATE TABLE credential_impact_confirmations (id character varying(32) NOT NULL, credential_id bigint NOT NULL, user_id bigint NOT NULL, operation character varying(16) NOT NULL, authz_version bigint DEFAULT 0 NOT NULL, out_of_scope_asset_ids text DEFAULT '[]'::text NOT NULL, created_at timestamp with time zone, CONSTRAINT credential_impact_confirmations_pkey PRIMARY KEY (id), CONSTRAINT credential_impact_confirmations_operation_check CHECK (operation IN ('set_secret','rotate')))`,
		`CREATE UNIQUE INDEX idx_credential_impact_confirmations_actor ON credential_impact_confirmations USING btree (user_id, credential_id, operation)`,
	}
}

// credentialOwnershipReportPrefix 報告日誌的固定前綴（升級程序以此比對試跑與正式）。
const credentialOwnershipReportPrefix = "credential_ownership_migration_report"

// CredentialOwnershipReport 遷移報告；只含筆數，不含名稱或秘密。
type CredentialOwnershipReport struct {
	// SharedToGlobal 待設定的共用憑證數（將設為 global）
	SharedToGlobal int64 `json:"shared_to_global"`
	// DedicatedToAsset 待設定的專用憑證數（將設為 asset）
	DedicatedToAsset int64 `json:"dedicated_to_asset"`
	// AlreadySet owner_kind 已有值而略過的列數
	AlreadySet int64 `json:"already_set"`
	// DedicatedNotSingleBinding 專用憑證中未刪除掛載數不是恰一的列數（只報告、不阻擋）
	DedicatedNotSingleBinding int64 `json:"dedicated_not_single_binding"`
}

// PlanCredentialOwnership 計算遷移報告；不寫入。
func PlanCredentialOwnership(db *gorm.DB) (CredentialOwnershipReport, error) {
	var r CredentialOwnershipReport
	counts := []struct {
		dst   *int64
		query string
		args  []any
	}{
		{&r.SharedToGlobal, `SELECT count(*) FROM credentials WHERE owner_kind IS NULL AND scope = ?`, []any{model.CredentialScopeShared}},
		{&r.DedicatedToAsset, `SELECT count(*) FROM credentials WHERE owner_kind IS NULL AND scope = ?`, []any{model.CredentialScopeDedicated}},
		{&r.AlreadySet, `SELECT count(*) FROM credentials WHERE owner_kind IS NOT NULL`, nil},
		{&r.DedicatedNotSingleBinding, `SELECT count(*) FROM credentials c WHERE c.scope = ? AND c.deleted_at IS NULL AND (SELECT count(*) FROM asset_accounts a WHERE a.credential_id = c.id AND a.deleted_at IS NULL) <> 1`, []any{model.CredentialScopeDedicated}},
	}
	for _, q := range counts {
		if err := db.Raw(q.query, q.args...).Scan(q.dst).Error; err != nil {
			return CredentialOwnershipReport{}, fmt.Errorf("計算憑證歸屬遷移報告失敗: %w", err)
		}
	}
	return r, nil
}

// expectedAfter 套用後重算應得的報告：待設定歸零，全部列都屬「已設定」，不變式計數不變。
func (r CredentialOwnershipReport) expectedAfter() CredentialOwnershipReport {
	return CredentialOwnershipReport{
		AlreadySet:                r.AlreadySet + r.SharedToGlobal + r.DedicatedToAsset,
		DedicatedNotSingleBinding: r.DedicatedNotSingleBinding,
	}
}

// credentialOwnershipVerifyHook 測試注入：套用後、重算前改動資料，以驗證不一致時整筆回滾。
var credentialOwnershipVerifyHook func(tx *gorm.DB) error

// BackfillCredentialOwnership 資料步驟（冪等）：只填 owner_kind 為 NULL 的列，套用後重算比對。
// 回傳套用前的報告；呼叫方應在交易內呼叫，錯誤時整筆回滾。
func BackfillCredentialOwnership(tx *gorm.DB) (CredentialOwnershipReport, error) {
	before, err := PlanCredentialOwnership(tx)
	if err != nil {
		return CredentialOwnershipReport{}, err
	}
	steps := []struct{ owner, scope string }{
		{model.CredentialOwnerGlobal, model.CredentialScopeShared},
		{model.CredentialOwnerAsset, model.CredentialScopeDedicated},
	}
	for _, s := range steps {
		if err := tx.Exec(`UPDATE credentials SET owner_kind = ?, owner_node_id = NULL WHERE owner_kind IS NULL AND scope = ?`,
			s.owner, s.scope).Error; err != nil {
			return CredentialOwnershipReport{}, fmt.Errorf("回填憑證歸屬失敗: %w", err)
		}
	}
	if credentialOwnershipVerifyHook != nil {
		if err := credentialOwnershipVerifyHook(tx); err != nil {
			return CredentialOwnershipReport{}, err
		}
	}
	after, err := PlanCredentialOwnership(tx)
	if err != nil {
		return CredentialOwnershipReport{}, err
	}
	if want := before.expectedAfter(); after != want {
		return CredentialOwnershipReport{}, fmt.Errorf("憑證歸屬遷移重算不一致：預估 %+v，實得 %+v", want, after)
	}
	return before, nil
}

func applyCredentialOwnership(db *gorm.DB) error {
	for _, stmt := range credentialOwnershipDDL() {
		if err := db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("執行 credential_ownership DDL 失敗（%.80s…）: %w", stmt, err)
		}
	}
	report, err := BackfillCredentialOwnership(db)
	if err != nil {
		return err
	}
	b, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("序列化憑證歸屬遷移報告失敗: %w", err)
	}
	log.Printf("%s %s", credentialOwnershipReportPrefix, b)
	return nil
}

// rollbackCredentialOwnership 不提供回滾；見檔頭 Down 契約。
func rollbackCredentialOwnership(_ *gorm.DB) error {
	return fmt.Errorf("credential ownership has no down migration; restore the pre-upgrade backup instead")
}
