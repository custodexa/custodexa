package database

// Down means disabling item readers/writers in the application while retaining
// all request/item evidence. It never drops access_request_items or its data.
import (
	"fmt"
	"gorm.io/gorm"
)

func accessRequestItemsDDL() []string {
	return []string{
		`ALTER TABLE access_requests ADD COLUMN executor_user_id bigint REFERENCES users(id)`,
		`ALTER TABLE access_requests ADD COLUMN closed_at timestamptz`,
		`CREATE TABLE access_request_items (
 id bigserial PRIMARY KEY, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz,
 request_id bigint NOT NULL REFERENCES access_requests(id), requester_id bigint NOT NULL REFERENCES users(id),
 asset_id bigint NOT NULL REFERENCES assets(id), accounts text, status varchar(20) NOT NULL,
 approved_duration_minutes bigint, approved_date_start timestamptz, decided_by bigint REFERENCES users(id),
 decided_at timestamptz, revoked_at timestamptz, revoked_by bigint REFERENCES users(id),
 policy_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb)`,
		`CREATE INDEX access_request_items_request_idx ON access_request_items(request_id)`,
		`CREATE INDEX access_request_items_requester_idx ON access_request_items(requester_id)`,
		`CREATE INDEX access_request_items_asset_idx ON access_request_items(asset_id)`,
		`CREATE INDEX access_request_items_deleted_idx ON access_request_items(deleted_at)`,
		`CREATE INDEX access_request_items_status_idx ON access_request_items(status)`,
		`CREATE UNIQUE INDEX access_request_items_pending_unique ON access_request_items(requester_id,asset_id) WHERE status='pending' AND deleted_at IS NULL`,
	}
}
func applyAccessRequestItems(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		stmts := accessRequestItemsDDL()
		// The pending constraint is installed only after the checked backfill.
		for _, stmt := range stmts[:len(stmts)-1] {
			if err := tx.Exec(stmt).Error; err != nil {
				return err
			}
		}
		var source int64
		if err := tx.Table("access_requests").Where("deleted_at IS NULL").Count(&source).Error; err != nil {
			return err
		}
		res := tx.Exec(`INSERT INTO access_request_items
  (created_at,updated_at,request_id,requester_id,asset_id,accounts,status,approved_duration_minutes,approved_date_start,decided_by,decided_at,revoked_at,revoked_by,policy_snapshot)
  SELECT created_at,updated_at,id,requester_id,asset_id,accounts,
  CASE WHEN revoked_at IS NOT NULL OR status IN ('cancelled','expired') THEN 'revoked' ELSE status END,
  approved_duration_minutes,approved_date_start,approver_id,decided_at,revoked_at,revoked_by,'{}'::jsonb
  FROM access_requests WHERE deleted_at IS NULL`)
		if res.Error != nil {
			return res.Error
		}
		var count, distinct int64
		if err := tx.Table("access_request_items").Count(&count).Error; err != nil {
			return err
		}
		if err := tx.Table("access_request_items").Distinct("request_id").Count(&distinct).Error; err != nil {
			return err
		}
		if res.RowsAffected != source || count != source || distinct != source {
			return fmt.Errorf("request item backfill mismatch: source=%d inserted=%d rows=%d requests=%d", source, res.RowsAffected, count, distinct)
		}
		return tx.Exec(stmts[len(stmts)-1]).Error
	})
}
func rollbackAccessRequestItems(*gorm.DB) error {
	return fmt.Errorf("access_request_items rollback requires disabling application readers/writers; evidence is retained")
}
