package database

import "gorm.io/gorm"

// Item decisions need stable ticket/vote identities; Down retains all evidence.
func accessRequestItemDecisionsDDL() []string {
	return []string{
		`ALTER TABLE access_request_items ADD COLUMN authorization_id bigint REFERENCES asset_authorizations(id)`,
		`ALTER TABLE access_request_items ADD COLUMN revoke_note varchar(1000)`,
		`CREATE UNIQUE INDEX idx_access_request_items_authorization_id ON access_request_items(authorization_id)`,
		`ALTER TABLE access_request_approvals ADD COLUMN item_id bigint REFERENCES access_request_items(id)`,
		`DROP INDEX idx_request_approval_once`,
		`CREATE UNIQUE INDEX idx_request_approval_once ON access_request_approvals(item_id,request_id,approver_id)`,
		`CREATE UNIQUE INDEX idx_request_approval_legacy_once ON access_request_approvals(request_id,approver_id) WHERE item_id IS NULL`,
		`CREATE INDEX idx_access_request_approvals_item_id ON access_request_approvals(item_id)`,
	}
}
func applyAccessRequestItemDecisions(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		for _, sql := range accessRequestItemDecisionsDDL() {
			if err := tx.Exec(sql).Error; err != nil {
				return err
			}
		}
		if err := tx.Exec(`UPDATE access_request_items i SET authorization_id=r.authorization_id,revoke_note=r.revoke_note FROM access_requests r WHERE i.request_id=r.id AND i.asset_id=r.asset_id`).Error; err != nil {
			return err
		}
		// The earlier adapter only mirrored the first ticket on the envelope.
		// Link later automatic items by their exact execution subject, asset and approved window;
		// never guess between multiple matching tickets.
		if err := tx.Exec(`UPDATE access_request_items i SET authorization_id=(
   SELECT min(aa.id) FROM asset_authorizations aa JOIN access_requests r ON r.id=i.request_id
   WHERE aa.source='ticket' AND aa.user_id=COALESCE(r.executor_user_id,r.requester_id) AND aa.asset_id=i.asset_id
    AND aa.date_start=i.approved_date_start AND aa.date_expired=i.approved_date_start + i.approved_duration_minutes * interval '1 minute'
   HAVING count(*)=1
  ) WHERE i.authorization_id IS NULL AND i.approved_date_start IS NOT NULL`).Error; err != nil {
			return err
		}
		return tx.Exec(`UPDATE access_request_approvals a SET item_id=i.id FROM access_request_items i,access_requests r WHERE a.request_id=r.id AND i.request_id=r.id AND i.asset_id=r.asset_id`).Error
	})
}
