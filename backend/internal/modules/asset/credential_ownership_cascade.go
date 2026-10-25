package asset

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 歸屬節點被刪除時的共用憑證承接。
//
// 在節點刪除交易內（同一把拓撲序列化鎖，由節點刪除交易在第一個動作取得）把歸屬該節點的共用憑證
// 改歸父節點；頂層節點改為全域。能被刪除的節點不是任何指派的範圍根（引用檢查先擋下），凡能管理它的
// 指派都經其祖先涵蓋，所以承接後「誰能管理這筆憑證」的集合不變；頂層節點只有全域主體能管，改為全域亦然。
//
// 不阻擋節點刪除、不讓憑證懸空：已軟刪的憑證同樣改寫（不寫審計），任何列都不留下指向已刪節點的歸屬。
// 每筆未刪除的承接寫一列歸屬變更審計；權限版本由節點刪除交易統一推進一次，本函式不推進。
//
// 屬 asset 模組自己的表，由節點刪除交易直接呼叫（不經注入），因此不存在「未接上就留下懸空歸屬」的形態。

// cascadeCredentialOwnershipTx 承接 nodeID 上的共用憑證歸屬；parentID 為 nil 表示頂層節點。
func cascadeCredentialOwnershipTx(tx *gorm.DB, sink port.TxSink, nodeID uint, parentID *uint,
	actorID uint, actorName string) error {

	var all []struct {
		ID      uint
		Deleted bool
	}
	if err := tx.Unscoped().Model(&model.Credential{}).
		Select("id, deleted_at IS NOT NULL AS deleted").
		Where("owner_kind = ? AND owner_node_id = ?", model.CredentialOwnerNode, nodeID).
		Order("id").Scan(&all).Error; err != nil {
		return fmt.Errorf("查詢節點歸屬的憑證失敗: %w", err)
	}
	if len(all) == 0 {
		return nil
	}
	ids := make([]uint, 0, len(all))
	alive := make([]uint, 0, len(all))
	for _, r := range all {
		ids = append(ids, r.ID)
		if !r.Deleted {
			alive = append(alive, r.ID)
		}
	}
	// 列鎖依識別升冪，排在節點刪除交易已取的拓撲序列化鎖之後
	if _, err := lockCredentialRowsOrdered(tx, alive...); err != nil {
		return err
	}
	to := CredentialOwnership{Kind: model.CredentialOwnerGlobal}
	if parentID != nil && *parentID != 0 {
		pid := *parentID
		to = CredentialOwnership{Kind: model.CredentialOwnerNode, NodeID: &pid}
	}
	if err := tx.Unscoped().Model(&model.Credential{}).Where("id IN ?", ids).
		Updates(ownershipColumns(to)).Error; err != nil {
		return fmt.Errorf("承接節點歸屬的憑證失敗: %w", err)
	}
	from := nodeID
	before := CredentialOwnership{Kind: model.CredentialOwnerNode, NodeID: &from}
	for _, id := range alive {
		if err := writeCredentialAudit(sink, tx, credentialAudit{
			CredentialID:    id,
			Operation:       model.AccountOpUpdate,
			Scope:           model.CredentialScopeShared,
			Fields:          []string{"ownership"},
			Ownership:       ownershipAudit(to),
			OwnershipBefore: ownershipAudit(before),
		}, actorID, actorName); err != nil {
			return err
		}
	}
	return nil
}
