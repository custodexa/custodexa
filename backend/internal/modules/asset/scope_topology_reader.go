package asset

import (
	"sort"

	"gorm.io/gorm"
)

// ScopeTopologyReader 節點範圍判定用的拓撲唯讀介面。
//
// 全部方法只讀、只用呼叫方交給的交易句柄、不取鎖、不留存任何結果。
// 已刪除的節點既不作為範圍節點，也不被穿過：從已刪節點往上不再延伸，
// 掛在已刪節點上的資產沒有掛載節點。
// 結構相容於 authz 的 ScopeTopology 介面（asset 不 import authz）。
type ScopeTopologyReader struct{}

// NewScopeTopologyReader 建立無狀態的拓撲讀取器。
func NewScopeTopologyReader() *ScopeTopologyReader { return &ScopeTopologyReader{} }

func sortIDs(ids []uint) []uint {
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func fresh(tx *gorm.DB) *gorm.DB { return tx.Session(&gorm.Session{NewDB: true}) }

// AssetCoverNodes 資產的掛載節點加上這些節點的未刪除祖先。
// 只有未刪除的資產 exists 為真；exists 為真而沒有掛載（未分組）時回空集合。
func (r *ScopeTopologyReader) AssetCoverNodes(tx *gorm.DB, assetID uint) ([]uint, bool, error) {
	db := fresh(tx)
	var n int64
	if err := db.Raw(`SELECT COUNT(*) FROM assets WHERE id = ? AND deleted_at IS NULL`, assetID).Scan(&n).Error; err != nil {
		return nil, false, err
	}
	if n == 0 {
		return nil, false, nil
	}
	// 起點與每個祖先都必須是未刪除節點：已刪除的節點不收入也不往上穿過
	var ids []uint
	err := db.Raw(`WITH RECURSIVE anc(id) AS (
		SELECT an.node_id FROM asset_nodes an
		JOIN asset_groups g ON g.id = an.node_id AND g.deleted_at IS NULL
		WHERE an.asset_id = ?
		UNION
		SELECT p.id FROM anc
		JOIN asset_groups g ON g.id = anc.id
		JOIN asset_groups p ON p.id = g.parent_id AND p.deleted_at IS NULL
	) SELECT id FROM anc`, assetID).Scan(&ids).Error
	if err != nil {
		return nil, false, err
	}
	return sortIDs(ids), true, nil
}

// NodeCoverNodes 節點自身加上未刪除祖先；已刪除或不存在的節點 exists 為假。
func (r *ScopeTopologyReader) NodeCoverNodes(tx *gorm.DB, nodeID uint) ([]uint, bool, error) {
	db := fresh(tx)
	var ids []uint
	err := db.Raw(`WITH RECURSIVE anc(id) AS (
		SELECT id FROM asset_groups WHERE id = ? AND deleted_at IS NULL
		UNION
		SELECT p.id FROM anc
		JOIN asset_groups g ON g.id = anc.id
		JOIN asset_groups p ON p.id = g.parent_id AND p.deleted_at IS NULL
	) SELECT id FROM anc`, nodeID).Scan(&ids).Error
	if err != nil {
		return nil, false, err
	}
	if len(ids) == 0 {
		return nil, false, nil
	}
	return sortIDs(ids), true, nil
}

// AccountAsset 資產帳號（掛載列）所屬的資產 ID；已刪除或不存在的帳號 exists 為假。
// 資產本身是否存在由呼叫方另以 AssetCoverNodes 判定。
func (r *ScopeTopologyReader) AccountAsset(tx *gorm.DB, accountID uint) (uint, bool, error) {
	var rows []uint
	if err := fresh(tx).Raw(`SELECT asset_id FROM asset_accounts WHERE id = ? AND deleted_at IS NULL`, accountID).Scan(&rows).Error; err != nil {
		return 0, false, err
	}
	if len(rows) == 0 {
		return 0, false, nil
	}
	return rows[0], true, nil
}

// CandidateAccount 改密候選所屬的資產帳號 ID；不存在的候選 exists 為假。
// 帳號與資產是否存在由呼叫方另以 AccountAsset 與 AssetCoverNodes 判定。
func (r *ScopeTopologyReader) CandidateAccount(tx *gorm.DB, candidateID uint) (uint, bool, error) {
	var rows []uint
	if err := fresh(tx).Raw(`SELECT account_id FROM change_secret_candidates WHERE id = ?`, candidateID).Scan(&rows).Error; err != nil {
		return 0, false, err
	}
	if len(rows) == 0 {
		return 0, false, nil
	}
	return rows[0], true, nil
}

// SubtreeNodeIDs 回子查詢：以 roots 為根的子樹內全部未刪除節點（含根自身）。
// 已刪除的根不起算，已刪除的中間節點不被穿過。
func (r *ScopeTopologyReader) SubtreeNodeIDs(tx *gorm.DB, roots []uint) *gorm.DB {
	return fresh(tx).Raw(`WITH RECURSIVE sub(id) AS (
		SELECT id FROM asset_groups WHERE id IN ? AND deleted_at IS NULL
		UNION
		SELECT g.id FROM asset_groups g JOIN sub ON g.parent_id = sub.id WHERE g.deleted_at IS NULL
	) SELECT id FROM sub`, nonNilIDs(roots))
}

// SubtreeAssetIDs 回子查詢：以 roots 為根的子樹內掛載的未刪除資產（去重）。
func (r *ScopeTopologyReader) SubtreeAssetIDs(tx *gorm.DB, roots []uint) *gorm.DB {
	return fresh(tx).Raw(`WITH RECURSIVE sub(id) AS (
		SELECT id FROM asset_groups WHERE id IN ? AND deleted_at IS NULL
		UNION
		SELECT g.id FROM asset_groups g JOIN sub ON g.parent_id = sub.id WHERE g.deleted_at IS NULL
	) SELECT DISTINCT an.asset_id FROM asset_nodes an
		JOIN assets a ON a.id = an.asset_id AND a.deleted_at IS NULL
		WHERE an.node_id IN (SELECT id FROM sub)`, nonNilIDs(roots))
}

// CredentialOwnership 憑證的管理歸屬（歸屬種類與歸屬節點）；已刪除或不存在的憑證 exists 為假。
// 歸屬尚未回填（NULL）時 kind 回空字串。
func (r *ScopeTopologyReader) CredentialOwnership(tx *gorm.DB, credentialID uint) (string, *uint, bool, error) {
	type ownerRow struct {
		OwnerKind   *string
		OwnerNodeID *uint
	}
	var rows []ownerRow
	if err := fresh(tx).Raw(`SELECT owner_kind, owner_node_id FROM credentials WHERE id = ? AND deleted_at IS NULL`,
		credentialID).Scan(&rows).Error; err != nil {
		return "", nil, false, err
	}
	if len(rows) == 0 {
		return "", nil, false, nil
	}
	kind := ""
	if rows[0].OwnerKind != nil {
		kind = *rows[0].OwnerKind
	}
	return kind, rows[0].OwnerNodeID, true, nil
}

// CredentialFirstMountAsset 憑證最早一筆未刪除掛載列所屬的資產 ID；沒有掛載回 0。
// 資產本身是否存在由呼叫方另以 AssetCoverNodes 判定。
func (r *ScopeTopologyReader) CredentialFirstMountAsset(tx *gorm.DB, credentialID uint) (uint, error) {
	var rows []uint
	if err := fresh(tx).Raw(`SELECT asset_id FROM asset_accounts WHERE credential_id = ? AND deleted_at IS NULL
		ORDER BY id ASC LIMIT 1`, credentialID).Scan(&rows).Error; err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0], nil
}

// CredentialsFirstMountedOn 回子查詢：最早一筆未刪除掛載列落在 assetIDs（子查詢）上的憑證 ID。
// 與 CredentialFirstMountAsset 同一口徑，使集合判定與單筆判定一致（多筆掛載時不以較晚的掛載放行）。
func (r *ScopeTopologyReader) CredentialsFirstMountedOn(tx *gorm.DB, assetIDs *gorm.DB) *gorm.DB {
	return fresh(tx).Raw(`SELECT a.credential_id FROM asset_accounts a WHERE a.deleted_at IS NULL AND a.asset_id IN (?)
		AND a.id = (SELECT min(b.id) FROM asset_accounts b WHERE b.credential_id = a.credential_id AND b.deleted_at IS NULL)`, assetIDs)
}

// CredentialsByID 回以 credentials 為主表、限定在 ids 內（排除已刪除）的查詢，供呼叫方再套範圍條件後取出識別。
func (r *ScopeTopologyReader) CredentialsByID(tx *gorm.DB, ids []uint) *gorm.DB {
	return fresh(tx).Table("credentials").Where("credentials.deleted_at IS NULL AND credentials.id IN ?", nonNilIDs(ids))
}

func nonNilIDs(ids []uint) []uint {
	if ids == nil {
		return []uint{}
	}
	return ids
}
