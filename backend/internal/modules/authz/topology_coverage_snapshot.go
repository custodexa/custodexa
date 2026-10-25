package authz

import (
	"errors"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 拓撲變更的涵蓋快照（實作 asset 的消費者側窄介面）：每個資產在三種來源的節點涵蓋。
//
//   - 連線授權：未撤銷的節點型授權，節點在資產的涵蓋節點內；取主體與等級。直接授予資產的授權不受拓撲影響，不納入。
//   - 審核範圍：未撤銷的資產型與節點型審核範圍；取審核方主體。
//   - 管理範圍：節點範圍指派（原始關係，指派紀錄存在）的範圍節點在資產的涵蓋節點內；取主體與角色。
//
// 涵蓋節點＝資產掛載節點加未刪除祖先（與範圍判定同一子樹語義），已刪節點與其上的列不計入。

var errCoverageNilTx = errors.New("authz: coverage snapshot without transaction")

// TopologyCoverageReader 涵蓋快照查詢。零值不可用；以 NewTopologyCoverageReader 建立。
type TopologyCoverageReader struct {
	topo ScopeTopology
}

// NewTopologyCoverageReader 以拓撲唯讀介面建立。
func NewTopologyCoverageReader(topo ScopeTopology) *TopologyCoverageReader {
	return &TopologyCoverageReader{topo: topo}
}

type coverGrantRow struct {
	UserID       *uint
	UserGroupID  *uint
	AssetGroupID uint
	Permission   string
}

type coverApproverRow struct {
	ApproverID      *uint
	ApproverGroupID *uint
	AssetID         *uint
	AssetGroupID    *uint
}

type coverManagerRow struct {
	SubjectKind string
	SubjectID   uint
	RoleID      uint
	NodeID      uint
}

func coverSubjectOf(userID, groupID *uint) (string, uint, bool) {
	switch {
	case userID != nil:
		return model.BindingSubjectUser, *userID, true
	case groupID != nil:
		return model.BindingSubjectUserGroup, *groupID, true
	}
	return "", 0, false
}

// CoverageSnapshot 回每個仍存在資產的涵蓋；查詢錯誤原樣回傳（呼叫方須回滾，不得無涵蓋差異完成）。
func (r *TopologyCoverageReader) CoverageSnapshot(tx *gorm.DB, assetIDs []uint) (asset.CoverageSnapshot, error) {
	if tx == nil {
		return asset.CoverageSnapshot{}, errCoverageNilTx
	}
	if r == nil || r.topo == nil {
		return asset.CoverageSnapshot{}, errNodeWriteScopeUnwired
	}
	out := asset.CoverageSnapshot{Assets: map[uint]asset.AssetCoverage{}}
	covers := map[uint]map[uint]struct{}{}
	var allNodes []uint
	seenNode := map[uint]struct{}{}
	for _, id := range assetIDs {
		nodes, exists, err := r.topo.AssetCoverNodes(tx, id)
		if err != nil {
			return asset.CoverageSnapshot{}, err
		}
		if !exists {
			continue
		}
		set := make(map[uint]struct{}, len(nodes))
		for _, n := range nodes {
			set[n] = struct{}{}
			if _, ok := seenNode[n]; !ok {
				seenNode[n] = struct{}{}
				allNodes = append(allNodes, n)
			}
		}
		covers[id] = set
		out.Assets[id] = asset.AssetCoverage{}
	}
	if len(covers) == 0 {
		return out, nil
	}
	db := tx.Session(&gorm.Session{NewDB: true})
	nodes := allNodes
	if nodes == nil {
		nodes = []uint{}
	}
	var grants []coverGrantRow
	if len(nodes) > 0 {
		if err := db.Raw(`SELECT user_id, user_group_id, asset_group_id, permission FROM asset_authorizations
			WHERE deleted_at IS NULL AND asset_group_id IN ?`, nodes).Scan(&grants).Error; err != nil {
			return asset.CoverageSnapshot{}, err
		}
	}
	ids := make([]uint, 0, len(covers))
	for id := range covers {
		ids = append(ids, id)
	}
	var approvers []coverApproverRow
	// 兩種形態各寫成字面量 SQL（表名可靜態解析）；沒有涵蓋節點時只比對資產
	approverQ := db.Raw(`SELECT approver_id, approver_group_id, asset_id, asset_group_id FROM approver_scopes
		WHERE deleted_at IS NULL AND asset_id IN ?`, ids)
	if len(nodes) > 0 {
		approverQ = db.Raw(`SELECT approver_id, approver_group_id, asset_id, asset_group_id FROM approver_scopes
			WHERE deleted_at IS NULL AND (asset_id IN ? OR asset_group_id IN ?)`, ids, nodes)
	}
	if err := approverQ.Scan(&approvers).Error; err != nil {
		return asset.CoverageSnapshot{}, err
	}
	var managers []coverManagerRow
	if len(nodes) > 0 {
		if err := db.Raw(`SELECT rbn.subject_kind, rbn.subject_id, rbn.role_id, rbn.node_id FROM role_binding_nodes rbn
			WHERE rbn.node_id IN ? AND `+bindingAssignmentExists, nodes).Scan(&managers).Error; err != nil {
			return asset.CoverageSnapshot{}, err
		}
	}
	for id, cover := range covers {
		out.Assets[id] = coverageFor(id, cover, grants, approvers, managers)
	}
	return out, nil
}

// coverageFor 依一個資產的涵蓋節點挑出三種來源的列（去重由差集產生器處理）。
func coverageFor(assetID uint, cover map[uint]struct{}, grants []coverGrantRow, approvers []coverApproverRow, managers []coverManagerRow) asset.AssetCoverage {
	var c asset.AssetCoverage
	for _, g := range grants {
		if _, ok := cover[g.AssetGroupID]; !ok {
			continue
		}
		if kind, sid, ok := coverSubjectOf(g.UserID, g.UserGroupID); ok {
			c.Grants = append(c.Grants, asset.CoverageGrant{Kind: kind, ID: sid, Level: g.Permission})
		}
	}
	for _, a := range approvers {
		hit := a.AssetID != nil && *a.AssetID == assetID
		if !hit && a.AssetGroupID != nil {
			_, hit = cover[*a.AssetGroupID]
		}
		if !hit {
			continue
		}
		if kind, sid, ok := coverSubjectOf(a.ApproverID, a.ApproverGroupID); ok {
			c.Approvers = append(c.Approvers, asset.CoverageSubject{Kind: kind, ID: sid})
		}
	}
	for _, m := range managers {
		if _, ok := cover[m.NodeID]; ok {
			c.Managers = append(c.Managers, asset.CoverageManager{Kind: m.SubjectKind, ID: m.SubjectID, RoleID: m.RoleID})
		}
	}
	return c
}
