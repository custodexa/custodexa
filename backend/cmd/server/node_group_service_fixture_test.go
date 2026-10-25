package main

import (
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
)

// newWiredAssetGroupService 與正式組裝相同接線的節點樹服務（拓撲鎖、範圍判定、引用查詢、涵蓋快照）。
// revoker 為 nil 時刪除依既有規則 fail-close。
// groupRevoker 節點刪除的授權級聯（asset 端介面未匯出，此處以同形介面承接）。
type groupRevoker interface {
	RevokeByAssetGroup(tx *gorm.DB, groupID uint) (int64, int64, error)
}

func newWiredAssetGroupService(db *gorm.DB, revoker groupRevoker) *asset.AssetGroupService {
	svc := asset.NewAssetGroupService(db, audit.NewTxSink(), revoker)
	svc.SetTopologyPermissionPort(authz.TopologyPermissionAdapter{})
	svc.SetNodeWriteScopePort(authz.NewNodeWriteScope(authz.NewScopeEvaluator(authz.ProductCatalogue(), asset.NewScopeTopologyReader())))
	svc.SetNodeScopeReferencePort(authz.NewNodeScopeReferenceReader())
	svc.SetCoverageSnapshotPort(authz.NewTopologyCoverageReader(asset.NewScopeTopologyReader()))
	return svc
}
