package asset

import (
	"context"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/audit/port"
)

// noopTopologyPort 只讓拓撲寫入通過「port 已注入」的前置檢查，不做任何事。
// 要驗版本推進行為的測試改用 TestTopologyAdvancesAuthzVersion 的記錄型 fake。
type noopTopologyPort struct{}

func (noopTopologyPort) LockTopology(*gorm.DB) error           { return nil }
func (noopTopologyPort) BeginPermissionChange(*gorm.DB) error  { return nil }
func (noopTopologyPort) AdvanceVersion(*gorm.DB) error         { return nil }
func (noopTopologyPort) SettlePermissionChange(*gorm.DB) error { return nil }

// newGroupSvc 建立已注入 noop 拓撲 port 的節點樹服務（測試夾具；要驗版本行為的測試另行注入記錄型 fake）。
func newGroupSvc(db *gorm.DB, auditTx port.TxSink, rv assetGroupAuthorizationRevoker) *AssetGroupService {
	s := NewAssetGroupService(db, auditTx, rv)
	s.SetTopologyPermissionPort(noopTopologyPort{})
	wireNodeTestPorts(s)
	return s
}

// allowNodeWrites 放行全部節點寫入的範圍判定替身（等同超級管理者，不帶跨指派標記）。
type allowNodeWrites struct{}

func (allowNodeWrites) AuthorizeNodeCreate(context.Context, *gorm.DB, *uint) error { return nil }
func (allowNodeWrites) AuthorizeNodeEdit(context.Context, *gorm.DB, uint) error    { return nil }
func (allowNodeWrites) AuthorizeNodeMove(context.Context, *gorm.DB, uint, *uint) (NodeMoveScope, error) {
	return NodeMoveScope{}, nil
}

// noNodeReferences 沒有任何範圍引用的替身。
type noNodeReferences struct{}

func (noNodeReferences) NodeScopeReferences(*gorm.DB, uint) (NodeReferences, error) {
	return NodeReferences{}, nil
}

// emptyCoverage 沒有任何涵蓋來源的快照替身。
type emptyCoverage struct{}

func (emptyCoverage) CoverageSnapshot(*gorm.DB, []uint) (CoverageSnapshot, error) {
	return CoverageSnapshot{}, nil
}

// wireNodeTestPorts 注入節點寫入需要的三個替身（範圍判定、引用查詢、涵蓋快照）。
func wireNodeTestPorts(s *AssetGroupService) {
	s.SetNodeWriteScopePort(allowNodeWrites{})
	s.SetNodeScopeReferencePort(noNodeReferences{})
	s.SetCoverageSnapshotPort(emptyCoverage{})
}
