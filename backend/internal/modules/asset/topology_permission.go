package asset

import (
	"errors"

	"gorm.io/gorm"
)

// TopologyPermissionPort 拓撲寫入交易需要的權限版本動作（tx-taking 窄 port）。
//
// 消費者側窄介面：asset 不 import authz，由組裝根注入 authz 的實作。四個動作都在
// 呼叫端交易內執行，本身不開交易、不提交。
//
//   - LockTopology：取拓撲序列化鎖，必須是拓撲寫入交易的第一個動作，早於憑證列、資產列等
//     任何業務列鎖。
//   - BeginPermissionChange：第一個權限相關寫入之前呼叫，不取鎖。
//   - AdvanceVersion：寫入之後推進權限版本；每個交易至多一次。
//   - SettlePermissionChange：版本推進之後仍有權限寫入時，於交易結尾補記。
type TopologyPermissionPort interface {
	LockTopology(tx *gorm.DB) error
	BeginPermissionChange(tx *gorm.DB) error
	AdvanceVersion(tx *gorm.DB) error
	SettlePermissionChange(tx *gorm.DB) error
}

// ErrTopologyPermissionPortMissing 拓撲寫入需要權限版本窄 port 而它沒有注入。
// 沿 fail-close：寧可整筆回滾，也不默默略過推進而讓舊快取繼續放行。
var ErrTopologyPermissionPortMissing = errors.New("asset: topology permission port not injected")

// SetTopologyPermissionPort 注入拓撲寫入用的權限版本窄 port（組裝時）。
func (s *AssetService) SetTopologyPermissionPort(p TopologyPermissionPort) {
	s.topologyPort = p
}

// lockTopologyTx 拓撲寫入交易的第一個動作。未注入回 ErrTopologyPermissionPortMissing。
func (s *AssetService) lockTopologyTx(tx *gorm.DB) error {
	if s.topologyPort == nil {
		return ErrTopologyPermissionPortMissing
	}
	return s.topologyPort.LockTopology(tx)
}

// beginTopologyChangeTx 第一個權限相關寫入之前呼叫（不取鎖）。
func (s *AssetService) beginTopologyChangeTx(tx *gorm.DB) error {
	if s.topologyPort == nil {
		return ErrTopologyPermissionPortMissing
	}
	return s.topologyPort.BeginPermissionChange(tx)
}

// advanceTopologyVersionTx 拓撲寫入完成後推進權限版本。
func (s *AssetService) advanceTopologyVersionTx(tx *gorm.DB) error {
	if s.topologyPort == nil {
		return ErrTopologyPermissionPortMissing
	}
	return s.topologyPort.AdvanceVersion(tx)
}

// SetTopologyPermissionPort 注入節點搬移與刪除用的拓撲序列化鎖與權限版本窄 port（組裝時）。
func (s *AssetGroupService) SetTopologyPermissionPort(p TopologyPermissionPort) {
	s.topologyPort = p
}

// lockTopologyTx 節點建立、搬移與刪除交易的第一個動作。未注入回 ErrTopologyPermissionPortMissing。
func (s *AssetGroupService) lockTopologyTx(tx *gorm.DB) error {
	if s.topologyPort == nil {
		return ErrTopologyPermissionPortMissing
	}
	return s.topologyPort.LockTopology(tx)
}

// beginTopologyChangeTx 第一個權限相關寫入之前呼叫（不取鎖）。
func (s *AssetGroupService) beginTopologyChangeTx(tx *gorm.DB) error {
	if s.topologyPort == nil {
		return ErrTopologyPermissionPortMissing
	}
	return s.topologyPort.BeginPermissionChange(tx)
}

// advanceTopologyVersionTx 節點樹形狀改變後推進權限版本。
func (s *AssetGroupService) advanceTopologyVersionTx(tx *gorm.DB) error {
	if s.topologyPort == nil {
		return ErrTopologyPermissionPortMissing
	}
	return s.topologyPort.AdvanceVersion(tx)
}
