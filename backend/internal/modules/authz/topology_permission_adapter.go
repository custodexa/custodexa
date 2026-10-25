package authz

import "gorm.io/gorm"

// TopologyPermissionAdapter 把拓撲序列化鎖與權限版本推進四個動作，以 asset 端定義的窄介面形狀
// 交給組裝根注入（asset 不 import authz）。四個方法直接轉呼叫，不加任何邏輯。
type TopologyPermissionAdapter struct{}

// LockTopology 取拓撲序列化鎖。
func (TopologyPermissionAdapter) LockTopology(tx *gorm.DB) error { return LockScopeTopologyTx(tx) }

// BeginPermissionChange 見同名函式；不取鎖。
func (TopologyPermissionAdapter) BeginPermissionChange(tx *gorm.DB) error {
	return BeginPermissionChange(tx)
}

// AdvanceVersion 見同名函式。
func (TopologyPermissionAdapter) AdvanceVersion(tx *gorm.DB) error { return AdvanceVersion(tx) }

// SettlePermissionChange 見同名函式。
func (TopologyPermissionAdapter) SettlePermissionChange(tx *gorm.DB) error {
	return SettlePermissionChange(tx)
}
