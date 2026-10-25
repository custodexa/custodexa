package proxy

import "gorm.io/gorm"

// noopTopologyPort 只讓資產拓撲寫入通過「版本介面已注入」的前置檢查，不做任何事。
// 版本推進行為的測試在 asset 與 authz 套件。
type noopTopologyPort struct{}

func (noopTopologyPort) LockTopology(*gorm.DB) error           { return nil }
func (noopTopologyPort) BeginPermissionChange(*gorm.DB) error  { return nil }
func (noopTopologyPort) AdvanceVersion(*gorm.DB) error         { return nil }
func (noopTopologyPort) SettlePermissionChange(*gorm.DB) error { return nil }
