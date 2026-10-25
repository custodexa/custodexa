package main

import "fmt"

// 授權規則寫入與臨時授權撤銷的範圍判定、交易內審計的組裝期自檢。
//
// 服務層在未注入時走不判定的內部路徑（程式內部建構與測試用）；產品組裝一律經本檔的自檢，
// 未注入即拒絕啟動，不降級。

// requireAuthorizationWriteScope 授權規則寫入的範圍判定已注入，否則回錯誤。
func requireAuthorizationWriteScope(svc interface{ RequireWriteScope() error }) error {
	if err := svc.RequireWriteScope(); err != nil {
		return fmt.Errorf("授權規則寫入的範圍判定未注入，拒絕啟動: %w", err)
	}
	return nil
}

// requireAccessRequestRevokeWiring 撤銷的範圍判定與交易內審計落地面已注入，否則回錯誤。
func requireAccessRequestRevokeWiring(svc interface{ RequireRevokeWiring() error }) error {
	if err := svc.RequireRevokeWiring(); err != nil {
		return fmt.Errorf("臨時授權撤銷的範圍判定或交易內審計未注入，拒絕啟動: %w", err)
	}
	return nil
}
