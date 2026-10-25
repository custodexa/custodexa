package main

import (
	"testing"

	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"gorm.io/gorm"
)

// 組裝根的系統告警落地面自檢：nil 與 typed-nil 都拒絕，真實建構通過；
// 組裝根（stage2.go）必須在建構後自檢，並在自檢失敗時中止啟動。
func TestRequireSystemAlertSink(t *testing.T) {
	if err := requireSystemAlertSink(nil); err == nil {
		t.Fatal("nil 應被拒絕")
	}
	var typedNil port.SystemAlertSink = (*typedNilSystemAlertSink)(nil)
	if err := requireSystemAlertSink(typedNil); err == nil {
		t.Fatal("typed-nil 應被拒絕")
	}
	if err := requireSystemAlertSink(audit.NewSystemAlertSink(nil)); err != nil {
		t.Fatalf("真實建構應通過: %v", err)
	}
}

type typedNilSystemAlertSink struct{}

func (*typedNilSystemAlertSink) RaiseInTx(_ *gorm.DB, _ port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, nil
}
