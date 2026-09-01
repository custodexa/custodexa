package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// 離機儲存保管鏈事件的落地面 adapter。
//
// `internal/offsite` 宣告消費者側窄介面 `CustodyJournal` 並**不直寫 `audit_logs`**
// （包內守衛擋 `AuditLog{}` 字面量）；由組裝根在此把它縫到 audit 模組的落地面上。
// 方向是 assembly→{audit, offsite}，不開 offsite→audit 的出向邊。
//
// **兩個方法對應兩種呼叫脈絡，不可互相替代**：
//
//	RecordInTx  設定寫入路徑（世代切換、停止離機、撤銷憑證）：與資料變更同交易，
//	            回 error 即整筆回滾——設定世代被改寫卻無審計紀錄不是可接受的終局。
//	Record      worker 與取回路徑：沒有呼叫方交易。
//
// # 事件字面量為何在兩個方法內各寫一次，而不抽成共用的轉換函式
//
// 初版把 `port.AuditEvent{…}` 抽進 `offsiteAuditEventOf` 由兩個方法共用，程式碼較短，
// 但那個形態**讓四道審計守衛同時失明**：字面量落在轉換函式內、sink 呼叫落在兩個方法內，
// 兩者是不同的行號。`TestAuditSinkCallSitesArePrimaryIndex`（sink 呼叫主索引）要求每個
// 消費端 sink 呼叫點在 manifest 有登記列，而 manifest 的雙向完備性守衛只認得「事件字面量」
// 那一軸——同一個位置不可能既是字面量又不是，於是兩軸永遠對不起來。
//
// 收口後的既有形態（`ldap_seed_migration.go:335`、`source_ip_baseline.go:184`）都是
// **字面量寫在 sink 呼叫的引數位置**，兩軸落在同一行。此處照辦：共用的只有 details 序列化。
type offsiteCustodyJournal struct {
	// tx 交易內同步落地面（audit.NewTxSink()）
	tx port.TxSink
	// async 非同步投遞面；由段 2 於 `auditService` 建構後注入（`stage2.go`）。
	// **seed 期的那一份 journal 仍為 nil**——它的登記必須早於 RunPostUnsealMigrations，
	// 而 auditService 更晚才建構；該份只被 seed 的 `RecordInTx` 使用。
	// nil 時 Record 退回「以根 DB 走同步落地面」，語義仍是
	// 「寫得進去就留痕、寫不進去回 error 由呼叫端記 log」。
	async gatewayapi.AsyncSink
	// db 根 DB（async 為 nil 時 Record 的落點）
	db *gorm.DB
}

func (j offsiteCustodyJournal) RecordInTx(tx *gorm.DB, ev offsite.CustodyEvent) error {
	details, err := offsiteCustodyDetails(ev)
	if err != nil {
		return err
	}
	// 主體恆為系統（UserID=0／Username="system"，沿 recording_failure_report.go 的
	// 退路慣例）：管理員的重試與測試連線另有中介層審計（admin 主體），兩列不合併。
	if err := port.WriteInTx(j.tx, tx, port.AuditEvent{
		Action:     ev.Action,
		Resource:   ev.Resource,
		ResourceID: ev.ResourceID,
		Status:     ev.Status,
		Actor:      gatewayapi.Actor{UserID: 0, Username: "system"},
		Details:    details,
	}); err != nil {
		return fmt.Errorf("寫入離機保管鏈事件失敗: %w", err)
	}
	return nil
}

func (j offsiteCustodyJournal) Record(ev offsite.CustodyEvent) error {
	// 非同步面未注入（seed 期的那一份）：以根 DB 走同步落地面。
	// **不另開第二個 sink 呼叫點**——同一件事有兩個落地位置時，其中一個被改成 no-op
	// 不會有任何東西轉紅（`audit_sink_call_index_test.go` 檔頭的下界只看得見總數）。
	if j.async == nil {
		return j.RecordInTx(j.db, ev)
	}
	details, err := offsiteCustodyDetails(ev)
	if err != nil {
		return err
	}
	j.async.Submit(context.Background(), gatewayapi.AuditEvent{
		Action:     ev.Action,
		Resource:   ev.Resource,
		ResourceID: ev.ResourceID,
		Status:     ev.Status,
		Actor:      gatewayapi.Actor{UserID: 0, Username: "system"},
		Details:    details,
	})
	return nil
}

// offsiteCustodyDetails 序列化保管鏈事件的 Details 負載。
//
// **只共用序列化、不共用事件字面量**：理由見型別宣告上方的段落。
func offsiteCustodyDetails(ev offsite.CustodyEvent) (string, error) {
	payload, err := json.Marshal(ev.Details)
	if err != nil {
		return "", fmt.Errorf("序列化離機保管鏈事件內容失敗: %w", err)
	}
	return string(payload), nil
}
