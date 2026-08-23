package audit

import (
	"context"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// alertRecorder 指令告警落地面。
//
// 介面契約見 pkg/gatewayapi/alert.go 的 AlertSink。
//
// # 告警落地面的結構性解法
//
// 收口前兩條寫入路徑：
//
//	internal/modules/audit/alert_matcher.go  批寫 → 通知 → syslog tee（完整）
//	internal/sshproxy/command_blocker.go     直寫 DB，**繞過 syslog tee**
//
// 本型別把「入庫＋通知＋離機轉發」三件事收成一個落地面，使 tee 結構性不可漏。
// 上述兩條路徑都已改接過來：阻斷告警自此與比對告警同軌，
// 離機 syslog 不再獨缺「實際被阻斷的指令」這一類最高價值證據。
// 「只有本檔可以寫 command_alerts 列」由 cmd/server/command_alert_write_guard_test.go 釘住。
//
// # 錯誤語義（與 gatewayapi.AlertSink 註解互為引用）
//
// RecordAlert／RecordAlerts 同步寫、error 原樣回傳、不吞不包裝、不入佇列。
// 呼叫端（阻斷路徑與比對路徑）維持「只記 log 不阻斷」——兩者都沒有可回滾的業務交易，
// 詳細理由寫在介面註解。fail-close 只掛在「sink 未注入」那一格（組裝根啟動自檢
// requireAlertSink ＋ 呼叫側 gatewayapi.ErrAlertSinkMissing），**不得降 no-op**。
type alertRecorder struct {
	db *gorm.DB
}

var _ gatewayapi.AlertSink = (*alertRecorder)(nil)

// NewAlertRecorder 建立告警落地面。
//
// **回傳介面、實作型別不匯出（export budget）**：消費者（AlertMatcher／commandBlocker）
// 只需要 gatewayapi.AlertSink。**唯一生產建構點在組裝根**（cmd/server/stage2.go），
// 由 requireAlertSink 於建構後立即自檢；兩個消費者一律經注入取得，不自行建構。
func NewAlertRecorder(db *gorm.DB) gatewayapi.AlertSink { return &alertRecorder{db: db} }

// RecordAlert 落地單筆告警。
func (s *alertRecorder) RecordAlert(ctx context.Context, a gatewayapi.CommandAlert) error {
	return s.RecordAlerts(ctx, []gatewayapi.CommandAlert{a})
}

// RecordAlerts 批次落地。
//
// **SHALL NOT 實作成迴圈呼叫 RecordAlert**（gatewayapi.AlertSink 契約明載）：
// matcher 路徑現況是一次 `Create(&alerts)`，拆成 N 次 INSERT 是效能與交易語義的
// 雙重行為變更。本實作是單次 Create；RecordAlert 反過來委派給它（單筆批次），
// 方向正確——批次是原語，單筆是特例。
func (s *alertRecorder) RecordAlerts(_ context.Context, as []gatewayapi.CommandAlert) error {
	if len(as) == 0 {
		return nil
	}
	if s == nil || s.db == nil {
		return fmt.Errorf("告警落地面未注入 DB 句柄")
	}
	rows := make([]model.CommandAlert, 0, len(as))
	for _, a := range as {
		rows = append(rows, alertRowOf(a))
	}
	if err := s.db.Create(&rows).Error; err != nil {
		return err
	}

	// 入庫成功後才推送與 tee（沿用 alert_matcher.go 的既有順序與語義）：
	// 通知與離機轉發是下游附加價值，寫入失敗不得發出「系統裡查不到」的幽靈告警。
	// 未初始化（單測）時靜默跳過——**這條寬鬆跳過只適用於下游 tee**，
	// 不適用於 sink 本身（4.7 的 nil 自檢管的是後者）。
	if notifier := GetAlertNotifier(); notifier != nil {
		for _, row := range rows {
			notifier.Enqueue(row)
		}
	}
	if forwarder := GetSyslogForwarder(); forwarder != nil {
		for i := range rows {
			forwarder.EnqueueAlert(&rows[i])
		}
	}
	return nil
}

// alertRowOf 由傳輸形狀組出落地列。
//
// Disposition **不補預設值**：gatewayapi.CommandAlert 的欄位註解明訂「實作端 SHALL
// 顯式設值，不得倚賴 DB default」。兩條路徑目前各自顯式寫 pending；在此補一層
// 預設會把「將來某條新路徑忘了設」重新藏起來，那正是這類缺陷的成因。
// 兩條路徑確實都設了 pending，由 TestBothAlertPathsWriteIdenticalShape 逐欄釘住。
func alertRowOf(a gatewayapi.CommandAlert) model.CommandAlert {
	return model.CommandAlert{
		RuleID:      a.RuleID,
		RuleName:    a.RuleName,
		Kind:        a.Kind,
		ReasonCode:  a.ReasonCode,
		SessionID:   a.SessionID,
		UserID:      a.Actor.UserID,
		AssetID:     a.AssetID,
		Command:     a.Command,
		Severity:    a.Level,
		TriggeredAt: a.OccurredAt,
		Disposition: a.Disposition,
		Blocked:     a.Blocked,
	}
}
