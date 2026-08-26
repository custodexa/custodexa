package audit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// SourceIPBaseline 帳號 × 來源位址的「已見」基準（user_source_ips）與新來源位址告警。
//
// # 兩個觀察點、兩種後果
//
//   - 建線（ObserveSession）：基準自「未見／未建線」轉為「已建線」與告警列的寫入在
//     **同一交易**內完成。交易任何一步失敗整筆回滾——基準不轉態、無告警列——下一次
//     自同位址建線會再取得資格並補發；不會出現「基準已標已見而證據永不補發」。
//   - 登入（ObserveLogin）：把位址納入基準（只設首次／最近見到），新建時在同一交易
//     內寫一筆審計標記（action=new_source_ip），**不進告警表、不推通知**——登入無會話
//     可綁，且登入與建線各響一次會違反「同位址不重響」。首次建線時刻與登入分開追蹤，
//     故「先登入再建線」的典型流程仍在建線時響一次、只響一次。
//
// # 單勝者
//
// 同帳號同位址的並發首連線各自執行同一句條件式 upsert：first_session_id 以 COALESCE
// 只讓第一個提交者寫入，RETURNING 回給每個呼叫者最終值——等於自己 session id 者才是
// 勝者並寫告警列；輸家只更新 last_seen_at。冪等鍵＝（user_id, client_ip, first_session_id）：
// 提交後當機或呼叫端重試都不會第二次成為勝者。
//
// # 失敗語義
//
// 基準或告警交易失敗只回 error 由呼叫端記 log，**不阻連線、不阻登入**——旁路功能
// 無權殺主流程。來源為空（不可解析而清單為空放行者）不觀察、不告警：無位址可記，
// 該會話於時間軸呈現為未知來源。
type SourceIPBaseline struct {
	db     *gorm.DB
	alerts txAlertSink
	audit  port.TxSink

	// 測試鉤子（同包測試設定；生產恆 nil）：於交易內寫告警列／審計列**之前**呼叫，
	// 回錯即讓交易失敗，用來證明回滾語義且注入點確實走到（鉤子內自計數）
	beforeAlertWrite func() error
	beforeAuditWrite func() error
}

// txAlertSink 告警落地面的交易內能力（alert_sink.go 的 alertRecorder 實作）。
//
// 不擴 gatewayapi.AlertSink：那個公開包零 gorm，交易句柄只能在同行程內傳遞。
type txAlertSink interface {
	RecordAlertInTx(tx *gorm.DB, a gatewayapi.CommandAlert) (model.CommandAlert, error)
	PublishCommitted(rows []model.CommandAlert)
}

var (
	// ErrSourceIPBaselineNotWired 基準服務未注入 DB 或告警落地面不支援交易內寫入。
	ErrSourceIPBaselineNotWired = errors.New("來源位址基準服務未接線（DB 或告警落地面缺席）")
	// ErrSourceIPBaselineAuditSink 交易內審計落地面未注入（登入標記寫不出去）。
	ErrSourceIPBaselineAuditSink = errors.New("來源位址基準服務未注入交易內審計落地面")
)

// NewSourceIPBaseline 建立基準服務。alerts 須為組裝根建構的告警落地面
// （其具體型別具交易內方法）；傳入其他實作時 ObserveSession 回 ErrSourceIPBaselineNotWired
// 而非靜默不告警。
// **區域變數不叫 tx**：本檔內另有 `Transaction(func(tx *gorm.DB) …)`，而交易句柄
// 逃逸守衛（cmd/server/audit_points_tx_dataflow_test.go）以檔為範圍按名字追
// 「交易句柄流進 struct 欄位」——一個同名的無關區域變數就會讓它判定全庫每一個
// 審計點的交易歸屬皆不可證。名字在此有語義負擔，不是風格問題。
func NewSourceIPBaseline(db *gorm.DB, alerts gatewayapi.AlertSink, auditSink port.TxSink) *SourceIPBaseline {
	b := &SourceIPBaseline{db: db, audit: auditSink}
	if txSink, ok := alerts.(txAlertSink); ok {
		b.alerts = txSink
	}
	return b
}

// upsertSessionSQL 建線觀察：新建或更新，並以 COALESCE 只讓第一位建線者寫入首次建線兩欄。
// RETURNING 回最終的 first_session_id，供呼叫端判定自己是否勝者。
// PostgreSQL 與 sqlite（modernc，測試路徑）皆支援 ON CONFLICT … DO UPDATE … RETURNING。
const upsertSessionSQL = `INSERT INTO user_source_ips
	(user_id, client_ip, first_seen_at, last_seen_at, first_session_at, first_session_id)
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT (user_id, client_ip) DO UPDATE SET
		last_seen_at = EXCLUDED.last_seen_at,
		first_session_at = COALESCE(user_source_ips.first_session_at, EXCLUDED.first_session_at),
		first_session_id = COALESCE(user_source_ips.first_session_id, EXCLUDED.first_session_id)
	RETURNING first_session_id`

// upsertLoginSQL 登入觀察：新建或只更新最近見到；不碰首次建線兩欄。
// RETURNING 以「first_seen_at 等於本次時刻」辨識本次是否為新建（兩種方言皆可）。
const upsertLoginSQL = `INSERT INTO user_source_ips
	(user_id, client_ip, first_seen_at, last_seen_at, first_session_at, first_session_id)
	VALUES (?, ?, ?, ?, NULL, NULL)
	ON CONFLICT (user_id, client_ip) DO UPDATE SET
		last_seen_at = EXCLUDED.last_seen_at
	RETURNING first_seen_at`

// ObserveSession 建線觀察。回傳本次是否取得首次建線資格（＝已於同交易寫入告警列）。
func (b *SourceIPBaseline) ObserveSession(ctx context.Context, userID uint, ip string,
	sessionID uint, assetID *uint, now time.Time) (bool, error) {
	if b == nil || b.db == nil || b.alerts == nil {
		return false, ErrSourceIPBaselineNotWired
	}
	canon, ok := sourceip.Canonical(ip)
	if !ok || userID == 0 || sessionID == 0 {
		return false, nil
	}
	now = normalizeObservedAt(now)

	winner := false
	var row model.CommandAlert
	err := b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var out struct{ FirstSessionID *uint }
		if err := tx.Raw(upsertSessionSQL, userID, canon, now, now, now, sessionID).Scan(&out).Error; err != nil {
			return fmt.Errorf("基準 upsert 失敗: %w", err)
		}
		if out.FirstSessionID == nil || *out.FirstSessionID != sessionID {
			return nil // 輸家：已有勝者，只更新最近見到
		}
		if b.beforeAlertWrite != nil {
			if err := b.beforeAlertWrite(); err != nil {
				return err
			}
		}
		var err error
		row, err = b.alerts.RecordAlertInTx(tx, newSourceIPAlert(userID, sessionID, assetID, now))
		if err != nil {
			return fmt.Errorf("新來源位址告警落地失敗: %w", err)
		}
		winner = true
		return nil
	})
	if err != nil {
		return false, err
	}
	if winner {
		// 提交之後才推送與 tee：入庫成功才發，不發幽靈告警
		b.alerts.PublishCommitted([]model.CommandAlert{row})
	}
	return winner, nil
}

// LoginObservation 登入觀察的輸入：審計標記需要請求脈絡才寫得出「誰從哪裡怎麼進來」。
type LoginObservation struct {
	UserID   uint
	Username string
	IP       string
	Method   string
	Path     string
	Now      time.Time
}

// ObserveLogin 登入觀察。回傳本次是否為新建（＝已於同交易寫入審計標記）。
// 不呼叫通知、不寫告警表。
func (b *SourceIPBaseline) ObserveLogin(ctx context.Context, in LoginObservation) (bool, error) {
	if b == nil || b.db == nil {
		return false, ErrSourceIPBaselineNotWired
	}
	canon, ok := sourceip.Canonical(in.IP)
	if !ok || in.UserID == 0 {
		return false, nil
	}
	now := normalizeObservedAt(in.Now)

	inserted := false
	err := b.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var out struct{ FirstSeenAt time.Time }
		if err := tx.Raw(upsertLoginSQL, in.UserID, canon, now, now).Scan(&out).Error; err != nil {
			return fmt.Errorf("基準 upsert 失敗: %w", err)
		}
		if !out.FirstSeenAt.Equal(now) {
			return nil // 已見：只更新最近見到
		}
		if b.beforeAuditWrite != nil {
			if err := b.beforeAuditWrite(); err != nil {
				return err
			}
		}
		ev := port.AuditEvent{
			OccurredAt: now,
			Actor:      gatewayapi.Actor{UserID: in.UserID, Username: in.Username},
			Action:     string(model.ActionNewSourceIP),
			Resource:   string(model.ResourceAuth),
			Status:     string(model.StatusSuccess),
			Request:    gatewayapi.RequestMeta{Method: in.Method, Path: in.Path, ClientIP: canon},
			Details:    `{"via":"login"}`,
		}
		if err := port.WriteInTx(b.audit, tx, ev); err != nil {
			if errors.Is(err, port.ErrTxSinkMissing) {
				return ErrSourceIPBaselineAuditSink
			}
			return fmt.Errorf("新來源位址審計標記寫入失敗: %w", err)
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// 觀察點的標記（記入 log，指出是哪一條路徑的基準寫入失敗）。
//
// **常數定義在本包而非呼叫端**：呼叫端是 `internal/sshproxy`／`internal/proxy`，
// 那兩個包受串流出口的中文字面量守衛約束（使用者可見文字一律走 apierror 碼）。
// 該守衛以「呼叫點是不是 log／fmt.Errorf／errors.New」判定，看不穿本函式其實
// 只寫 log——把標記收成本包的常數，呼叫點就不再出現字面量，
// 守衛的判準與現實因此不再打架（而不是去 allowlist 開一個豁免）。
const (
	// ObserveSiteTerminal 文字終端建線點
	ObserveSiteTerminal = "文字終端建線"
	// ObserveSiteGraphics 圖形建線點
	ObserveSiteGraphics = "圖形建線"
	// ObserveSiteLogin 正式會話發放點（登入類）
	ObserveSiteLogin = "登入"
)

// LogObserveError 呼叫端的統一記錄：基準失敗不阻主流程，但不得靜默。
// where 取上方 ObserveSite* 常數。
func LogObserveError(where string, userID uint, err error) {
	if err == nil {
		return
	}
	log.Printf("[SourceIPBaseline] %s 觀察失敗（不阻斷主流程，下次同位址再補）: userID=%d err=%v", where, userID, err)
}

// newSourceIPAlert 新來源位址告警的形狀（沿指令審計降級告警的非規則類慣例）。
func newSourceIPAlert(userID, sessionID uint, assetID *uint, now time.Time) gatewayapi.CommandAlert {
	return gatewayapi.CommandAlert{
		Kind: model.AlertKindNewSourceIP,
		// RuleID 留 nil：本類告警不掛規則，DB CHECK 亦不允許它有
		RuleID: nil,
		// RuleName 填機器碼：本類無規則名可快照，使用者可見文案由前端依 kind／reason_code 對映
		RuleName:   model.AlertKindNewSourceIP,
		ReasonCode: model.AlertReasonNewSourceIPSession,
		SessionID:  sessionID,
		Actor:      gatewayapi.Actor{UserID: userID},
		AssetID:    assetID,
		// Command 恆為空：沒有指令文字，填任何東西都是捏造
		Command: "",
		// medium：新位址同時是日常事件與異常訊號，本版不宣稱已分離兩者
		Level:       "medium",
		OccurredAt:  now,
		Disposition: model.AlertDispositionPending,
	}
}

// normalizeObservedAt 以 UTC 微秒精度記錄：PostgreSQL timestamptz 只有微秒，
// 登入觀察以「回讀的 first_seen_at 等於本次時刻」辨識新建，奈秒尾數會讓相等判定失真。
func normalizeObservedAt(t time.Time) time.Time {
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Truncate(time.Microsecond)
}
