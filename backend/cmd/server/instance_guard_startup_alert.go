package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 啟動時偵測其他實例。
//
// 單實例守衛不是 fencing：確認覆寫後兩個實例可以並存，而主機金鑰的信任世代只由新版服務
// 推進。新版在段 2 告警落地面建構之後、改密排程啟動之前做一次偵測，成立就同交易寫一筆
// instance_guard 審計與一則系統安全告警，讓管理者在混版窗口內看得到這件事。
// 偵測只告警、不阻擋啟動；每次啟動至多一則。

const (
	startupPeerEvent           = "peer_detected_at_startup"
	startupPeerSignalOverride  = "overridden"
	startupPeerSignalPeers     = "peers"
	startupPeerQueryOK         = "ok"
	startupPeerQueryFailed     = "failed"
	startupPeerAlertTargetName = "instance_guard"
)

// instanceGuardStartupCheck 啟動檢查。零欄位以外的狀態只有 done：同一次啟動再呼叫不再發第二則。
type instanceGuardStartupCheck struct {
	db       *gorm.DB
	audit    port.TxSink
	alerts   port.SystemAlertSink
	snapshot func() database.GuardSnapshot
	probe    func(context.Context) (int, error)
	now      func() time.Time

	mu   sync.Mutex
	done bool
}

// newInstanceGuardStartupCheck 生產組裝：守衛快照與對等數查詢都取自包級單例。
func newInstanceGuardStartupCheck(db *gorm.DB, auditSink port.TxSink, alerts port.SystemAlertSink) *instanceGuardStartupCheck {
	return &instanceGuardStartupCheck{
		db: db, audit: auditSink, alerts: alerts,
		snapshot: database.InstanceGuardSnapshot,
		probe:    database.InstanceGuardProbePeers,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// Run 執行一次偵測。任何失敗都只記 CRITICAL 日誌，回 nil：告警不阻擋啟動。
//
// 兩個信號分開判定：守衛狀態為 overridden（不需查詢即成立），或對等數查詢成功且大於 0。
// 查詢失敗而 overridden 已成立時照發（peers_query=failed、不帶 peers）；
// 沒有已成立的信號時，查詢失敗只記日誌。
func (c *instanceGuardStartupCheck) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.done {
		c.mu.Unlock()
		return nil
	}
	c.done = true
	c.mu.Unlock()

	snap := c.snapshot()
	overridden := snap.State == database.GuardStateOverridden

	peers, probeErr := c.probe(ctx)
	if probeErr != nil {
		log.Printf("[InstanceGuard] CRITICAL：啟動時查詢其他實例的連線數失敗（不以 0 假稱無其他實例）: %v", probeErr)
	}
	peersSignal := probeErr == nil && peers > 0
	if !overridden && !peersSignal {
		return nil
	}

	signal := startupPeerSignalPeers
	if overridden {
		signal = startupPeerSignalOverride
	}
	if err := c.record(snap, signal, peers, probeErr == nil); err != nil {
		log.Printf("[InstanceGuard] CRITICAL：啟動時偵測到其他實例的跡象（signal=%s），但審計與系統告警未寫入（交易已回滾，啟動照常）: %v", signal, err)
		return nil
	}
	log.Printf("[InstanceGuard] CRITICAL：啟動時偵測到其他實例的跡象（signal=%s peers_query=%s），已寫入審計與系統告警",
		signal, peersQueryLabel(probeErr == nil))
	return nil
}

func peersQueryLabel(ok bool) string {
	if ok {
		return startupPeerQueryOK
	}
	return startupPeerQueryFailed
}

// record 同一交易寫 instance_guard 審計與 concurrent_instance_detected 告警，告警的
// CorrelationID 等於審計 details 內的同名欄。任一步失敗整筆回滾。
func (c *instanceGuardStartupCheck) record(snap database.GuardSnapshot, signal string, peers int, queryOK bool) error {
	corr, err := newStartupCorrelationID()
	if err != nil {
		return err
	}
	at := c.now()

	details := map[string]any{
		"event":          startupPeerEvent,
		"signal":         signal,
		"peers_query":    peersQueryLabel(queryOK),
		"correlation_id": corr,
		"guard_state":    string(snap.State),
		"at":             at.Format(time.RFC3339),
		"instance": map[string]any{
			"hostname":   snap.Instance.Hostname,
			"pid":        snap.Instance.PID,
			"started_at": rfc3339OrEmpty(snap.Instance.StartedAt),
		},
		"db_session_pid": snap.DBSessionPID,
	}
	params := map[string]string{
		"signal":      signal,
		"peers_query": peersQueryLabel(queryOK),
	}
	if queryOK {
		details["peers"] = peers
		params["peers"] = strconv.Itoa(peers)
	}
	if snap.State == database.GuardStateOverridden {
		if snap.Holder != nil {
			details["holder"] = map[string]any{
				"application_name":   snap.Holder.ApplicationName,
				"pid":                snap.Holder.PID,
				"backend_start":      snap.Holder.BackendStart,
				"code":               snap.Holder.Code,
				"fingerprint_source": snap.Holder.Source,
			}
		}
		details["ack"] = snap.Ack
		details["actor"] = snap.Actor
		details["actor_source"] = snap.ActorSource
		if snap.ActorSource != "" {
			params["confirm_source"] = snap.ActorSource
		}
		if snap.Actor != "" {
			params["confirmed_by"] = snap.Actor
		}
	}
	body, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("編碼啟動偵測審計失敗: %w", err)
	}

	return c.db.Transaction(func(tx *gorm.DB) error {
		if err := port.WriteInTx(c.audit, tx, port.AuditEvent{
			OccurredAt: at,
			Actor:      gatewayapi.Actor{UserID: 0, Username: port.SystemAlertSystemActorName},
			Action:     string(model.ActionExecute),
			Resource:   string(model.ResourceInstanceGuard),
			Status:     string(model.StatusFailure),
			Details:    string(body),
		}); err != nil {
			return fmt.Errorf("寫入啟動偵測審計失敗: %w", err)
		}
		if _, err := port.RaiseInTx(c.alerts, tx, port.SystemAlertEvent{
			Type:          port.SystemAlertConcurrentInstanceDetected,
			Actor:         port.SystemAlertActor{UserID: 0, Username: port.SystemAlertSystemActorName},
			OccurredAt:    at,
			Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetSystemSetting, ID: startupPeerAlertTargetName},
			CorrelationID: corr,
			Params:        params,
		}); err != nil {
			return fmt.Errorf("產生並行實例系統告警失敗: %w", err)
		}
		return nil
	})
}

func newStartupCorrelationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("產生關聯識別失敗: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
