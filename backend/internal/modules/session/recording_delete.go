package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strconv"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 刪除單一會話錄影：先留痕、後刪檔。
//
// 單一交易內依序：鎖定會話列並重讀 → 交易內審計（details 帶 correlation_id）→
// recording_deleted 系統告警（同一關聯識別與操作者）→ 清空錄影欄 → 提交。提交成功後
// 才移除本機檔。審計或告警寫不進去時整筆回滾、檔案仍在。審計走交易內落地面，不受
// 審計日誌總開關或任何政策鍵、角色影響。提交後刪檔失敗時資料庫已不再指向該檔（孤兒檔），
// 另以根 DB 經同一落地面同步補寫一筆失敗審計；孤兒檔只在錄影保留天數為正數時由保留清理移除。
// 已離機保存的遠端物件不刪。

// RecordingDeleteActor 刪除錄影的操作者（handler 從認證脈絡取得）。
type RecordingDeleteActor struct {
	ID       uint
	Name     string
	ClientIP string
}

var (
	// ErrRecordingDeleteActorMissing 刪錄影缺操作者（不動任何資料）。
	ErrRecordingDeleteActorMissing = errors.New("刪除錄影缺操作者")
	// ErrRecordingDeleteAlertRaise 刪錄影的系統告警寫入失敗（整筆已回滾、檔案仍在）。
	ErrRecordingDeleteAlertRaise = errors.New("刪除錄影的系統告警寫入失敗")
	// ErrRecordingFileRemove 資料庫已清空但本機檔移除失敗（已補寫失敗審計）。
	ErrRecordingFileRemove = errors.New("錄影檔移除失敗")
)

// SetEvidenceSinks 注入刪錄影的交易內審計與系統告警落地面（組裝根在兩者建構與自檢之後呼叫）。
func (s *RecordingService) SetEvidenceSinks(txSink port.TxSink, alerts port.SystemAlertSink) {
	s.txSink, s.alerts = txSink, alerts
}

// EvidenceSinksReady 組裝根啟動自檢：兩個落地面都已注入（含 typed-nil）。
func (s *RecordingService) EvidenceSinksReady() error {
	if isNilSink(s.txSink) {
		return fmt.Errorf("錄影服務: %w", port.ErrTxSinkMissing)
	}
	if isNilSink(s.alerts) {
		return fmt.Errorf("錄影服務: %w", port.ErrSystemAlertSinkMissing)
	}
	return nil
}

func isNilSink(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Ptr && rv.IsNil()
}

func newRecordingDeleteCorrelationID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("產生刪錄影關聯識別失敗: %w", err)
	}
	return "rec-" + hex.EncodeToString(b), nil
}

// recordingKind 錄影種類（依副檔名）：文字 cast、圖形 guac，其餘為 unknown。
func recordingKind(path string) string {
	switch filepath.Ext(path) {
	case ".cast":
		return "cast"
	case ".guac":
		return "guac"
	}
	return "unknown"
}

// DeleteRecording 刪除單一會話的錄影（見本檔說明）。
func (s *RecordingService) DeleteRecording(sessionID uint, actor RecordingDeleteActor) error {
	if actor.ID == 0 {
		return ErrRecordingDeleteActorMissing
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// 未注入時一律回錯，不退化成無審計刪除。缺審計落地面時經 port.WriteInTx 的同一個錯誤表達
	if s.txSink == nil {
		return port.ErrTxSinkMissing
	}
	if s.alerts == nil {
		return port.ErrSystemAlertSinkMissing
	}
	cid, err := newRecordingDeleteCorrelationID()
	if err != nil {
		return err
	}
	deleteID := sessionID
	var filePath string
	var assetID *uint
	err = database.DB.Transaction(func(tx *gorm.DB) error {
		q := tx
		if tx.Dialector.Name() == "postgres" {
			q = tx.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		var sess model.Session
		if err := q.First(&sess, sessionID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrSessionNotFound
			}
			return fmt.Errorf("查詢 Session 失敗: %w", err)
		}
		if sess.RecordingPath == "" {
			return ErrSessionHasNoRecording
		}
		filePath, assetID = sess.RecordingPath, sess.AssetID
		details, _ := json.Marshal(map[string]any{
			"session_id": sessionID, "kind": recordingKind(filePath), "size": sess.RecordingSize,
			"correlation_id": cid,
		})
		if err := port.WriteInTx(s.txSink, tx, port.AuditEvent{
			Actor:  gatewayapi.Actor{UserID: actor.ID, Username: actor.Name},
			Action: string(model.ActionDelete), Resource: string(model.ResourceRecording),
			ResourceID: &deleteID, AssetID: assetID, Status: string(model.StatusSuccess),
			Request: gatewayapi.RequestMeta{ClientIP: actor.ClientIP}, Details: string(details),
		}); err != nil {
			return fmt.Errorf("寫入刪除錄影審計失敗: %w", err)
		}
		if _, err := port.RaiseInTx(s.alerts, tx, port.SystemAlertEvent{
			Type:          port.SystemAlertRecordingDeleted,
			Actor:         port.SystemAlertActor{UserID: actor.ID, Username: actor.Name},
			ClientIP:      actor.ClientIP,
			Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetSession, ID: strconv.FormatUint(uint64(sessionID), 10)},
			AssetID:       assetID,
			CorrelationID: cid,
			Params:        map[string]string{"session_id": strconv.FormatUint(uint64(sessionID), 10)},
		}); err != nil {
			return fmt.Errorf("%w: %w", ErrRecordingDeleteAlertRaise, err)
		}
		if err := tx.Model(&model.Session{}).Where("id = ?", sessionID).Updates(map[string]any{
			"recording_path": "", "recording_size": 0, "has_recording": false,
		}).Error; err != nil {
			return fmt.Errorf("更新 Session 失敗: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// 提交之後才刪檔
	if rmErr := os.Remove(filePath); rmErr != nil && !os.IsNotExist(rmErr) {
		failed, _ := json.Marshal(map[string]any{
			"session_id": sessionID, "kind": recordingKind(filePath),
			"reason": "file_remove_failed", "correlation_id": cid,
		})
		// 以根 DB 另開一筆短交易同步寫失敗列（原交易已提交）
		if aerr := database.DB.Transaction(func(tx *gorm.DB) error {
			return port.WriteInTx(s.txSink, tx, port.AuditEvent{
				Actor:  gatewayapi.Actor{UserID: actor.ID, Username: actor.Name},
				Action: string(model.ActionDelete), Resource: string(model.ResourceRecording),
				ResourceID: &deleteID, AssetID: assetID, Status: string(model.StatusFailure),
				Request: gatewayapi.RequestMeta{ClientIP: actor.ClientIP}, Details: string(failed),
			})
		}); aerr != nil {
			log.Printf("[Recording] 刪錄影：資料庫已清空但檔案移除失敗，失敗審計亦寫入失敗 session=%d: %v", sessionID, aerr)
		}
		return fmt.Errorf("%w: %w", ErrRecordingFileRemove, rmErr)
	}
	return nil
}
