package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 版本說明的個人關閉狀態。
//
// 缺列等於尚未關閉：讀取不寫庫；關閉是冪等 upsert，主體一律取自認證結果，
// 不接受外部傳入的使用者識別。偏好更新沿既有 update／user 審計，與狀態寫入同交易；
// 重複關閉不再寫審計，審計寫入失敗整筆回滾、狀態不變。這項偏好不改授權，
// 因此不推進權限版本，也不發系統告警。

// ReleaseGuidanceVersion 目前的說明版本。與產品 patch 版號分開：同一說明版本只提醒一次。
const ReleaseGuidanceVersion = "1.18.0"

// ReleaseGuidanceAuditEvent 關閉狀態審計的事件碼（Details.event）。
const ReleaseGuidanceAuditEvent = "release_guidance_dismissed"

// ErrUnknownGuidanceVersion 說明版本不在允許清單內。
var ErrUnknownGuidanceVersion = errors.New("未知的說明版本")

// ErrGuidanceNotWired 關閉狀態服務缺少必要依賴（資料庫或交易內審計落地面）。
var ErrGuidanceNotWired = errors.New("版本說明關閉狀態服務未接線")

// IsKnownGuidanceVersion 回報版本是否在允許清單內（目前只有一個說明版本）。
func IsKnownGuidanceVersion(version string) bool {
	return version == ReleaseGuidanceVersion
}

// ReleaseGuidanceService 本人版本說明關閉狀態。
type ReleaseGuidanceService struct {
	db    *gorm.DB
	audit port.TxSink
	now   func() time.Time
}

// NewReleaseGuidanceService 建構服務。資料庫或審計落地面缺少時回錯（不建出缺審計的可用服務）。
func NewReleaseGuidanceService(db *gorm.DB, sink port.TxSink) (*ReleaseGuidanceService, error) {
	if db == nil || sink == nil {
		return nil, ErrGuidanceNotWired
	}
	return &ReleaseGuidanceService{db: db, audit: sink, now: time.Now}, nil
}

// Dismissed 回報本人是否已關閉該說明版本。無列即 false，不寫庫。
func (s *ReleaseGuidanceService) Dismissed(userID uint, version string) (bool, error) {
	if !IsKnownGuidanceVersion(version) {
		return false, ErrUnknownGuidanceVersion
	}
	var n int64
	if err := s.db.Model(&model.UserReleaseGuidance{}).
		Where("user_id = ? AND notice_version = ?", userID, version).
		Count(&n).Error; err != nil {
		return false, fmt.Errorf("讀取版本說明關閉狀態失敗: %w", err)
	}
	return n > 0, nil
}

// Dismiss 關閉該說明版本（冪等）。首次關閉才在同一交易內寫審計；已關閉者不改列、不寫審計。
func (s *ReleaseGuidanceService) Dismiss(op Operator, version string) error {
	if !IsKnownGuidanceVersion(version) {
		return ErrUnknownGuidanceVersion
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		var user model.User
		if err := tx.First(&user, op.UserID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrUserNotFound
			}
			return fmt.Errorf("查詢使用者失敗: %w", err)
		}
		if !user.Active {
			return ErrUserInactive
		}
		res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&model.UserReleaseGuidance{
			UserID:        op.UserID,
			NoticeVersion: version,
			DismissedAt:   s.now(),
		})
		if res.Error != nil {
			return fmt.Errorf("寫入版本說明關閉狀態失敗: %w", res.Error)
		}
		if res.RowsAffected == 0 {
			return nil
		}
		payload, err := json.Marshal(map[string]any{
			"event": ReleaseGuidanceAuditEvent, "notice_version": version, "dismissed": true,
		})
		if err != nil {
			return fmt.Errorf("序列化版本說明審計失敗: %w", err)
		}
		id := op.UserID
		if err := port.WriteInTx(s.audit, tx, port.AuditEvent{
			Action:     string(model.ActionUpdate),
			Resource:   string(model.ResourceUser),
			ResourceID: &id,
			Status:     string(model.StatusSuccess),
			Actor:      gatewayapi.Actor{UserID: op.UserID, Username: op.Username},
			Request:    gatewayapi.RequestMeta{ClientIP: op.ClientIP},
			Details:    string(payload),
		}); err != nil {
			return fmt.Errorf("寫入版本說明審計失敗: %w", err)
		}
		return nil
	})
}
