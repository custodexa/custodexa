package offsite

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	"gorm.io/gorm"
)

// 離機副本停用與改目的地的系統告警。
//
// 停用（Disable）與已有現行世代時切換到新世代（Save 直接切換與 Confirm 都經
// switchGenerationLocked）在同一個鎖交易內、既有保管鏈事件之後產生一筆告警；保管鏈
// 事件與告警帶同一個關聯識別與真實操作者。不新增審計列。初次建立與同世代就地更新不告警。
// 告警寫入失敗即整筆回滾：設定不變、事件不留。

// 離機變更的告警種類（與系統告警目錄的 change 參數同值）。
const (
	OffsiteChangeDisabled           = "disabled"
	OffsiteChangeDestinationChanged = "destination_changed"
)

// ErrChangeAlertSinkMissing 離機變更告警落地面未注入。
var ErrChangeAlertSinkMissing = errors.New("離機儲存變更告警落地面未注入")

// ErrChangeAlertRaise 離機變更告警寫入失敗（整筆已回滾）。
var ErrChangeAlertRaise = errors.New("離機儲存變更告警寫入失敗")

// ChangeAlert 一筆離機變更告警（只含純值，本包不直接依賴告警模組）。
type ChangeAlert struct {
	Change        string // OffsiteChange*
	Actor         OffsiteActor
	CorrelationID string
}

// ChangeAlertRaiser 離機變更告警落地面的消費端窄介面；實作在組裝根，包裝交易內系統告警落地面。
type ChangeAlertRaiser interface {
	RaiseOffsiteChangeInTx(tx *gorm.DB, a ChangeAlert) error
}

// SetChangeAlertRaiser 注入離機變更告警落地面（組裝根在系統告警落地面建構與自檢之後呼叫）。
func (s *OffsiteProfileService) SetChangeAlertRaiser(r ChangeAlertRaiser) { s.alerts = r }

// ChangeAlertSinkReady 組裝根啟動自檢：告警落地面已注入（含 typed-nil）。
func (s *OffsiteProfileService) ChangeAlertSinkReady() error {
	if s.alerts == nil {
		return ErrChangeAlertSinkMissing
	}
	if rv := reflect.ValueOf(s.alerts); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return ErrChangeAlertSinkMissing
	}
	return nil
}

// raiseChange 在鎖交易內產生離機變更告警（保管鏈事件已寫入之後呼叫）。
func (s *OffsiteProfileService) raiseChange(tx *gorm.DB, change string, actor OffsiteActor, correlationID string) error {
	if err := s.ChangeAlertSinkReady(); err != nil {
		return fmt.Errorf("%w: %w", ErrChangeAlertRaise, err)
	}
	if err := s.alerts.RaiseOffsiteChangeInTx(tx, ChangeAlert{Change: change, Actor: actor, CorrelationID: correlationID}); err != nil {
		return fmt.Errorf("%w: %w", ErrChangeAlertRaise, err)
	}
	return nil
}

// newCustodyCorrelationID 保管鏈事件與告警共用的關聯識別（隨機、不含任何輸入內容）。
func newCustodyCorrelationID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("產生離機變更關聯識別失敗: %w", err)
	}
	return "ofs-" + hex.EncodeToString(b), nil
}
