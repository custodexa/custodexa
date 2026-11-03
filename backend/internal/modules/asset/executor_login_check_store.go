package asset

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/custodexa/backend/internal/model"
)

// 測試登入結果表的讀寫。每個專用帳號掛載一列，重測覆蓋；讀取時以當下的掛載與就位版本比對，
// 掛載被更換、憑證或版本不同的舊列視為過期，不回報成「已測試」。

// ErrExecutorCheckResultInvalid 寫入的結果值不在登錄的集合內。
var ErrExecutorCheckResultInvalid = errors.New("測試登入結果值不在允許的集合內")

// ExecutorLoginCheckState 讀取回應：最近一次測試登入的結果與是否過期。
type ExecutorLoginCheckState struct {
	// Tested 有一筆與當下掛載、憑證、就位版本都相符的結果
	Tested bool `json:"tested"`
	// Stale 有結果，但掛載、憑證或就位版本已與測試當時不同
	Stale bool `json:"stale"`
	// Success 只在 Tested 時有意義；結果碼為空即成功
	Success bool `json:"success"`
	// Code 失敗時的結果碼；成功為空
	Code            string     `json:"code"`
	Method          string     `json:"method"`
	InventoryRead   string     `json:"inventory_read"`
	AccountUsername string     `json:"account_username,omitempty"`
	CheckedAt       *time.Time `json:"checked_at,omitempty"`
}

func validExecutorCheckResult(result string) bool {
	if result == "" {
		return true
	}
	for _, code := range model.ExecutorCheckResultCodes() {
		if code == result {
			return true
		}
	}
	return false
}

func validExecutorCheckMethod(method string) bool {
	switch method {
	case "", model.ExecutorCheckMethodRoot, model.ExecutorCheckMethodSudoNopasswd, model.ExecutorCheckMethodSudoPassword:
		return true
	}
	return false
}

func validExecutorCheckInventoryRead(v string) bool {
	switch v {
	case "", model.ExecutorCheckInventoryOK, model.ExecutorCheckInventoryDenied,
		model.ExecutorCheckInventoryNotNeeded, model.ExecutorCheckInventoryNotChecked:
		return true
	}
	return false
}

// upsertExecutorLoginCheck 在 tx 內寫入（或覆蓋）該掛載的測試結果。值不在登錄集合內回
// ErrExecutorCheckResultInvalid，不寫入。
func upsertExecutorLoginCheck(tx *gorm.DB, row *model.ExecutorLoginCheck) error {
	if row == nil || row.AssetAccountID == 0 {
		return fmt.Errorf("測試登入結果缺少掛載識別")
	}
	if !validExecutorCheckResult(row.Result) || !validExecutorCheckMethod(row.Method) ||
		!validExecutorCheckInventoryRead(row.InventoryRead) {
		return ErrExecutorCheckResultInvalid
	}
	return tx.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "asset_account_id"}},
		UpdateAll: true,
	}).Create(row).Error
}

// loadExecutorLoginCheck 讀該資產最近一次測試登入的狀態。回傳的釘住值為 nil 表示資產沒有專用帳號
// （呼叫端回 404）。查詢出錯不當作「沒有」。
func loadExecutorLoginCheck(db *gorm.DB, assetID uint) (*ExecutorLoginCheckState, *ExecutorPin, error) {
	pin, err := readExecutorPin(db, assetID)
	if err != nil {
		return nil, nil, err
	}
	if pin == nil {
		return nil, nil, nil
	}
	var row model.ExecutorLoginCheck
	// 以資產查最近一列：掛載被更換後，舊掛載的列仍在，但識別與當下不同，視為過期
	if err := db.Where("asset_id = ?", assetID).Order("checked_at DESC").Limit(1).Find(&row).Error; err != nil {
		return nil, pin, err
	}
	if row.AssetAccountID == 0 {
		return &ExecutorLoginCheckState{}, pin, nil
	}
	if row.AssetAccountID != pin.AccountID || row.CredentialID != pin.CredentialID || row.CredentialVersionID != pin.EffectiveVersionID {
		return &ExecutorLoginCheckState{Stale: true}, pin, nil
	}
	checkedAt := row.CheckedAt
	return &ExecutorLoginCheckState{
		Tested: true, Success: row.Result == "", Code: row.Result, Method: row.Method,
		InventoryRead: row.InventoryRead, AccountUsername: pin.Username, CheckedAt: &checkedAt,
	}, pin, nil
}
