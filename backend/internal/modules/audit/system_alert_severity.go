package audit

import (
	"errors"
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"gorm.io/gorm"
)

// 系統告警的分級調整。
//
// 分級只影響呈現與通知優先序：調到最低仍產生告警、仍送到每個啟用的通道。
// 系統告警沒有刪除或停用入口，這裡只提供「調分級」一個動作。

var (
	// ErrSystemAlertTypeUnknown 類型鍵未登錄。
	ErrSystemAlertTypeUnknown = errors.New("系統告警類型未登錄")
	// ErrSystemAlertSeverityInvalid 分級不是 high／medium／low。
	ErrSystemAlertSeverityInvalid = errors.New("系統告警分級只接受 high、medium、low")
)

// SystemAlertSeverityChange 一次分級調整的前後有效分級（供呼叫端寫同交易審計）。
type SystemAlertSeverityChange struct {
	Type   port.SystemAlertType
	Before string
	After  string
}

// SetSystemAlertSeverityInTx 在呼叫方交易內寫入分級覆寫並回傳前後有效分級。
// 覆寫列一律保留；有效分級等於預設時視圖不標「已調整」。
func SetSystemAlertSeverityInTx(tx *gorm.DB, t port.SystemAlertType, severity string, updatedBy uint) (SystemAlertSeverityChange, error) {
	def, ok := LookupSystemAlertType(t)
	if !ok {
		return SystemAlertSeverityChange{}, ErrSystemAlertTypeUnknown
	}
	if !ValidSystemAlertSeverity(severity) {
		return SystemAlertSeverityChange{}, ErrSystemAlertSeverityInvalid
	}
	if tx == nil {
		return SystemAlertSeverityChange{}, errors.New("系統告警分級調整未取得交易控制代碼")
	}
	before, err := effectiveSystemAlertSeverity(tx, def)
	if err != nil {
		return SystemAlertSeverityChange{}, err
	}
	var rows []model.SystemAlertSeverityOverride
	if err := tx.Where("alert_type = ?", string(t)).Limit(1).Find(&rows).Error; err != nil {
		return SystemAlertSeverityChange{}, fmt.Errorf("讀取系統告警分級覆寫失敗: %w", err)
	}
	now := time.Now()
	if len(rows) == 0 {
		err = tx.Create(&model.SystemAlertSeverityOverride{
			AlertType: string(t), Severity: severity, UpdatedBy: updatedBy, UpdatedAt: now,
		}).Error
	} else {
		err = tx.Model(&model.SystemAlertSeverityOverride{}).Where("alert_type = ?", string(t)).
			Updates(map[string]any{"severity": severity, "updated_by": updatedBy, "updated_at": now}).Error
	}
	if err != nil {
		return SystemAlertSeverityChange{}, fmt.Errorf("寫入系統告警分級覆寫失敗: %w", err)
	}
	return SystemAlertSeverityChange{Type: t, Before: before, After: severity}, nil
}

// SystemAlertSeverityView 目錄每列的分級視圖。
type SystemAlertSeverityView struct {
	Type      port.SystemAlertType
	Default   string
	Effective string
	Adjusted  bool
}

// ListSystemAlertSeverities 依登錄順序回傳每個類型的預設與有效分級。
func ListSystemAlertSeverities(db *gorm.DB) ([]SystemAlertSeverityView, error) {
	var rows []model.SystemAlertSeverityOverride
	if err := db.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取系統告警分級覆寫失敗: %w", err)
	}
	overrides := make(map[string]string, len(rows))
	for _, r := range rows {
		if ValidSystemAlertSeverity(r.Severity) {
			overrides[r.AlertType] = r.Severity
		}
	}
	out := make([]SystemAlertSeverityView, 0, len(systemAlertCatalogData()))
	for _, d := range systemAlertCatalogData() {
		v := SystemAlertSeverityView{Type: d.Type, Default: d.DefaultSeverity, Effective: d.DefaultSeverity}
		if sev, ok := overrides[string(d.Type)]; ok {
			v.Effective = sev
			v.Adjusted = sev != d.DefaultSeverity
		}
		out = append(out, v)
	}
	return out, nil
}
