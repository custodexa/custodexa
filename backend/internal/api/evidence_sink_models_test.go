package api

import "github.com/custodexa/backend/internal/model"

// evidenceSinkModels 交易內審計與系統告警落地面需要的表（測試以 model 建表）。
func evidenceSinkModels() []any {
	return []any{
		&model.AuditLog{}, &model.CommandAlert{}, &model.NotificationChannel{},
		&model.SystemAlertDetail{}, &model.SystemAlertOutbox{}, &model.SystemAlertSeverityOverride{},
	}
}
