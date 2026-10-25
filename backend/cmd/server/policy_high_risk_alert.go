package main

import (
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
)

// policyHighRiskAlertAdapter 把政策服務的共用高危掛點接到交易內系統告警落地面。
// 政策模組不直接依賴告警模組，類型鍵以字串傳入、在此轉成告警類型；目標一律是
// 該政策鍵（系統設定），來源位址與關聯識別原樣帶入，與同交易審計列對應。
type policyHighRiskAlertAdapter struct {
	sink port.SystemAlertSink
}

func (a policyHighRiskAlertAdapter) RaiseHighRiskInTx(tx *gorm.DB, ev policy.HighRiskAlert) error {
	_, err := port.RaiseInTx(a.sink, tx, port.SystemAlertEvent{
		Type:          port.SystemAlertType(ev.Type),
		Actor:         port.SystemAlertActor{UserID: ev.ActorID, Username: ev.ActorName},
		ClientIP:      ev.ClientIP,
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetSystemSetting, ID: ev.Key},
		CorrelationID: ev.CorrelationID,
		Params:        ev.Params,
	})
	return err
}
