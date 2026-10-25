package main

import (
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/offsite"
)

// offsiteChangeAlertAdapter 把離機儲存的停用與改目的地告警接到交易內系統告警落地面。
// offsite 包不直接依賴告警模組，包裝放在組裝根。
type offsiteChangeAlertAdapter struct {
	sink port.SystemAlertSink
}

func (a offsiteChangeAlertAdapter) RaiseOffsiteChangeInTx(tx *gorm.DB, ev offsite.ChangeAlert) error {
	_, err := port.RaiseInTx(a.sink, tx, port.SystemAlertEvent{
		Type:          port.SystemAlertOffsiteOrSyslogChanged,
		Actor:         port.SystemAlertActor{UserID: ev.Actor.ID, Username: ev.Actor.Name},
		ClientIP:      ev.Actor.IP,
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetSystemSetting, ID: "offsite"},
		CorrelationID: ev.CorrelationID,
		Params:        map[string]string{"subject": "offsite", "change": ev.Change},
	})
	return err
}
