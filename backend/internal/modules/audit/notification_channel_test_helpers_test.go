package audit

import (
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// newChannelSvc 建立帶通道寫入所需落地面的服務：服務層審計與系統告警都與變更同交易，
// 沒有注入就寫不進去，所以測試一律走這個建構點。DB 缺的表在此補齊。
func newChannelSvc(t *testing.T, db *gorm.DB, codec crypto.ColumnCodec) *NotificationChannelService {
	t.Helper()
	ensureSystemAlertTables(t, db)
	svc := NewNotificationChannelService(db, codec)
	svc.SetAuditTxSink(NewTxSink())
	svc.SetSystemAlertSink(NewSystemAlertSink(codec))
	return svc
}
