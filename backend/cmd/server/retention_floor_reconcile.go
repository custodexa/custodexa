package main

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// retentionFloorAuditor 把保留下限對帳的審計接到交易內審計落地面：每個被抬升的鍵一列
// retention_floor_raised（resource=security_policy），與政策列、抬升紀錄同交易。
// 操作者記系統（啟動時沒有應用內操作者）。
func retentionFloorAuditor(sink port.TxSink) policy.FloorRaiseAuditor {
	return func(tx *gorm.DB, r policy.FloorRaise) error {
		details, err := json.Marshal(map[string]any{
			"key": r.Key, "old_value": r.OldValue, "new_value": r.NewValue, "floor": r.Floor, "reason": r.Reason,
		})
		if err != nil {
			return fmt.Errorf("編碼保留下限抬升審計失敗: %w", err)
		}
		return port.WriteInTx(sink, tx, port.AuditEvent{
			Actor:    gatewayapi.Actor{UserID: 0, Username: "system"},
			Action:   string(model.ActionRetentionFloorRaised),
			Resource: string(model.ResourceSecurityPolicy),
			Status:   string(model.StatusSuccess),
			Details:  string(details),
		})
	}
}

// reconcileRetentionFloor 段 2 的保留下限對帳步驟：必須在交易內審計落地面建構之後、
// 任何保留讀者（錄影保留讀取、檢查點驗證、保留清理）與保留排程啟動之前。失敗即段 2 失敗。
func reconcileRetentionFloor(svc *policy.SecurityPolicyService, sink port.TxSink) error {
	_, err := svc.ReconcileRetentionFloor(retentionFloorAuditor(sink), Version)
	return err
}
