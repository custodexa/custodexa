package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// 審核範圍管理鍵的補鍵資料步驟。
//
// 申請人型審核範圍的管理能力由獨立權限點承擔後，持有審核範圍管理權限點的自訂角色須一併取得它，
// 才保有原本對申請人型的管理能力。這是一次合法的權限擴充：每個需補的角色各走一個交易，
// 依角色定義寫入鏈的次序——權限狀態比對、寫入、定義版本、權限版本、系統身分審計、狀態事件——
// 任一步失敗整筆回滾。不以直寫 role_permissions 的方式補鍵（直寫會被下一次權限變更記成無來源變動）。
//
// 可重入：已同時持有兩鍵的角色略過；重跑零寫入、不推進任何版本、不新增審計或事件。
// 內建範本的集合由程式定義，不經本步驟。須在權限狀態事件寫入器組裝之後呼叫。

// ApproverScopeKeySystemStep 審計詳情中標示本步驟的值。
const ApproverScopeKeySystemStep = "approver_scope_management_key"

var errApproverScopeKeyWiring = errors.New("approver scope key backfill: audit sink or event writer missing")

// ApproverScopeKeyReport 補鍵報告；dry-run 與正式執行的 Candidates 相同。
type ApproverScopeKeyReport struct {
	DryRun     bool
	Candidates int
	Updated    int
	RoleIDs    []uint
	// AlreadyDone 執行標記已存在：本步驟曾完成評估，不挑候選、零寫入。
	AlreadyDone bool
}

// BackfillApproverScopeManagementKey 替持有審核範圍管理鍵而未持有申請人型管理鍵的自訂角色補鍵。
// dryRun 為真時只回報、不寫入。audit 與 events 任一為 nil（且需寫入）即回錯，不當成功略過。
func BackfillApproverScopeManagementKey(ctx context.Context, db *gorm.DB, audit port.TxSink, events RoleStateEventWriter, dryRun bool) (ApproverScopeKeyReport, error) {
	report := ApproverScopeKeyReport{DryRun: dryRun, RoleIDs: []uint{}}
	// 只執行一次：標記已寫入即不再挑候選（管理員之後撤掉的鍵不被補回）。
	var marked int64
	if err := db.WithContext(ctx).Model(&database.SchemaMigration{}).
		Where("version = ?", database.ApproverScopeKeyMarkerVersion).Count(&marked).Error; err != nil {
		return report, fmt.Errorf("查詢補鍵執行標記失敗: %w", err)
	}
	if marked > 0 {
		report.AlreadyDone = true
		return report, nil
	}
	ids, err := approverScopeKeyCandidates(db.WithContext(ctx))
	if err != nil {
		return report, err
	}
	report.Candidates = len(ids)
	if dryRun {
		report.RoleIDs = append(report.RoleIDs, ids...)
		return report, nil
	}
	if len(ids) > 0 && (audit == nil || events == nil) {
		return report, errApproverScopeKeyWiring
	}
	for _, id := range ids {
		done, err := backfillApproverScopeKeyForRole(ctx, db, audit, events, id)
		if err != nil {
			return report, err
		}
		if done {
			report.Updated++
			report.RoleIDs = append(report.RoleIDs, id)
		}
	}
	if err := db.WithContext(ctx).Create(&database.SchemaMigration{
		Version: database.ApproverScopeKeyMarkerVersion, AppliedAt: time.Now()}).Error; err != nil {
		return report, fmt.Errorf("寫入補鍵執行標記失敗: %w", err)
	}
	return report, nil
}

// approverScopeKeyCandidates 自訂角色（非內建、定義版本大於 0、未刪除）中有 K 無 KA 者，依 ID 排序。
func approverScopeKeyCandidates(tx *gorm.DB) ([]uint, error) {
	var ids []uint
	err := tx.Table("roles").
		Joins("JOIN role_permissions k ON k.role_id = roles.id AND k.permission_key = ?", string(authz.PermApproverScopeManage)).
		Joins("LEFT JOIN role_permissions ka ON ka.role_id = roles.id AND ka.permission_key = ?", string(authz.PermApproverScopeApplicantManage)).
		Where("roles.builtin_key IS NULL AND roles.definition_version > 0 AND roles.deleted_at IS NULL AND ka.role_id IS NULL").
		Order("roles.id").Pluck("roles.id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("查詢待補鍵的自訂角色失敗: %w", err)
	}
	return ids, nil
}

func backfillApproverScopeKeyForRole(ctx context.Context, db *gorm.DB, audit port.TxSink, events RoleStateEventWriter, roleID uint) (bool, error) {
	changed := false
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		changed = false
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		var role model.Role
		if err := tx.First(&role, roleID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil // 已被刪除：無需補鍵
			}
			return fmt.Errorf("讀取角色失敗: %w", err)
		}
		// 交易內重驗：仍是自訂角色、仍有 K、仍無 KA（重入與並行皆零寫入）
		if role.BuiltinKey != nil || role.DefinitionVersion == 0 {
			return nil
		}
		before, err := permissionsOf(tx, &role)
		if err != nil {
			return err
		}
		hasK, hasKA := false, false
		for _, k := range before {
			hasK = hasK || k == string(authz.PermApproverScopeManage)
			hasKA = hasKA || k == string(authz.PermApproverScopeApplicantManage)
		}
		if !hasK || hasKA {
			return nil
		}
		if err := tx.Create(&model.RolePermission{RoleID: role.ID, PermissionKey: string(authz.PermApproverScopeApplicantManage)}).Error; err != nil {
			return fmt.Errorf("補寫角色權限失敗: %w", err)
		}
		if err := bumpDefinition(tx, &role, map[string]any{}); err != nil {
			return err
		}
		if err := authz.AdvanceVersion(tx); err != nil {
			return err
		}
		authzVersion, err := authz.CurrentVersion(tx)
		if err != nil {
			return err
		}
		after, err := permissionsOf(tx, &role)
		if err != nil {
			return err
		}
		res := &writeResult{role: &role, before: before, after: after}
		details := roleDefinitionAuditDetails(model.ActionRoleDefinitionUpdate, res, authzVersion)
		details["system_step"] = ApproverScopeKeySystemStep
		raw, err := json.Marshal(details)
		if err != nil {
			return fmt.Errorf("序列化角色定義稽核詳情失敗: %w", err)
		}
		rid := role.ID
		if err := port.WriteInTx(audit, tx, port.AuditEvent{
			Actor:      gatewayapi.Actor{Username: "system"},
			Action:     string(model.ActionRoleDefinitionUpdate),
			Resource:   string(model.ResourceRole),
			ResourceID: &rid,
			Status:     string(model.StatusSuccess),
			Details:    string(raw),
		}); err != nil {
			return fmt.Errorf("角色定義留痕失敗: %w", err)
		}
		if err := events.WriteRoleDefinitionEvent(tx, RoleDefinitionEvent{Action: string(model.ActionRoleDefinitionUpdate), RoleID: rid,
			DefinitionVersion: role.DefinitionVersion, AuthzVersion: authzVersion, Before: before, After: after}); err != nil {
			return fmt.Errorf("寫入權限狀態事件失敗: %w", err)
		}
		changed = true
		return nil
	})
	authz.NotifyVersionCommittedAfter(db, err)
	if err != nil {
		return false, err
	}
	return changed, nil
}
