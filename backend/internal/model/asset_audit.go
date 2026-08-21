package model

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// DiffAsset 比較兩個 Asset 物件的差異。
//
// **W6 6.2 由 diffAsset 匯出**：T-2 的服務側審計（`writeAssetChangeAudit`）與
// T-3 的 GORM hook（`AfterUpdate`，依 B-1 裁決維持直寫）共用同一份 diff 規則。
// hook 走不掉 `internal/model`（model 不得 import 模組），故規則必須留在此處；
// 複製一份到 asset 側等於製造第二個會漂移的變更判定。
func DiffAsset(old, new *Asset) []AssetChange {
	changes := []AssetChange{}

	if old.Name != new.Name {
		changes = append(changes, AssetChange{
			Field: "name",
			Old:   old.Name,
			New:   new.Name,
		})
	}

	if old.Protocol != new.Protocol {
		changes = append(changes, AssetChange{
			Field: "protocol",
			Old:   old.Protocol,
			New:   new.Protocol,
		})
	}

	if old.Host != new.Host {
		changes = append(changes, AssetChange{
			Field: "host",
			Old:   old.Host,
			New:   new.Host,
		})
	}

	if old.Port != new.Port {
		changes = append(changes, AssetChange{
			Field: "port",
			Old:   old.Port,
			New:   new.Port,
		})
	}

	if old.Description != new.Description {
		changes = append(changes, AssetChange{
			Field: "description",
			Old:   old.Description,
			New:   new.Description,
		})
	}

	if old.Active != new.Active {
		changes = append(changes, AssetChange{
			Field: "active",
			Old:   old.Active,
			New:   new.Active,
		})
	}

	if old.Username != new.Username {
		changes = append(changes, AssetChange{
			Field: "username",
			Old:   old.Username,
			New:   new.Username,
		})
	}

	if old.Tags != new.Tags {
		changes = append(changes, AssetChange{
			Field: "tags",
			Old:   old.Tags,
			New:   new.Tags,
		})
	}

	// 節點掛載（asset-node-tree）為 M2M 非資產欄位，不經 hook diff——
	// 成員變更審計在 asset service 的節點同步邏輯落（node_ids 差集）

	// AccessPolicy nil＝跟隨全域，審計以空字串表示（asset-level-access-policy）
	oldPolicy := ""
	if old.AccessPolicy != nil {
		oldPolicy = *old.AccessPolicy
	}
	newPolicy := ""
	if new.AccessPolicy != nil {
		newPolicy = *new.AccessPolicy
	}
	if oldPolicy != newPolicy {
		changes = append(changes, AssetChange{
			Field: "access_policy",
			Old:   oldPolicy,
			New:   newPolicy,
		})
	}

	return changes
}

// getUserFromContext 從 context 提取用戶資訊
func getUserFromContext(ctx context.Context) (userID uint, username string) {
	if ctx == nil {
		return 0, "system"
	}

	// 嘗試提取 userID
	if val := ctx.Value("userID"); val != nil {
		if id, ok := val.(uint); ok {
			userID = id
		}
	}

	// 嘗試提取 username
	if val := ctx.Value("username"); val != nil {
		if name, ok := val.(string); ok {
			username = name
		}
	}

	// 如果沒有用戶資訊，使用系統
	if userID == 0 {
		userID = 0
		username = "system"
	}

	return userID, username
}

// AfterCreate Hook - 記錄資產創建
func (a *Asset) AfterCreate(tx *gorm.DB) error {
	userID, username := getUserFromContext(tx.Statement.Context)

	// 創建操作不需要 diff，只記錄創建事件
	auditLog := &AuditLog{
		CreatedAt:  time.Now(),
		UserID:     userID,
		Username:   username,
		Action:     ActionCreate,
		Resource:   ResourceAsset,
		ResourceID: &a.ID,
		// 主體鍵與 ResourceID 同值仍要各記一次（auditor-workbench D4）：資產樞紐只認
		// AssetID，靠 (Resource, ResourceID) 反推會把改密計畫／授權列的同號 id 一併撈進來
		AssetID: &a.ID,
		Status:  StatusSuccess,
		Details: "", // 創建操作不需要詳情
	}

	// 使用新的 session 避免嵌套事務問題
	return tx.Session(&gorm.Session{NewDB: true}).Create(auditLog).Error
}

// AfterUpdate Hook - 記錄資產變更
func (a *Asset) AfterUpdate(tx *gorm.DB) error {
	userID, username := getUserFromContext(tx.Statement.Context)

	// 從 Statement.Dest 獲取更新前的值
	// 注意：GORM 在 AfterUpdate 時，Statement.Dest 包含更新後的值
	// 我們需要從 Statement.Changed 獲取變更的欄位
	// 但 Statement.Changed 在 GORM v2 中不可用
	// 因此我們需要在 BeforeUpdate 中保存原始值

	// 簡化方案：只記錄更新事件，不做 diff
	// 完整 diff 需要在 Service 層實作
	auditLog := &AuditLog{
		CreatedAt:  time.Now(),
		UserID:     userID,
		Username:   username,
		Action:     ActionUpdate,
		Resource:   ResourceAsset,
		ResourceID: &a.ID,
		AssetID:    &a.ID,
		Status:     StatusSuccess,
		Details:    "", // 簡化版本先不做 diff
	}

	return tx.Session(&gorm.Session{NewDB: true}).Create(auditLog).Error
}

// AfterDelete Hook - 記錄資產刪除
func (a *Asset) AfterDelete(tx *gorm.DB) error {
	userID, username := getUserFromContext(tx.Statement.Context)

	auditLog := &AuditLog{
		CreatedAt:  time.Now(),
		UserID:     userID,
		Username:   username,
		Action:     ActionDelete,
		Resource:   ResourceAsset,
		ResourceID: &a.ID,
		AssetID:    &a.ID,
		Status:     StatusSuccess,
		Details:    "", // 刪除操作不需要詳情
	}

	return tx.Session(&gorm.Session{NewDB: true}).Create(auditLog).Error
}

// **W6 6.1／6.2**：`RecordAssetChange` 與 `RecordAssetNodeChange` 已隨 T-2 收口
// 遷入 asset 模組（`internal/modules/asset/asset_audit_events.go` 的
// `writeAssetChangeAudit`／`writeAssetNodeChangeAudit`），落地一律經
// `audit/port.WriteInTx`。`internal/model` 自此只留資料型別與 T-3 的 GORM hook
// （後者維持直寫，見 tasks.md 4.5 與 backlog B-1），不再是第四個審計落地入口。
