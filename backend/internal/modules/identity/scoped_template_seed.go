package identity

import (
	"context"
	"fmt"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"gorm.io/gorm"
)

// 兩個範圍化管理範本（資產管理員、授權管理員）的啟動資料步驟。
//
// 時機：權限附證來源注入之後、對外服務之前。遷移只重建內建識別的值域（純 DDL）；角色列在這裡
// 以單一交易種入：BeginPermissionChange（不取鎖）→ 寫兩列鎖定範本 → AdvanceVersion（權限版本
// 恆在最後）。附證已啟用時同交易留下一筆可重放事件；未啟用時事件寫入依既有規則不做。
// 集合在程式中（authz.TemplatePermissions），不寫 role_permissions，也不建任何指派。
//
// 可重入：兩列已存在且內容相同時不寫、不推進版本、不寫事件。同名或同識別但內容不同時整筆不套用、
// 不改寫該列，結果在報告的衝突欄指出；呼叫端照常啟動，改名後下一次啟動補做。

// scopedTemplateSeeds 兩個範本的種子（名稱、說明、識別）；儲存名稱與識別同值。
func scopedTemplateSeeds() []model.Role {
	k1, k2 := model.BuiltinAssetAdmin, model.BuiltinAuthzAdmin
	return []model.Role{
		{Name: k1, Description: "資產管理員（鎖定範本）", BuiltinKey: &k1, DefinitionVersion: 1},
		{Name: k2, Description: "授權管理員（鎖定範本）", BuiltinKey: &k2, DefinitionVersion: 1},
	}
}

// ScopedTemplateSeedReport 種入報告；試跑與正式的 Line 逐欄相同。
type ScopedTemplateSeedReport struct {
	DryRun bool
	// Planned 本次要新建的範本識別；Existing 已存在且內容相同者；Conflicts 為「識別:原因」。
	Planned   []string
	Existing  []string
	Conflicts []string
	// VersionBefore 執行前的權限版本；Attestation 權限附證鏈是否已啟用。
	VersionBefore int64
	Attestation   bool
	// Applied 與 VersionAfter 只有正式執行有值。
	Applied      bool
	VersionAfter int64
}

// Line 固定前綴的報告行，只含試跑與正式可逐欄比對的欄位。
func (r ScopedTemplateSeedReport) Line() string {
	att := "off"
	if r.Attestation {
		att = "on"
	}
	return fmt.Sprintf("[ScopedTemplateSeed] create=%s existing=%s conflicts=%d conflict_detail=%s version=%d attestation=%s",
		strings.Join(r.Planned, ","), strings.Join(r.Existing, ","), len(r.Conflicts),
		strings.Join(r.Conflicts, ","), r.VersionBefore, att)
}

const (
	scopedTemplateConflictNameInUse = "name_in_use"
	scopedTemplateConflictDiffers   = "different_content"
)

type scopedTemplatePlan struct {
	create    []model.Role
	existing  []string
	conflicts []string
}

// planScopedTemplates 只讀：對每個範本分成「新建」「已存在且相同」「衝突」。
func planScopedTemplates(db *gorm.DB) (scopedTemplatePlan, error) {
	var plan scopedTemplatePlan
	for _, seed := range scopedTemplateSeeds() {
		key := *seed.BuiltinKey
		var rows []model.Role
		if err := db.Unscoped().Where("name = ? OR builtin_key = ?", seed.Name, key).Find(&rows).Error; err != nil {
			return plan, fmt.Errorf("查詢範本 %s 失敗: %w", key, err)
		}
		if len(rows) == 0 {
			plan.create = append(plan.create, seed)
			continue
		}
		reason := ""
		for _, e := range rows {
			if e.BuiltinKey == nil || *e.BuiltinKey != key || e.Name != seed.Name {
				reason = scopedTemplateConflictNameInUse
				break
			}
			var perms int64
			if err := db.Model(&model.RolePermission{}).Where("role_id = ?", e.ID).Count(&perms).Error; err != nil {
				return plan, fmt.Errorf("查詢範本 %s 的權限列失敗: %w", key, err)
			}
			if e.DeletedAt.Valid || e.DefinitionVersion < 1 || perms != 0 {
				reason = scopedTemplateConflictDiffers
			}
		}
		if reason != "" {
			plan.conflicts = append(plan.conflicts, key+":"+reason)
			continue
		}
		plan.existing = append(plan.existing, key)
	}
	return plan, nil
}

func (p scopedTemplatePlan) fill(r *ScopedTemplateSeedReport) {
	r.Planned, r.Existing, r.Conflicts = []string{}, p.existing, p.conflicts
	if r.Existing == nil {
		r.Existing = []string{}
	}
	if r.Conflicts == nil {
		r.Conflicts = []string{}
	}
	for _, c := range p.create {
		r.Planned = append(r.Planned, *c.BuiltinKey)
	}
}

// SeedScopedTemplates 依上述規則種入兩個範本。dryRun 為真只回報、不寫入。
// 任何資料庫或事件寫入失敗回錯並整筆回滾（呼叫端據此停止啟動）。
func SeedScopedTemplates(ctx context.Context, db *gorm.DB, dryRun bool) (ScopedTemplateSeedReport, error) {
	rep := ScopedTemplateSeedReport{DryRun: dryRun}
	db = db.WithContext(ctx)
	ver, err := authz.CurrentVersion(db)
	if err != nil {
		return rep, err
	}
	rep.VersionBefore = ver
	if rep.Attestation, err = audit.PermissionAttestationEnabled(ctx, db); err != nil {
		return rep, err
	}
	plan, err := planScopedTemplates(db)
	if err != nil {
		return rep, err
	}
	plan.fill(&rep)
	// 任一衝突整筆不套用；全部已存在則重入，零寫入。
	if dryRun || len(plan.conflicts) > 0 || len(plan.create) == 0 {
		rep.VersionAfter = ver
		return rep, nil
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := authz.BeginPermissionChange(tx); err != nil {
			return err
		}
		for _, seed := range plan.create {
			row := seed
			if err := tx.Create(&row).Error; err != nil {
				return fmt.Errorf("建立範本 %s 失敗: %w", *seed.BuiltinKey, err)
			}
		}
		return authz.AdvanceVersion(tx)
	})
	if err != nil {
		return rep, err
	}
	rep.Applied = true
	if rep.VersionAfter, err = authz.CurrentVersion(db); err != nil {
		return rep, err
	}
	return rep, nil
}
