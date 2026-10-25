package database

import (
	"encoding/json"
	"fmt"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 權限模型遷移報告。
//
// 規劃函式在套用前後各算一次，兩者不同即整筆回滾；同一份輸入資料必得同一份報告
// （決定性：固定順序、不含時間與環境資訊），故升級前備份在隔離環境演練取得的報告，
// 可與正式升級寫入 authz_state.model_migration_report 的報告逐字比對。
//
// 報告以**角色名稱**計算而非 builtin_key，所以套用前（尚無 builtin_key）與套用後
// 算出的是同一組數字。

// authzBuiltinOrderEntry 內建角色名與其內建範本識別。
type authzBuiltinOrderEntry struct{ Name, Key string }

// authzBuiltinOrder 四個內建角色名與其內建範本識別，固定順序（報告與標記共用）。
func authzBuiltinOrder() []authzBuiltinOrderEntry {
	return []authzBuiltinOrderEntry{
		{model.RoleAdmin, model.BuiltinSuperAdmin},
		{model.RoleAuditor, model.BuiltinAuditor},
		{model.RoleUser, model.BuiltinUser},
		{model.RoleApprover, model.BuiltinApprover},
	}
}

// AuthzTemplateCount 一個內建範本的指派計數。
type AuthzTemplateCount struct {
	Name   string `json:"name"`
	Key    string `json:"builtin_key"`
	Direct int64  `json:"direct"` // user_roles 列數（含所有來源）
	Mapped int64  `json:"source_mapped"`
	Both   int64  `json:"source_both"`
}

// AuthzUnknownRole 非內建名稱的未刪除角色與其指派數。
type AuthzUnknownRole struct {
	Name        string `json:"name"`
	Assignments int64  `json:"assignments"`
}

// AuthzMigrationReport 權限模型遷移報告。
type AuthzMigrationReport struct {
	Templates []AuthzTemplateCount `json:"templates"`
	// LocalSuperAdmins 依最後本地超管不變式的判準計算的本地管理員數（以 admin 角色名稱）。
	LocalSuperAdmins int64 `json:"local_super_admins"`
	// UnknownRoles 未知角色名與其指派數，只列報告，不阻擋。
	UnknownRoles []AuthzUnknownRole `json:"unknown_roles"`
	// DanglingAssignments 指向已刪除或不存在角色的指派數，只列報告，不阻擋。
	DanglingAssignments int64 `json:"dangling_assignments"`
	// SeededRoles 本次遷移依種子補列的內建角色名。不參與前後比對（補列是套用的一部分）。
	SeededRoles []string `json:"seeded_roles"`
}

// comparable 回傳參與前後比對的 JSON（排除 SeededRoles）。
func (r AuthzMigrationReport) comparable() (string, error) {
	r.SeededRoles = nil
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("序列化遷移報告失敗: %w", err)
	}
	return string(b), nil
}

// authzReportPlanner 規劃函式型別；測試可替換以驗證「前後不同即回滾」。
type authzReportPlanner func(db *gorm.DB) (AuthzMigrationReport, error)

// planAuthzModelReport 唯讀計算報告。
func planAuthzModelReport(db *gorm.DB) (AuthzMigrationReport, error) {
	var rep AuthzMigrationReport

	type tplRow struct {
		Name   string
		Total  int64
		Mapped int64
		Both   int64
	}
	var rows []tplRow
	if err := db.Raw(`SELECT r.name AS name, COUNT(*) AS total,
 COALESCE(SUM(CASE WHEN ur.source = ? THEN 1 ELSE 0 END), 0) AS mapped,
 COALESCE(SUM(CASE WHEN ur.source = ? THEN 1 ELSE 0 END), 0) AS both
 FROM user_roles ur JOIN roles r ON r.id = ur.role_id AND r.deleted_at IS NULL
 GROUP BY r.name`, model.RoleSourceMapped, model.RoleSourceBoth).Scan(&rows).Error; err != nil {
		return rep, fmt.Errorf("計算內建範本指派數失敗: %w", err)
	}
	byName := make(map[string]tplRow, len(rows))
	for _, r := range rows {
		byName[r.Name] = r
	}
	for _, b := range authzBuiltinOrder() {
		r := byName[b.Name]
		rep.Templates = append(rep.Templates, AuthzTemplateCount{
			Name: b.Name, Key: b.Key, Direct: r.Total, Mapped: r.Mapped, Both: r.Both,
		})
	}

	// 本地超管數：判準與 identity.localAdminScope 相同（database 不得依賴 identity，
	// 故此處以同樣的條件重述；情境與期望值由 TestAuthzModelMigration 的 1.17 形狀 fixture 釘住）。
	if err := db.Model(&model.User{}).
		Joins("JOIN user_roles ON user_roles.user_id = users.id").
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("roles.name = ? AND roles.deleted_at IS NULL", model.RoleAdmin).
		Where("user_roles.source IN ?", []string{model.RoleSourceManual, model.RoleSourceBoth}).
		Where("users.active = ?", true).
		Where("users.deleted_at IS NULL").
		Where("users.external_credential = ?", false).
		Where("users.is_ldap = ?", false).
		Where("users.password IS NOT NULL AND TRIM(users.password) <> ''").
		Where("users.provisioning_origin IS NULL OR users.provisioning_origin = '' OR users.provisioning_origin = ?",
			model.AuthSourceLocal).
		Distinct("users.id").Count(&rep.LocalSuperAdmins).Error; err != nil {
		return rep, fmt.Errorf("計算本地管理員數失敗: %w", err)
	}

	rep.UnknownRoles = []AuthzUnknownRole{}
	if err := db.Raw(`SELECT r.name AS name, COUNT(ur.user_id) AS assignments
 FROM roles r LEFT JOIN user_roles ur ON ur.role_id = r.id
 WHERE r.deleted_at IS NULL AND r.name NOT IN ?
 GROUP BY r.name ORDER BY r.name`, authzBuiltinNames()).Scan(&rep.UnknownRoles).Error; err != nil {
		return rep, fmt.Errorf("計算未知角色失敗: %w", err)
	}

	if err := db.Raw(`SELECT COUNT(*) FROM user_roles ur LEFT JOIN roles r ON r.id = ur.role_id
 WHERE r.id IS NULL OR r.deleted_at IS NOT NULL`).Scan(&rep.DanglingAssignments).Error; err != nil {
		return rep, fmt.Errorf("計算懸空指派失敗: %w", err)
	}
	rep.SeededRoles = []string{}
	return rep, nil
}

func authzBuiltinNames() []string {
	out := make([]string, 0, len(authzBuiltinOrder()))
	for _, b := range authzBuiltinOrder() {
		out = append(out, b.Name)
	}
	return out
}
