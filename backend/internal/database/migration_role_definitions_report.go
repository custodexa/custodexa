package database

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// 角色定義遷移報告。
//
// 升級前後各算一次：存量角色目錄與全部角色指派（直接、群組）的內容摘要必須相同，
// 否則整筆回滾。兩個新範本以名稱排除（遷移前置檢查保證升級前沒有同名列），所以
// 套用前與套用後算的是同一組輸入。報告決定性：固定排序、不含時間與環境資訊，
// 因此升級前備份在隔離環境的演練（PlanRoleDefinitionsReport）可與正式升級的前後報告逐字比較。
// 只含計數與 SHA-256，不含角色名稱以外的內容。

// RoleDefinitionsReport 存量角色與指派的決定性摘要。
type RoleDefinitionsReport struct {
	Roles          int64  `json:"roles"`
	RolesDigest    string `json:"roles_digest"`
	UserRoles      int64  `json:"user_roles"`
	UserRolesSHA   string `json:"user_roles_digest"`
	GroupRoles     int64  `json:"user_group_roles"`
	GroupRolesSHA  string `json:"user_group_roles_digest"`
	ExcludedByName int    `json:"excluded_template_names"`
}

// ErrRoleDefinitionsReportMismatch 升級前後存量摘要不同（整筆回滾）。
var ErrRoleDefinitionsReportMismatch = errors.New("role definitions migration refused: legacy role catalog or assignments changed")

func digestRows(db *gorm.DB, query string, args ...any) (int64, string, error) {
	rows, err := db.Raw(query, args...).Rows()
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	var n int64
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return 0, "", err
		}
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				vals[i] = string(b)
			}
		}
		line, err := json.Marshal(vals)
		if err != nil {
			return 0, "", err
		}
		h.Write(line)
		h.Write([]byte{'\n'})
		n++
	}
	if err := rows.Err(); err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// PlanRoleDefinitionsReport 唯讀計算報告（可在升級前備份還原的隔離資料庫演練）。
func PlanRoleDefinitionsReport(db *gorm.DB) (RoleDefinitionsReport, error) {
	var rep RoleDefinitionsReport
	names := make([]string, 0, 2)
	for _, s := range lockedTemplateSeeds() {
		names = append(names, s.Name)
	}
	rep.ExcludedByName = len(names)
	var err error
	if rep.Roles, rep.RolesDigest, err = digestRows(db,
		`SELECT id, name, description, COALESCE(builtin_key, ''), (deleted_at IS NOT NULL) FROM roles WHERE name NOT IN ? ORDER BY id`, names); err != nil {
		return rep, fmt.Errorf("計算存量角色摘要失敗: %w", err)
	}
	if rep.UserRoles, rep.UserRolesSHA, err = digestRows(db,
		`SELECT user_id, role_id, source, scope_kind FROM user_roles WHERE role_id IN (SELECT id FROM roles WHERE name NOT IN ?) ORDER BY user_id, role_id`, names); err != nil {
		return rep, fmt.Errorf("計算使用者角色指派摘要失敗: %w", err)
	}
	if rep.GroupRoles, rep.GroupRolesSHA, err = digestRows(db,
		`SELECT user_group_id, role_id, scope_kind FROM user_group_roles WHERE role_id IN (SELECT id FROM roles WHERE name NOT IN ?) ORDER BY user_group_id, role_id`, names); err != nil {
		return rep, fmt.Errorf("計算群組角色指派摘要失敗: %w", err)
	}
	return rep, nil
}

// JSON 報告的決定性文字。
func (r RoleDefinitionsReport) JSON() (string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("序列化角色定義遷移報告失敗: %w", err)
	}
	return string(b), nil
}
