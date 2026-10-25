package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 權限模型遷移的資料步驟、前置檢查與報告保存。
//
// 與 DDL 同一版本、同一交易（見 applyAuthzPermissionModel）。流程：
//
//  1. 前置檢查：四個內建角色名各恰一列未刪除；只剩軟刪除列即整筆不套用。
//  2. 套用前報告（規劃函式）。
//  3. 完全缺列的內建角色依種子補列。
//  4. 只對 builtin_key IS NULL 的四個內建名稱列標記。
//  5. 套用後報告，須與步驟 2 逐字相同，否則整筆回滾。
//  6. 寫入 authz_state 初始列與報告（已有報告則不動，故重跑狀態不變）。
//
// 資料步驟本身冪等：重複執行不改變資料庫狀態。DDL 無條件，重跑依專案慣例大聲失敗。

// authzBuiltinRoleUnusableError 內建角色無法無歧義地指定（只剩軟刪除列，或同名多列未刪除）。
type authzBuiltinRoleUnusableError struct {
	Problems []string
}

func (e *authzBuiltinRoleUnusableError) Error() string {
	return "權限模型遷移不套用（資料庫未變動）：內建角色無法無歧義地指定：" + strings.Join(e.Problems, "；") +
		"。處置：確認該角色列是否被誤刪，還原後重新啟動；或還原升級前備份。"
}

// ErrAuthzBuiltinRoleUnusable 前置檢查失敗的哨兵值（errors.Is 比對用）。
var ErrAuthzBuiltinRoleUnusable = errors.New("authz: built-in role cannot be identified")

func (e *authzBuiltinRoleUnusableError) Is(target error) bool {
	return target == ErrAuthzBuiltinRoleUnusable
}

// authzLogPrefix 遷移報告印在後端日誌的固定前綴，供升級後與演練報告比對。
const authzLogPrefix = "[AuthzModelMigration] report="

// checkAuthzBuiltinRoles 前置檢查（c）：每個內建名稱「未刪除列恰一」或「完全缺列」。
// 回傳缺列的名稱供補列。
func checkAuthzBuiltinRoles(db *gorm.DB) (missing []string, err error) {
	var problems []string
	for _, b := range authzBuiltinOrder() {
		var live, total int64
		if err := db.Model(&model.Role{}).Where("name = ?", b.Name).Count(&live).Error; err != nil {
			return nil, fmt.Errorf("前置檢查查詢角色 %s 失敗: %w", b.Name, err)
		}
		if err := db.Unscoped().Model(&model.Role{}).Where("name = ?", b.Name).Count(&total).Error; err != nil {
			return nil, fmt.Errorf("前置檢查查詢角色 %s 失敗: %w", b.Name, err)
		}
		switch {
		case live == 1:
		case live > 1:
			problems = append(problems, fmt.Sprintf("角色 %s 有 %d 列未刪除", b.Name, live))
		case total > 0:
			problems = append(problems, fmt.Sprintf("角色 %s 只剩已刪除列", b.Name))
		default:
			missing = append(missing, b.Name)
		}
	}
	if len(problems) > 0 {
		return nil, &authzBuiltinRoleUnusableError{Problems: problems}
	}
	return missing, nil
}

// applyAuthzModelData 資料步驟（冪等）。plan 為報告規劃函式。
func applyAuthzModelData(db *gorm.DB, plan authzReportPlanner) error {
	missing, err := checkAuthzBuiltinRoles(db)
	if err != nil {
		return err
	}
	before, err := plan(db)
	if err != nil {
		return err
	}

	// 缺列依種子補列（語義同 seedRoles：缺哪個補哪個），補列時直接帶內建識別。
	// 依 builtinRoleSeeds 的順序補，使全新庫的角色 ID 與 seedRoles 建出的相同。
	seeded := []string{}
	missingSet := map[string]bool{}
	for _, name := range missing {
		missingSet[name] = true
	}
	keyOf := map[string]string{}
	for _, b := range authzBuiltinOrder() {
		keyOf[b.Name] = b.Key
	}
	for _, role := range builtinRoleSeeds() {
		if !missingSet[role.Name] {
			continue
		}
		key := keyOf[role.Name]
		role.BuiltinKey = &key
		// 省略後續增量才加入的欄位（definition_version、template_role_id）：此刻它們還不存在。
		if err := db.Omit("DefinitionVersion", "TemplateRoleID").Create(&role).Error; err != nil {
			return fmt.Errorf("補建內建角色 %s 失敗: %w", role.Name, err)
		}
		seeded = append(seeded, role.Name)
	}

	// 標記：只動 builtin_key 仍為空的內建名稱列。
	for _, b := range authzBuiltinOrder() {
		if err := db.Model(&model.Role{}).
			Where("name = ? AND builtin_key IS NULL", b.Name).
			Update("builtin_key", b.Key).Error; err != nil {
			return fmt.Errorf("標記內建角色 %s 失敗: %w", b.Name, err)
		}
	}
	// 事後條件：每個內建名稱的未刪除列都帶預期的識別。
	for _, b := range authzBuiltinOrder() {
		var n int64
		if err := db.Model(&model.Role{}).
			Where("name = ? AND builtin_key = ?", b.Name, b.Key).Count(&n).Error; err != nil {
			return fmt.Errorf("驗證內建角色 %s 標記失敗: %w", b.Name, err)
		}
		if n != 1 {
			return fmt.Errorf("內建角色 %s 標記後未帶識別 %s（列數 %d）", b.Name, b.Key, n)
		}
	}

	after, err := plan(db)
	if err != nil {
		return err
	}
	bj, err := before.comparable()
	if err != nil {
		return err
	}
	aj, err := after.comparable()
	if err != nil {
		return err
	}
	if bj != aj {
		return fmt.Errorf("權限模型遷移套用前後報告不一致，整筆回滾：套用前 %s；套用後 %s", bj, aj)
	}

	after.SeededRoles = seeded
	return saveAuthzMigrationReport(db, after)
}

// saveAuthzMigrationReport 寫入 authz_state 初始列與報告；已有報告則不動（重跑狀態不變）。
func saveAuthzMigrationReport(db *gorm.DB, rep AuthzMigrationReport) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("序列化遷移報告失敗: %w", err)
	}
	if err := db.Exec(`INSERT INTO authz_state (id, version) VALUES (1, 0) ON CONFLICT (id) DO NOTHING`).Error; err != nil {
		return fmt.Errorf("建立 authz_state 初始列失敗: %w", err)
	}
	res := db.Exec(`UPDATE authz_state SET model_migrated_at = ?, model_migration_report = ?
 WHERE id = 1 AND model_migration_report IS NULL`, time.Now().UTC(), string(b))
	if res.Error != nil {
		return fmt.Errorf("寫入遷移報告失敗: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		log.Printf("%s%s", authzLogPrefix, string(b))
		announceAuthzWarning(rep)
	}
	return nil
}

// ReadAuthzMigrationReport 讀回 authz_state 保存的遷移報告（升級後與演練報告比對用）。
func ReadAuthzMigrationReport(db *gorm.DB) (AuthzMigrationReport, error) {
	var raw *string
	if err := db.Raw(`SELECT model_migration_report FROM authz_state WHERE id = 1`).Scan(&raw).Error; err != nil {
		return AuthzMigrationReport{}, fmt.Errorf("讀取遷移報告失敗: %w", err)
	}
	if raw == nil {
		return AuthzMigrationReport{}, errors.New("authz_state 尚無遷移報告")
	}
	var rep AuthzMigrationReport
	if err := json.Unmarshal([]byte(*raw), &rep); err != nil {
		return AuthzMigrationReport{}, fmt.Errorf("遷移報告格式錯誤: %w", err)
	}
	return rep, nil
}
