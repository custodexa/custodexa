package database

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 政策組增量的**宣告面與語義面**測試（兩段的第一段）。
//
// 與同名 _pg_test.go 不重疊：那一檔問「這條 migration 在真的 postgres 上跑不跑
// 得起來、Down 之後能不能再 Up」，本檔問「宣告的物件是不是我們要的那些、Down
// 有沒有把 Up 建的每一樣都卸掉」，以及「這四張表的主鍵與唯一索引在實際的資料庫
// 上是不是真的擋得住重複」。結構面測試是 PG-gated 的（未設 DSN 即 skip），
// 只有它會讓「唯一索引其實沒建出來」這種缺陷完全沒有本機訊號。

// policyGroupsExpectedTables 本增量建立的表（Down 必須逐一卸下）。
var policyGroupsExpectedTables = []string{
	"policy_groups",
	"policy_clauses",
	"policy_clause_controls",
	"policy_clause_annotations",
}

// TestMigrationPolicyGroupsDDLDeclaration 宣告面：登記、建立的物件、Down 的反序完整性。
func TestMigrationPolicyGroupsDDLDeclaration(t *testing.T) {
	const version = "20260909_policy_groups"

	var found *Migration
	for i := range migrations {
		if migrations[i].Version == version {
			found = &migrations[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("migrations 內找不到版本 %s：DDL 寫了但沒登記，全新安裝不會建出這四張表", version)
	}
	if found.Up == nil || found.Down == nil {
		t.Fatalf("migration %s 的 Up／Down 不得為 nil", version)
	}

	stmts := policyGroupsDDL()
	created := map[string]bool{}
	indexes := map[string]bool{}
	for _, stmt := range stmts {
		s := strings.Join(strings.Fields(stmt), " ")
		switch {
		case strings.HasPrefix(s, "CREATE TABLE "):
			created[strings.Fields(s)[2]] = true
		case strings.HasPrefix(s, "CREATE UNIQUE INDEX "):
			indexes[strings.Fields(s)[3]] = true
		default:
			t.Errorf("非預期的 DDL 語句形態（本增量只建表與唯一索引）：%.60s…", s)
		}
	}
	for _, tb := range policyGroupsExpectedTables {
		if !created[tb] {
			t.Errorf("DDL 未建立表 %s", tb)
		}
	}
	if len(created) != len(policyGroupsExpectedTables) {
		t.Errorf("DDL 建了 %d 張表，預期 %d 張", len(created), len(policyGroupsExpectedTables))
	}
	if !indexes["idx_policy_clause_controls_group_key"] {
		t.Error("缺少 (group_code, policy_key) 的唯一索引：同組內同一個鍵可被寫入兩個互相矛盾的要求，" +
			"而判定結果會取決於列的讀取順序")
	}

	// 欄位的存在性只挑三個承載語義的：升級移除標記、參考值旗標、自建組原文語言。
	// 其餘欄位由 model↔DDL 的 parity 守衛雙向比對，此處不重複
	joined := strings.Join(stmts, "\n")
	for _, col := range []string{"removed_in_version", "reference_only", "locale"} {
		if !strings.Contains(joined, col) {
			t.Errorf("DDL 缺少欄位 %s", col)
		}
	}

	// Down 的反序完整性：Up 建的每一樣都要被卸下。殘留物會讓下一次 Up 的
	// 無條件 DDL 撞上既有物件
	dropped := map[string]bool{}
	for _, stmt := range policyGroupsRollbackDDL() {
		fields := strings.Fields(strings.Join(strings.Fields(stmt), " "))
		if len(fields) < 3 || fields[0] != "DROP" {
			t.Errorf("Down 出現非 DROP 語句：%.60s…", stmt)
			continue
		}
		dropped[fields[2]] = true
	}
	for _, tb := range policyGroupsExpectedTables {
		if !dropped[tb] {
			t.Errorf("Down 未卸下表 %s", tb)
		}
	}
	if !dropped["idx_policy_clause_controls_group_key"] {
		t.Error("Down 未卸下唯一索引 idx_policy_clause_controls_group_key")
	}

	// 本增量的 DDL 必須進入 schema 事實源，否則 model↔schema 的 parity 守衛
	// 對這四張表整個失效
	all := strings.Join(schemaDDLStatements(), "\n")
	for _, tb := range policyGroupsExpectedTables {
		if !strings.Contains(all, "CREATE TABLE "+tb+" ") {
			t.Errorf("schemaDDLStatements() 不含 %s 的建表語句：parity 守衛看不到這張表", tb)
		}
	}
}

// TestMigrationPolicyGroupsConstraintsSQLite 語義面：主鍵與唯一索引真的擋得住重複，
// 且備註不隨條文列消失。
//
// 在 sqlite 上以 model 建表而非跑 DDL：baseline 與增量 DDL 是 postgres 方言
// （bigserial、::character varying），sqlite 跑不動。受測對象是**約束的語義**
// ——同一組同一個鍵只能有一個要求、同一組同一條號只能有一列條文、備註表與條文表
// 沒有外鍵牽連。方言面由 _pg_test.go 承擔。
func TestMigrationPolicyGroupsConstraintsSQLite(t *testing.T) {
	db := newPolicyGroupsSQLiteDB(t)

	if err := db.Create(&model.PolicyGroup{
		Code: "demo", Name: "示範組", Source: model.PolicyGroupSourceCustom, Enabled: true,
	}).Error; err != nil {
		t.Fatalf("建組: %v", err)
	}
	clause := model.PolicyClause{
		GroupCode: "demo", ClauseNo: "1-1", Title: "示範條文", Kind: model.PolicyClauseKindSetting,
	}
	if err := db.Create(&clause).Error; err != nil {
		t.Fatalf("建條文: %v", err)
	}
	if err := db.Create(&model.PolicyClause{
		GroupCode: "demo", ClauseNo: "1-1", Title: "重複條號", Kind: model.PolicyClauseKindSetting,
	}).Error; err == nil {
		t.Error("同組同條號被寫入第二列：（組代號，條號）主鍵沒有生效，" +
			"升級 upsert 與備註掛靠都會指向不確定的那一列")
	}

	ctl := model.PolicyClauseControl{
		GroupCode: "demo", ClauseNo: "1-1", PolicyKey: "password_min_length",
		Comparator: model.PolicyControlComparatorMin, ExpectedValue: "12",
	}
	if err := db.Create(&ctl).Error; err != nil {
		t.Fatalf("建控制: %v", err)
	}
	if err := db.Create(&model.PolicyClauseControl{
		GroupCode: "demo", ClauseNo: "1-2", PolicyKey: "password_min_length",
		Comparator: model.PolicyControlComparatorMin, ExpectedValue: "14",
	}).Error; err == nil {
		t.Error("同一組內同一個鍵被寫入第二個要求：唯一索引沒有生效，" +
			"該組對自己自相矛盾而判定結果取決於讀取順序")
	}

	confirmedAt := time.Now()
	if err := db.Create(&model.PolicyClauseAnnotation{
		GroupCode: "demo", ClauseNo: "1-1", Note: "機構備註",
		ConfirmedBy: "admin", ConfirmedAt: &confirmedAt, ConfirmationNote: "已核對",
	}).Error; err != nil {
		t.Fatalf("建備註: %v", err)
	}
	// 條文列消失後備註仍在：兩者刻意沒有外鍵，因為條文會被升級標記移除而
	// 備註必須活得比它久
	if err := db.Where("group_code = ? AND clause_no = ?", "demo", "1-1").
		Delete(&model.PolicyClause{}).Error; err != nil {
		t.Fatalf("刪條文: %v", err)
	}
	var note model.PolicyClauseAnnotation
	if err := db.Where("group_code = ? AND clause_no = ?", "demo", "1-1").
		First(&note).Error; err != nil {
		t.Fatalf("條文列消失後備註也不見了（不得設外鍵到條文列）: %v", err)
	}
	if note.Note != "機構備註" {
		t.Errorf("備註原文被改動: %q", note.Note)
	}
}

// newPolicyGroupsSQLiteDB 以 model 在 sqlite 建出四張表。
func newPolicyGroupsSQLiteDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	// :memory: 連線池陷阱：多條連線各自是一個空庫，寫在 A 讀在 B 會偶發查無資料
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })

	if err := db.AutoMigrate(&model.PolicyGroup{}, &model.PolicyClause{},
		&model.PolicyClauseControl{}, &model.PolicyClauseAnnotation{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}
