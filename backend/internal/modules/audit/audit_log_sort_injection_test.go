package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/glebarez/sqlite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 審計日誌列表排序參數的注入防線（CodeQL go/sql-injection #10）。
//
// 這裡釘的不是「排序有沒有生效」，而是**沒有第二條路徑能把字串送進 ORDER BY**：
// `.Order()` 收 string 時是逐字寫入、不參數化，`sort_by=(CASE WHEN ...)` 這類載荷
// 一旦抵達即構成布林盲注，讀得到整個審計庫。收斂點刻意放在 AuditLogService.List
// 而非 handler——AuditExportService 也經 List 查詢，收在 handler 會漏掉它。

// setupSortTestService 裝一個 sqlite 測試庫並回傳走 database.DB 的服務。
func setupSortTestService(t *testing.T) *AuditLogService {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1) // :memory: 連線池陷阱：多連線各自拿到空 DB（ff51836 教訓）
	if err := db.AutoMigrate(&model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	return NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
}

// seedSortRows 寫入三列時間遞增的審計日誌，回傳由舊到新的 username 順序。
func seedSortRows(t *testing.T, base time.Time) []string {
	t.Helper()
	names := []string{"alice", "bob", "carol"}
	for i, name := range names {
		row := &model.AuditLog{
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
			Action:    model.ActionCreate,
			Resource:  model.ResourceAsset,
			Status:    model.StatusSuccess,
			UserID:    uint(i + 1),
			Username:  name,
		}
		if err := database.DB.Create(row).Error; err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	return names
}

// captureListSQL 以 sqlmock 攔下 List 實際送出的 SQL（不比對、只記錄）。
func captureListSQL(t *testing.T, filter *AuditLogFilter) []string {
	t.Helper()
	var captured []string
	sqlDB, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(
		sqlmock.QueryMatcherFunc(func(_, actualSQL string) error {
			captured = append(captured, actualSQL)
			return nil // 一律視為匹配：斷言做在捕獲的 SQL 原文上，比正則更直白
		})))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	gormDB, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("gorm: %v", err)
	}

	old := database.DB
	database.DB = gormDB
	t.Cleanup(func() {
		database.DB = old
		sqlDB.Close()
	})

	mock.ExpectQuery("").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery("").WillReturnRows(sqlmock.NewRows([]string{"id"}))

	svc := NewAuditLogService(&config.FeatureFlags{AuditLogEnabled: true})
	if _, err := svc.List(filter); err != nil {
		t.Fatalf("List: %v", err)
	}
	return captured
}

func TestNormalizeAuditSortBy(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"白名單欄位原樣通過", "username", "username"},
		{"底線欄位原樣通過", "status_code", "status_code"},
		{"空字串退回預設", "", defaultAuditSortBy},
		{"未知欄位退回預設", "password", defaultAuditSortBy},
		{"大寫欄位不視為白名單（DB 欄位名全小寫）", "CREATED_AT", defaultAuditSortBy},
		{"布林盲注載荷退回預設", "(CASE WHEN (SELECT 1)=1 THEN id ELSE username END)", defaultAuditSortBy},
		{"堆疊查詢載荷退回預設", "id; DROP TABLE audit_logs--", defaultAuditSortBy},
		{"子查詢外洩載荷退回預設", "(SELECT password_hash FROM users LIMIT 1)", defaultAuditSortBy},
		{"合法欄位加尾綴退回預設", "created_at, (SELECT 1)", defaultAuditSortBy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeAuditSortBy(tc.input); got != tc.want {
				t.Errorf("normalizeAuditSortBy(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestNormalizeAuditSortOrder(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"asc 原樣通過", "asc", "asc"},
		{"desc 原樣通過", "desc", "desc"},
		{"大寫正規化為小寫", "ASC", "asc"},
		{"混合大小寫正規化為小寫", "DeSc", "desc"},
		{"空字串退回預設", "", defaultAuditSortOrder},
		{"未知方向退回預設", "random", defaultAuditSortOrder},
		{"堆疊查詢載荷退回預設", "asc; DROP TABLE audit_logs", defaultAuditSortOrder},
		{"合法方向加尾綴退回預設", "desc--", defaultAuditSortOrder},
		{"UNION 載荷退回預設", "asc UNION SELECT 1", defaultAuditSortOrder},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeAuditSortOrder(tc.input); got != tc.want {
				t.Errorf("normalizeAuditSortOrder(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestAuditSortableColumnsAreRealColumns 白名單的每個名字都必須是 audit_logs 的
// 真實欄位——不存在的名字不會靜默退回預設，而是讓整筆查詢失敗（稽核列表整頁壞掉）。
func TestAuditSortableColumnsAreRealColumns(t *testing.T) {
	svc := setupSortTestService(t)
	seedSortRows(t, time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC))

	for column := range auditSortableColumns {
		t.Run(column, func(t *testing.T) {
			res, err := svc.List(&AuditLogFilter{SortBy: column, SortOrder: "asc"})
			if err != nil {
				t.Fatalf("以 %q 排序查詢失敗（白名單含非真實欄位）: %v", column, err)
			}
			if res.Total != 3 {
				t.Errorf("Total = %d, want 3", res.Total)
			}
		})
	}
}

// TestListSortOrderNormalizationApplies 合法欄位＋大小寫混合方向要真的改變結果順序。
func TestListSortOrderNormalizationApplies(t *testing.T) {
	svc := setupSortTestService(t)
	names := seedSortRows(t, time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC))
	oldest, newest := names[0], names[len(names)-1]

	cases := []struct {
		name      string
		sortBy    string
		sortOrder string
		wantFirst string
	}{
		{"created_at 升冪", "created_at", "asc", oldest},
		{"created_at 降冪", "created_at", "desc", newest},
		{"大寫 ASC 正規化後仍為升冪", "created_at", "ASC", oldest},
		{"混合大小寫 DeSc 正規化後仍為降冪", "created_at", "DeSc", newest},
		{"username 升冪", "username", "asc", oldest},
		{"未指定時走預設（created_at desc）", "", "", newest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := svc.List(&AuditLogFilter{SortBy: tc.sortBy, SortOrder: tc.sortOrder})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if len(res.Data) != 3 {
				t.Fatalf("len(Data) = %d, want 3", len(res.Data))
			}
			if res.Data[0].Username != tc.wantFirst {
				t.Errorf("首列 = %q, want %q", res.Data[0].Username, tc.wantFirst)
			}
		})
	}
}

// TestListInjectedSortFallsBackWithoutError 注入載荷不得讓查詢失敗，也不得改變順序：
// 回錯等於給探測者回饋，改變順序等於載荷已生效。
func TestListInjectedSortFallsBackWithoutError(t *testing.T) {
	svc := setupSortTestService(t)
	names := seedSortRows(t, time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC))
	oldest, newest := names[0], names[len(names)-1]

	// wantFirst：載荷被丟棄後只剩「created_at ＋ 該欄自身合法的方向」，
	// 方向欄本身合法（asc／ASC）時仍應生效——收斂不是把兩個參數一起作廢
	payloads := []struct {
		sortBy    string
		sortOrder string
		wantFirst string
	}{
		{"(CASE WHEN (SELECT COUNT(*) FROM users)>0 THEN id ELSE username END)", "asc", oldest},
		{"created_at", "asc; DROP TABLE audit_logs", newest},
		{"id) UNION SELECT 1--", "desc", newest},
		{"CASE WHEN (SELECT COUNT(*) FROM audit_logs) > 2 THEN username END DESC, id", "ASC", oldest},
	}
	for _, p := range payloads {
		t.Run(p.sortBy+"|"+p.sortOrder, func(t *testing.T) {
			res, err := svc.List(&AuditLogFilter{SortBy: p.sortBy, SortOrder: p.sortOrder})
			if err != nil {
				t.Fatalf("注入載荷不應使查詢失敗（錯誤本身即回饋通道）: %v", err)
			}
			if len(res.Data) != 3 {
				t.Fatalf("len(Data) = %d, want 3", len(res.Data))
			}
			if res.Data[0].Username != p.wantFirst {
				t.Errorf("首列 = %q, want %q（載荷改變了排序＝已生效）", res.Data[0].Username, p.wantFirst)
			}
			var remaining int64
			if err := database.DB.Model(&model.AuditLog{}).Count(&remaining).Error; err != nil {
				t.Fatalf("count: %v", err)
			}
			if remaining != 3 {
				t.Errorf("列數 = %d, want 3（載荷的破壞性語句已執行）", remaining)
			}
		})
	}
}

// TestListOrderClauseNeverCarriesUserPayload 直接檢查送進 DB 的 SQL 原文：
// ORDER BY 只能是收斂後的欄位＋方向，載荷片段一個字都不得出現。
func TestListOrderClauseNeverCarriesUserPayload(t *testing.T) {
	cases := []struct {
		name      string
		sortBy    string
		sortOrder string
		wantOrder string
		forbidden []string
	}{
		{
			name:      "盲注載荷被整段丟棄",
			sortBy:    "(CASE WHEN (SELECT 1)=1 THEN id ELSE username END)",
			sortOrder: "asc",
			wantOrder: "ORDER BY created_at asc",
			forbidden: []string{"CASE", "SELECT 1"},
		},
		{
			name:      "方向欄的堆疊查詢被整段丟棄",
			sortBy:    "created_at",
			sortOrder: "asc; DROP TABLE audit_logs",
			wantOrder: "ORDER BY created_at desc",
			forbidden: []string{"DROP", ";"},
		},
		{
			name:      "註解截斷載荷被整段丟棄",
			sortBy:    "id--",
			sortOrder: "desc--",
			wantOrder: "ORDER BY created_at desc",
			forbidden: []string{"--"},
		},
		{
			name:      "合法組合原樣出現（收斂不是把功能關掉）",
			sortBy:    "status_code",
			sortOrder: "ASC",
			wantOrder: "ORDER BY status_code asc",
			forbidden: []string{"ASC"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			queries := captureListSQL(t, &AuditLogFilter{SortBy: tc.sortBy, SortOrder: tc.sortOrder})
			if len(queries) == 0 {
				t.Fatal("未捕獲任何 SQL")
			}
			find := queries[len(queries)-1]
			if !strings.Contains(find, tc.wantOrder) {
				t.Errorf("SQL = %q, want 含 %q", find, tc.wantOrder)
			}
			for _, frag := range tc.forbidden {
				if strings.Contains(find, frag) {
					t.Errorf("SQL 內含使用者載荷片段 %q: %q", frag, find)
				}
			}
		})
	}
}

// TestExportListSharesSortNormalization 匯出走的是同一個 List，故同享收斂——
// 這一條釘的是收斂點的位置：若哪天被搬回 handler，本測試會轉紅。
func TestExportListSharesSortNormalization(t *testing.T) {
	svc := setupSortTestService(t)
	names := seedSortRows(t, time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC))

	// 匯出建構 filter 時不設排序欄位（audit_export_service.go 的呼叫形態）
	filter := &AuditLogFilter{Page: 1, PageSize: 1000}
	res, err := svc.List(filter)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if filter.SortBy != defaultAuditSortBy || filter.SortOrder != defaultAuditSortOrder {
		t.Errorf("收斂後 filter = %q/%q, want %q/%q",
			filter.SortBy, filter.SortOrder, defaultAuditSortBy, defaultAuditSortOrder)
	}
	if res.Data[0].Username != names[len(names)-1] {
		t.Errorf("首列 = %q, want %q", res.Data[0].Username, names[len(names)-1])
	}
}
