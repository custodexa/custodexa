package audit

import (
	"errors"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupAlertRuleDB 建 alert_rules 表並**顯式**加上 name 的唯一索引。
//
// 時序說明：正式的唯一索引由 migration baseline 建立
// （migration-baseline-compression 任務 4.1，種子冪等的前提），本次改動不碰
// migration。測試因此自行建立同形約束——`CREATE UNIQUE INDEX ... (name)`，
// 與 baseline 將建的那條語義相同（該表無 DeletedAt，故為一般唯一索引而非
// partial）。這樣測的仍是「真實約束觸發 → 服務轉譯」的完整路徑，而不是把
// 約束替換成應用層預查；baseline 落地後索引來源改變，本測仍原樣通過。
func setupAlertRuleDB(t *testing.T) (*AlertRuleService, *gorm.DB) {
	t.Helper()
	// 刻意**不**開 TranslateError：正式環境（internal/database）未啟用它，開了
	// 就只會測到 gorm.ErrDuplicatedKey 那半邊，而生產實際走的是驅動原始訊息
	// 經 dberr.IsUniqueViolation 的方言比對那半邊。
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.AlertRule{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Exec(`CREATE UNIQUE INDEX uniq_alert_rules_name ON alert_rules(name)`).Error; err != nil {
		t.Fatalf("建立唯一索引: %v", err)
	}
	return NewAlertRuleService(db), db
}

// TestAlertRuleNameUniqueConstraintIsLive 前置守衛：證明測試環境的唯一索引真的
// 生效。少了這條，下面三個情境即使約束不存在也可能因其他原因「看起來對」，
// 整組測試會變成不驗證真實約束的空殼。
func TestAlertRuleNameUniqueConstraintIsLive(t *testing.T) {
	_, db := setupAlertRuleDB(t)
	stmt := `INSERT INTO alert_rules (name, pattern, severity, action, protocols, enabled, created_at, updated_at)
	         VALUES (?, 'x', 'low', 'alert', '', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`
	if err := db.Exec(stmt, "dup").Error; err != nil {
		t.Fatalf("首次插入不應失敗: %v", err)
	}
	err := db.Exec(stmt, "dup").Error
	if err == nil {
		t.Fatal("同名第二次插入竟成功：唯一索引未生效，本檔其餘測試皆為假綠")
	}
	if !isNameConflict(err) {
		t.Fatalf("唯一鍵衝突未被 isNameConflict 認出（判定會漏接真實違反）: %v", err)
	}
}

func newRuleReq(name string) *AlertRuleRequest {
	return &AlertRuleRequest{Name: name, Pattern: `rm\s+-rf`, Severity: "high"}
}

// TestAlertRuleCreateDuplicateName 情境 1：建立撞名 → 哨兵錯誤（handler 映 400）。
func TestAlertRuleCreateDuplicateName(t *testing.T) {
	svc, db := setupAlertRuleDB(t)

	if _, err := svc.Create(newRuleReq("危險刪除")); err != nil {
		t.Fatalf("首次建立不應失敗: %v", err)
	}

	_, err := svc.Create(newRuleReq("危險刪除"))
	if !errors.Is(err, ErrAlertRuleNameExists) {
		t.Fatalf("撞名建立應回 ErrAlertRuleNameExists，得到 %v", err)
	}
	assertNoDBDetail(t, err)

	var count int64
	db.Model(&model.AlertRule{}).Count(&count)
	if count != 1 {
		t.Fatalf("撞名後列數 = %d, want 1（第二次未落庫）", count)
	}
}

// TestAlertRuleUpdateToExistingName 情境 2：改名撞既有規則 → 哨兵錯誤。
func TestAlertRuleUpdateToExistingName(t *testing.T) {
	svc, db := setupAlertRuleDB(t)

	first, err := svc.Create(newRuleReq("規則甲"))
	if err != nil {
		t.Fatalf("建立規則甲: %v", err)
	}
	second, err := svc.Create(newRuleReq("規則乙"))
	if err != nil {
		t.Fatalf("建立規則乙: %v", err)
	}

	req := newRuleReq("規則甲") // 把乙改名成甲
	_, err = svc.Update(second.ID, req)
	if !errors.Is(err, ErrAlertRuleNameExists) {
		t.Fatalf("改名撞既有規則應回 ErrAlertRuleNameExists，得到 %v", err)
	}
	assertNoDBDetail(t, err)

	// 失敗的改名不得留下半套狀態
	var reloaded model.AlertRule
	if err := db.First(&reloaded, second.ID).Error; err != nil {
		t.Fatalf("重讀規則乙: %v", err)
	}
	if reloaded.Name != "規則乙" {
		t.Fatalf("撞名後名稱 = %q, want 規則乙（不應被改動）", reloaded.Name)
	}
	if first.Name != "規則甲" {
		t.Fatalf("對照規則甲名稱被動到: %q", first.Name)
	}
}

// TestAlertRuleUpdateKeepsOwnName 情境 3：改成自己原本的名字**不算**撞名。
//
// 這格最容易漏：漏了會讓「編輯其他欄位但不改名」——最常見的一種編輯——
// 也被 400 擋住，等於功能整個不能用。
func TestAlertRuleUpdateKeepsOwnName(t *testing.T) {
	svc, db := setupAlertRuleDB(t)

	rule, err := svc.Create(newRuleReq("不改名的規則"))
	if err != nil {
		t.Fatalf("建立: %v", err)
	}
	// 對照組：庫裡另有一條別的規則，確保「同名列存在」這件事本身不是通過的原因
	if _, err := svc.Create(newRuleReq("另一條規則")); err != nil {
		t.Fatalf("建立對照規則: %v", err)
	}

	req := &AlertRuleRequest{Name: "不改名的規則", Pattern: `\bmkfs`, Severity: "low"}
	updated, err := svc.Update(rule.ID, req)
	if err != nil {
		t.Fatalf("名稱不變的更新不應被當成撞名: %v", err)
	}
	if updated == nil {
		t.Fatal("更新成功卻回 nil 規則")
	}

	var reloaded model.AlertRule
	if err := db.First(&reloaded, rule.ID).Error; err != nil {
		t.Fatalf("重讀: %v", err)
	}
	if reloaded.Name != "不改名的規則" || reloaded.Pattern != `\bmkfs` || reloaded.Severity != "low" {
		t.Fatalf("其他欄位未寫入: %+v", reloaded)
	}
}

// assertNoDBDetail 哨兵錯誤不得挾帶資料庫層細節（表名／索引名／SQL／驅動碼）。
// service 的回傳值是 handler 唯一的資訊來源，這裡守住等於守住 API 回應。
func assertNoDBDetail(t *testing.T, err error) {
	t.Helper()
	msg := strings.ToLower(err.Error())
	for _, leak := range []string{
		"alert_rules", "uniq_alert_rules_name", "unique", "constraint",
		"insert", "update", "sql", "23505", "duplicate",
	} {
		if strings.Contains(msg, leak) {
			t.Errorf("錯誤訊息外洩資料庫層細節 %q: %q", leak, err.Error())
		}
	}
}
