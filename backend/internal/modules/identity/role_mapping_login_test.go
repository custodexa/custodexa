package identity

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 目錄途徑的登入重算：命中升權、移出降權並推進世代、純追加不推進、
// 認證脈絡帶推進後的世代，以及兩種跳過的處置。
//
// 全部走真 sqlite ＋ 真登入流程——重算的每一件事（鎖、交易、投影更新、
// 世代推進、留痕）都在寫入路徑上，以替身取代任何一環都會讓斷言失去意義。

const roleMappingTestSecret = "role-mapping-test-secret-value"

// roleMappingInnerGroup 受映射群組的辨識名稱（與開發靶機同值，便於對照）
const roleMappingInnerGroup = "cn=inner,ou=groups,dc=example,dc=org"

// ── SQL 語句記錄器 ─────────────────────────────────────────────────────
//
// **為什麼不用 sqlmock 的期望集合表達「沒有多出語句」**：
// `ExpectationsWereMet` 只回答「宣告過的期望有沒有被滿足」，對**未宣告的
// 呼叫**一律沉默——多出的呼叫只在其驅動錯誤被上層上拋時才間接讓測試紅，
// 而登入路徑上存在把查詢錯誤吞掉後續行的位置，於是「零額外語句」這種
// 命題用它寫出來會恆綠。改為在連線池層記錄**實際執行過的每一句**，
// 斷言直接落在計數上。
//
// 攔在 gorm.ConnPool 而不是 gorm logger：交易的 BEGIN／COMMIT 不經過
// logger，而「有沒有開交易」正是這裡要證的事之一。

// recordedStmt 一句實際執行過的語句；txID 為 0 表示不在交易內。
type recordedStmt struct {
	sql  string
	txID int
}

// sqlRecorder 記錄型連線池：轉發給真 *sql.DB，順手記下語句與交易歸屬。
type sqlRecorder struct {
	mu    sync.Mutex
	base  *sql.DB
	stmts []recordedStmt
	txSeq int
}

func (r *sqlRecorder) record(txID int, query string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stmts = append(r.stmts, recordedStmt{sql: query, txID: txID})
}

// reset 清空記錄：測試的觀察窗自被測動作起算，不含環境架設。
func (r *sqlRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stmts = nil
	r.txSeq = 0
}

func (r *sqlRecorder) snapshot() []recordedStmt {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedStmt, len(r.stmts))
	copy(out, r.stmts)
	return out
}

func (r *sqlRecorder) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	r.record(0, query)
	return r.base.PrepareContext(ctx, query)
}

func (r *sqlRecorder) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	r.record(0, query)
	return r.base.ExecContext(ctx, query, args...)
}

func (r *sqlRecorder) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	r.record(0, query)
	return r.base.QueryContext(ctx, query, args...)
}

func (r *sqlRecorder) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	r.record(0, query)
	return r.base.QueryRowContext(ctx, query, args...)
}

// BeginTx gorm.ConnPoolBeginner：交易本身就是一筆記錄（BEGIN 記在自己的交易編號下）。
func (r *sqlRecorder) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	tx, err := r.base.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.txSeq++
	id := r.txSeq
	r.mu.Unlock()
	r.record(id, "BEGIN")
	return &recordedTx{rec: r, id: id, tx: tx}, nil
}

// GetDBConn gorm.GetDBConnector：讓 db.DB() 仍取得得到底層連線池。
func (r *sqlRecorder) GetDBConn() (*sql.DB, error) { return r.base, nil }

// recordedTx 交易內的記錄型連線池。
type recordedTx struct {
	rec *sqlRecorder
	id  int
	tx  *sql.Tx
}

func (t *recordedTx) PrepareContext(ctx context.Context, query string) (*sql.Stmt, error) {
	t.rec.record(t.id, query)
	return t.tx.PrepareContext(ctx, query)
}

func (t *recordedTx) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	t.rec.record(t.id, query)
	return t.tx.ExecContext(ctx, query, args...)
}

func (t *recordedTx) QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	t.rec.record(t.id, query)
	return t.tx.QueryContext(ctx, query, args...)
}

func (t *recordedTx) QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	t.rec.record(t.id, query)
	return t.tx.QueryRowContext(ctx, query, args...)
}

func (t *recordedTx) StmtContext(ctx context.Context, stmt *sql.Stmt) *sql.Stmt {
	return t.tx.StmtContext(ctx, stmt)
}

func (t *recordedTx) Commit() error   { return t.tx.Commit() }
func (t *recordedTx) Rollback() error { return t.tx.Rollback() }

// stmtsTouching 記錄中提及指定資料表的語句。
//
// 表名連同界定符一起比對，否則 user_roles 會誤配 user_role_mappings；
// 兩種界定符都收（sqlite 用反引號、postgres 用雙引號）。
func stmtsTouching(stmts []recordedStmt, table string) []recordedStmt {
	quoted := []string{"`" + table + "`", `"` + table + `"`}
	var out []recordedStmt
	for _, s := range stmts {
		for _, q := range quoted {
			if strings.Contains(s.sql, q) {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// txCount 記錄中開過的交易筆數。
func txCount(stmts []recordedStmt) int {
	seen := map[int]bool{}
	for _, s := range stmts {
		if s.txID != 0 {
			seen[s.txID] = true
		}
	}
	return len(seen)
}

// txIDsTouching 提及指定資料表的語句所在的交易編號集合（0 不計）。
func txIDsTouching(stmts []recordedStmt, tables ...string) map[int]bool {
	out := map[int]bool{}
	for _, table := range tables {
		for _, s := range stmtsTouching(stmts, table) {
			if s.txID != 0 {
				out[s.txID] = true
			}
		}
	}
	return out
}

// dumpStmts 供失敗訊息與計數輸出使用的可讀形態。
func dumpStmts(stmts []recordedStmt) string {
	var b strings.Builder
	for i, s := range stmts {
		tx := "-"
		if s.txID != 0 {
			tx = fmt.Sprintf("%d", s.txID)
		}
		fmt.Fprintf(&b, "\n  %02d tx=%s %s", i+1, tx, collapseSQL(s.sql))
	}
	return b.String()
}

func collapseSQL(q string) string {
	one := strings.Join(strings.Fields(q), " ")
	if len(one) > 120 {
		return one[:120] + "…"
	}
	return one
}

// setupRoleMappingEnv 真 sqlite 換入 database.DB，接上映射審計落地面。
func setupRoleMappingEnv(t *testing.T) (*AuthService, *policy.SecurityPolicyService, *gorm.DB) {
	t.Helper()
	authService, policies, db, _ := setupRoleMappingEnvRecording(t)
	return authService, policies, db
}

// setupRoleMappingEnvRecording 同上，另交出連線池層的語句記錄器。
func setupRoleMappingEnvRecording(t *testing.T) (
	*AuthService, *policy.SecurityPolicyService, *gorm.DB, *sqlRecorder,
) {
	t.Helper()
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫
	base, err := sql.Open(sqlite.DriverName, ":memory:")
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	base.SetMaxOpenConns(1)
	t.Cleanup(func() { base.Close() })
	rec := &sqlRecorder{base: base}
	db, err := gorm.Open(&sqlite.Dialector{Conn: rec}, &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("gorm: %v", err)
	}
	// **UserRole 必須排在 User 與 Role 之後**：GORM 對關聯表的處理會蓋掉排在
	// 它之前的關聯 model 宣告，放錯位置建出的關聯表會少一欄，而編譯與 vet
	// 都看不出來
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.UserRole{},
		&model.RefreshToken{}, &model.AuditLog{}, &model.SecurityPolicy{},
		&model.PasswordHistory{}, &model.GroupRoleMapping{}, &model.UserRoleMapping{},
		&model.LDAPDirectory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, name := range []string{model.RoleUser, model.RoleAuditor, model.RoleAdmin} {
		if err := db.Create(&model.Role{Name: name}).Error; err != nil {
			t.Fatalf("seed role %s: %v", name, err)
		}
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	authService := NewAuthService(roleMappingTestSecret, 15*time.Minute)
	policies := policy.NewSecurityPolicyService(db)
	authService.SetSecurityPolicies(policies)
	authService.SetTransmissionPolicy(policy.NewTransmissionPolicyService(policies, nil))
	authService.SetRoleMappingAuditSink(audit.NewTxSink())
	return authService, policies, db, rec
}

// roleMappingDirectoryResolver 真撥號快照 ＋ 只替身「對外撥號」那一環。
//
// 未設群組屬性名的目錄列走的是快照建構本身：規則表計數就發生在那裡，
// 以替身 resolver 直接餵旗標會讓那一句永遠不被執行，斷言也就驗不到它。
// 唯一替身掉的是認證器工廠——真認證器會去撥網路。
func roleMappingDirectoryResolver(t *testing.T, db *gorm.DB, username string) LDAPLoginResolver {
	t.Helper()
	dirSvc := NewLDAPDirectoryService(db, aesColumnCodec(t, kmTestKey(0x42)), audit.NewTxSink())
	dirSvc.SetTransmissionPolicy(ldapAllowAllGate{})
	enc, err := dirSvc.encryptBindPassword(context.Background(), "s3cret-bind")
	if err != nil {
		t.Fatalf("加密 bind 密碼: %v", err)
	}
	// AttrGroup 留空＝這兩格要驗的情境（未設群組屬性名）
	if err := db.Create(ldapCompleteRow(enc)).Error; err != nil {
		t.Fatalf("插目錄設定列: %v", err)
	}
	return newLDAPLoginResolverWith(dirSvc, func(LDAPDialSnapshot) LDAPAuthenticator {
		return &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: username}}
	})
}

// roleMappingUser 建一個目錄供應的帳號並綁基本角色（來源＝管理者指派）。
func roleMappingUser(t *testing.T, db *gorm.DB, username string) *model.User {
	t.Helper()
	user := &model.User{
		Username:           username,
		Password:           "irrelevant",
		Active:             true,
		IsLDAP:             true,
		ExternalCredential: true,
		ProvisioningOrigin: model.AuthSourceLDAP,
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("建帳號: %v", err)
	}
	if err := model.AssignUserRole(db, user.ID, roleMappingRoleID(t, db, model.RoleUser),
		model.RoleOriginLDAP); err != nil {
		t.Fatalf("綁基本角色: %v", err)
	}
	return user
}

func roleMappingRoleID(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	var role model.Role
	if err := db.Where("name = ?", name).First(&role).Error; err != nil {
		t.Fatalf("查角色 %s: %v", name, err)
	}
	return role.ID
}

// roleMappingRule 建一條啟用中的目錄映射規則。
func roleMappingRule(t *testing.T, db *gorm.DB, directoryID uint, matchValue, roleName string) {
	t.Helper()
	dir := directoryID
	rule := &model.GroupRoleMapping{
		LDAPDirectoryID: &dir,
		MatchValue:      matchValue,
		RoleID:          roleMappingRoleID(t, db, roleName),
		Enabled:         true,
		CreatedBy:       1,
	}
	if err := db.Create(rule).Error; err != nil {
		t.Fatalf("建映射規則: %v", err)
	}
}

// mappingResolver 帶群組設定的登入解析器替身。
func mappingResolver(directoryID uint, groupAttr string, info *LDAPUserInfo) LDAPLoginResolver {
	return func() LDAPLoginResolution {
		return LDAPLoginResolution{
			State:       LDAPLoginReady,
			Auth:        &fakeLDAPAuthenticator{info: info},
			DirectoryID: directoryID,
			GroupAttr:   groupAttr,
		}
	}
}

// ldapInfoWithGroups 認證結果替身：已取得群組（可為空集合）。
func ldapInfoWithGroups(username string, groups ...string) *LDAPUserInfo {
	return &LDAPUserInfo{Username: username, Groups: groups, GroupsKnown: true}
}

// effectiveRoles 帳號現行的有效角色名（依角色名排序由 DB 給出）。
func effectiveRoles(t *testing.T, db *gorm.DB, userID uint) []string {
	t.Helper()
	var names []string
	if err := db.Table("user_roles").
		Select("roles.name").
		Joins("JOIN roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Order("roles.name").
		Pluck("roles.name", &names).Error; err != nil {
		t.Fatalf("讀有效角色: %v", err)
	}
	return names
}

func hasRole(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// credentialEpochOf 現行憑證世代。
func credentialEpochOf(t *testing.T, db *gorm.DB, userID uint) int {
	t.Helper()
	var user model.User
	if err := db.Select("credential_epoch").First(&user, userID).Error; err != nil {
		t.Fatalf("讀憑證世代: %v", err)
	}
	return user.CredentialEpoch
}

// roleMappingAuditRows 取指定機器碼的映射審計列。
func roleMappingAuditRows(t *testing.T, db *gorm.DB, code string) []model.AuditLog {
	t.Helper()
	var rows []model.AuditLog
	if err := db.Where("error_msg = ?", code).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀審計列: %v", err)
	}
	return rows
}

// ── 3.1 未設群組屬性名的兩格 ───────────────────────────────────────────

// TestLDAPGroupAttrUnsetNoRuleShortCircuits 未設屬性名且無啟用規則＝完全短路。
//
// **斷言對象是實際執行過的語句計數**（連線池層記錄，見 sqlRecorder 的註解）：
// 映射不得開任何一次交易、不得寫任何一筆審計、不得碰事實表；規則表至多被
// 問一次，而那一次只能是索引計數。這一格就是「未啟用映射的部署只多一次
// 索引計數」這句話的機器形態。
//
// 路徑走真撥號快照：規則表那一次計數發生在快照建構期，以替身 resolver
// 直接餵旗標的話它根本不會被執行，斷言就落在空處。
//
// 審計落地面刻意**接上**：短路被移除時程式會走到留痕跳過，那會開一次交易
// 並寫一筆審計——不接落地面反而讓這兩條斷言失去辨識力。
func TestLDAPGroupAttrUnsetNoRuleShortCircuits(t *testing.T) {
	authService, _, db, rec := setupRoleMappingEnvRecording(t)
	roleMappingUser(t, db, "testldap")
	// 該來源無任何映射規則
	authService.SetLDAPResolver(roleMappingDirectoryResolver(t, db, "testldap"))

	rec.reset()
	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "ldappass123"})
	if err != nil {
		t.Fatalf("登入不應失敗: %v", err)
	}
	if resp == nil || resp.Token == "" {
		t.Fatal("應核發正式權杖")
	}

	stmts := rec.snapshot()
	t.Logf("語句計數：總計 %d 句、交易 %d 筆、規則表 %d 句、事實表 %d 句、審計表 %d 句%s",
		len(stmts), txCount(stmts),
		len(stmtsTouching(stmts, "group_role_mappings")),
		len(stmtsTouching(stmts, "user_role_mappings")),
		len(stmtsTouching(stmts, "audit_logs")),
		dumpStmts(stmts))

	// 交易：映射一筆都不得開（登入本身的兩筆＝更新登入狀態、發放刷新憑證）
	if got := txIDsTouching(stmts, "group_role_mappings", "user_role_mappings", "audit_logs"); len(got) != 0 {
		t.Errorf("映射相關交易 = %d 筆, want 0（短路不得開交易）%s", len(got), dumpStmts(stmts))
	}
	if got := txCount(stmts); got != roleMappingLoginBaselineTx {
		t.Errorf("交易筆數 = %d, want %d（登入本身的兩筆；多出的即映射開的）%s",
			got, roleMappingLoginBaselineTx, dumpStmts(stmts))
	}
	// 審計寫入零
	if got := stmtsTouching(stmts, "audit_logs"); len(got) != 0 {
		t.Errorf("審計語句 = %d 句, want 0（短路不得留痕）%s", len(got), dumpStmts(stmts))
	}
	// 事實表零
	if got := stmtsTouching(stmts, "user_role_mappings"); len(got) != 0 {
		t.Errorf("映射事實表語句 = %d 句, want 0%s", len(got), dumpStmts(stmts))
	}
	// 規則表至多一句，且那一句是計數
	rules := stmtsTouching(stmts, "group_role_mappings")
	if len(rules) > 1 {
		t.Errorf("規則表語句 = %d 句, want ≤ 1%s", len(rules), dumpStmts(stmts))
	}
	for _, s := range rules {
		if !strings.Contains(strings.ToLower(s.sql), "count(") {
			t.Errorf("規則表語句非索引計數: %s", collapseSQL(s.sql))
		}
		if s.txID != 0 {
			t.Errorf("規則表計數落在交易內（tx=%d）: %s", s.txID, collapseSQL(s.sql))
		}
	}
}

// roleMappingLoginBaselineTx 一次成功登入本身開的交易筆數（更新登入狀態、
// 發放刷新憑證）。映射若開了交易，總數就會超過這個值。
const roleMappingLoginBaselineTx = 2

// TestLDAPGroupAttrUnsetWithRuleWritesSkipEvent 未設屬性名但有啟用規則＝留痕跳過。
//
// 沒有這一筆，這個部署會永遠零命中而沒有任何訊號：管理者看到規則列在頁上、
// 狀態是啟用，卻沒有一個人拿到角色。角色列一列都不能動——它只是留痕。
func TestLDAPGroupAttrUnsetWithRuleWritesSkipEvent(t *testing.T) {
	authService, _, db, rec := setupRoleMappingEnvRecording(t)
	user := roleMappingUser(t, db, "testldap")
	// 同一份目錄設定列（屬性名未設），差別只在這一格有啟用中的規則
	authService.SetLDAPResolver(roleMappingDirectoryResolver(t, db, "testldap"))
	roleMappingRule(t, db, 1, roleMappingInnerGroup, model.RoleAuditor)

	rec.reset()
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("跳過事件不得讓登入失敗: %v", err)
	}

	stmts := rec.snapshot()
	t.Logf("語句計數：總計 %d 句、交易 %d 筆、規則表 %d 句、事實表 %d 句、審計表 %d 句%s",
		len(stmts), txCount(stmts),
		len(stmtsTouching(stmts, "group_role_mappings")),
		len(stmtsTouching(stmts, "user_role_mappings")),
		len(stmtsTouching(stmts, "audit_logs")),
		dumpStmts(stmts))

	// 規則表仍只被問一次（快照期的計數），留痕跳過不需要再讀規則
	rules := stmtsTouching(stmts, "group_role_mappings")
	if len(rules) != 1 {
		t.Errorf("規則表語句 = %d 句, want 1（快照期的索引計數）%s", len(rules), dumpStmts(stmts))
	}
	for _, s := range rules {
		if !strings.Contains(strings.ToLower(s.sql), "count(") {
			t.Errorf("規則表語句非索引計數: %s", collapseSQL(s.sql))
		}
	}
	// 事實表一句都不碰：跳過只留痕，不動任何一列
	if got := stmtsTouching(stmts, "user_role_mappings"); len(got) != 0 {
		t.Errorf("映射事實表語句 = %d 句, want 0%s", len(got), dumpStmts(stmts))
	}
	// 留痕本身是一次交易內的一筆寫入
	if got := len(txIDsTouching(stmts, "audit_logs")); got != 1 {
		t.Errorf("含審計寫入的交易 = %d 筆, want 1%s", got, dumpStmts(stmts))
	}

	rows := roleMappingAuditRows(t, db, RoleMappingSkipSourceAttrUnset)
	if len(rows) != 1 {
		t.Fatalf("跳過事件筆數 = %d, want 1", len(rows))
	}
	if rows[0].UserID != user.ID {
		t.Errorf("審計列的使用者識別 = %d, want %d（記目標而非登入者）", rows[0].UserID, user.ID)
	}
	if got := effectiveRoles(t, db, user.ID); len(got) != 1 || got[0] != model.RoleUser {
		t.Errorf("角色集 = %v, want 僅基本角色（跳過不得動任何一列）", got)
	}
	var facts int64
	if err := db.Model(&model.UserRoleMapping{}).Count(&facts).Error; err != nil {
		t.Fatalf("數映射事實: %v", err)
	}
	if facts != 0 {
		t.Errorf("映射事實列 = %d, want 0", facts)
	}
}

// ── 3.3 重算四格 ───────────────────────────────────────────────────────

// TestLDAPLoginRecomputesMappedRoles 命中即取得角色，且來源標為映射。
func TestLDAPLoginRecomputesMappedRoles(t *testing.T) {
	authService, _, db := setupRoleMappingEnv(t)
	user := roleMappingUser(t, db, "testldap")
	roleMappingRule(t, db, 1, roleMappingInnerGroup, model.RoleAuditor)
	authService.SetLDAPResolver(mappingResolver(1, "memberOf",
		ldapInfoWithGroups("testldap", roleMappingInnerGroup)))

	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"})
	if err != nil {
		t.Fatalf("登入: %v", err)
	}

	roles := effectiveRoles(t, db, user.ID)
	if !hasRole(roles, model.RoleAuditor) {
		t.Fatalf("角色集 = %v, want 含 %s", roles, model.RoleAuditor)
	}
	// 回應必須反映重算後的角色——重算完不重載，這次登入的人拿到的是舊快照
	if !hasRole(resp.User.Roles, model.RoleAuditor) {
		t.Errorf("登入回應的角色 = %v, want 含 %s（重算後未重載）", resp.User.Roles, model.RoleAuditor)
	}

	var row model.UserRole
	if err := db.Table("user_roles").
		Where("user_id = ? AND role_id = ?", user.ID, roleMappingRoleID(t, db, model.RoleAuditor)).
		First(&row).Error; err != nil {
		t.Fatalf("讀角色列: %v", err)
	}
	if row.Source != model.RoleSourceMapped {
		t.Errorf("來源 = %q, want %q", row.Source, model.RoleSourceMapped)
	}

	var fact model.UserRoleMapping
	if err := db.Where("user_id = ?", user.ID).First(&fact).Error; err != nil {
		t.Fatalf("讀映射事實: %v", err)
	}
	if want := model.RoleMappingChannel(model.RoleMappingChannelKindDirectory, 1); fact.Channel != want {
		t.Errorf("通道 = %q, want %q", fact.Channel, want)
	}
	if rows := roleMappingAuditRows(t, db, RoleMappingEventApplied); len(rows) != 1 {
		t.Errorf("套用事件筆數 = %d, want 1", len(rows))
	}
}

// TestLDAPLoginShrinkBumpsEpoch 移出群組後再次登入＝失去角色、推進世代、撤刷新憑證。
func TestLDAPLoginShrinkBumpsEpoch(t *testing.T) {
	authService, _, db := setupRoleMappingEnv(t)
	user := roleMappingUser(t, db, "testldap")
	roleMappingRule(t, db, 1, roleMappingInnerGroup, model.RoleAuditor)

	// 第一次：在群組裡
	authService.SetLDAPResolver(mappingResolver(1, "memberOf",
		ldapInfoWithGroups("testldap", roleMappingInnerGroup)))
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("第一次登入: %v", err)
	}
	epochAfterGrant := credentialEpochOf(t, db, user.ID)

	// 第二次：已被移出群組（讀得到、集合是空的）
	authService.SetLDAPResolver(mappingResolver(1, "memberOf", ldapInfoWithGroups("testldap")))
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("第二次登入: %v", err)
	}

	if roles := effectiveRoles(t, db, user.ID); hasRole(roles, model.RoleAuditor) {
		t.Errorf("角色集 = %v, want 不含 %s", roles, model.RoleAuditor)
	}
	if got := credentialEpochOf(t, db, user.ID); got <= epochAfterGrant {
		t.Errorf("憑證世代 = %d, want > %d（有列被移除即推進）", got, epochAfterGrant)
	}
	var facts int64
	if err := db.Model(&model.UserRoleMapping{}).Where("user_id = ?", user.ID).Count(&facts).Error; err != nil {
		t.Fatalf("數映射事實: %v", err)
	}
	if facts != 0 {
		t.Errorf("映射事實列 = %d, want 0（不再命中的列要刪）", facts)
	}
}

// TestLDAPLoginAdditiveNoBump 純追加不推進世代——推進只會把人無故踢下線。
func TestLDAPLoginAdditiveNoBump(t *testing.T) {
	authService, _, db := setupRoleMappingEnv(t)
	user := roleMappingUser(t, db, "testldap")
	roleMappingRule(t, db, 1, roleMappingInnerGroup, model.RoleAuditor)
	before := credentialEpochOf(t, db, user.ID)

	authService.SetLDAPResolver(mappingResolver(1, "memberOf",
		ldapInfoWithGroups("testldap", roleMappingInnerGroup)))
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("登入: %v", err)
	}

	if !hasRole(effectiveRoles(t, db, user.ID), model.RoleAuditor) {
		t.Fatal("前提不成立：本次登入應確實取得角色，否則本格什麼都沒驗到")
	}
	if got := credentialEpochOf(t, db, user.ID); got != before {
		t.Errorf("憑證世代 = %d, want %d（純追加不推進）", got, before)
	}

	// 同一組群組再登入一次：既無新增也無移除，連審計列都不該多一筆
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("第二次登入: %v", err)
	}
	if rows := roleMappingAuditRows(t, db, RoleMappingEventApplied); len(rows) != 1 {
		t.Errorf("套用事件筆數 = %d, want 1（無變動不寫列）", len(rows))
	}
	if got := credentialEpochOf(t, db, user.ID); got != before {
		t.Errorf("重複登入後憑證世代 = %d, want %d", got, before)
	}
}

// TestLDAPLoginAuthContextUsesBumpedEpoch 這次核發的權杖帶推進後的世代。
//
// 帶舊世代的話，降權的那一次登入自己就會被世代閘拒——每次降權即自我鎖死。
func TestLDAPLoginAuthContextUsesBumpedEpoch(t *testing.T) {
	authService, _, db := setupRoleMappingEnv(t)
	user := roleMappingUser(t, db, "testldap")
	roleMappingRule(t, db, 1, roleMappingInnerGroup, model.RoleAuditor)

	authService.SetLDAPResolver(mappingResolver(1, "memberOf",
		ldapInfoWithGroups("testldap", roleMappingInnerGroup)))
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("第一次登入: %v", err)
	}

	authService.SetLDAPResolver(mappingResolver(1, "memberOf", ldapInfoWithGroups("testldap")))
	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"})
	if err != nil {
		t.Fatalf("降權的那一次登入: %v", err)
	}
	if resp == nil || resp.Token == "" {
		t.Fatal("降權的那一次登入仍應核發權杖")
	}

	epoch := credentialEpochOf(t, db, user.ID)
	claims, err := crypto.NewJWTManager(roleMappingTestSecret, 15*time.Minute).ValidateToken(resp.Token)
	if err != nil {
		t.Fatalf("解析權杖: %v", err)
	}
	if claims.CredEpoch != epoch {
		t.Errorf("權杖世代 = %d, want %d（帶舊世代即自我鎖死）", claims.CredEpoch, epoch)
	}
}

// ── 3.4 多因子強制的正確性 ─────────────────────────────────────────────

// TestMappedAdminTriggersMFAEnrollment 映射賦予管理員角色的那一次登入要被導向註冊。
//
// 判定讀的是同一個記憶體物件：重算後只重讀世代而不重載角色，這次拿到管理員
// 的人不會被要求註冊第二因子——一個提權路徑就這樣繞過了強制政策。
func TestMappedAdminTriggersMFAEnrollment(t *testing.T) {
	authService, policies, db := setupRoleMappingEnv(t)
	if _, err := policies.Update(policy.PolicyMFARequired, policy.MFARequiredAdminOnly, "admin"); err != nil {
		t.Fatalf("設定強制政策: %v", err)
	}
	roleMappingUser(t, db, "testldap")
	roleMappingRule(t, db, 1, roleMappingInnerGroup, model.RoleAdmin)
	authService.SetLDAPResolver(mappingResolver(1, "memberOf",
		ldapInfoWithGroups("testldap", roleMappingInnerGroup)))

	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"})
	if err != nil {
		t.Fatalf("登入: %v", err)
	}
	if !resp.MFAEnrollmentRequired || resp.EnrollmentToken == "" {
		t.Errorf("映射賦予管理員的登入 = %+v, want 導向第二因子註冊", resp)
	}
}

// TestMappedDemotionSkipsMFAEnrollment 反向：這次被降權的人不該再被要求註冊。
func TestMappedDemotionSkipsMFAEnrollment(t *testing.T) {
	authService, policies, db := setupRoleMappingEnv(t)
	if _, err := policies.Update(policy.PolicyMFARequired, policy.MFARequiredAdminOnly, "admin"); err != nil {
		t.Fatalf("設定強制政策: %v", err)
	}
	user := roleMappingUser(t, db, "testldap")
	roleMappingRule(t, db, 1, roleMappingInnerGroup, model.RoleAdmin)

	// 先讓他因映射取得管理員（前提：上一格已釘住這一步會導向註冊）
	authService.SetLDAPResolver(mappingResolver(1, "memberOf",
		ldapInfoWithGroups("testldap", roleMappingInnerGroup)))
	if _, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"}); err != nil {
		t.Fatalf("第一次登入: %v", err)
	}
	if !hasRole(effectiveRoles(t, db, user.ID), model.RoleAdmin) {
		t.Fatal("前提不成立：第一次登入應取得管理員角色")
	}

	// 移出群組後再登入：本次判定必須讀到重載後的角色集
	authService.SetLDAPResolver(mappingResolver(1, "memberOf", ldapInfoWithGroups("testldap")))
	resp, err := authService.Login(&LoginRequest{Username: "testldap", Password: "pass"})
	if err != nil {
		t.Fatalf("第二次登入: %v", err)
	}
	if resp.MFAEnrollmentRequired {
		t.Errorf("被降權者仍被要求註冊第二因子: %+v", resp)
	}
	if resp.Token == "" {
		t.Error("降權後應直接核發正式權杖")
	}
}
