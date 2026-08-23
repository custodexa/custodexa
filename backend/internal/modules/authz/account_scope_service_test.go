package authz

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 授權帳號維度解析器的語義鎖。
//
// 為何用真 SQLite 而非 sqlmock：本解析器的正確性幾乎全在 SQL 條件本身
// （四路徑主體聯集、節點含子樹客體、時效窗），sqlmock 只會複誦我寫的 SQL 字串，
// 對「群組授權有沒有真的被撈到」零證明力。
//
// `:memory:` 連線池釘為 1（ff51836 教訓）：多連線各自拿到獨立的空記憶體庫，
// 症狀是單獨跑綠、整包跑紅。
func setupScopeEnv(t *testing.T) (*AssetAuthorizationService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	// AuditLog 必備：Asset 與 AssetAccount 的寫入掛審計 hook（asset_audit.go／
	// asset_account_audit.go），缺表會讓 seed 直接失敗
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{},
		&model.Asset{}, &model.AssetGroup{}, &model.AssetNode{},
		&model.AssetAccount{}, &model.AssetAuthorization{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewAssetAuthorizationService(db), db
}

// seedScopeFixture 資產 1 帶 root/app/deploy 三帳號；user 1 為一般使用者、
// 隸屬群組 1。回傳 assetID
func seedScopeFixture(t *testing.T, db *gorm.DB) uint {
	t.Helper()
	if err := db.Create(&model.User{Username: "alice", Active: true}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := db.Create(&model.UserGroup{Name: "ops"}).Error; err != nil {
		t.Fatalf("seed group: %v", err)
	}
	// user_group_members 是 many2many join 表（無獨立 model），沿既有測試慣例直插
	if err := db.Exec("INSERT INTO user_group_members (user_group_id, user_id) VALUES (1, 1)").Error; err != nil {
		t.Fatalf("seed member: %v", err)
	}
	asset := model.Asset{Name: "box", Protocol: model.ProtocolSSH, Host: "h", Port: 22, CreatedBy: 1, Active: true}
	if err := db.Create(&asset).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	for _, name := range []string{"root", "app", "deploy"} {
		acc := model.AssetAccount{AssetID: asset.ID, Username: name, IsDefault: name == "root"}
		if err := db.Create(&acc).Error; err != nil {
			t.Fatalf("seed account: %v", err)
		}
	}
	return asset.ID
}

// grantWithScope 建一筆 connect 授權（主體/客體/時窗/帳號範圍可控）
func grantWithScope(t *testing.T, db *gorm.DB, auth model.AssetAuthorization) {
	t.Helper()
	auth.Permission = model.PermissionConnect
	auth.GrantedBy = 1
	if auth.Source == "" {
		auth.Source = model.AuthorizationSourceManual
	}
	if err := db.Create(&auth).Error; err != nil {
		t.Fatalf("grant: %v", err)
	}
}

func userCtx() context.Context {
	return context.WithValue(context.Background(), "role", model.RoleUser)
} //nolint:staticcheck
func adminRoleCtx() context.Context {
	return context.WithValue(context.Background(), "role", model.RoleAdmin)
} //nolint:staticcheck

// TestAccountScope_DefaultAllIsExistingBehaviour 既有授權行為零變化：
// migration 把既有列回填 @ALL，@ALL 展開為資產全部帳號——與多帳號維度
// 引入前「有連線權即可用任一憑證」完全一致。**本測試是回歸基準**：
// 它紅了就代表升級改變了既有使用者的可連帳號集合
func TestAccountScope_DefaultAllIsExistingBehaviour(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{model.AccountScopeAll}})

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !scope.Matched || !scope.All {
		t.Fatalf("回填 @ALL 的既有授權應為全帳號: %+v", scope)
	}
	for _, name := range []string{"root", "app", "deploy"} {
		if !scope.Allows(name) {
			t.Fatalf("@ALL 應涵蓋帳號 %q", name)
		}
	}
}

// TestAccountScope_NilScopeTreatedAsAll 未經 migration 的空值（NULL）亦視為
// @ALL——回歸安全方向：漏設此欄若被讀成「零帳號可用」會靜默切斷連線
func TestAccountScope_NilScopeTreatedAsAll(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{UserID: uptrScope(1), AssetID: &assetID})
	// 直接把欄位打回 NULL，模擬 migration 未跑過的舊列
	if err := db.Exec(`UPDATE asset_authorizations SET accounts = NULL`).Error; err != nil {
		t.Fatalf("null out: %v", err)
	}

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !scope.Matched || !scope.All || !scope.Allows("root") {
		t.Fatalf("NULL accounts 應等同 @ALL: %+v", scope)
	}
}

// TestAccountScope_NamedOnly 個別指定：只列出的 username 在範圍內
func TestAccountScope_NamedOnly(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{"app"}})

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.All {
		t.Fatal("具名範圍不應為 All")
	}
	if !scope.Allows("app") {
		t.Fatal("app 應在範圍內")
	}
	if scope.Allows("root") || scope.Allows("deploy") {
		t.Fatalf("未指定的帳號不應在範圍內: %+v", scope)
	}
}

// TestAccountScope_UnionTakesWider 聯集取寬（「聯集語義」）：
// 個人授權 ["app"] ＋ 群組授權 @ALL ＝ 全部帳號。
// 授權模型純加法無 deny，帳號維度採交集會憑空造出 deny 語義
func TestAccountScope_UnionTakesWider(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{"app"}})
	grantWithScope(t, db, model.AssetAuthorization{
		UserGroupID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{model.AccountScopeAll}})

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !scope.All || !scope.Allows("root") {
		t.Fatalf("個人具名 ∪ 群組 @ALL 應為全帳號: %+v", scope)
	}
}

// TestAccountScope_UnionOfNamed 兩筆具名授權的聯集
func TestAccountScope_UnionOfNamed(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{"app"}})
	grantWithScope(t, db, model.AssetAuthorization{
		UserGroupID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{"deploy"}})

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.All {
		t.Fatal("兩筆具名不應塌成 All")
	}
	if !scope.Allows("app") || !scope.Allows("deploy") {
		t.Fatalf("聯集應含兩者: %+v", scope)
	}
	if scope.Allows("root") {
		t.Fatalf("root 未被任一授權涵蓋: %+v", scope)
	}
}

// TestAccountScope_GroupInheritance 群組授權的帳號範圍由成員繼承
func TestAccountScope_GroupInheritance(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{
		UserGroupID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{"deploy"}})

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !scope.Matched || !scope.Allows("deploy") || scope.Allows("root") {
		t.Fatalf("群組授權帳號範圍應被成員繼承: %+v", scope)
	}
}

// TestAccountScope_AssetGroupObject 資產群組客體的帳號範圍涵蓋組內資產
func TestAccountScope_AssetGroupObject(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	if err := db.Create(&model.AssetGroup{Name: "prod"}).Error; err != nil {
		t.Fatalf("seed asset group: %v", err)
	}
	if err := db.Create(&model.AssetNode{AssetID: assetID, NodeID: 1}).Error; err != nil {
		t.Fatalf("seed asset node: %v", err)
	}
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetGroupID: uptrScope(1), Accounts: model.AccountScope{"app"}})

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !scope.Matched || !scope.Allows("app") || scope.Allows("root") {
		t.Fatalf("資產群組客體授權的帳號範圍應涵蓋組內資產: %+v", scope)
	}
}

// TestAccountScope_ExpiredTicketExcluded 時效窗過期的 ticket 授權不貢獻帳號範圍
// （到期＝解析不命中，記錄留存供審計）
func TestAccountScope_ExpiredTicketExcluded(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	past := time.Now().Add(-2 * time.Hour)
	expired := time.Now().Add(-1 * time.Hour)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Source: model.AuthorizationSourceTicket,
		DateStart: &past, DateExpired: &expired, Accounts: model.AccountScope{"root"}})

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.Matched {
		t.Fatalf("已過期授權不應命中: %+v", scope)
	}
	if scope.Allows("root") {
		t.Fatal("過期授權不得放行帳號")
	}
}

// TestAccountScope_ActiveTicketContributes 時窗內 ticket 臨時授權貢獻帳號範圍
func TestAccountScope_ActiveTicketContributes(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	start := time.Now().Add(-1 * time.Minute)
	end := time.Now().Add(1 * time.Hour)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Source: model.AuthorizationSourceTicket,
		DateStart: &start, DateExpired: &end, Accounts: model.AccountScope{"root"}})

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !scope.Matched || !scope.Allows("root") {
		t.Fatalf("時窗內臨時授權應貢獻帳號範圍: %+v", scope)
	}
}

// TestAccountScope_ScheduledNotYetActive 未達 date_start 的授權不生效
func TestAccountScope_ScheduledNotYetActive(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	future := time.Now().Add(1 * time.Hour)
	later := time.Now().Add(2 * time.Hour)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Source: model.AuthorizationSourceTicket,
		DateStart: &future, DateExpired: &later, Accounts: model.AccountScope{"root"}})

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.Matched || scope.Allows("root") {
		t.Fatalf("未生效授權不應命中: %+v", scope)
	}
}

// TestAccountScope_AdminFullAccess admin 全量短路（與 CheckPermission 同語義）
func TestAccountScope_AdminFullAccess(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	// 刻意不建任何授權列

	scope, err := svc.EffectiveConnectAccountScope(adminRoleCtx(), 99, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !scope.All || !scope.Allows("root") {
		t.Fatalf("admin 應為全量: %+v", scope)
	}
}

// TestAccountScope_AuditorNotAutoConnect auditor 不因角色取得連線帳號範圍
// （職責分離：稽核者只檢視不連線）——但可視範圍仍短路全量，
// 稽核視圖不被本 change 收窄
func TestAccountScope_AuditorNotAutoConnect(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	auditorCtx := context.WithValue(context.Background(), "role", model.RoleAuditor) //nolint:staticcheck

	connectScope, err := svc.EffectiveConnectAccountScope(auditorCtx, 99, assetID)
	if err != nil {
		t.Fatalf("resolve connect: %v", err)
	}
	if connectScope.Matched || connectScope.Allows("root") {
		t.Fatalf("auditor 不應自動取得連線帳號範圍: %+v", connectScope)
	}

	viewScope, err := svc.EffectiveViewAccountScope(auditorCtx, 99, assetID)
	if err != nil {
		t.Fatalf("resolve view: %v", err)
	}
	if !viewScope.All {
		t.Fatalf("auditor 的可視帳號範圍應維持全量: %+v", viewScope)
	}
}

// TestAccountScope_NoGrantFailClose 零命中授權列＝拒絕（fail-close）
func TestAccountScope_NoGrantFailClose(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)

	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.Matched || scope.Allows("root") || scope.Allows("") {
		t.Fatalf("無授權應一律拒絕: %+v", scope)
	}
}

// TestAuthorizeConnectAccount_K8sExempt k8s 走系統預設帳號語義，不經 per-account
// 判定——否則 k8s 資產在無帳號授權時會連不上，而它根本沒有選帳號的概念
func TestAuthorizeConnectAccount_K8sExempt(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)

	if err := svc.AuthorizeConnectAccount(userCtx(), 1, assetID, model.ProtocolK8s, "root"); err != nil {
		t.Fatalf("k8s 應豁免 per-account 判定: %v", err)
	}
	// 對照：同樣無授權的 SSH 必須被擋
	if err := svc.AuthorizeConnectAccount(userCtx(), 1, assetID, model.ProtocolSSH, "root"); err == nil {
		t.Fatal("SSH 無授權應被擋")
	}
}

// TestAuthorizeConnectAccount_RevocationTakesEffectImmediately 撤授權即時生效：
// 解析器一律 DB 現查，撤銷（軟刪）後同一使用者立刻失去帳號範圍。
// 這是兌換點複查能歸零撤權殘窗的底層保證
func TestAuthorizeConnectAccount_RevocationTakesEffectImmediately(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{"root"}})

	if err := svc.AuthorizeConnectAccount(userCtx(), 1, assetID, model.ProtocolSSH, "root"); err != nil {
		t.Fatalf("撤銷前應放行: %v", err)
	}
	if err := db.Where("user_id = ?", 1).Delete(&model.AssetAuthorization{}).Error; err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := svc.AuthorizeConnectAccount(userCtx(), 1, assetID, model.ProtocolSSH, "root"); err == nil {
		t.Fatal("撤銷後應立即拒絕（DB 現查，無快取殘窗）")
	}
}

// TestAuthorizeConnectAccount_ScopeNarrowingTakesEffect 帳號範圍收緊即時生效
// （「帳號範圍收緊即時生效」的服務層基礎）
func TestAuthorizeConnectAccount_ScopeNarrowingTakesEffect(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{model.AccountScopeAll}})

	if err := svc.AuthorizeConnectAccount(userCtx(), 1, assetID, model.ProtocolSSH, "root"); err != nil {
		t.Fatalf("@ALL 應放行 root: %v", err)
	}
	if _, err := svc.UpdateAccountScope(context.Background(), 1, &[]string{"app"}); err != nil {
		t.Fatalf("收緊範圍: %v", err)
	}
	if err := svc.AuthorizeConnectAccount(userCtx(), 1, assetID, model.ProtocolSSH, "root"); err == nil {
		t.Fatal("收緊為 [app] 後 root 應被拒")
	}
	if err := svc.AuthorizeConnectAccount(userCtx(), 1, assetID, model.ProtocolSSH, "app"); err != nil {
		t.Fatalf("app 應仍放行: %v", err)
	}
}

// TestUpdateAccountScope_TicketImmutable 臨時授權的帳號範圍不可由授權管理入口改
func TestUpdateAccountScope_TicketImmutable(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	start := time.Now().Add(-time.Minute)
	end := time.Now().Add(time.Hour)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Source: model.AuthorizationSourceTicket,
		DateStart: &start, DateExpired: &end, Accounts: model.AccountScope{"app"}})

	if _, err := svc.UpdateAccountScope(context.Background(), 1, &[]string{model.AccountScopeAll}); err == nil {
		t.Fatal("ticket 列的帳號範圍不應可改")
	}
}

// TestNormalizeAccountScope_Semantics 正規化語義鎖：去重、排序、@ALL 塌縮、
// 欄位省略＝@ALL、顯式空清單拒收、全空白拒收、元素上限。
//
// **三種輸入形態的分別是本測試的重點**（共同指認）：
// 舊版簽名收 `[]string`，使「欄位省略」與「顯式 `[]`」在伺服端不可區分，
// 兩者都被正規化成 `@ALL`——管理員送出「收到零個帳號」反而得到「全部帳號」
func TestNormalizeAccountScope_Semantics(t *testing.T) {
	strs := func(v ...string) *[]string { s := v; return &s }
	empty := []string{}
	tooMany := make([]string, MaxAccountScopeEntries+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("u%d", i)
	}

	cases := []struct {
		name    string
		in      *[]string
		want    []string
		wantErr bool
	}{
		{name: "欄位省略（nil）＝未指定＝@ALL", in: nil, want: nil},
		{name: "顯式空清單拒收（不得靜默溢授為 @ALL）", in: &empty, wantErr: true},
		{name: "去重與排序", in: strs("root", "app", "root"), want: []string{"app", "root"}},
		{name: "@ALL 與具名混用塌縮為 @ALL", in: strs("app", "@ALL"), want: []string{"@ALL"}},
		{name: "前後空白修剪", in: strs("  app  "), want: []string{"app"}},
		{name: "全空白項拒收", in: strs("  ", ""), wantErr: true},
		{name: "控制字元拒收", in: strs("ro\not"), wantErr: true},
		{name: "冒號拒收", in: strs("ro:ot"), wantErr: true},
		{name: "@ 前綴保留字拒收（非 @ALL）", in: strs("@SPEC"), wantErr: true},
		{name: "超過元素上限拒收", in: &tooMany, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeGrantAccounts(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("應拒收: got=%v", got)
				}
				if !errors.Is(err, ErrAccountScopeInvalid) {
					t.Fatalf("應為 ErrAccountScopeInvalid: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不應報錯: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("長度不符: got=%v want=%v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("內容不符: got=%v want=%v", got, tc.want)
				}
			}
		})
	}
}

// TestUpdateAccountScope_RequiresExplicitAccounts `PUT .../accounts` 省略欄位
// 一律拒——本端點的唯一職責就是設定範圍，猜錯的方向是溢授
func TestUpdateAccountScope_RequiresExplicitAccounts(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{"app"}})

	if _, err := svc.UpdateAccountScope(context.Background(), 1, nil); !errors.Is(err, ErrAccountScopeRequired) {
		t.Fatalf("省略 accounts 應回 ErrAccountScopeRequired: %v", err)
	}
	// 未被改動：仍為原範圍，未溢授為 @ALL
	var after model.AssetAuthorization
	if err := db.First(&after, 1).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if after.Accounts.IsAll() {
		t.Fatalf("拒收後不得留下 @ALL: %+v", after.Accounts)
	}
}

// TestUpdateAccountScope_EmptyArrayRejected 顯式空陣列拒收，且**不改動既有範圍**
// ——本 change 唯一「操作失誤即溢授」路徑的回歸守衛
func TestUpdateAccountScope_EmptyArrayRejected(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{
		UserID: uptrScope(1), AssetID: &assetID, Accounts: model.AccountScope{"app"}})

	if _, err := svc.UpdateAccountScope(context.Background(), 1, &[]string{}); !errors.Is(err, ErrAccountScopeInvalid) {
		t.Fatalf("空陣列應回 ErrAccountScopeInvalid: %v", err)
	}
	scope, err := svc.EffectiveConnectAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.All || !scope.Allows("app") || scope.Allows("root") {
		t.Fatalf("拒收後範圍不得變動（尤其不得變成全帳號）: %+v", scope)
	}
}

// TestGrantAccountScope_EmptyArrayRejected 建立授權路徑同樣拒收顯式空陣列，
// 但省略欄位（nil）維持 @ALL——舊前端與既有腳本不壞
func TestGrantAccountScope_EmptyArrayRejected(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)

	if _, err := svc.Grant(context.Background(), GrantSpec{
		UserID: uptrScope(1), AssetID: &assetID,
		Permission: model.PermissionConnect, GrantedBy: 1, Accounts: &[]string{},
	}); !errors.Is(err, ErrAccountScopeInvalid) {
		t.Fatalf("建立授權時空陣列應拒收: %v", err)
	}

	auth, err := svc.Grant(context.Background(), GrantSpec{
		UserID: uptrScope(1), AssetID: &assetID,
		Permission: model.PermissionConnect, GrantedBy: 1, Accounts: nil,
	})
	if err != nil {
		t.Fatalf("省略 accounts 應成功（@ALL）: %v", err)
	}
	if !auth.Accounts.IsAll() {
		t.Fatalf("省略 accounts 應為 @ALL: %+v", auth.Accounts)
	}
}

// TestAccountScope_ApproverScopeDoesNotGrantAccounts 刻意的不同構：
// `CheckPermission(view)` 有「審核範圍隱含 view」第三來源，帳號範圍解析器沒有。
//
// 理由：該來源是為了讓 approver 看得見待審申請所指的資產，而帳號清單是**憑證
// 身分的盤點**（含 privileged 標記）——正是本階段從一般 asset:view 使用者手上
// 收回的偵察面。approver 身分若能換來全資產帳號清單，等於用一個管理角色
// 把剛關上的門重新打開。approver 要用某帳號連線，走正常授權即可
func TestAccountScope_ApproverScopeDoesNotGrantAccounts(t *testing.T) {
	svc, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	if err := db.AutoMigrate(&model.ApproverScope{}); err != nil {
		t.Fatalf("migrate approver scope: %v", err)
	}
	aid := assetID
	uid := uint(1)
	if err := db.Create(&model.ApproverScope{ApproverID: &uid, AssetID: &aid}).Error; err != nil {
		t.Fatalf("seed approver scope: %v", err)
	}

	// 對照：CheckPermission(view) 因第三來源而放行（既有語義，未被本 change 改變）
	visible, err := svc.CheckPermission(userCtx(), 1, assetID, model.PermissionView)
	if err != nil {
		t.Fatalf("CheckPermission: %v", err)
	}
	if !visible {
		t.Fatal("approver 應可視範圍內資產（既有語義）")
	}

	// 帳號範圍：刻意不含該來源 → 空（fail-close），資產可見但帳號不可見
	scope, err := svc.EffectiveViewAccountScope(userCtx(), 1, assetID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if scope.Matched || scope.Allows("root") {
		t.Fatalf("approver 審核範圍不得換來帳號清單: %+v", scope)
	}
}

// TestAccountScope_ValueScanRoundTrip 欄位序列化往返：空值落庫為 ["@ALL"]，
// 使庫內不存在「語義待解讀的 NULL」（稽核直讀該欄即知範圍）
func TestAccountScope_ValueScanRoundTrip(t *testing.T) {
	_, db := setupScopeEnv(t)
	assetID := seedScopeFixture(t, db)
	grantWithScope(t, db, model.AssetAuthorization{UserID: uptrScope(1), AssetID: &assetID})

	var raw string
	if err := db.Raw(`SELECT accounts FROM asset_authorizations WHERE id = 1`).Scan(&raw).Error; err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if raw != `["@ALL"]` {
		t.Fatalf("空範圍應落庫為 [\"@ALL\"]，實得 %q", raw)
	}

	var reloaded model.AssetAuthorization
	if err := db.First(&reloaded, 1).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.Accounts.IsAll() || !reloaded.Accounts.Contains("anything") {
		t.Fatalf("往返後應為 @ALL: %+v", reloaded.Accounts)
	}
}
