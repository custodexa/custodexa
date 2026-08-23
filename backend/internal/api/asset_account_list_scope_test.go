package api

import (
	"context"
	"encoding/json"
	"github.com/custodexa/backend/internal/modules/authz"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/modules/audit"
)

// 帳號列表的有效範圍過濾。
//
// 過濾前，本端點只需 asset:view 就回傳資產的**全部**帳號含 privileged 標記——
// 等於把「這台機器上有哪些特權帳號」公開給只該看到自己那組帳號的人，
// 是攻擊面偵察的現成清單。

func setupAccountListEnv(t *testing.T) (*AssetAccountHandler, *gorm.DB) {
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
	if err := db.AutoMigrate(&model.User{}, &model.UserGroup{}, &model.Asset{}, &model.AssetGroup{},
		&model.AssetNode{}, &model.AssetAccount{}, &model.AssetAuthorization{},
		&model.ApproverScope{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	db.Create(&model.User{Username: "u1", Email: emailPtr("u@x"), Active: true})
	db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "h", Port: 22, CreatedBy: 1, Active: true})
	for _, spec := range []struct {
		name       string
		privileged bool
		isDefault  bool
	}{{"root", true, true}, {"app", false, false}, {"deploy", false, false}} {
		if err := db.Create(&model.AssetAccount{AssetID: 1, Username: spec.name,
			Privileged: spec.privileged, IsDefault: spec.isDefault}).Error; err != nil {
			t.Fatalf("seed account: %v", err)
		}
	}

	codec := aesColumnCodec(t, make([]byte, 32))
	assetSvc, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	authz := authz.NewAssetAuthorizationService(db)
	return NewAssetAccountHandler(asset.NewAssetAccountService(assetSvc, codec, audit.NewTxSink()), authz), db
}

func listAccounts(handler *AssetAccountHandler, role string) (int, []string) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/assets/:id/accounts", func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("role", role)
		handler.List(c)
	})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/1/accounts", nil))

	var resp struct {
		Data []struct {
			Username string `json:"username"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	names := make([]string, 0, len(resp.Data))
	for _, d := range resp.Data {
		names = append(names, d.Username)
	}
	return w.Code, names
}

func grantView(t *testing.T, db *gorm.DB, scope model.AccountScope) {
	t.Helper()
	uid, aid := uint(1), uint(1)
	if err := db.Create(&model.AssetAuthorization{
		UserID: &uid, AssetID: &aid, Permission: model.PermissionConnect, GrantedBy: 1,
		Accounts: scope,
	}).Error; err != nil {
		t.Fatalf("grant: %v", err)
	}
}

// TestAccountListFilteredByScope 具名範圍：只回傳範圍內帳號，
// 特權的 root 不再對範圍外使用者曝光
func TestAccountListFilteredByScope(t *testing.T) {
	handler, db := setupAccountListEnv(t)
	grantView(t, db, model.AccountScope{"app"})

	code, names := listAccounts(handler, model.RoleUser)
	if code != http.StatusOK {
		t.Fatalf("列表應 200: %d", code)
	}
	if len(names) != 1 || names[0] != "app" {
		t.Fatalf("應只回範圍內帳號，實得 %v", names)
	}
}

// TestAccountListAllScopeUnchanged 既有行為零變化：@ALL（migration 回填值）
// 回傳全部帳號，與過濾引入前一致
func TestAccountListAllScopeUnchanged(t *testing.T) {
	handler, db := setupAccountListEnv(t)
	grantView(t, db, model.AccountScope{model.AccountScopeAll})

	code, names := listAccounts(handler, model.RoleUser)
	if code != http.StatusOK || len(names) != 3 {
		t.Fatalf("@ALL 應回全部三個帳號: code=%d names=%v", code, names)
	}
}

// TestAccountListAdminAndAuditorUnfiltered admin 與 auditor 不過濾
// （管理與稽核視圖語義不被本 change 收窄）
func TestAccountListAdminAndAuditorUnfiltered(t *testing.T) {
	handler, _ := setupAccountListEnv(t)
	// 刻意不建任何授權列
	for _, role := range []string{model.RoleAdmin, model.RoleAuditor} {
		code, names := listAccounts(handler, role)
		if code != http.StatusOK || len(names) != 3 {
			t.Fatalf("%s 應看到全部帳號: code=%d names=%v", role, code, names)
		}
	}
}

// TestAccountListNoGrantEmpty 無授權者回空清單而非 403——
// 範圍外帳號在請求者的世界裡就是不存在，403 反而洩漏「這台有你看不到的帳號」
func TestAccountListNoGrantEmpty(t *testing.T) {
	handler, _ := setupAccountListEnv(t)

	code, names := listAccounts(handler, model.RoleUser)
	if code != http.StatusOK || len(names) != 0 {
		t.Fatalf("無授權應回空清單: code=%d names=%v", code, names)
	}
}

// TestAccountCopyCrossAssetVisibilityGuard 跨資產複製建號的來源可見性
// （階段 2 backlog）：沒有這道判定，只管得到自己那台的管理員可以把
// 生產核心機的 root 密文複製到自己的資產上，再從自己的資產連上去——
// 密文原樣搬運不需解密即可用，是完整的憑證竊取路徑
func TestAccountCopyCrossAssetVisibilityGuard(t *testing.T) {
	_, db := setupAccountListEnv(t)
	// 另一台資產（user 1 對它無任何授權）與其 root 帳號
	if err := db.Create(&model.Asset{Name: "secret", Protocol: "ssh", Host: "h2", Port: 22,
		CreatedBy: 2, Active: true}).Error; err != nil {
		t.Fatalf("seed asset2: %v", err)
	}
	foreign := model.AssetAccount{AssetID: 2, Username: "root", Privileged: true, IsDefault: true}
	if err := db.Create(&foreign).Error; err != nil {
		t.Fatalf("seed foreign account: %v", err)
	}

	codec := aesColumnCodec(t, make([]byte, 32))
	assetSvc, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	accountSvc := asset.NewAssetAccountService(assetSvc, codec, audit.NewTxSink()).
		WithAuthorization(authz.NewAssetAuthorizationService(db))

	ctx := context.WithValue(context.Background(), "userID", uint(1)) //nolint:staticcheck
	ctx = context.WithValue(ctx, "role", model.RoleUser)              //nolint:staticcheck

	_, err = accountSvc.Create(ctx, 1, &asset.CreateAssetAccountRequest{
		Username: "stolen", CopyFromAccountID: foreign.ID,
	})
	if err == nil {
		t.Fatal("不可見來源資產的帳號不得被複製")
	}

	// admin 短路：管理員複製不受限（既有能力不被收窄）
	adminCtx := context.WithValue(context.Background(), "userID", uint(2)) //nolint:staticcheck
	adminCtx = context.WithValue(adminCtx, "role", model.RoleAdmin)        //nolint:staticcheck
	if _, err := accountSvc.Create(adminCtx, 1, &asset.CreateAssetAccountRequest{
		Username: "copied", CopyFromAccountID: foreign.ID,
	}); err != nil {
		t.Fatalf("admin 應可複製: %v", err)
	}
}
