package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"fmt"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/crypto/vaulttransit"
)

// 全新安裝直接以委託模式開機的驗證段守衛（任務 6.1／6.2）。
//
// 射程界定：本檔守兩段。
//
//  1. **臨界區內的驗證段**——鍵集、初始管理員憑證、拓撲逐欄驗證、以輸入憑證完成
//     連通性與權限預檢。驗證段**不寫任何一張表**。
//  2. **同事務落庫**——首批資料金鑰的產生、以外部 KEK 包裹與落表，連同拓撲，落在
//     `keyvault.InitKeyManagerWithBootstrap` 的單一交易內。本檔以**雙向**注入證明
//     該事務性：包裹／落表失敗則拓撲不得存在，拓撲寫入失敗則金鑰列不得存在。
//     測試呼叫的是段 2 實際呼叫的那一對函式（`delegatedTopologyBootstrapHook` 與
//     `InitKeyManagerWithBootstrap`），不另造平行路徑。
//  3. **接線**——`TestDelegatedBootstrapEndToEnd` 走真實 HTTP 端點與 production
//     的接線完成空庫四步，證明段 2 確實把 hook 接上（機制存在不等於路徑接上）。
//     唯一的替身是保管處本身；真保管處的封存到解封整圈另有專屬測試。
//
// 失敗路徑守的是「不留半套」：任一步失敗後，金鑰表與拓撲表必須同時為空——否則
// 下一次啟動會拿著一個指向失敗目的地的設定去解一個還不存在的金鑰表，或反過來
// 拿著一批無處可解的金鑰。

func bootstrapTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.KEKTopology{}, &model.DataKey{}, &model.User{},
		&model.Role{}, &model.UserRole{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 初始管理員：段 1 的種子在解封之前就建好了，故全新安裝時它必然存在。
	admin := model.User{Username: bootstrapAdminUser,
		Password: crypto.MustHashForTest(bootstrapAdminPassword), Active: true}
	if err := db.Create(&admin).Error; err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	role := model.Role{Name: model.RoleAdmin}
	if err := db.Create(&role).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := db.Create(&model.UserRole{UserID: admin.ID, RoleID: role.ID}).Error; err != nil {
		t.Fatalf("seed user_role: %v", err)
	}
	prev := database.DB
	database.DB = db
	t.Cleanup(func() {
		database.DB = prev
		_ = sqlDB.Close()
	})
	return db
}

const (
	bootstrapAdminUser     = "bootstrap-admin"
	bootstrapAdminPassword = "bootstrap-password-fixture"
)

func bootstrapStage1(t *testing.T, provider string, build func(context.Context, *credentialOwner) (crypto.KEKProvider, error)) *stage1 {
	t.Helper()
	d := &config.KEKDecision{Mode: config.KEKModeKMS}
	d.KMS.Provider = provider
	return &stage1{kekDecision: d, delegatedProviderSource: build}
}

func bootstrapVaultBody() string {
	return fmt.Sprintf(`{"username":%q,"password":%q,"address":"https://vault.example:8200",`+
		`"transit_key_name":"custodexa-kek","role_id":"role-fixture","vault_secret_id":"secret-fixture"}`,
		bootstrapAdminUser, bootstrapAdminPassword)
}

// TestDelegatedBootstrapInit 全新安裝的驗證段逐步成立。
func TestDelegatedBootstrapInit(t *testing.T) {
	db := bootstrapTestDB(t)
	var sawSecret bool
	s1 := bootstrapStage1(t, vaulttransit.ProviderVault, func(_ context.Context, o *credentialOwner) (crypto.KEKProvider, error) {
		settings, err := o.settings()
		if err != nil {
			return nil, err
		}
		// 憑證與拓撲都必須經**世代持有者**送達建構點。
		sawSecret = settings.Vault.SecretID == "secret-fixture" &&
			settings.Vault.Address == "https://vault.example:8200" &&
			settings.Vault.RoleID == "role-fixture" &&
			settings.KeyID == "custodexa-kek"
		return bootstrapFakeProvider{}, nil
	})

	pending := &bootstrapPendingState{}
	v, err := verifyDelegatedUnseal(context.Background(), s1, []byte(bootstrapVaultBody()), pending)
	if err != nil {
		t.Fatalf("全新安裝的驗證段應通過: %v", err)
	}
	if !v.bootstrap || v.adminUsername != bootstrapAdminUser {
		t.Fatalf("應標示為初始化路徑並記下宣告者: %+v", v)
	}
	if !sawSecret {
		t.Fatal("憑證或拓撲未經世代持有者送達建構點")
	}
	if armed, name := pending.snapshot(); !armed || name != bootstrapAdminUser {
		t.Fatalf("初始化待決未武裝：armed=%v name=%q", armed, name)
	}
	// **驗證段不寫表**：拓撲隨載荷帶到段 2，此刻資料庫仍是空的。
	if _, lerr := keyvault.LoadKEKTopology(db); !errors.Is(lerr, keyvault.ErrKEKTopologyNotConfigured) {
		t.Fatalf("驗證段不得寫拓撲（它要與首批金鑰同事務），得 %v", lerr)
	}
	if v.topology == nil {
		t.Fatal("已驗證的拓撲未隨載荷帶往段 2")
	}
	if v.topology.Address != "https://vault.example:8200" || v.topology.RoleID != "role-fixture" ||
		v.topology.TransitKeyName != "custodexa-kek" || v.topology.UpdatedBy != bootstrapAdminUser {
		t.Fatalf("帶往段 2 的拓撲不符: %+v", v.topology)
	}
	v.credentials.Close()

	// 段 2 的落庫：金鑰列與拓撲同一筆交易。
	km, err := keyvault.InitKeyManagerWithBootstrap(db, bootstrapFakeProvider{},
		delegatedTopologyBootstrapHook(v.topology))
	if err != nil {
		t.Fatalf("段 2 的同事務落庫應成立: %v", err)
	}
	km.ZeroizeForRelease()
	var n int64
	db.Model(&model.DataKey{}).Count(&n)
	if n != 2 {
		t.Fatalf("首批金鑰列數應為 2（data＋audit_integrity），得 %d", n)
	}
	row, err := keyvault.LoadKEKTopology(db)
	if err != nil {
		t.Fatalf("拓撲應與金鑰列一併落庫: %v", err)
	}
	if row.Address != "https://vault.example:8200" || row.RoleID != "role-fixture" ||
		row.TransitKeyName != "custodexa-kek" || row.UpdatedBy != bootstrapAdminUser {
		t.Fatalf("落庫的拓撲不符: %+v", row)
	}
}

// TestDelegatedBootstrapInitSameTransaction 同事務的**雙向**注入。
//
// 單向只證明「拓撲寫在金鑰之後」；兩個方向都空才證明它們共用一次 commit。
func TestDelegatedBootstrapInitSameTransaction(t *testing.T) {
	topo := &keyvault.KEKTopologyInput{
		Provider: keyvault.TopologyProviderVault, Address: "https://vault.example:8200",
		TransitKeyName: "custodexa-kek", RoleID: "role-fixture", UpdatedBy: bootstrapAdminUser,
	}
	assertBothEmpty := func(t *testing.T, db *gorm.DB) {
		t.Helper()
		var n int64
		db.Model(&model.DataKey{}).Count(&n)
		if n != 0 {
			t.Fatalf("失敗後不得留下金鑰列，得 %d", n)
		}
		if _, lerr := keyvault.LoadKEKTopology(db); !errors.Is(lerr, keyvault.ErrKEKTopologyNotConfigured) {
			t.Fatalf("失敗後不得留下拓撲列，得 %v", lerr)
		}
	}

	t.Run("包裹失敗則拓撲亦不落庫", func(t *testing.T) {
		db := bootstrapTestDB(t)
		_, err := keyvault.InitKeyManagerWithBootstrap(db, bootstrapFakeProvider{wrapErr: errWrapInjected},
			delegatedTopologyBootstrapHook(topo))
		if err == nil {
			t.Fatal("包裹失敗時不得成功")
		}
		assertBothEmpty(t, db)
	})

	t.Run("落表失敗則拓撲亦不落庫", func(t *testing.T) {
		db := bootstrapTestDB(t)
		// 以「刪掉金鑰表」製造落表失敗：交易內的第一筆 INSERT 即失敗。
		if err := db.Migrator().DropTable(&model.DataKey{}); err != nil {
			t.Fatalf("drop data_keys: %v", err)
		}
		_, err := keyvault.InitKeyManagerWithBootstrap(db, bootstrapFakeProvider{},
			delegatedTopologyBootstrapHook(topo))
		if err == nil {
			t.Fatal("落表失敗時不得成功")
		}
		if _, lerr := keyvault.LoadKEKTopology(db); !errors.Is(lerr, keyvault.ErrKEKTopologyNotConfigured) {
			t.Fatalf("落表失敗後不得留下拓撲列，得 %v", lerr)
		}
	})

	t.Run("拓撲寫入失敗則金鑰列亦不落庫", func(t *testing.T) {
		db := bootstrapTestDB(t)
		bad := *topo
		bad.Address = "http://vault.example:8200" // 非 HTTPS：hook 內的逐欄驗證會擋下
		_, err := keyvault.InitKeyManagerWithBootstrap(db, bootstrapFakeProvider{},
			delegatedTopologyBootstrapHook(&bad))
		if err == nil {
			t.Fatal("拓撲寫入失敗時不得成功")
		}
		assertBothEmpty(t, db)
	})

	t.Run("金鑰表非空時附帶寫入 fail-close", func(t *testing.T) {
		db := bootstrapTestDB(t)
		km, err := keyvault.InitKeyManagerWithBootstrap(db, bootstrapFakeProvider{}, nil)
		if err != nil {
			t.Fatalf("首次 bootstrap: %v", err)
		}
		km.ZeroizeForRelease()
		// 金鑰表已非空＝這不是一次全新安裝；此時仍帶著拓撲 hook 進來，
		// 靜默略過會讓拓撲回到「另一筆交易寫」的形態，故必須拒絕。
		if _, err := keyvault.InitKeyManagerWithBootstrap(db, bootstrapFakeProvider{},
			delegatedTopologyBootstrapHook(topo)); !errors.Is(err, keyvault.ErrBootstrapHookOnNonEmptyKeyTable) {
			t.Fatalf("金鑰表非空時應 fail-close，得 %v", err)
		}
		if _, lerr := keyvault.LoadKEKTopology(db); !errors.Is(lerr, keyvault.ErrKEKTopologyNotConfigured) {
			t.Fatalf("被拒的附帶寫入不得留下拓撲列，得 %v", lerr)
		}
	})
}

// TestDelegatedBootstrapPartialFailure 失敗路徑不留半套。
func TestDelegatedBootstrapPartialFailure(t *testing.T) {
	t.Run("預檢失敗不寫拓撲", func(t *testing.T) {
		db := bootstrapTestDB(t)
		s1 := bootstrapStage1(t, vaulttransit.ProviderVault, func(context.Context, *credentialOwner) (crypto.KEKProvider, error) {
			return nil, vaulttransit.ErrAuth
		})
		_, err := verifyDelegatedUnseal(context.Background(), s1, []byte(bootstrapVaultBody()), &bootstrapPendingState{})
		if err == nil {
			t.Fatal("預檢失敗時不得通過")
		}
		if _, lerr := keyvault.LoadKEKTopology(db); !errors.Is(lerr, keyvault.ErrKEKTopologyNotConfigured) {
			t.Fatalf("預檢失敗之後不得留下拓撲列，得 %v", lerr)
		}
		var n int64
		db.Model(&model.DataKey{}).Count(&n)
		if n != 0 {
			t.Fatalf("預檢失敗之後不得留下金鑰列，得 %d", n)
		}
	})

	t.Run("憑證錯不寫拓撲", func(t *testing.T) {
		db := bootstrapTestDB(t)
		s1 := bootstrapStage1(t, vaulttransit.ProviderVault, func(context.Context, *credentialOwner) (crypto.KEKProvider, error) {
			t.Fatal("初始管理員憑證未通過時不得走到建構")
			return nil, nil
		})
		body := fmt.Sprintf(`{"username":%q,"password":"wrong","address":"https://vault.example:8200",`+
			`"transit_key_name":"custodexa-kek","role_id":"role-fixture","vault_secret_id":"secret-fixture"}`,
			bootstrapAdminUser)
		if _, err := verifyDelegatedUnseal(context.Background(), s1, []byte(body), &bootstrapPendingState{}); err == nil {
			t.Fatal("錯誤的初始管理員憑證應被拒")
		}
		if _, lerr := keyvault.LoadKEKTopology(db); !errors.Is(lerr, keyvault.ErrKEKTopologyNotConfigured) {
			t.Fatalf("憑證未過之前不得寫拓撲，得 %v", lerr)
		}
	})

	t.Run("鍵集不符即拒", func(t *testing.T) {
		db := bootstrapTestDB(t)
		s1 := bootstrapStage1(t, vaulttransit.ProviderVault, func(context.Context, *credentialOwner) (crypto.KEKProvider, error) {
			t.Fatal("鍵集不符時不得走到建構")
			return nil, nil
		})
		for name, body := range map[string]string{
			"缺拓撲欄位": fmt.Sprintf(`{"username":%q,"password":%q,"vault_secret_id":"s"}`,
				bootstrapAdminUser, bootstrapAdminPassword),
			"混用兩種 Vault 憑證": fmt.Sprintf(`{"username":%q,"password":%q,"address":"https://vault.example:8200",`+
				`"transit_key_name":"k","role_id":"r","vault_secret_id":"s","vault_token":"t"}`,
				bootstrapAdminUser, bootstrapAdminPassword),
			"夾帶他家欄位": fmt.Sprintf(`{"username":%q,"password":%q,"address":"https://vault.example:8200",`+
				`"transit_key_name":"k","role_id":"r","vault_secret_id":"s","region":"ap-northeast-1"}`,
				bootstrapAdminUser, bootstrapAdminPassword),
		} {
			if _, err := verifyDelegatedUnseal(context.Background(), s1, []byte(body), &bootstrapPendingState{}); err == nil {
				t.Errorf("%s 應被拒", name)
			}
		}
		if _, lerr := keyvault.LoadKEKTopology(db); !errors.Is(lerr, keyvault.ErrKEKTopologyNotConfigured) {
			t.Fatalf("鍵集不符之後不得留下拓撲列，得 %v", lerr)
		}
	})

	// 發佈階段失敗（落庫已 commit、段 2 其後步驟或發佈失敗）：狀態回已封存，
	// 重試沿一般解封路徑續作，且**事件仍記為初始化**（bootstrapPendingState）。
	// 這一條是「不宣稱未做任何變更」的具體形狀：金鑰與拓撲確實已寫入，重試要
	// 在那個已成立的事實上續跑，而不是假裝上一次什麼都沒發生。
	t.Run("發佈失敗後可受控重試且仍記為初始化", func(t *testing.T) {
		db := bootstrapTestDB(t)
		s1 := bootstrapStage1(t, vaulttransit.ProviderVault, func(context.Context, *credentialOwner) (crypto.KEKProvider, error) {
			return bootstrapFakeProvider{}, nil
		})
		pending := &bootstrapPendingState{}
		v, err := verifyDelegatedUnseal(context.Background(), s1, []byte(bootstrapVaultBody()), pending)
		if err != nil {
			t.Fatalf("首次驗證應通過: %v", err)
		}
		v.credentials.Close()
		km, err := keyvault.InitKeyManagerWithBootstrap(db, bootstrapFakeProvider{},
			delegatedTopologyBootstrapHook(v.topology))
		if err != nil {
			t.Fatalf("同事務落庫應成立: %v", err)
		}
		km.ZeroizeForRelease()
		// 此處模擬「落庫之後、發佈之前」失敗：pending 未被 clear。

		// 重試：金鑰表已非空 → 走一般解封路徑，須帶當前拓撲摘要。
		view, _, err := delegatedTopologySnapshot(vaulttransit.ProviderVault)
		if err != nil {
			t.Fatalf("讀拓撲快照: %v", err)
		}
		retry := fmt.Sprintf(`{"vault_secret_id":"secret-fixture","topology_digest":%q}`, view.Digest)
		v2, err := verifyDelegatedUnseal(context.Background(), s1, []byte(retry), pending)
		if err != nil {
			t.Fatalf("重試應可受控續作: %v", err)
		}
		defer v2.credentials.Close()
		if !v2.bootstrap || v2.adminUsername != bootstrapAdminUser {
			t.Fatalf("重試仍屬同一次初始化，事件須可區分: bootstrap=%v user=%q", v2.bootstrap, v2.adminUsername)
		}
		if v2.topology != nil {
			t.Fatal("重試不得再帶一份待落庫的拓撲（它已在上一次交易中落地）")
		}
		var n int64
		db.Model(&model.DataKey{}).Count(&n)
		if n != 2 {
			t.Fatalf("重試不得重複鑄鑰，金鑰列應維持 2，得 %d", n)
		}
	})
}

// errWrapInjected 注入的外部 KEK 包裹失敗（保管處在落表前一刻拒絕）。
var errWrapInjected = errors.New("注入：外部 KEK 包裹失敗")

// bootstrapFakeProvider 只回答身分，不做任何密碼學運算。
// wrapErr 非 nil 時模擬「包裹階段失敗」，用以驗證同事務的另一個方向。
type bootstrapFakeProvider struct{ wrapErr error }

func (bootstrapFakeProvider) KeyRef() crypto.KeyRef {
	return crypto.KeyRef{Provider: crypto.KeyRefProviderVault, KeyID: "custodexa-kek"}
}
func (bootstrapFakeProvider) Mode() string      { return crypto.KEKModeKMS }
func (bootstrapFakeProvider) FormatTag() string { return crypto.WrappedFormatVault }
func (p bootstrapFakeProvider) Wrap(context.Context, []byte, []byte) ([]byte, error) {
	if p.wrapErr != nil {
		return nil, p.wrapErr
	}
	return []byte("wrapped"), nil
}
func (bootstrapFakeProvider) Unwrap(context.Context, []byte, []byte) ([]byte, error) {
	return make([]byte, 32), nil
}
func (p bootstrapFakeProvider) ReEncrypt(ctx context.Context, wrapped, aad []byte, from crypto.KEKProvider) ([]byte, error) {
	raw, err := from.Unwrap(ctx, wrapped, aad)
	if err != nil {
		return nil, err
	}
	return p.Wrap(ctx, raw, aad)
}

// TestDelegatedBootstrapEndToEnd 空庫 → 委託模式段 1 停在已封存 → 走真實 HTTP
// 端點完成四步 → 段 2 起來、業務可用。
//
// **這是「同事務落庫真的被接上」的唯一證據**：前面的案例直接呼叫
// `InitKeyManagerWithBootstrap`，證明得了事務語義卻證明不了段 2 有沒有把 hook
// 傳進去。此處走的是 production 的接線（`newSealMachine` → `verifyDelegatedUnseal`
// → `runStage2`），唯一的替身是保管處本身（`delegatedProviderSource`）——
// dev 環境的 Vault 靶機只有 HTTP，而拓撲驗證要求 HTTPS，真保管處的整圈另有專屬測試。
func TestDelegatedBootstrapEndToEnd(t *testing.T) {
	env := newSealIntegrationEnvWith(t, func(s1 *stage1) {
		s1.kekDecision = &config.KEKDecision{Mode: config.KEKModeKMS, MatrixRow: "test", Rationale: "委託整合測試"}
		s1.kekDecision.KMS.Provider = keyvault.TopologyProviderVault
		s1.delegatedProviderSource = func(_ context.Context, o *credentialOwner) (crypto.KEKProvider, error) {
			settings, err := o.settings()
			if err != nil {
				return nil, err
			}
			if settings.Vault.Address != "https://vault.example:8200" || settings.Vault.RoleID != "role-fixture" {
				return nil, fmt.Errorf("拓撲未送達建構點: %+v", settings.Vault)
			}
			return bootstrapFakeProvider{}, nil
		}
	})

	// 第 0 步：段 1 停在已封存，金鑰表與拓撲皆空，業務路由 503。
	if n := dataKeyCount(t); n != 0 {
		t.Fatalf("段 1 不得建立金鑰，得 %d", n)
	}
	if _, err := keyvault.LoadKEKTopology(database.DB); !errors.Is(err, keyvault.ErrKEKTopologyNotConfigured) {
		t.Fatalf("段 1 不得寫拓撲，得 %v", err)
	}
	if w := env.do(http.MethodGet, "/api/v1/keys", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("封印期 /api/v1/keys 回 %d，期望 503", w.Code)
	}

	// 狀態端點指出這是全新安裝，且此時無可核對的目的地。
	var st map[string]any
	w := env.do(http.MethodGet, "/api/v1/seal/status", "")
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatalf("解析 status 失敗: %v", err)
	}
	if st["initialization_required"] != true {
		t.Fatalf("空庫時 initialization_required 為 %v，期望 true", st["initialization_required"])
	}

	// 第 1 步（帳密）：`do` 內部先走 /seal/authorize 取脈絡——沒有脈絡即不可能
	// 走到第 3 步，故此處以「無脈絡送出必拒」把該前提釘住。
	noGrant := httptest.NewRequest(http.MethodPost, "/api/v1/seal/unseal",
		strings.NewReader(delegatedBootstrapBody()))
	noGrant.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.swap.ServeHTTP(rec, noGrant)
	if rec.Code == http.StatusOK {
		t.Fatal("未經帳密授權的解封不得成立")
	}

	// 第 2／3／4 步：拓撲欄位與憑證同一份請求送出，段 2 於同一臨界區完成建鑰與發佈。
	if w := env.do(http.MethodPost, "/api/v1/seal/unseal", delegatedBootstrapBody()); w.Code != http.StatusOK {
		t.Fatalf("全新安裝的委託解封回 %d：%s", w.Code, w.Body.String())
	}
	if got := env.machine.Snapshot().State; got != seal.StateUnsealed {
		t.Fatalf("解封後狀態為 %s，期望 unsealed", got)
	}

	// 落庫結果：首批金鑰與拓撲同時存在（同一筆交易的兩半）。
	if n := dataKeyCount(t); n != 2 {
		t.Fatalf("首批金鑰列數應為 2，得 %d", n)
	}
	row, err := keyvault.LoadKEKTopology(database.DB)
	if err != nil {
		t.Fatalf("拓撲應已與金鑰列一併落庫: %v", err)
	}
	if row.Address != "https://vault.example:8200" || row.RoleID != "role-fixture" ||
		row.TransitKeyName != "custodexa-kek" || row.UpdatedBy != testAdminUser {
		t.Fatalf("落庫的拓撲不符: %+v", row)
	}
	keyRef, err := keyvault.CurrentKEKID(database.DB)
	if err != nil || keyRef != "custodexa-kek" {
		t.Fatalf("金鑰列的 KEK 引用應為建構時解析出的識別，得 %q（err=%v）", keyRef, err)
	}

	// 服務可用：完整路由已換上，且可實際登入。
	if w := env.do(http.MethodGet, "/api/v1/ping", ""); w.Code != http.StatusOK {
		t.Fatalf("解封後 /ping 回 %d，期望 200", w.Code)
	}
	login := fmt.Sprintf(`{"username":%q,"password":%q}`, testAdminUser, testAdminPassword)
	if w := env.do(http.MethodPost, "/api/v1/auth/login", login); w.Code != http.StatusOK {
		t.Fatalf("解封後登入回 %d：%s", w.Code, w.Body.String())
	}

	// 稽核可回答「這個部署的 KEK 是誰初始化的」：事件須為初始化而非一般解封。
	var sawInitialize bool
	for _, d := range sealAuditDetails(t) {
		if strings.Contains(d, sealAuditEventInitialize) {
			sawInitialize = true
		}
	}
	if !sawInitialize {
		t.Fatalf("審計未留下初始化事件，得 %v", sealAuditDetails(t))
	}
}

// delegatedBootstrapBody 全新安裝的委託解封請求（Vault 角色分支）。
func delegatedBootstrapBody() string {
	return fmt.Sprintf(`{"username":%q,"password":%q,"address":"https://vault.example:8200",`+
		`"transit_key_name":"custodexa-kek","role_id":"role-fixture","vault_secret_id":"secret-fixture"}`,
		testAdminUser, testAdminPassword)
}
