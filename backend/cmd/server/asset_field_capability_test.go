package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/pkg/crypto"
)

// 資產寫入的欄位級能力（建立、更新、匯入）。
//
// 只持資產寫入能力的全域自訂角色，不能變更帳號與憑證秘密，也不能掛載既有憑證；
// 以「實際會變更」為準判定，缺任一能力整筆拒絕且資料零變更。

// fieldCapTestCodec 測試用 ColumnCodec：與正式組裝同樣以欄位身分綁定 AAD。
type fieldCapTestCodec struct{ c *crypto.AESCrypto }

func (a fieldCapTestCodec) EncryptFor(_ context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	raw, err := a.c.EncryptBytesAAD([]byte(plaintext), ref.AAD())
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func (a fieldCapTestCodec) DecryptFor(_ context.Context, ref crypto.CipherRef, ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", crypto.ErrInvalidCiphertext
	}
	plain, err := a.c.DecryptBytesAAD(data, ref.AAD())
	return string(plain), err
}

func (a fieldCapTestCodec) EncryptBytesFor(ctx context.Context, ref crypto.CipherRef, plaintext []byte) (string, error) {
	return a.EncryptFor(ctx, ref, string(plaintext))
}

func (a fieldCapTestCodec) DecryptBytesFor(_ context.Context, ref crypto.CipherRef, ciphertext string) (*material.Secret, error) {
	if ciphertext == "" {
		return material.Adopt(nil), nil
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, crypto.ErrInvalidCiphertext
	}
	return material.AdoptResult(a.c.DecryptBytesAAD(data, ref.AAD()))
}

type fieldCapEnv struct {
	db     *gorm.DB
	assets *asset.AssetService
	creds  *asset.CredentialService
	codec  crypto.ColumnCodec
	// current 本次請求的主體：服務層的憑證管理關卡以它重判，對應正式組裝以同一使用者
	// 從資料庫重新解析主體（credentialManagementAdapter）
	current *authz.Principal
	// lastDenial 最近一次請求經能力拒絕寫出函式存下的依據（未經它拒絕為 nil）
	lastDenial *middleware.CapabilityDenial
}

// fieldCapManagementAuthorizer 服務層憑證管理關卡的測試替身：以本次請求的主體判定能力。
// 正式組裝的判定器以 actor 從資料庫重解析；本測試的主體只存在於請求脈絡，故改讀 env.current。
// 主體缺席即拒絕，與正式判定器的空主體語義一致。
type fieldCapManagementAuthorizer struct{ env *fieldCapEnv }

func (a fieldCapManagementAuthorizer) AuthorizeCredentialManagement(_ context.Context, _ *gorm.DB,
	_ asset.CredentialManagementActor, req asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	for _, c := range req.Capabilities {
		if !a.env.current.Has(authz.Permission(c)) {
			return asset.CredentialManagementDecision{Missing: c, AuthzVersion: 1}, nil
		}
	}
	return asset.CredentialManagementDecision{Allowed: true, AuthzVersion: 1}, nil
}

// fieldCapSeedAuthorizer 只供夾具建立共用憑證（不在本測試的判定範圍內）。
type fieldCapSeedAuthorizer struct{}

func (fieldCapSeedAuthorizer) AuthorizeCredentialManagement(context.Context, *gorm.DB,
	asset.CredentialManagementActor, asset.CredentialManagementRequest) (asset.CredentialManagementDecision, error) {
	return asset.CredentialManagementDecision{Allowed: true, AuthzVersion: 1}, nil
}

type noopAlertSink struct{}

func (noopAlertSink) RaiseInTx(*gorm.DB, port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, nil
}

func operatorCtx() context.Context {
	ctx := context.WithValue(context.Background(), "userID", uint(7)) //nolint:staticcheck // 沿用審計 context 慣例
	return context.WithValue(ctx, "username", "field-cap")            //nolint:staticcheck
}

func newFieldCapEnv(t *testing.T) *fieldCapEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.Credential{},
		&model.CredentialSecretVersion{}, &model.ChangeSecretCandidate{}, &model.AuditLog{},
		&model.AssetGroup{}, &model.AssetNode{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return fieldCapEnvOn(t, db)
}

// fieldCapEnvOn 在已建好表的資料庫上組服務（並把 database.DB 換成它，測試結束還原）。
func fieldCapEnvOn(t *testing.T, db *gorm.DB) *fieldCapEnv {
	t.Helper()
	old := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = old })

	aes, err := crypto.NewAESCrypto(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	codec := fieldCapTestCodec{c: aes}
	assets, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	assets.SetTopologyPermissionPort(noopTopologyPort{})
	if err != nil {
		t.Fatal(err)
	}
	assets.SetSecurityChangeAlertSink(noopAlertSink{})
	// 本夾具的主體為合成主體（不在使用者表），寫入範圍判定與涵蓋快照注入替身；範圍化夾具另換真實作
	assets.SetAssetWriteScopePort(allowAllAssetWriteScope{})
	assets.SetCoverageSnapshotPort(emptyCoverageSnapshot{})
	env := &fieldCapEnv{db: db, assets: assets, codec: codec}
	// 與正式組裝同形：資產表單內嵌的秘密宣告與掛載走同一道憑證管理關卡（未注入即 fail closed）
	assets.WithManagementAuthorizer(fieldCapManagementAuthorizer{env: env}).WithSystemAlertSink(noopAlertSink{})
	env.creds = asset.NewCredentialService(assets, codec, audit.NewTxSink()).WithOwnershipScope(globalOwnershipScopeForTest{}).
		WithManagementAuthorizer(fieldCapSeedAuthorizer{}).WithSystemAlertSink(noopAlertSink{})
	return env
}

func (e *fieldCapEnv) engine(p *authz.Principal) *gin.Engine {
	h := api.NewAssetHandler(e.assets, nil, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(7))
		c.Set("username", "field-cap")
		middleware.SetPrincipal(c, p)
		c.Next()
		if d, ok := middleware.CapabilityDenialFrom(c); ok {
			e.lastDenial = &d
		}
	})
	g := r.Group("/api/v1/assets")
	g.POST("", middleware.EnforceRegistry(), h.Create)
	g.POST("/import/preview", middleware.EnforceRegistry(), h.PreviewImport)
	g.POST("/import", middleware.EnforceRegistry(), h.Import)
	g.PUT("/:id", middleware.EnforceRegistry(), h.Update)
	return r
}

func customPrincipal(perms ...authz.Permission) *authz.Principal {
	return authz.NewPrincipal(7, authz.TokenFacts{}, []authz.Assignment{{
		RoleName: "field-cap-custom", Via: authz.ViaDirect, Scope: model.ScopeKindGlobal,
		Permissions: perms, Custom: true,
	}})
}

func (e *fieldCapEnv) call(p *authz.Principal, method, path, body string) (int, string) {
	e.current = p
	e.lastDenial = nil
	defer func() { e.current = nil }()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.engine(p).ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (e *fieldCapEnv) count(t *testing.T, m interface{}) int64 {
	t.Helper()
	var n int64
	if err := e.db.Unscoped().Model(m).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func jsonTags(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]asset.FieldCapClass) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// assetCredentialFieldPerm 資產表單帳號與秘密欄位對應的憑證語義鍵：建立一律為建立憑證；更新時帳號名稱類為
// 更新憑證、秘密類為更換憑證秘密。
func assetCredentialFieldPerm(method, field string) authz.Permission {
	if method == "POST" {
		return authz.PermCredentialCreate
	}
	switch field {
	case "password", "private_key", "sftp_password":
		return authz.PermCredentialSetSecret
	}
	return authz.PermCredentialUpdate
}

func TestAssetFieldCapabilities(t *testing.T) {
	updateOnly := customPrincipal(authz.PermAssetUpdate, authz.PermAssetView)
	createOnly := customPrincipal(authz.PermAssetCreate, authz.PermAssetView)
	var all []authz.Permission
	for _, d := range authz.Catalog() {
		all = append(all, d.Key)
	}
	fullCustom := customPrincipal(all...)
	superAdmin := principalWith(model.BuiltinSuperAdmin, model.RoleAdmin)

	t.Run("歸類表與請求結構及路由登錄零落差", func(t *testing.T) {
		for _, c := range []struct {
			name    string
			typ     reflect.Type
			classes map[string]asset.FieldCapClass
			method  string
			path    string
		}{
			{"更新請求", reflect.TypeOf(asset.UpdateAssetRequest{}), asset.UpdateRequestFieldCaps, "PUT", "/api/v1/assets/:id"},
			{"建立請求", reflect.TypeOf(asset.CreateAssetRequest{}), asset.CreateRequestFieldCaps, "POST", "/api/v1/assets"},
			{"匯入列", reflect.TypeOf(asset.ImportRow{}), asset.ImportRowFieldCaps, "POST", "/api/v1/assets/import"},
		} {
			if got, want := jsonTags(c.typ), sortedKeys(c.classes); !reflect.DeepEqual(got, want) {
				t.Errorf("%s：結構欄位 %v 與歸類表 %v 有落差", c.name, got, want)
			}
			entry, ok := authz.LookupRoute(c.method, c.path)
			if !ok {
				t.Fatalf("%s %s 未登錄", c.method, c.path)
			}
			var declared, declaredBind []string
			for _, f := range entry.Fields {
				if f.Field == authz.FieldWildcard {
					continue // 僅需登入路由的萬用條件（資產編輯能力），不屬欄位歸類
				}
				if f.Field == "access_policy" {
					if f.Perm != authz.PermAccessPolicyManage {
						t.Errorf("%s：access_policy 宣告的能力應為存取政策權限點，實為 %s", c.name, f.Perm)
					}
					continue
				}
				if c.classes[f.Field] == asset.FieldCapCredentialBind {
					// 掛載既有共用憑證：欄位條件為掛載能力（範圍由掛載來源判定收斂）
					if f.Perm != authz.PermCredentialBind {
						t.Errorf("%s：欄位 %s 宣告的能力應為憑證掛載，實為 %s", c.name, f.Field, f.Perm)
					}
					declaredBind = append(declaredBind, f.Field)
					continue
				}
				// 帳號與秘密欄位：權限點為對應的憑證語義鍵，全域持有的憑證管理為相容並列能力
				if want := assetCredentialFieldPerm(c.method, f.Field); f.Perm != want {
					t.Errorf("%s：欄位 %s 宣告的能力應為 %s，實為 %s", c.name, f.Field, want, f.Perm)
				}
				if !reflect.DeepEqual(f.AnyOf, []authz.Permission{authz.PermCredentialManage}) {
					t.Errorf("%s：欄位 %s 的相容並列能力應為憑證管理，實為 %v", c.name, f.Field, f.AnyOf)
				}
				declared = append(declared, f.Field)
			}
			sort.Strings(declared)
			if want := asset.CredentialFieldNames(c.classes); !reflect.DeepEqual(declared, want) {
				t.Errorf("%s：登錄宣告 %v 與歸類表的憑證欄位 %v 不一致", c.name, declared, want)
			}
			sort.Strings(declaredBind)
			if want := asset.CredentialBindFieldNames(c.classes); !reflect.DeepEqual(declaredBind, want) {
				t.Errorf("%s：登錄宣告 %v 與歸類表的掛載欄位 %v 不一致", c.name, declaredBind, want)
			}
		}
		// 存取政策欄位由存取政策段宣告為獨立能力（TestAccessPolicyFieldGate 逐路由驗證）
		if asset.UpdateRequestFieldCaps["access_policy"] != asset.FieldCapAccessPolicy ||
			asset.CreateRequestFieldCaps["access_policy"] != asset.FieldCapAccessPolicy ||
			asset.ImportRowFieldCaps["access_policy"] != asset.FieldCapAccessPolicy {
			t.Error("access_policy 應歸為存取政策能力")
		}
	})

	t.Run("更新：缺憑證能力的逐欄變更皆 403 且零變更", func(t *testing.T) {
		env := newFieldCapEnv(t)
		a, err := env.assets.Create(asset.WithSystemCaller(context.Background()), &asset.CreateAssetRequest{
			Name: "srv", Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22,
			Username: "root", Password: "seed-pw", CreatedBy: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		accounts, audits := env.count(t, &model.AssetAccount{}), env.count(t, &model.AuditLog{})
		// 另一主體持有與這些欄位無關的憑證語義能力（建立、掛載）：五欄所需的是更新或更換秘密，
		// 仍一律 403，證明欄位能力依欄位對應的語義鍵判定，不因持有任一憑證能力就放行
		updateWithOtherCaps := customPrincipal(authz.PermAssetUpdate, authz.PermAssetView, authz.PermCredentialCreate, authz.PermCredentialBind)
		for name, p := range map[string]*authz.Principal{"只持資產寫入": updateOnly, "另持無關憑證能力": updateWithOtherCaps} {
			for _, body := range []string{
				`{"username":"other"}`, `{"password":"NewSecret-1"}`, `{"private_key":"-----BEGIN KEY-----"}`,
				`{"sftp_username":"sftp"}`, `{"sftp_password":"SftpSecret-1"}`,
			} {
				code, resp := env.call(p, "PUT", fmt.Sprintf("/api/v1/assets/%d", a.ID), body)
				if code != http.StatusForbidden {
					t.Errorf("%s %s：狀態 %d，應 403", name, body, code)
				}
				for _, leak := range []string{"credential:", "asset:update", "required_permission", "admin"} {
					if strings.Contains(resp, leak) {
						t.Errorf("%s %s：回應含 %q：%s", name, body, leak, resp)
					}
				}
			}
		}
		var row model.Asset
		env.db.First(&row, a.ID)
		if row.Username != "root" || env.count(t, &model.AssetAccount{}) != accounts || env.count(t, &model.AuditLog{}) != audits {
			t.Error("被拒絕的更新改動了資產列、帳號列或審計列")
		}

		// 同值 username＋空密碼：沒有實際變更，成功
		code, resp := env.call(updateOnly, "PUT", fmt.Sprintf("/api/v1/assets/%d", a.ID),
			`{"username":"root","password":"","description":"d1"}`)
		if code != http.StatusOK {
			t.Fatalf("同值 username 加空密碼應成功，狀態 %d：%s", code, resp)
		}

		// 夾帶伺服器自有欄位：不被套用
		code, _ = env.call(updateOnly, "PUT", fmt.Sprintf("/api/v1/assets/%d", a.ID),
			`{"description":"d2","created_by":999,"last_test_status":"success"}`)
		env.db.First(&row, a.ID)
		if code != http.StatusOK || row.CreatedBy == 999 || row.LastTestStatus == "success" {
			t.Errorf("伺服器自有欄位被套用：狀態 %d created_by=%d last_test_status=%q", code, row.CreatedBy, row.LastTestStatus)
		}

		// 持憑證管理能力者與超管：成功
		for name, p := range map[string]*authz.Principal{"全能力自訂角色": fullCustom, "超管": superAdmin} {
			code, resp := env.call(p, "PUT", fmt.Sprintf("/api/v1/assets/%d", a.ID),
				`{"username":"root","password":"Rotated-9","sftp_username":"sftp","sftp_password":"S-9"}`)
			if code != http.StatusOK {
				t.Errorf("%s：狀態 %d：%s", name, code, resp)
			}
		}
	})

	t.Run("建立：缺憑證能力的逐欄皆 403 且零變更", func(t *testing.T) {
		env := newFieldCapEnv(t)
		cred, err := env.creds.Create(operatorCtx(), &asset.CreateCredentialRequest{
			Name: "shared", Username: "root", Password: "pw", ProtocolFamily: model.ProtocolFamilySSH})
		if err != nil {
			t.Fatal(err)
		}
		base := `"name":"n%d","protocol":"ssh","host":"10.0.0.2","port":22`
		assets0, accounts0, audits0 := env.count(t, &model.Asset{}), env.count(t, &model.AssetAccount{}), env.count(t, &model.AuditLog{})
		extras := []string{
			`"username":"u"`, `"password":"p"`, `"private_key":"k"`, `"sftp_username":"s"`, `"sftp_password":"s"`,
			`"credential":{"username":"u","password":"p"}`, fmt.Sprintf(`"credential_id":%d`, cred.ID),
		}
		for i, extra := range extras {
			code, resp := env.call(createOnly, "POST", "/api/v1/assets", "{"+fmt.Sprintf(base, i)+","+extra+"}")
			if code != http.StatusForbidden {
				t.Errorf("%s：狀態 %d，應 403：%s", extra, code, resp)
			}
			if strings.Contains(resp, "credential:manage") || strings.Contains(resp, "asset:create") {
				t.Errorf("%s：回應含權限鍵：%s", extra, resp)
			}
		}
		if env.count(t, &model.Asset{}) != assets0 || env.count(t, &model.AssetAccount{}) != accounts0 || env.count(t, &model.AuditLog{}) != audits0 {
			t.Error("被拒絕的建立改動了資產、帳號或審計列")
		}

		// 不帶受限欄位且夾帶伺服器自有欄位：成功，自有欄位不被套用
		code, resp := env.call(createOnly, "POST", "/api/v1/assets",
			`{"name":"plain","protocol":"vnc","host":"10.0.0.3","port":5900,"created_by":999,"last_test_status":"success"}`)
		if code != http.StatusCreated {
			t.Fatalf("無受限欄位的建立應成功，狀態 %d：%s", code, resp)
		}
		var row model.Asset
		env.db.Where("name = ?", "plain").First(&row)
		if row.CreatedBy == 999 || row.LastTestStatus == "success" {
			t.Errorf("伺服器自有欄位被套用：created_by=%d last_test_status=%q", row.CreatedBy, row.LastTestStatus)
		}

		for name, p := range map[string]*authz.Principal{"全能力自訂角色": fullCustom, "超管": superAdmin} {
			code, resp := env.call(p, "POST", "/api/v1/assets",
				fmt.Sprintf(`{"name":"ok-%s","protocol":"ssh","host":"10.0.0.4","port":22,"username":"root","password":"pw"}`, name))
			if code != http.StatusCreated {
				t.Errorf("%s：狀態 %d：%s", name, code, resp)
			}
		}
	})

	t.Run("匯入：預檢與提交套用同一判定，任一列缺能力整批拒絕", func(t *testing.T) {
		env := newFieldCapEnv(t)
		cred, err := env.creds.Create(operatorCtx(), &asset.CreateCredentialRequest{
			Name: "shared", Username: "root", Password: "pw", ProtocolFamily: model.ProtocolFamilySSH})
		if err != nil {
			t.Fatal(err)
		}
		withCred := fmt.Sprintf(`{"source":"form","rows":[
			{"name":"i1","protocol":"ssh","host":"10.1.0.1"},
			{"name":"i2","protocol":"ssh","host":"10.1.0.2","credential_id":%d},
			{"name":"i3","protocol":"ssh","host":"10.1.0.3"}]}`, cred.ID)
		plain := `{"source":"form","rows":[
			{"name":"p1","protocol":"ssh","host":"10.1.1.1"},{"name":"p2","protocol":"ssh","host":"10.1.1.2"}]}`

		n0 := env.count(t, &model.Asset{})
		if code, _ := env.call(createOnly, "POST", "/api/v1/assets/import/preview", withCred); code != http.StatusForbidden {
			t.Errorf("缺能力主體的預檢應 403，實為 %d", code)
		}
		if code, _ := env.call(createOnly, "POST", "/api/v1/assets/import", withCred); code != http.StatusForbidden {
			t.Errorf("缺能力主體的提交應 403，實為 %d", code)
		}
		if env.count(t, &model.Asset{}) != n0 {
			t.Error("被拒絕的匯入改動了資產數")
		}

		// 預檢以超管通過後，改用缺能力主體提交仍 403
		if code, resp := env.call(superAdmin, "POST", "/api/v1/assets/import/preview", withCred); code != http.StatusOK {
			t.Fatalf("超管預檢應通過，狀態 %d：%s", code, resp)
		}
		if code, _ := env.call(createOnly, "POST", "/api/v1/assets/import", withCred); code != http.StatusForbidden {
			t.Errorf("預檢通過後以缺能力主體提交仍應 403，實為 %d", code)
		}
		if env.count(t, &model.Asset{}) != n0 {
			t.Error("提交被拒後資產數改變")
		}

		// 全部列都不帶受限欄位：缺能力主體也能匯入
		if code, resp := env.call(createOnly, "POST", "/api/v1/assets/import", plain); code != http.StatusCreated {
			t.Errorf("不帶受限欄位的匯入應成功，狀態 %d：%s", code, resp)
		}
		if got := env.count(t, &model.Asset{}); got != n0+2 {
			t.Errorf("匯入後資產數 %d，應為 %d", got, n0+2)
		}
		if code, resp := env.call(superAdmin, "POST", "/api/v1/assets/import", withCred); code != http.StatusCreated {
			t.Errorf("超管匯入含憑證列應成功，狀態 %d：%s", code, resp)
		}
	})
}
