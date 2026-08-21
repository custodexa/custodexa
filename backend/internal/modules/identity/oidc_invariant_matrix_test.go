package identity

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 資料層不變式與解綁判準矩陣（idp-oidc-integration tasks 4.16）。
//
// 本檔補的是既有測試的**矩陣缺格**，不重複既有案：
//
//	nbf 容忍窗內外兩側    已由 oidc_verify_test.go 覆蓋（逾窗拒、窗內過、
//	                      已生效過、型別不符拒 共四案），本檔不重複。
//	password='' ⟹        新增：遍歷全部會寫 users 的操作後掃全表斷言。
//	  external_credential  單看個別操作的回傳值測不到這條——它是「任一寫入
//	                      路徑漏設旗標」的橫向守衛。
//	解綁判準正反矩陣      external_identity_service_test.go 已覆蓋三分支的
//	                      代表案；本檔補漂移形態（旗標與密碼不一致）、目錄
//	                      供應的兩種形態、以及「多身分逐筆解綁到被拒後改走
//	                      解綁＋停用」的完整出路。

// --- password='' ⟹ external_credential=true 守衛 ---

// assertNoOrphanEmptyPassword 掃 users 全表：密碼為空者必為外部化帳號。
//
// 為什麼是不變式而非個別斷言：空密碼列代表「本地密碼登入永遠無法成立」，
// 若該列的 external_credential 仍是 false，系統會把它當本地帳號——
// 解綁判準（hasLoginPathAfterUnbind）會認定它「仍可本地登入」而放行解綁最後
// 一筆外部身分，製造出零登入途徑的孤兒帳號
func assertNoOrphanEmptyPassword(t *testing.T, db *gorm.DB, step string) {
	t.Helper()
	var rows []model.User
	if err := db.Where("TRIM(password) = '' AND external_credential = ?", false).
		Find(&rows).Error; err != nil {
		t.Fatalf("[%s] 掃描 users 失敗: %v", step, err)
	}
	for _, u := range rows {
		t.Errorf("[%s] 不變式破損：id=%d username=%q 密碼為空卻未標記 external_credential",
			step, u.ID, u.Username)
	}
}

// TestUsersEmptyPasswordImpliesExternalAcrossWritePaths（4.16）遍歷全部會寫入
// users 的路徑，每一步後斷言不變式。
//
// 涵蓋三個建號路徑（本地建號／LDAP 影子供應／OIDC 首登供應）、密碼設定路徑、
// 外部身分四操作，以及狀態類更新（停用、資料更新、解鎖）
func TestUsersEmptyPasswordImpliesExternalAcrossWritePaths(t *testing.T) {
	env := setupRegressionEnv(t)
	extEnv := newExtIdentityEnv(t, env.db)
	// 身分域唯一索引：production 由 migration 建（partial），AutoMigrate 不產生
	if err := env.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_uei_domain_matrix
		ON user_external_identities(issuer, client_id, subject) WHERE deleted_at IS NULL`).Error; err != nil {
		t.Fatalf("identity domain unique index: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "初始")

	// (1) 本地建號
	created, err := env.users.Create(&CreateUserRequest{
		Username: "local-created", Password: "InitPassword123",
		Email: "local-created@example.com", Roles: []string{model.RoleUser}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "UserService.Create")

	// (2) admin 重設與自助改密
	if err := env.users.ChangePassword(created.ID, "ResetPassword456"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "UserService.ChangePassword")
	if err := env.users.SelfChangePassword(created.ID, "ResetPassword456", "SelfPassword789"); err != nil {
		t.Fatalf("SelfChangePassword: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "UserService.SelfChangePassword")

	// (3) LDAP 影子供應（走真實登入路徑，不直接造列）
	env.auth.SetLDAPResolver(staticLDAPResolver(&fakeLDAPAuthenticator{
		info: &LDAPUserInfo{Username: "dir-shadow"}}))
	if _, err := env.auth.Login(&LoginRequest{Username: "dir-shadow", Password: "dirpass"}); err != nil {
		t.Fatalf("LDAP 首登: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "provisionShadowUser")

	// (4) OIDC 首登供應（JIT）
	jit := jitProvider(t, env.db)
	login := NewOIDCLoginService(env.db, NewOIDCProviderService(env.db, nil, testEgress(), nil,
		"https://bastion.example.com"), NewOIDCDiscoveryService(testEgress()), env.auth, nil)
	login.audit = newRecordingAudit()
	if _, err := login.resolveOrProvision(jit, oidcClaims("sub-jit", map[string]any{
		"preferred_username": "jit-user", "hd": "corp.example"}), &oidcAuditTrail{}); err != nil {
		t.Fatalf("OIDC 首登供應: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "provisionFromClaims")

	// (5) 外部身分綁定 → 改為僅外部登入（唯一會把 password 寫成空字串的路徑）
	seedRegressionUser(t, env, "keeper-admin", "KeeperPass1", nil) // 保住本地 admin 不變式不擋路
	p := seedExtProvider(t, env.db, "corp2", "https://idp2.example.com", "cid-2")
	idKeep := mustBind(t, extEnv, created.ID, p, "sub-created")
	assertNoOrphanEmptyPassword(t, env.db, "BindExternalIdentity")

	if err := extEnv.svc.ConvertToExternalOnly(created.ID, testActor); err != nil {
		t.Fatalf("ConvertToExternalOnly: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "ConvertToExternalOnly")
	// 前提校驗：本步驟確實製造了空密碼列（否則不變式恆真而測試無效）
	if converted := reloadUser(t, env.db, created.ID); converted.Password != "" ||
		!converted.ExternalCredential {
		t.Fatalf("轉換後應為 (password='', external_credential=true)，got (%q, %v)",
			converted.Password, converted.ExternalCredential)
	}

	// (6) 解綁＋停用（外部化帳號移除最後一筆身分的正當出路）
	if err := extEnv.svc.UnbindExternalIdentityAndDisable(created.ID, idKeep, testActor); err != nil {
		t.Fatalf("UnbindExternalIdentityAndDisable: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "UnbindExternalIdentityAndDisable")

	// (7) 狀態類更新：停用、資料更新、解鎖、解綁
	other := seedRegressionUser(t, env, "other-local", "OtherPass1", nil)
	idOther := mustBind(t, extEnv, other.ID, p, "sub-other")
	if err := extEnv.svc.UnbindExternalIdentity(other.ID, idOther, testActor); err != nil {
		t.Fatalf("UnbindExternalIdentity: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "UnbindExternalIdentity")
	if err := env.users.UpdateStatus(other.ID, false); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "UpdateStatus")
	if _, _, err := env.users.Update(other.ID, &UpdateUserRequest{FullName: "Renamed"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "UserService.Update")
	if err := env.users.Unlock(other.ID); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	assertNoOrphanEmptyPassword(t, env.db, "Unlock")
}

// TestEmptyPasswordAccountCannotLoginLocally（4.16）空密碼帳號的本地登入必敗。
//
// 守衛的另一半：即使某條路徑真的留下了空密碼的非外部化列（漂移），
// 空字串也不得成為可用密碼——bcrypt 對空雜湊必然比對失敗，此處把該行為
// 釘成契約，避免日後有人為「相容」而在比對前特判空值
func TestEmptyPasswordAccountCannotLoginLocally(t *testing.T) {
	env := setupRegressionEnv(t)
	// 直接造漂移列（繞過所有服務路徑）：這是守衛要防的最壞情況
	drift := seedRegressionUser(t, env, "drifted", "", nil)
	if reloadUser(t, env.db, drift.ID).Password != "" {
		t.Fatal("前提不成立：漂移列的密碼應為空")
	}

	for _, pwd := range []string{"", " ", "anything"} {
		if _, err := env.auth.Login(&LoginRequest{Username: "drifted", Password: pwd}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("空密碼帳號以 %q 登入 = %v, want ErrInvalidCredentials", pwd, err)
		}
	}
}

// --- 解綁判準正反矩陣（補缺格） ---

// unbindCase 一種帳號形態下解綁「最後一筆／非最後一筆」的期望
type unbindCase struct {
	name string
	// spec 帳號三訊號
	spec adminSpec
	// emptyPassword 把密碼雜湊清成空字串（模擬旗標與密碼不一致的漂移）
	emptyPassword bool
	// identities 綁定的身分數；解綁其中第一筆
	identities int
	wantAllow  bool
}

// TestUnbindCriterionMatrix（4.16）解綁判準的正反矩陣。
//
// 既有測試（external_identity_service_test.go）已覆蓋三分支的代表案：
// 本地密碼者解綁最後一筆、目錄供應帳號、外部化者被拒、非最後一筆可解。
// 此處補的是**組合與漂移形態**：
//
//	目錄旗標與供應來源各自單獨成立時是否皆放行（兩個訊號是 OR 關係）；
//	external_credential=false 但密碼為空的漂移列必須 fail-close（該分支
//	  只有這一格會走到，缺它等於「額外的 fail-close」形同未測）；
//	OIDC 來源但保有本地密碼（旗標未設）仍視為外部——IsExternal() 以來源
//	  判定，此格釘住語義，避免日後有人把判準改成只看 external_credential
func TestUnbindCriterionMatrix(t *testing.T) {
	cases := []unbindCase{
		{
			name:       "本地帳號有密碼／最後一筆",
			spec:       adminSpec{username: "u", active: true},
			identities: 1, wantAllow: true,
		},
		{
			name:          "本地旗標但密碼為空（漂移）／最後一筆",
			spec:          adminSpec{username: "u", active: true},
			emptyPassword: true,
			identities:    1, wantAllow: false,
		},
		{
			name:       "LDAP 影子帳號（is_ldap＋外部化）／最後一筆",
			spec:       adminSpec{username: "u", active: true, ldapUser: true, extCred: true, origin: model.AuthSourceLDAP},
			identities: 1, wantAllow: true,
		},
		{
			name:       "僅供應來源為 ldap（旗標漂移）／最後一筆",
			spec:       adminSpec{username: "u", active: true, origin: model.AuthSourceLDAP},
			identities: 1, wantAllow: true,
		},
		{
			name:       "OIDC 外部化／最後一筆",
			spec:       adminSpec{username: "u", active: true, extCred: true, origin: model.AuthSourceOIDC},
			identities: 1, wantAllow: false,
		},
		{
			name:       "OIDC 外部化／非最後一筆",
			spec:       adminSpec{username: "u", active: true, extCred: true, origin: model.AuthSourceOIDC},
			identities: 2, wantAllow: true,
		},
		{
			name:       "OIDC 來源但保有本地密碼（旗標未設）／最後一筆",
			spec:       adminSpec{username: "u", active: true, origin: model.AuthSourceOIDC},
			identities: 1, wantAllow: false,
		},
		{
			name:          "僅外部登入（來源 local＋旗標＋空密碼）／最後一筆",
			spec:          adminSpec{username: "u", active: true, extCred: true},
			emptyPassword: true,
			identities:    1, wantAllow: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			db := extIdentityDB(t)
			env := newExtIdentityEnv(t, db)
			u := seedAccount(t, db, c.spec)
			if c.emptyPassword {
				if err := db.Model(&model.User{}).Where("id = ?", u.ID).
					Update("password", "").Error; err != nil {
					t.Fatalf("清空密碼: %v", err)
				}
			}
			var target uint
			for i := 0; i < c.identities; i++ {
				p := seedExtProvider(t, db, "p"+string(rune('a'+i)),
					"https://idp"+string(rune('a'+i))+".example.com", "cid-"+string(rune('a'+i)))
				id := mustBind(t, env, u.ID, p, "sub-"+string(rune('a'+i)))
				if i == 0 {
					target = id
				}
			}

			err := env.svc.UnbindExternalIdentity(u.ID, target, testActor)
			if c.wantAllow {
				if err != nil {
					t.Fatalf("應允許解綁，got %v", err)
				}
				if n := identityCount(t, db, u.ID); n != int64(c.identities-1) {
					t.Fatalf("解綁後身分數 = %d, want %d", n, c.identities-1)
				}
				if e := reloadUser(t, db, u.ID).CredentialEpoch; e != 1 {
					t.Fatalf("成功解綁應推進世代，got %d", e)
				}
				return
			}
			if !errors.Is(err, ErrLastLoginPath) {
				t.Fatalf("應以登入途徑判準拒絕，got %v", err)
			}
			// 拒絕零副作用
			if n := identityCount(t, db, u.ID); n != int64(c.identities) {
				t.Fatalf("拒絕後身分應原封不動，got %d", n)
			}
			if e := reloadUser(t, db, u.ID).CredentialEpoch; e != 0 {
				t.Fatalf("拒絕後不得推進世代，got %d", e)
			}
			if len(env.sessions.calls)+len(env.subs.calls)+len(env.tokens.calls) != 0 {
				t.Fatal("拒絕後不得執行任何收線")
			}
		})
	}
}

// TestUnbindLastIdentityFallsBackToUnbindAndDisable（4.16）正反矩陣的完整出路：
// 多身分外部化帳號逐筆解綁 → 最後一筆被拒 → 改走「解綁＋停用」成功。
//
// 三步必須串在同一個帳號上：分開測會漏掉「被拒之後帳號仍處於可再操作的乾淨
// 狀態」這一點（例如拒絕路徑若殘留半推進的世代或已刪的身分，第三步就不成立）
func TestUnbindLastIdentityFallsBackToUnbindAndDisable(t *testing.T) {
	db := extIdentityDB(t)
	env := newExtIdentityEnv(t, db)
	u := seedAccount(t, db, adminSpec{username: "oidcer", active: true,
		extCred: true, origin: model.AuthSourceOIDC})
	p1 := seedExtProvider(t, db, "corp", "https://idp.example.com", "cid-1")
	p2 := seedExtProvider(t, db, "okta", "https://okta.example.com", "cid-2")
	id1 := mustBind(t, env, u.ID, p1, "sub-1")
	id2 := mustBind(t, env, u.ID, p2, "sub-2")

	if err := env.svc.UnbindExternalIdentity(u.ID, id1, testActor); err != nil {
		t.Fatalf("解綁非最後一筆應允許: %v", err)
	}
	if err := env.svc.UnbindExternalIdentity(u.ID, id2, testActor); !errors.Is(err, ErrLastLoginPath) {
		t.Fatalf("解綁最後一筆 = %v, want ErrLastLoginPath", err)
	}
	if err := env.svc.UnbindExternalIdentityAndDisable(u.ID, id2, testActor); err != nil {
		t.Fatalf("解綁＋停用應為正當出路: %v", err)
	}

	if n := identityCount(t, db, u.ID); n != 0 {
		t.Fatalf("身分應已全數解除，got %d", n)
	}
	final := reloadUser(t, db, u.ID)
	if final.Active {
		t.Fatal("帳號應已停用（不得停在「已解綁但仍宣稱可登入」的中間態）")
	}
	// 世代推進次數＝成功操作數（解綁 1 次＋解綁停用 1 次），被拒那次不算
	if final.CredentialEpoch != 2 {
		t.Fatalf("credential_epoch = %d, want 2（兩次成功操作，被拒者不推進）",
			final.CredentialEpoch)
	}
}
