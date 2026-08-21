package identity

import (
	"context"
	"github.com/custodexa/backend/internal/modules/policy"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 登入路徑的單次設定解析（ldap-settings-migration D2／tasks 2.8）。
//
// 本檔驗的是**接線的不變式**而非 LDAP 判定規則：
//
//  1. 每次登入只解析一次，且傳輸閘看到的參數就是撥號用的參數；
//  2. 設定於登入進行中被改動時不出現「閘按安全設定放行、撥號用不安全設定
//     送出密碼」的交錯；
//  3. 解析故障 fail-close，且**不偽裝成「未啟用」**——可由審計辨識。

// recordingLDAPAuth 記錄「這次撥號用的是哪一份 URL」的認證器替身。
//
// 沒有這個接縫就無從證明閘與撥號同源：真認證器會直接去撥網路，
// 而 fake 認證器不帶設定，兩者都看不出「撥號實際使用了哪一份解析結果」
type recordingLDAPAuth struct {
	url    string
	info   *LDAPUserInfo
	mu     *sync.Mutex
	dialed *[]string
}

func (r *recordingLDAPAuth) Authenticate(username, password string) (*LDAPUserInfo, error) {
	if r.mu != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
	}
	*r.dialed = append(*r.dialed, r.url)
	return r.info, nil
}

// setupLDAPResolutionEnv 真 sqlite 換入 database.DB（登入全流程真跑）；
// 傳輸政策服務不接 provider——風險項一律來自登入解析結果，正是本檔要釘的事
func setupLDAPResolutionEnv(t *testing.T) (*AuthService, *policy.SecurityPolicyService, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// 單連線：sqlite :memory: 每條連線是各自獨立的庫（本專案既有 flaky 真因，ff51836）
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.User{}, &model.Role{}, &model.RefreshToken{},
		&model.AuditLog{}, &model.SecurityPolicy{}, &model.PasswordHistory{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Create(&model.Role{Name: model.RoleUser}).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	authService := NewAuthService("test-secret", 15*time.Minute)
	policies := policy.NewSecurityPolicyService(db)
	authService.SetTransmissionPolicy(policy.NewTransmissionPolicyService(policies, nil))
	return authService, policies, db
}

// TestLDAPLoginSingleResolutionPerLogin 一次登入只解析一次，且閘與撥號同源。
//
// resolver 每被呼叫一次就回不同的設定（第 1 次 ldaps 安全、第 2 次 ldap 明文），
// 政策為 strict。正確接線下：解析一次、閘看見無風險而放行、撥號用第 1 次的
// ldaps。若日後有人把撥號改成「再解析一次」，第 2 次解析的明文設定就會在
// strict 檔位下被送出——本格以「解析次數」與「實際撥號的 URL」雙重釘住
func TestLDAPLoginSingleResolutionPerLogin(t *testing.T) {
	authService, policies, _ := setupLDAPResolutionEnv(t)
	if _, err := policies.Update(policy.PolicyTransportLDAPLevel, policy.TransportLevelStrict, "admin"); err != nil {
		t.Fatalf("設定政策檔位: %v", err)
	}

	views := []policy.LDAPRiskView{
		{Enabled: true, URL: "ldaps://dir.internal:636"},
		{Enabled: true, URL: "ldap://dir.internal:389"},
	}
	calls := 0
	var dialed []string
	authService.SetLDAPResolver(func() LDAPLoginResolution {
		view := views[len(views)-1]
		if calls < len(views) {
			view = views[calls]
		}
		calls++
		return LDAPLoginResolution{
			State: LDAPLoginReady,
			Risks: policy.LDAPRisksOf(view),
			Auth: &recordingLDAPAuth{
				url:    view.URL,
				info:   &LDAPUserInfo{Username: "ldapuser"},
				dialed: &dialed,
			},
		}
	})

	if _, err := authService.Login(&LoginRequest{Username: "ldapuser", Password: "pass123"}); err != nil {
		t.Fatalf("第一次解析為安全設定，strict 不應擋: %v", err)
	}
	if calls != 1 {
		t.Errorf("單次登入的解析次數 = %d, want 1（閘與撥號各讀一次即開 TOCTOU 窗口）", calls)
	}
	if len(dialed) != 1 || dialed[0] != "ldaps://dir.internal:636" {
		t.Errorf("撥號使用的設定 = %v, want [ldaps://dir.internal:636]（閘判定所依據的那一份）", dialed)
	}
}

// TestLDAPLoginNoInterleaveUnderConcurrentSettingChange 設定於登入進行中被改動時，
// 閘判定與撥號使用同一份解析結果。
//
// 以真 LDAPDirectoryService 現讀 DB，另一 goroutine 持續在 ldaps://（安全）與
// ldap://（明文）之間翻動設定；政策為 strict。不變式：**明文設定永遠不會被
// 撥號**——要嘛解析到 ldaps 而正常撥號，要嘛解析到 ldap 而在撥號前被閘擋下。
// 若閘與撥號各讀一次 DB，翻動會落進兩次讀取之間而讓明文設定被送出
func TestLDAPLoginNoInterleaveUnderConcurrentSettingChange(t *testing.T) {
	authService, policies, _ := setupLDAPResolutionEnv(t)
	if _, err := policies.Update(policy.PolicyTransportLDAPLevel, policy.TransportLevelStrict, "admin"); err != nil {
		t.Fatalf("設定政策檔位: %v", err)
	}

	dirSvc, dirDB := newLDAPDirectorySvc(t)
	if _, err := dirSvc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
		t.Fatalf("建立目錄設定: %v", err)
	}

	var mu sync.Mutex
	var dialed []string
	authService.SetLDAPResolver(newLDAPLoginResolverWith(dirSvc, func(snap LDAPDialSnapshot) LDAPAuthenticator {
		return &recordingLDAPAuth{
			url:    snap.URL,
			info:   &LDAPUserInfo{Username: "ldapuser"},
			mu:     &mu,
			dialed: &dialed,
		}
	}))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		urls := []string{"ldap://dir.example:389", "ldaps://dir.example:636"}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := dirDB.Model(&model.LDAPDirectory{}).Where("singleton = 1").
				Update("url", urls[i%len(urls)]).Error; err != nil {
				return
			}
			runtime.Gosched()
		}
	}()

	const rounds = 200
	for i := 0; i < rounds; i++ {
		// 成敗皆可接受：明文設定被 strict 擋下是正確行為，本格斷言的是撥號內容
		_, _ = authService.Login(&LoginRequest{Username: "ldapuser", Password: "pass123"})
	}
	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(dialed) == 0 {
		t.Fatal("整輪沒有任何撥號——本格未實際覆蓋撥號路徑")
	}
	for _, url := range dialed {
		if !strings.HasPrefix(strings.ToLower(url), "ldaps://") {
			t.Fatalf("strict 檔位下以 %q 撥號：閘判定與撥號用了不同的解析結果（%d 次撥號中出現明文）",
				url, len(dialed))
		}
	}
}

// TestLDAPLoginFailCloseOnResolveFailure 解析故障 fail-close 且可辨識。
//
// 三件事同時成立才算正確：(1) 登入被拒；(2) 不撥號（密碼不出門）；
// (3) 審計留下可辨識為「設定解析失敗」的事件——**不得偽裝成「未啟用」**。
// 第 (3) 點是重點：金鑰事故下全體目錄使用者同時登不進來，若審計只留一片
// 「密碼錯誤」，管理員會去查目錄與使用者，而真因在金鑰
func TestLDAPLoginFailCloseOnResolveFailure(t *testing.T) {
	authService, _, db := setupLDAPResolutionEnv(t)

	var dialed []string
	authService.SetLDAPResolver(func() LDAPLoginResolution {
		return LDAPLoginResolution{
			State: LDAPLoginFailed,
			Err:   context.DeadlineExceeded,
			// 故障態仍附認證器：若實作誤把故障當可用，撥號就會發生而被下方斷言抓到
			Auth: &recordingLDAPAuth{url: "ldap://dir.internal:389", dialed: &dialed,
				info: &LDAPUserInfo{Username: "ldapuser"}},
		}
	})

	_, err := authService.Login(&LoginRequest{Username: "ldapuser", Password: "pass123"})
	if err == nil {
		t.Fatal("解析故障時登入應被拒（fail-close）")
	}
	// 對外收斂為憑證錯誤：不洩漏「系統內部出事了」這個訊號
	if err != ErrInvalidCredentials {
		t.Errorf("對外錯誤 = %v, want ErrInvalidCredentials（不洩漏內部狀態）", err)
	}
	if len(dialed) != 0 {
		t.Errorf("解析故障仍撥號 %v——密碼已出門", dialed)
	}

	var n int64
	if err := db.Model(&model.AuditLog{}).
		Where("resource = ? AND details LIKE ?", model.ResourceAuth, "%ldap_resolve_failed%").
		Count(&n).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	if n != 1 {
		t.Errorf("ldap_resolve_failed 審計筆數 = %d, want 1（故障不得偽裝成未啟用而無痕）", n)
	}

	// 本地帳號不受影響（故障只擋目錄路徑）
	hashed, herr := bcrypt.GenerateFromPassword([]byte("localpass123"), bcrypt.MinCost)
	if herr != nil {
		t.Fatal(herr)
	}
	if err := db.Create(&model.User{Username: "localadmin", Password: string(hashed), Active: true}).Error; err != nil {
		t.Fatalf("seed local user: %v", err)
	}
	if _, err := authService.Login(&LoginRequest{Username: "localadmin", Password: "localpass123"}); err != nil {
		t.Errorf("目錄解析故障時本地登入仍應成功: %v", err)
	}
}

// TestLDAPLoginUnavailableKeepsDisabledSemantics 未設定／已停用維持既有
// 「LDAP 未啟用」語義：查無帳號回憑證錯誤、不撥號、無故障審計
func TestLDAPLoginUnavailableKeepsDisabledSemantics(t *testing.T) {
	authService, _, db := setupLDAPResolutionEnv(t)

	var dialed []string
	authService.SetLDAPResolver(func() LDAPLoginResolution {
		return LDAPLoginResolution{
			State: LDAPLoginUnavailable,
			Auth: &recordingLDAPAuth{url: "ldap://dir.internal:389", dialed: &dialed,
				info: &LDAPUserInfo{Username: "ldapuser"}},
		}
	})

	if _, err := authService.Login(&LoginRequest{Username: "ldapuser", Password: "pass123"}); err != ErrInvalidCredentials {
		t.Errorf("未啟用時錯誤 = %v, want ErrInvalidCredentials", err)
	}
	if len(dialed) != 0 {
		t.Errorf("未啟用仍撥號 %v", dialed)
	}
	var n int64
	db.Model(&model.AuditLog{}).Where("details LIKE ?", "%ldap_resolve_failed%").Count(&n)
	if n != 0 {
		t.Errorf("未啟用不應產生解析故障審計，實得 %d 筆", n)
	}
}

// TestLDAPLoginResolverDisabledRowIsUnavailable 生產 resolver 對「有設定列但停用」
// 回 unavailable（停用即時生效，spec scenario），對「無列」亦然；兩者皆不建認證器
func TestLDAPLoginResolverDisabledRowIsUnavailable(t *testing.T) {
	dirSvc, _ := newLDAPDirectorySvc(t)
	built := 0
	resolver := newLDAPLoginResolverWith(dirSvc, func(LDAPDialSnapshot) LDAPAuthenticator {
		built++
		return &fakeLDAPAuthenticator{info: &LDAPUserInfo{Username: "ldapuser"}}
	})

	if got := resolver(); got.State != LDAPLoginUnavailable {
		t.Errorf("無設定列的解析 = %q, want unavailable", got.State)
	}
	if _, err := dirSvc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
		r.Enabled = false
	})); err != nil {
		t.Fatalf("建立停用設定: %v", err)
	}
	if got := resolver(); got.State != LDAPLoginUnavailable {
		t.Errorf("停用設定的解析 = %q, want unavailable", got.State)
	}
	if built != 0 {
		t.Errorf("不可撥號的狀態仍建了 %d 次認證器", built)
	}

	if _, err := dirSvc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
		t.Fatalf("改為啟用: %v", err)
	}
	got := resolver()
	if got.State != LDAPLoginReady || got.Auth == nil {
		t.Errorf("啟用設定的解析 = %q, auth 空=%v, want ready＋認證器", got.State, got.Auth == nil)
	}
	if len(got.Risks) != 0 {
		t.Errorf("ldaps 設定的風險項 = %v, want 空", riskKeys(got.Risks))
	}
}
