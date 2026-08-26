package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// LDAPDirectoryService 的 singleton CRUD、存檔閘與三態解析覆蓋。
//
// 測試庫以 AutoMigrate 建表——**刻意的例外**，同 newLDAPSeedDB 的理由：生產走
// versioned migration（CHECK 約束需求），本檔驗的是服務層語義，不依賴 CHECK。
// DB 層不變式的驗證在 repository 的 pg-gated 測試。

// ldapRiskProvider／ldapRiskProviderState／newTransmissionSvc 測試助手。
// 原宣告於 transmission_policy_service_test.go，該檔已遷入 internal/modules/policy；
// 本包測試仍在用，故保留同名同義的宣告（實作逐行相同，只調整型別限定）。
func ldapRiskProvider(view policy.LDAPRiskView) func() policy.LDAPRiskResult {
	return func() policy.LDAPRiskResult {
		return policy.LDAPRiskResult{State: policy.LDAPResolveOK, View: view}
	}
}

func ldapRiskProviderState(state policy.LDAPResolveState) func() policy.LDAPRiskResult {
	return func() policy.LDAPRiskResult {
		return policy.LDAPRiskResult{State: state}
	}
}

// newPolicyServiceForTest 建一個以 in-memory sqlite 為底的政策服務
// （原 setupPolicyDB 隨 security_policy_service_test.go 遷入 policy 包）
func newPolicyServiceForTest(t *testing.T) *policy.SecurityPolicyService {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.SecurityPolicy{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return policy.NewSecurityPolicyService(db)
}

func newTransmissionSvc(t *testing.T, provider func() policy.LDAPRiskResult) *policy.TransmissionPolicyService {
	t.Helper()
	return policy.NewTransmissionPolicyService(newPolicyServiceForTest(t), provider)
}

// riskKeys 取風險項 key 清單（測試比對用）。
// 原宣告於 transmission_policy_service_test.go，該檔已遷入 internal/modules/policy；
// 本包測試仍在用，故保留同名同義的宣告。
func riskKeys(risks []policy.RiskItem) []string {
	out := make([]string, 0, len(risks))
	for _, r := range risks {
		out = append(out, r.Key)
	}
	return out
}

func newLDAPDirectoryDB(t *testing.T) *gorm.DB {
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
	if err := db.AutoMigrate(&model.LDAPDirectory{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// ldapAllowAllGate 明確的放行閘（測試專用）。
//
// **測試不得靠 nil gate 取得放行**：nil 已是 fail-close 的哨兵語義
// （ErrLDAPTransmissionGateUnavailable），若測試沿用 nil 表達「不關心閘」，
// 「閘缺席等於沒有防護」這個突變就永遠不會被任何一格抓到
type ldapAllowAllGate struct{}

func (ldapAllowAllGate) CheckSettingSave(string, []policy.RiskItem, bool) error { return nil }
func (ldapAllowAllGate) ChannelLevel(string) string                             { return policy.TransportLevelOff }

// newLDAPDirectorySvc 建服務＋真 AES codec（密文須真的不是明文，才驗得到「抹密文」）
// ＋明確的 allow-all 閘（閘語義另由 newLDAPGateSvc 的真 policy 覆蓋）
func newLDAPDirectorySvc(t *testing.T) (*LDAPDirectoryService, *gorm.DB) {
	t.Helper()
	db := newLDAPDirectoryDB(t)
	svc := NewLDAPDirectoryService(db, aesColumnCodec(t, kmTestKey(0x42)), audit.NewTxSink())
	svc.SetTransmissionPolicy(ldapAllowAllGate{})
	return svc, db
}

// ldapDirReq 合法的啟用態請求（ldaps 無風險，故存檔閘不介入密碼語義測試）
func ldapDirReq(mut func(*LDAPDirectoryRequest)) LDAPDirectoryRequest {
	req := LDAPDirectoryRequest{
		Name:         "主目錄",
		URL:          "ldaps://dir.example:636",
		BindDN:       "cn=svc,dc=example,dc=com",
		BaseDN:       "ou=users,dc=example,dc=com",
		UserFilter:   "(uid=%s)",
		AttrEmail:    "mail",
		AttrFullName: "cn",
		BindPassword: "s3cret-bind",
		Enabled:      true,
		Actor:        LDAPDirectoryActor{ID: 7, Name: "admin", IP: "10.1.2.3"},
	}
	if mut != nil {
		mut(&req)
	}
	return req
}

func ldapDirRow(t *testing.T, db *gorm.DB) model.LDAPDirectory {
	t.Helper()
	var rows []model.LDAPDirectory
	if err := db.Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("查詢設定列: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("live 列數 = %d, want 1", len(rows))
	}
	return rows[0]
}

func ldapDirAudits(t *testing.T, db *gorm.DB) []map[string]any {
	t.Helper()
	var logs []model.AuditLog
	if err := db.Order("id ASC").Find(&logs).Error; err != nil {
		t.Fatalf("查詢審計: %v", err)
	}
	out := make([]map[string]any, 0, len(logs))
	for _, l := range logs {
		var d map[string]any
		if err := json.Unmarshal([]byte(l.Details), &d); err != nil {
			t.Fatalf("審計 details 非 JSON: %v", err)
		}
		d["_status"] = string(l.Status)
		d["_action"] = string(l.Action)
		out = append(out, d)
	}
	return out
}

func ldapDirAuditOf(t *testing.T, db *gorm.DB, event string) map[string]any {
	t.Helper()
	for _, a := range ldapDirAudits(t, db) {
		if a["event"] == event {
			return a
		}
	}
	t.Fatalf("審計缺 event=%s，實得 %v", event, ldapDirAudits(t, db))
	return nil
}

// ── 密碼語義四格 ───────────────────────────────────────────────────

func TestLDAPDirectoryBindPasswordSemantics(t *testing.T) {
	t.Run("空密碼沿用既存", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
			t.Fatalf("建立: %v", err)
		}
		before := ldapDirRow(t, db).BindPasswordEnc

		view, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.BindPassword = ""
			r.BaseDN = "ou=staff,dc=example,dc=com"
		}))
		if err != nil {
			t.Fatalf("更新: %v", err)
		}
		if !view.HasBindPassword {
			t.Error("沿用後 has_bind_password 應為 true")
		}
		row := ldapDirRow(t, db)
		if row.BindPasswordEnc != before {
			t.Error("空密碼應沿用既存密文，實得已變更")
		}
		if row.BaseDN != "ou=staff,dc=example,dc=com" {
			t.Errorf("base_dn 未更新 = %q", row.BaseDN)
		}
		// 撥號快照仍解得回原密碼
		res := svc.ResolveDialSnapshot(context.Background())
		if res.State != policy.LDAPResolveOK || res.Snapshot.BindPassword != "s3cret-bind" {
			t.Errorf("解析 = %+v, want ok 且密碼沿用", res.State)
		}
	})

	t.Run("顯式清除抹除密文", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
			t.Fatalf("建立: %v", err)
		}
		// enabled=true 要求 has_bind_password，清除後只能是草稿
		view, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.BindPassword = ""
			r.ClearBindPassword = true
			r.Enabled = false
		}))
		if err != nil {
			t.Fatalf("清除: %v", err)
		}
		if view.HasBindPassword {
			t.Error("清除後 has_bind_password 應為 false")
		}
		if enc := ldapDirRow(t, db).BindPasswordEnc; enc != "" {
			t.Errorf("清除後 bind_password_enc 應被抹除，實得 %q", enc)
		}
	})

	t.Run("密碼與清除旗標衝突被拒", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
			t.Fatalf("建立: %v", err)
		}
		before := ldapDirRow(t, db)

		_, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.BindPassword = "另一個密碼"
			r.ClearBindPassword = true
		}))
		if !errors.Is(err, ErrLDAPBindPasswordConflict) {
			t.Fatalf("錯誤 = %v, want ErrLDAPBindPasswordConflict", err)
		}
		if ldapDirRow(t, db).BindPasswordEnc != before.BindPasswordEnc {
			t.Error("被拒的請求不得改動既存密碼")
		}
		rej := ldapDirAuditOf(t, db, LDAPAuditEventSaveRejected)
		if rej["reason"] != LDAPRejectBindPasswordConflict || rej["_status"] != string(model.StatusDenied) {
			t.Errorf("拒絕審計 = %v", rej)
		}
	})

	t.Run("URL變更且既存有密碼時空密碼被拒", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
			t.Fatalf("建立: %v", err)
		}
		before := ldapDirRow(t, db)

		_, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.URL = "ldaps://attacker.example:636"
			r.BindPassword = ""
		}))
		if !errors.Is(err, ErrLDAPBindPasswordRequired) {
			t.Fatalf("錯誤 = %v, want ErrLDAPBindPasswordRequired", err)
		}
		row := ldapDirRow(t, db)
		if row.URL != before.URL || row.BindPasswordEnc != before.BindPasswordEnc {
			t.Error("被拒的請求不得改動既存設定或密碼")
		}
		rej := ldapDirAuditOf(t, db, LDAPAuditEventSaveRejected)
		if rej["reason"] != LDAPRejectBindPasswordRequired {
			t.Errorf("拒絕審計 reason = %v", rej["reason"])
		}
	})

	t.Run("URL變更但同時提供新密碼可存檔", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
			t.Fatalf("建立: %v", err)
		}
		if _, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.URL = "ldaps://other.example:636"
			r.BindPassword = "新密碼"
		})); err != nil {
			t.Fatalf("更新: %v", err)
		}
		if got := ldapDirRow(t, db).URL; got != "ldaps://other.example:636" {
			t.Errorf("url = %q", got)
		}
	})

	t.Run("既存無密碼時改URL應通過", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		// 草稿：無 bind 密碼
		if _, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.Enabled = false
			r.BindPassword = ""
		})); err != nil {
			t.Fatalf("建立草稿: %v", err)
		}
		// 修正打錯的 URL——當下無憑證可被沿用，不套重供規則
		if _, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.Enabled = false
			r.BindPassword = ""
			r.URL = "ldaps://corrected.example:636"
		})); err != nil {
			t.Fatalf("草稿改 URL 應通過，實得: %v", err)
		}
		if got := ldapDirRow(t, db).URL; got != "ldaps://corrected.example:636" {
			t.Errorf("url = %q", got)
		}
	})

	t.Run("canonical origin 相等不算URL變更", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
			t.Fatalf("建立: %v", err)
		}
		// `ldaps://dir.example` 與 `ldaps://dir.example:636` 是同一端點：
		// 字面比較會誤擋這格
		if _, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.URL = "ldaps://DIR.example"
			r.BindPassword = ""
		})); err != nil {
			t.Fatalf("同端點的不同字面不應被擋，實得: %v", err)
		}
	})
}

// ── 存檔閘三格（2.4）───────────────────────────────────────────────

// newLDAPGateSvc 建服務並接上真的 TransmissionPolicyService（非自製 fake——
// 閘的判定語義是既有共用契約，用 fake 等於驗自己寫的假設）
func newLDAPGateSvc(t *testing.T, level string) (*LDAPDirectoryService, *gorm.DB) {
	t.Helper()
	svc, db := newLDAPDirectorySvc(t)
	policies := newPolicyServiceForTest(t)
	if level != policy.TransportLevelOff {
		if _, err := policies.Update(policy.PolicyTransportLDAPLevel, level, "admin"); err != nil {
			t.Fatalf("設定政策檔位: %v", err)
		}
	}
	svc.SetTransmissionPolicy(policy.NewTransmissionPolicyService(policies, nil))
	return svc, db
}

func TestLDAPDirectorySaveGate(t *testing.T) {
	plaintext := func(r *LDAPDirectoryRequest) { r.URL = "ldap://dir.example:389" }

	t.Run("strict 拒存", func(t *testing.T) {
		svc, db := newLDAPGateSvc(t, policy.TransportLevelStrict)
		_, err := svc.Upsert(context.Background(), ldapDirReq(plaintext))
		var gateErr *policy.TransmissionGateError
		if !errors.As(err, &gateErr) || gateErr.Code != policy.TransmissionGateStrictReject {
			t.Fatalf("錯誤 = %v, want strict_reject", err)
		}
		var n int64
		db.Model(&model.LDAPDirectory{}).Count(&n)
		if n != 0 {
			t.Error("strict 拒存後不應有設定列")
		}
		rej := ldapDirAuditOf(t, db, LDAPAuditEventSaveRejected)
		if rej["reason"] != LDAPRejectTransmissionGate || rej["detail"] != policy.TransmissionGateStrictReject {
			t.Errorf("拒絕審計 = %v", rej)
		}
	})

	t.Run("warn 缺確認拒", func(t *testing.T) {
		svc, db := newLDAPGateSvc(t, policy.TransportLevelWarn)
		_, err := svc.Upsert(context.Background(), ldapDirReq(plaintext))
		var gateErr *policy.TransmissionGateError
		if !errors.As(err, &gateErr) || gateErr.Code != policy.TransmissionGateAckRequired {
			t.Fatalf("錯誤 = %v, want ack_required", err)
		}
		rej := ldapDirAuditOf(t, db, LDAPAuditEventSaveRejected)
		if rej["detail"] != policy.TransmissionGateAckRequired {
			t.Errorf("拒絕審計 detail = %v", rej["detail"])
		}
	})

	t.Run("warn 帶確認過", func(t *testing.T) {
		svc, db := newLDAPGateSvc(t, policy.TransportLevelWarn)
		_, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			plaintext(r)
			r.RiskAcknowledged = true
		}))
		if err != nil {
			t.Fatalf("warn 帶確認應通過: %v", err)
		}
		save := ldapDirAuditOf(t, db, LDAPAuditEventSave)
		if save["risk_acknowledged"] != true {
			t.Errorf("存檔審計未記確認聲明: %v", save)
		}
		risks, _ := save["transmission_risks"].([]any)
		if len(risks) != 1 {
			t.Errorf("存檔審計風險項 = %v", save["transmission_risks"])
		}
	})

	t.Run("停用草稿不受閘限", func(t *testing.T) {
		svc, db := newLDAPGateSvc(t, policy.TransportLevelStrict)
		if _, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			plaintext(r)
			r.Enabled = false
		})); err != nil {
			t.Fatalf("enabled=false 不應過閘: %v", err)
		}
		if got := ldapDirRow(t, db).URL; got != "ldap://dir.example:389" {
			t.Errorf("草稿未存入 = %q", got)
		}
	})
}

// ── 三態解析（2.7）─────────────────────────────────────────────────

// ldapDecryptFailCodec 模擬金鑰事故：加密正常、解密恆失敗
type ldapDecryptFailCodec struct{ inner crypto.ColumnCodec }

func (c ldapDecryptFailCodec) EncryptFor(ctx context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	return c.inner.EncryptFor(ctx, ref, plaintext)
}

func (c ldapDecryptFailCodec) DecryptFor(context.Context, crypto.CipherRef, string) (string, error) {
	return "", errors.New("模擬 DEK 事故：密文無法解密")
}

func TestLDAPDirectoryResolveTriState(t *testing.T) {
	t.Run("未設定", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		if got := svc.ResolveDialSnapshot(context.Background()).State; got != policy.LDAPResolveUnconfigured {
			t.Errorf("state = %q, want unconfigured", got)
		}
		if got := svc.ResolveRiskView(context.Background()).State; got != policy.LDAPResolveUnconfigured {
			t.Errorf("risk view state = %q, want unconfigured", got)
		}
	})

	t.Run("有效", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
			t.Fatalf("建立: %v", err)
		}
		res := svc.ResolveDialSnapshot(context.Background())
		if res.State != policy.LDAPResolveOK {
			t.Fatalf("state = %q, want ok", res.State)
		}
		if res.Snapshot.BindPassword != "s3cret-bind" || res.Snapshot.BaseDN != "ou=users,dc=example,dc=com" {
			t.Errorf("快照 = %+v", res.Snapshot)
		}
		if !res.Snapshot.Enabled || res.Snapshot.ParsedURL.CanonicalOrigin() != "ldaps://dir.example:636" {
			t.Errorf("內嵌 risk view / 解析結果不符: %+v", res.Snapshot)
		}
		rv := svc.ResolveRiskView(context.Background())
		if rv.State != policy.LDAPResolveOK || !rv.View.Enabled {
			t.Errorf("risk view = %+v", rv)
		}
	})

	t.Run("故障不得偽裝未啟用", func(t *testing.T) {
		db := newLDAPDirectoryDB(t)
		good := NewLDAPDirectoryService(db, aesColumnCodec(t, kmTestKey(0x42)), audit.NewTxSink())
		good.SetTransmissionPolicy(ldapAllowAllGate{})
		if _, err := good.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
			t.Fatalf("建立: %v", err)
		}
		// 同一份資料，換成解密恆失敗的 codec＝金鑰事故
		broken := NewLDAPDirectoryService(db, ldapDecryptFailCodec{inner: aesColumnCodec(t, kmTestKey(0x42))}, audit.NewTxSink())

		dial := broken.ResolveDialSnapshot(context.Background())
		if dial.State != policy.LDAPResolveFailed {
			t.Fatalf("撥號解析 state = %q, want failed", dial.State)
		}
		if dial.Err == nil {
			t.Error("故障態必須帶可辨識的錯誤供內部 log")
		}

		// 清冊／政策端同樣須看到故障，**不得**被併吞成未設定或未啟用——
		// 否則 DEK 事故時清冊顯示「未啟用」而設定頁顯示「已啟用」，
		// 兩個管理面互相打臉並把排錯指向錯誤方向
		rv := broken.ResolveRiskView(context.Background())
		if rv.State != policy.LDAPResolveFailed {
			t.Fatalf("risk view state = %q, want failed", rv.State)
		}
		if rv.State == policy.LDAPResolveUnconfigured {
			t.Fatal("故障被偽裝為未設定")
		}
		// provider 形狀同樣三態
		if got := broken.RiskViewProvider()(); got.State != policy.LDAPResolveFailed {
			t.Errorf("provider state = %q, want failed", got.State)
		}
	})

	t.Run("多live列取id最小者", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		// 直接插兩列：sqlite 測試庫無 partial unique index，服務層仍須有確定性行為。
		// 欄位須齊全且密文可解——啟用態的完整性重驗（fail-close）會把殘缺列判為
		// failed，本格要驗的是「多列時取誰」而非完整性
		enc, err := svc.encryptBindPassword(context.Background(), "s3cret-bind")
		if err != nil {
			t.Fatalf("加密: %v", err)
		}
		for _, name := range []string{"first", "second"} {
			if err := db.Create(&model.LDAPDirectory{
				Singleton: 1, Name: name, URL: "ldaps://dir.example:636", Enabled: true,
				BindDN: "cn=svc,dc=example,dc=com", BaseDN: "ou=users,dc=example,dc=com",
				UserFilter: "(uid=%s)", AttrEmail: "mail", AttrFullName: "cn",
				BindPasswordEnc: enc,
			}).Error; err != nil {
				t.Fatalf("插列: %v", err)
			}
		}
		res := svc.ResolveDialSnapshot(context.Background())
		if res.State != policy.LDAPResolveOK || res.Snapshot.DirectoryID != 1 {
			t.Fatalf("解析 = %+v, want id 最小者", res.Snapshot)
		}
		view, err := svc.Get(context.Background())
		if err != nil || view.Name != "first" {
			t.Errorf("Get = %+v, err=%v, want name=first", view, err)
		}
	})
}

// TestLDAPRisksOfMatchesTransmissionPolicy 純函式版本與 TransmissionPolicyService.LDAPRisks
// 逐格等價（8 組輸入）。
//
// **2.9 後本格的意義**：LDAPRisks 已改為「經 provider 取得三態視圖後委派
// LDAPRisksOf」，故本格釘住的是「provider→委派」這段接線對每一種輸入形狀都
// 原樣傳遞，沒有在換資料來源時順手加上額外條件（例如把未啟用當成有風險、
// 或把空 URL 特判掉）。判準本體的正確性另由 TestLDAPRisks 逐格覆蓋
func TestLDAPRisksOfMatchesTransmissionPolicy(t *testing.T) {
	cases := []policy.LDAPRiskView{
		{Enabled: false, URL: "ldap://d:389"},
		{Enabled: false, URL: "ldaps://d:636", SkipTLSVerify: true},
		{Enabled: true, URL: "ldap://d:389"},
		{Enabled: true, URL: "ldap://d:389", SkipTLSVerify: true},
		{Enabled: true, URL: "ldaps://d:636"},
		{Enabled: true, URL: "ldaps://d:636", SkipTLSVerify: true},
		{Enabled: true, URL: "LDAPS://d:636"},
		{Enabled: true, URL: ""},
	}
	for _, view := range cases {
		want := newTransmissionSvc(t, ldapRiskProvider(view)).LDAPRisks()
		got := policy.LDAPRisksOf(view)
		if strings.Join(riskKeys(got), ",") != strings.Join(riskKeys(want), ",") {
			t.Errorf("policy.LDAPRisksOf(%+v) = %v, want %v（與 LDAPRisks 判準不一致）",
				view, riskKeys(got), riskKeys(want))
		}
	}
}

// TestLDAPRisksThreeStates 三態下的風險回報：只有解析成功才判定，
// 未設定與故障皆不回報風險項——捏造「無風險」與捏造風險同樣不誠實，
// 故障的可見性由清冊的專屬 note 碼承擔（見 TestInventoryLDAPResolveStates）
func TestLDAPRisksThreeStates(t *testing.T) {
	if got := newTransmissionSvc(t, ldapRiskProviderState(policy.LDAPResolveUnconfigured)).LDAPRisks(); len(got) != 0 {
		t.Errorf("未設定態風險項 = %v, want 空", riskKeys(got))
	}
	if got := newTransmissionSvc(t, ldapRiskProviderState(policy.LDAPResolveFailed)).LDAPRisks(); len(got) != 0 {
		t.Errorf("故障態風險項 = %v, want 空", riskKeys(got))
	}
	// provider 未注入（不接目錄服務的組裝）＝未設定，不得 panic
	if got := newTransmissionSvc(t, nil).LDAPRisks(); len(got) != 0 {
		t.Errorf("nil provider 風險項 = %v, want 空", riskKeys(got))
	}
}

// ── 刪除與密文抹除 ─────────────────────────────────────────────────

func TestLDAPDirectoryDeleteWipesCiphertext(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
		t.Fatalf("建立: %v", err)
	}
	actor := LDAPDirectoryActor{ID: 7, Name: "admin"}
	if err := svc.Delete(context.Background(), actor); err != nil {
		t.Fatalf("刪除: %v", err)
	}

	var tombs []model.LDAPDirectory
	if err := db.Unscoped().Find(&tombs).Error; err != nil {
		t.Fatalf("查 tombstone: %v", err)
	}
	if len(tombs) != 1 || !tombs[0].DeletedAt.Valid {
		t.Fatalf("應留下一列軟刪 tombstone，實得 %+v", tombs)
	}
	if tombs[0].BindPasswordEnc != "" {
		t.Errorf("tombstone 仍留可解密密文 %q", tombs[0].BindPasswordEnc)
	}
	if view, err := svc.Get(context.Background()); err != nil || view.Configured {
		t.Errorf("刪除後 Get = %+v, err=%v, want configured=false", view, err)
	}
	ldapDirAuditOf(t, db, LDAPAuditEventDelete)

	// 軟刪列不佔 singleton：可重建
	if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
		t.Fatalf("刪除後重建: %v", err)
	}
	if err := svc.Delete(context.Background(), actor); err != nil {
		t.Fatalf("再次刪除: %v", err)
	}
	if err := svc.Delete(context.Background(), actor); !errors.Is(err, ErrLDAPDirectoryNotFound) {
		t.Errorf("無列時刪除 = %v, want ErrLDAPDirectoryNotFound", err)
	}
}

// ── 審計：URL 變更為高權重事件 ────────────────────────────────────

func TestLDAPDirectoryURLChangeAudit(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
		t.Fatalf("建立: %v", err)
	}
	// 建立當下不應產生 URL 變更事件（新設定的位址已記在建立事件裡）
	for _, a := range ldapDirAudits(t, db) {
		if a["event"] == LDAPAuditEventURLChanged {
			t.Fatal("建立不應產生 URL 變更事件")
		}
	}
	// 同端點的更新亦不應產生
	if _, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
		r.BindPassword = ""
		r.Name = "改名"
	})); err != nil {
		t.Fatalf("同端點更新: %v", err)
	}
	for _, a := range ldapDirAudits(t, db) {
		if a["event"] == LDAPAuditEventURLChanged {
			t.Fatal("端點未變不應產生 URL 變更事件")
		}
	}

	if _, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
		r.URL = "ldaps://elsewhere.example:636"
		r.BindPassword = "重供的密碼"
	})); err != nil {
		t.Fatalf("改指向: %v", err)
	}
	ev := ldapDirAuditOf(t, db, LDAPAuditEventURLChanged)
	if ev["old_url"] != "ldaps://dir.example:636" || ev["new_url"] != "ldaps://elsewhere.example:636" {
		t.Errorf("URL 變更審計未記舊→新 canonical origin: %v", ev)
	}
	if ev["host_changed"] != true {
		t.Errorf("host 變更旗標 = %v, want true", ev["host_changed"])
	}
}

func TestLDAPDirectoryAuditNeverLeaksSecrets(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
		t.Fatalf("建立: %v", err)
	}
	var logs []model.AuditLog
	if err := db.Find(&logs).Error; err != nil {
		t.Fatalf("查審計: %v", err)
	}
	enc := ldapDirRow(t, db).BindPasswordEnc
	for _, l := range logs {
		if strings.Contains(l.Details, "s3cret-bind") || (enc != "" && strings.Contains(l.Details, enc)) {
			t.Fatalf("審計含密碼或密文: %s", l.Details)
		}
	}
	// 讀取視圖在型別上即不含密碼；序列化後亦不得出現
	view, err := svc.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), "s3cret-bind") || strings.Contains(string(raw), enc) {
		t.Fatalf("讀取回應含密碼: %s", raw)
	}
	if !view.HasBindPassword {
		t.Error("讀取回應應以 has_bind_password 表達密碼存在")
	}
}

func TestLDAPDirectoryInvalidURLRejectedWithoutLeak(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	_, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
		r.URL = "ldap://user:secret@dir.example/ou=x?scope"
	}))
	if !errors.Is(err, ErrLDAPURLInvalid) {
		t.Fatalf("錯誤 = %v, want ErrLDAPURLInvalid", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("錯誤訊息洩漏 userinfo: %v", err)
	}
	var logs []model.AuditLog
	db.Find(&logs)
	for _, l := range logs {
		if strings.Contains(l.Details, "secret") {
			t.Fatalf("審計洩漏 userinfo: %s", l.Details)
		}
	}
	var n int64
	db.Model(&model.LDAPDirectory{}).Count(&n)
	if n != 0 {
		t.Error("非法 URL 不得寫入")
	}
}

// ── 並發線性化 ─────────────────────────────────────────────────────

// TestLDAPDirectoryConcurrentUpsert 兩個並發 Upsert 只有一個成功寫入，
// 另一個回可重試的機器碼（**非 500**）。
//
// **檔案型 sqlite ＋兩條連線**（同 localAdminConcurrentDB 的理由）：:memory:
// 單連線會把兩個 goroutine 的 DB 存取序列化，把互斥拿掉的突變會因為第二者的
// 讀取被迫等到第一者提交而看似仍然安全，測試就失去辨識力。
func TestLDAPDirectoryConcurrentUpsert(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "ldapdir.db") + "?_pragma=busy_timeout(5000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(2)
	if err := db.AutoMigrate(&model.LDAPDirectory{}, &model.AuditLog{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc := NewLDAPDirectoryService(db, aesColumnCodec(t, kmTestKey(0x42)), audit.NewTxSink())
	svc.SetTransmissionPolicy(ldapAllowAllGate{})

	entered := make(chan struct{})
	release := make(chan struct{})
	var hits int32
	ldapDirectoryPreWriteHook = func() {
		// 只擋第一位：突變（拿掉互斥）時第二位可繼續前進而暴露雙寫
		if atomic.AddInt32(&hits, 1) == 1 {
			close(entered)
			<-release
		}
	}
	t.Cleanup(func() { ldapDirectoryPreWriteHook = nil })

	firstErr := make(chan error, 1)
	go func() {
		_, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
			r.Name = "first"
		}))
		firstErr <- err
	}()

	<-entered
	_, secondErr := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
		r.Name = "second"
	}))
	close(release)

	if err := <-firstErr; err != nil {
		t.Fatalf("先進入者應成功，實得: %v", err)
	}
	if !errors.Is(secondErr, ErrLDAPDirectoryBusy) && !errors.Is(secondErr, ErrLDAPDirectoryConflict) {
		t.Fatalf("後到者 = %v, want ErrLDAPDirectoryBusy（可重試機器碼，非 500）", secondErr)
	}
	var n int64
	if err := db.Model(&model.LDAPDirectory{}).Count(&n).Error; err != nil {
		t.Fatalf("計數: %v", err)
	}
	if n != 1 {
		t.Fatalf("live 列數 = %d, want 1（並發未線性化）", n)
	}
	var row model.LDAPDirectory
	db.First(&row)
	if row.Name != "first" {
		t.Errorf("成功寫入者 = %q, want first", row.Name)
	}
}

// TestLDAPDirectoryLockKeyDistinct advisory lock key 撞號守衛
// （沿 TestLocalAdminLockKeyDistinct 的先例）
func TestLDAPDirectoryLockKeyDistinct(t *testing.T) {
	for name, key := range map[string]int64{
		"keyvault.KEKDataKeysLockKey": keyvault.KEKDataKeysLockKey,
		"LocalAdminLockKey":           LocalAdminLockKey,
	} {
		if LDAPDirectoryLockKey == key {
			t.Fatalf("advisory lock key 撞號：LDAPDirectoryLockKey 與 %s 同為 %#x", name, key)
		}
	}
}

// TestLDAPDirectoryLockRejectsUnknownDialect 未知 dialect fail-close
// （靜默退化為行程內鎖會讓多實例部署失去保護）
func TestLDAPDirectoryLockUsesTransaction(t *testing.T) {
	db := newLDAPDirectoryDB(t)
	called := false
	err := WithLDAPDirectoryLock(db, func(tx *gorm.DB) error {
		called = true
		// 判定必須在鎖內以 tx 重讀
		row, err := ldapDirectoryLiveRow(tx)
		if err != nil {
			return err
		}
		if row != nil {
			t.Error("空庫不應有 live 列")
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("WithLDAPDirectoryLock err=%v called=%v", err, called)
	}
}

// ── 安全與健壯性補強─────────────────────

// captureLDAPLog 攔截 operational log，回傳「取得目前輸出」的函式。
//
// 敏感值是否落進日誌是多格測試的**直接斷言對象**：日誌的存取面遠大於密文
// 本身，「不外傳」與「不入日誌」必須分別驗證
func captureLDAPLog(t *testing.T) func() string {
	t.Helper()
	var buf strings.Builder
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return buf.String
}

// ldapLeakyCodec 模擬「錯誤訊息夾帶輸入片段」的 codec。
//
// 真實 AEAD 實作的錯誤未必含輸入，但這是**呼叫端無法保證**的事——服務層若把
// codec 的原始錯誤原樣上拋，是否洩漏就取決於底層實作的善意。本替身把該假設
// 變成可驗證的斷言
type ldapLeakyCodec struct {
	inner       crypto.ColumnCodec
	failEncrypt bool
}

func (c ldapLeakyCodec) EncryptFor(ctx context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	if c.failEncrypt {
		return "", fmt.Errorf("aead seal failed: plaintext=%q", plaintext)
	}
	return c.inner.EncryptFor(ctx, ref, plaintext)
}

func (c ldapLeakyCodec) DecryptFor(_ context.Context, _ crypto.CipherRef, enc string) (string, error) {
	return "", fmt.Errorf("aead open failed: ciphertext=%q", enc)
}

// ldapCountingCodec 記錄解密次數（供「證明同源前不得解密」的斷言）
type ldapCountingCodec struct {
	inner    crypto.ColumnCodec
	decrypts *int32
}

func (c ldapCountingCodec) EncryptFor(ctx context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	return c.inner.EncryptFor(ctx, ref, plaintext)
}

func (c ldapCountingCodec) DecryptFor(ctx context.Context, ref crypto.CipherRef, enc string) (string, error) {
	atomic.AddInt32(c.decrypts, 1)
	return c.inner.DecryptFor(ctx, ref, enc)
}

// ldapCompleteRow 齊全的啟用態資料列（供直接插列的測試使用）
func ldapCompleteRow(enc string) *model.LDAPDirectory {
	return &model.LDAPDirectory{
		Singleton:       1,
		Name:            "主目錄",
		URL:             "ldaps://dir.example:636",
		BindDN:          "cn=svc,dc=example,dc=com",
		BaseDN:          "ou=users,dc=example,dc=com",
		UserFilter:      "(uid=%s)",
		AttrEmail:       "mail",
		AttrFullName:    "cn",
		Enabled:         true,
		BindPasswordEnc: enc,
	}
}

// TestLDAPDirectoryNilGateFailsClosed 閘未接線時存檔一律拒絕。
//
// **突變辨識力的關鍵在於請求本身無傳輸風險**（ldaps）：舊行為（nil＝放行）下
// 這個請求會成功存檔，故把 fail-close 改回 `if s.gate != nil` 即轉紅。
// 若改用有風險的 ldap:// 請求，兩種行為都會「被拒」，測試就分不出差異
func TestLDAPDirectoryNilGateFailsClosed(t *testing.T) {
	db := newLDAPDirectoryDB(t)
	// 刻意不呼叫 SetTransmissionPolicy——模擬生產組裝漏掉 setter
	svc := NewLDAPDirectoryService(db, aesColumnCodec(t, kmTestKey(0x42)), audit.NewTxSink())

	_, err := svc.Upsert(context.Background(), ldapDirReq(nil))
	if !errors.Is(err, ErrLDAPTransmissionGateUnavailable) {
		t.Fatalf("錯誤 = %v, want ErrLDAPTransmissionGateUnavailable（閘缺席須 fail-close）", err)
	}
	var n int64
	if err := db.Model(&model.LDAPDirectory{}).Count(&n).Error; err != nil {
		t.Fatalf("計數: %v", err)
	}
	if n != 0 {
		t.Error("閘未接線時不得寫入設定列")
	}
	rej := ldapDirAuditOf(t, db, LDAPAuditEventSaveRejected)
	if rej["reason"] != LDAPRejectTransmissionGateUnavailable {
		t.Errorf("拒絕審計 reason = %v, want %s", rej["reason"], LDAPRejectTransmissionGateUnavailable)
	}
	if rej["_status"] != string(model.StatusDenied) {
		t.Errorf("拒絕審計 status = %v", rej["_status"])
	}

	// 注入明確的 allow-all 閘後同一請求即通過——證明上面的拒絕確實出自閘缺席，
	// 而非請求本身有問題
	svc.SetTransmissionPolicy(ldapAllowAllGate{})
	if _, err := svc.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
		t.Fatalf("接上閘後同一請求應通過: %v", err)
	}
}

// TestLDAPDirectoryCodecErrorSanitized 加解密邊界的錯誤不得夾帶密文／明文。
//
// 斷言分兩面：**外傳的錯誤鏈**與 **operational log**——兩者的存取面不同，
// 只驗其一會漏掉另一條管道
func TestLDAPDirectoryCodecErrorSanitized(t *testing.T) {
	t.Run("解密錯誤不夾帶密文", func(t *testing.T) {
		db := newLDAPDirectoryDB(t)
		good := NewLDAPDirectoryService(db, aesColumnCodec(t, kmTestKey(0x42)), audit.NewTxSink())
		good.SetTransmissionPolicy(ldapAllowAllGate{})
		if _, err := good.Upsert(context.Background(), ldapDirReq(nil)); err != nil {
			t.Fatalf("建立: %v", err)
		}
		enc := ldapDirRow(t, db).BindPasswordEnc
		if enc == "" {
			t.Fatal("前置條件：既存列須有密文")
		}

		broken := NewLDAPDirectoryService(db, ldapLeakyCodec{inner: aesColumnCodec(t, kmTestKey(0x42))}, audit.NewTxSink())
		broken.SetTransmissionPolicy(ldapAllowAllGate{})
		logged := captureLDAPLog(t)

		res := broken.ResolveDialSnapshot(context.Background())
		if res.State != policy.LDAPResolveFailed {
			t.Fatalf("state = %q, want failed", res.State)
		}
		if !errors.Is(res.Err, ErrLDAPBindPasswordDecrypt) {
			t.Errorf("錯誤 = %v, want 靜態哨兵 ErrLDAPBindPasswordDecrypt", res.Err)
		}
		if strings.Contains(res.Err.Error(), enc) {
			t.Errorf("外傳錯誤夾帶密文: %v", res.Err)
		}
		if strings.Contains(res.Err.Error(), "aead open failed") {
			t.Errorf("外傳錯誤含 codec 底層文字: %v", res.Err)
		}
		if out := logged(); strings.Contains(out, enc) || strings.Contains(out, "aead open failed") {
			t.Errorf("operational log 含密文或 codec 底層文字: %s", out)
		}
	})

	t.Run("加密錯誤不夾帶明文", func(t *testing.T) {
		db := newLDAPDirectoryDB(t)
		svc := NewLDAPDirectoryService(db, ldapLeakyCodec{
			inner:       aesColumnCodec(t, kmTestKey(0x42)),
			failEncrypt: true,
		}, audit.NewTxSink())
		svc.SetTransmissionPolicy(ldapAllowAllGate{})
		logged := captureLDAPLog(t)

		_, err := svc.Upsert(context.Background(), ldapDirReq(nil))
		if !errors.Is(err, ErrLDAPBindPasswordEncrypt) {
			t.Fatalf("錯誤 = %v, want 靜態哨兵 ErrLDAPBindPasswordEncrypt", err)
		}
		if strings.Contains(err.Error(), "s3cret-bind") {
			t.Errorf("外傳錯誤夾帶 bind 明文: %v", err)
		}
		if out := logged(); strings.Contains(out, "s3cret-bind") {
			t.Errorf("operational log 夾帶 bind 明文: %s", out)
		}
	})
}

// TestLDAPNilDependencyResolvesFailedNotPanic nil 依賴落 failed 三態而非 panic。
//
// factory 在 nil 依賴下能成功建出 closure 是 Go 的既有語義，問題在於錯誤被
// 延遲到**實際登入當下**才以 panic 形態爆發——那既不是三態的任何一格，也讓
// 一次組裝疏漏變成整條認證路徑的崩潰
func TestLDAPNilDependencyResolvesFailedNotPanic(t *testing.T) {
	t.Run("risk view provider", func(t *testing.T) {
		var nilSvc *LDAPDirectoryService
		got := nilSvc.RiskViewProvider()()
		if got.State != policy.LDAPResolveFailed {
			t.Errorf("state = %q, want failed", got.State)
		}
		if !errors.Is(got.Err, ErrLDAPDirectoryServiceUnavailable) {
			t.Errorf("錯誤 = %v, want ErrLDAPDirectoryServiceUnavailable", got.Err)
		}
	})

	t.Run("nil DB 的服務", func(t *testing.T) {
		svc := NewLDAPDirectoryService(nil, nil, audit.NewTxSink())
		if got := svc.ResolveDialSnapshot(context.Background()).State; got != policy.LDAPResolveFailed {
			t.Errorf("state = %q, want failed", got)
		}
		if got := svc.RiskViewProvider()().State; got != policy.LDAPResolveFailed {
			t.Errorf("provider state = %q, want failed", got)
		}
	})

	t.Run("登入 resolver", func(t *testing.T) {
		built := 0
		resolver := newLDAPLoginResolverWith(nil, func(LDAPDialSnapshot) LDAPAuthenticator {
			built++
			return &fakeLDAPAuthenticator{}
		})
		got := resolver()
		if got.State != LDAPLoginFailed {
			t.Errorf("state = %q, want failed（不得為 unavailable——那會偽裝成 LDAP 未啟用）", got.State)
		}
		if got.Auth != nil {
			t.Error("failed 態不得帶認證器")
		}
		if built != 0 {
			t.Errorf("nil 依賴下仍建了 %d 次認證器", built)
		}
	})

	t.Run("生產 factory", func(t *testing.T) {
		if got := NewLDAPLoginResolver(nil)(); got.State != LDAPLoginFailed {
			t.Errorf("state = %q, want failed", got.State)
		}
	})

	t.Run("nil factory", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		if got := newLDAPLoginResolverWith(svc, nil)(); got.State != LDAPLoginFailed {
			t.Errorf("state = %q, want failed", got.State)
		}
	})
}

// TestLDAPDirectoryEnabledIncompleteRowIsFailed 啟用態缺必要欄位＝failed。
//
// migration、手工 SQL 或資料損壞可留下 enabled=true 但欄位殘缺的列。該列在
// 解密路徑上毫無異常（沒有密文就不會解密失敗），舊行為一路回 OK、登入
// resolver 隨即回 ready——形成設計只承認三態之外的第四狀態「存在但無效」。
//
// **必須是 failed 而非 unconfigured**：後者會把資料損壞偽裝成「管理員沒設定」，
// 與本檔禁止的併吞形態同一件事
func TestLDAPDirectoryEnabledIncompleteRowIsFailed(t *testing.T) {
	cases := map[string]func(*model.LDAPDirectory){
		"密文為空":          func(r *model.LDAPDirectory) { r.BindPasswordEnc = "" },
		"bind_dn 為空白字元": func(r *model.LDAPDirectory) { r.BindDN = "   " },
		"缺 base_dn":     func(r *model.LDAPDirectory) { r.BaseDN = "" },
		"缺 user_filter": func(r *model.LDAPDirectory) { r.UserFilter = "" },
		"缺 url":         func(r *model.LDAPDirectory) { r.URL = "" },
		"缺 attr_email":  func(r *model.LDAPDirectory) { r.AttrEmail = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			svc, db := newLDAPDirectorySvc(t)
			enc, err := svc.encryptBindPassword(context.Background(), "s3cret-bind")
			if err != nil {
				t.Fatalf("加密: %v", err)
			}
			row := ldapCompleteRow(enc)
			mut(row)
			if err := db.Create(row).Error; err != nil {
				t.Fatalf("插列: %v", err)
			}

			res := svc.ResolveDialSnapshot(context.Background())
			if res.State == policy.LDAPResolveUnconfigured {
				t.Fatal("殘缺列被偽裝為未設定（禁止的併吞形態）")
			}
			if res.State != policy.LDAPResolveFailed {
				t.Fatalf("state = %q, want failed", res.State)
			}
			if res.Err == nil {
				t.Error("failed 態須帶可辨識的錯誤供內部 log")
			}

			// 清冊／政策端同樣看到故障
			if got := svc.ResolveRiskView(context.Background()).State; got != policy.LDAPResolveFailed {
				t.Errorf("risk view state = %q, want failed", got)
			}

			// 登入 resolver 不得回 ready，也不得回 unavailable
			built := 0
			login := newLDAPLoginResolverWith(svc, func(LDAPDialSnapshot) LDAPAuthenticator {
				built++
				return &fakeLDAPAuthenticator{}
			})()
			if login.State == LDAPLoginReady {
				t.Error("殘缺的啟用列被判為 ready（存在但無效的第四狀態）")
			}
			if login.State == LDAPLoginUnavailable {
				t.Error("故障被偽裝為未啟用")
			}
			if login.State != LDAPLoginFailed {
				t.Errorf("登入解析 state = %q, want failed", login.State)
			}
			if built != 0 {
				t.Errorf("不可撥號的狀態仍建了 %d 次認證器", built)
			}
		})
	}

	// 對照組：**停用**的殘缺列仍是 OK——草稿本來就允許不完整，
	// 把它一併判為故障會讓「先存草稿、稍後補齊」變成看似壞掉
	t.Run("停用的殘缺列仍為 ok", func(t *testing.T) {
		svc, db := newLDAPDirectorySvc(t)
		row := ldapCompleteRow("")
		row.Enabled = false
		row.BaseDN = ""
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("插列: %v", err)
		}
		res := svc.ResolveDialSnapshot(context.Background())
		if res.State != policy.LDAPResolveOK {
			t.Errorf("state = %q, want ok（草稿允許不完整）", res.State)
		}
	})
}
