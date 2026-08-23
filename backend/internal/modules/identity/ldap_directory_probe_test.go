package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// LDAP 連線測試（階梯、oracle 收斂、密碼沿用三條件、測試閘、資源上限、審計）
// 的服務層覆蓋。
//
// 撥號一律走注入的接縫（ldapProbeRuntime.dial），使階梯的每一格分支都能在
// 無真實目錄的環境下驗證；真實撥號路徑另有一格整合測試（見檔尾）釘住
// 「留空密碼＋改 URL 時，舊密碼確實沒離開本機」——該格的斷言對象是**送出
// 內容本身**，不依賴遠端回應（部分目錄把空密碼視為匿名 bind 而回成功）。

// ── 測試替身 ────────────────────────────────────────────────────────────

// fakeLDAPBind 一次 bind 呼叫的記錄（**斷言對象**：撥號層實際收到什麼）
type fakeLDAPBind struct {
	dn       string
	password string
}

type fakeLDAPConn struct {
	mu sync.Mutex

	binds     []fakeLDAPBind
	bindErr   error
	bindDelay time.Duration

	searchReqs   []*ldap.SearchRequest
	searchResult *ldap.SearchResult
	searchErr    error
	searchDelay  time.Duration

	closes  int
	timeout time.Duration
}

func (c *fakeLDAPConn) Bind(dn, password string) error {
	c.mu.Lock()
	c.binds = append(c.binds, fakeLDAPBind{dn: dn, password: password})
	delay, err := c.bindDelay, c.bindErr
	c.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	return err
}

func (c *fakeLDAPConn) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	c.mu.Lock()
	c.searchReqs = append(c.searchReqs, req)
	delay, res, err := c.searchDelay, c.searchResult, c.searchErr
	c.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	return res, err
}

func (c *fakeLDAPConn) SetTimeout(d time.Duration) {
	c.mu.Lock()
	c.timeout = d
	c.mu.Unlock()
}

func (c *fakeLDAPConn) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	return nil
}

func (c *fakeLDAPConn) bindCalls() []fakeLDAPBind {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]fakeLDAPBind(nil), c.binds...)
}

func (c *fakeLDAPConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// fakeLDAPDialer 撥號接縫的記錄與可程式化回應
type fakeLDAPDialer struct {
	mu       sync.Mutex
	calls    []string
	corrIDs  []string
	conn     *fakeLDAPConn
	dialErr  error
	skipSeen []bool
}

func (d *fakeLDAPDialer) dial(rawURL string, skipTLSVerify bool, correlationID string) (ldapProbeConn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, rawURL)
	d.corrIDs = append(d.corrIDs, correlationID)
	d.skipSeen = append(d.skipSeen, skipTLSVerify)
	conn, err := d.conn, d.dialErr
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *fakeLDAPDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

// installLDAPProbeRuntime 換上測試用執行期資源（撥號接縫＋乾淨限流器），
// 結束時還原——package 層級單例的既有慣例（同 ldapDirectoryPreWriteHook）
func installLDAPProbeRuntime(t *testing.T, dialer *fakeLDAPDialer, limits ldapProbeLimits) {
	t.Helper()
	prev := ldapProbeCurrentRuntime
	ldapProbeCurrentRuntime = &ldapProbeRuntime{
		dial:    dialer.dial,
		limiter: newLDAPProbeLimiter(limits),
	}
	t.Cleanup(func() { ldapProbeCurrentRuntime = prev })
}

// okSearchResult 三筆命中、首筆兩個映射屬性皆有值
func okSearchResult() *ldap.SearchResult {
	entry := func(dn, mail, cn string) *ldap.Entry {
		attrs := []*ldap.EntryAttribute{}
		if mail != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{mail}})
		}
		if cn != "" {
			attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{cn}})
		}
		return &ldap.Entry{DN: dn, Attributes: attrs}
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{
		entry("uid=a,ou=users,dc=example,dc=com", "a@example.com", "使用者 A"),
		entry("uid=b,ou=users,dc=example,dc=com", "b@example.com", "使用者 B"),
		entry("uid=c,ou=users,dc=example,dc=com", "", ""),
	}}
}

// newProbeDialer 撥號成功、bind 成功、搜尋回三筆的預設替身
func newProbeDialer() *fakeLDAPDialer {
	return &fakeLDAPDialer{conn: &fakeLDAPConn{searchResult: okSearchResult()}}
}

// ldapTestReq 合法的測試請求（ldaps：無傳輸風險，使密碼／階梯測試不被閘干擾）
func ldapTestReq(mut func(*LDAPDirectoryTestRequest)) LDAPDirectoryTestRequest {
	req := LDAPDirectoryTestRequest{
		URL:          "ldaps://dir.example:636",
		BindDN:       "cn=svc,dc=example,dc=com",
		BaseDN:       "ou=users,dc=example,dc=com",
		UserFilter:   "(uid=%s)",
		AttrEmail:    "mail",
		AttrFullName: "cn",
		BindPassword: "form-secret",
		Enabled:      true,
		Actor:        LDAPDirectoryActor{ID: 7, Name: "admin", IP: "10.1.2.3"},
	}
	if mut != nil {
		mut(&req)
	}
	return req
}

// ldapProbeAudit 取指定 event 的審計列（無則 fatal）
func ldapProbeAudit(t *testing.T, db *gorm.DB, event string) map[string]any {
	t.Helper()
	return ldapDirAuditOf(t, db, event)
}

// ── 階段 3／4：成功回報 ─────────────────────────────────────────────────

func TestLDAPTestConnectionSuccess(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	dialer := newProbeDialer()
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
	if err != nil {
		t.Fatalf("測試不應被前置拒絕: %v", err)
	}
	if !result.Success {
		t.Fatalf("結果 = %+v, want success", result)
	}
	if result.MatchedCount != 3 || result.MatchedAtLeast {
		t.Errorf("matched = %d/at_least=%v, want 3/false", result.MatchedCount, result.MatchedAtLeast)
	}
	if !result.AttrSample.Sampled || !result.AttrSample.EmailPresent || !result.AttrSample.FullNamePresent {
		t.Errorf("屬性抽樣 = %+v, want 三項皆真", result.AttrSample)
	}
	if result.Target != "ldaps://dir.example:636" {
		t.Errorf("target = %q", result.Target)
	}
	// 三階段皆成功且順序固定
	want := []string{LDAPTestStageDial, LDAPTestStageBind, LDAPTestStageSearch}
	if len(result.Stages) != len(want) {
		t.Fatalf("階段數 = %d, want %d（%+v）", len(result.Stages), len(want), result.Stages)
	}
	for i, stage := range result.Stages {
		if stage.Stage != want[i] || !stage.OK {
			t.Errorf("階段[%d] = %+v, want %s ok", i, stage, want[i])
		}
	}
	// 成功不帶 diagnostic_id（它是失敗事件的關聯識別碼）
	if result.DiagnosticID != "" {
		t.Errorf("成功不應帶 diagnostic_id，實得 %q", result.DiagnosticID)
	}

	// 搜尋請求形狀：SizeLimit=1000、客戶端自行封頂、只取兩個映射屬性
	if len(dialer.conn.searchReqs) != 1 {
		t.Fatalf("搜尋請求數 = %d", len(dialer.conn.searchReqs))
	}
	sr := dialer.conn.searchReqs[0]
	if sr.SizeLimit != ldapProbeSizeLimit || !sr.EnforceSizeLimit {
		t.Errorf("SizeLimit = %d / Enforce = %v, want %d/true", sr.SizeLimit, sr.EnforceSizeLimit, ldapProbeSizeLimit)
	}
	if sr.BaseDN != "ou=users,dc=example,dc=com" {
		t.Errorf("BaseDN = %q", sr.BaseDN)
	}
	// **唯一不經 EscapeFilter 的 `%s` 展開**：未轉義萬用字元
	if sr.Filter != "(uid=*)" {
		t.Errorf("filter = %q, want (uid=*)（未轉義萬用字元展開）", sr.Filter)
	}
	if strings.Contains(sr.Filter, `\2a`) {
		t.Error("filter 的萬用字元被轉義——測試路徑的唯一例外未生效")
	}
	// 審計：成功亦入
	audit := ldapProbeAudit(t, db, LDAPAuditEventTest)
	if audit["outcome"] != "success" || audit["_status"] != string(model.StatusSuccess) {
		t.Errorf("審計 = %v, want outcome=success", audit)
	}
	if audit["url"] != "ldaps://dir.example:636" {
		t.Errorf("審計 url = %v", audit["url"])
	}
	if audit["matched_count"] != float64(3) {
		t.Errorf("審計 matched_count = %v", audit["matched_count"])
	}
}

func TestLDAPTestSizeLimitReportsAtLeast(t *testing.T) {
	entries := make([]*ldap.Entry, ldapProbeSizeLimit)
	for i := range entries {
		entries[i] = &ldap.Entry{DN: fmt.Sprintf("uid=u%d,ou=users,dc=example,dc=com", i)}
	}

	cases := map[string]error{
		// 客戶端自行封頂
		"客戶端封頂": ldap.ErrSizeLimitExceeded,
		// 目錄回報 sizeLimitExceeded
		"目錄回報": ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit exceeded")),
	}
	for name, searchErr := range cases {
		t.Run(name, func(t *testing.T) {
			svc, _ := newLDAPDirectorySvc(t)
			dialer := newProbeDialer()
			dialer.conn.searchResult = &ldap.SearchResult{Entries: entries}
			dialer.conn.searchErr = searchErr
			installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

			result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
			if err != nil {
				t.Fatalf("不應前置拒絕: %v", err)
			}
			if !result.Success {
				t.Fatalf("達上限應視為成功，實得 %+v", result)
			}
			if result.MatchedCount != ldapProbeSizeLimit || !result.MatchedAtLeast {
				t.Errorf("matched = %d/at_least=%v, want %d/true",
					result.MatchedCount, result.MatchedAtLeast, ldapProbeSizeLimit)
			}
		})
	}
}

// ── oracle 收斂：撥號單一碼、bind 之後專屬碼 ───────────────────────────

func TestLDAPTestBindFailureLocatedAtBindStage(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	dialer := newProbeDialer()
	dialer.conn.bindErr = ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
	if err != nil {
		t.Fatalf("不應前置拒絕: %v", err)
	}
	if result.Success {
		t.Fatal("bind 失敗不應回成功")
	}
	if result.FailedStage != LDAPTestStageBind || result.Code != LDAPTestCodeBindFailed {
		t.Errorf("定位 = %s/%s, want bind/bind_failed", result.FailedStage, result.Code)
	}
	// 撥號階段須標示成功（階梯的定位價值就在這裡）
	if len(result.Stages) != 2 || !result.Stages[0].OK || result.Stages[0].Stage != LDAPTestStageDial {
		t.Errorf("階段 = %+v, want dial ok + bind failed", result.Stages)
	}
	if result.DiagnosticID == "" {
		t.Error("失敗回應須附 diagnostic_id")
	}
	audit := ldapProbeAudit(t, db, LDAPAuditEventTest)
	if audit["stage"] != LDAPTestStageBind || audit["diagnostic_id"] != result.DiagnosticID {
		t.Errorf("審計 = %v, want stage=bind 且 diagnostic_id 一致", audit)
	}
	// admin 可見的審計欄位不得含目錄回傳的 result code（那屬 operational log）
	if raw, _ := json.Marshal(audit); strings.Contains(string(raw), "ldap_result_") {
		t.Errorf("審計含粗分類原因: %s", raw)
	}
}

// TestLDAPTestDialFailureSingleCode 撥號失敗只得單一「無法連線」碼。
//
// **負向斷言**：回應（序列化後）不得出現任何粗分類字樣——把撥號失敗改回細分
// 原因（DNS／逾時／拒絕／TLS）即轉紅
func TestLDAPTestDialFailureSingleCode(t *testing.T) {
	classified := map[string]error{
		"DNS":  &net.DNSError{Err: "no such host", Name: "dir.example", IsNotFound: true},
		"逾時":   &net.OpError{Op: "dial", Err: &timeoutErrStub{}},
		"連線被拒": &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
		"TLS":  errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority"),
	}
	// 粗分類字樣：出現於回應即代表 oracle 解析度被放大
	forbidden := []string{
		"dns", "timeout", "timed out", "refused", "tls", "x509",
		"no such host", "unreachable", "certificate",
	}

	for name, dialErr := range classified {
		t.Run(name, func(t *testing.T) {
			svc, db := newLDAPDirectorySvc(t)
			dialer := newProbeDialer()
			dialer.dialErr = dialErr
			installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

			result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
			if err != nil {
				t.Fatalf("不應前置拒絕: %v", err)
			}
			// 非 Fatal：即使碼判定已失敗，下面的字樣掃描仍須跑完
			//（兩道斷言各自獨立，突變時應同時轉紅）
			if result.FailedStage != LDAPTestStageDial || result.Code != LDAPTestCodeConnectFailed {
				t.Errorf("定位 = %s/%s, want dial/%s", result.FailedStage, result.Code, LDAPTestCodeConnectFailed)
			}
			raw, mErr := json.Marshal(result)
			if mErr != nil {
				t.Fatalf("序列化: %v", mErr)
			}
			lowered := strings.ToLower(string(raw))
			for _, word := range forbidden {
				if strings.Contains(lowered, word) {
					t.Errorf("回應含粗分類字樣 %q（oracle 解析度被放大）: %s", word, raw)
				}
			}
			// 審計同樣不得含粗分類。`skip_tls_verify` 是設定欄位而非失敗分類，
			// 掃描前先移除（否則欄名本身會把 "tls" 這個字誤判為分類洩漏）
			audit := ldapProbeAudit(t, db, LDAPAuditEventTest)
			delete(audit, "skip_tls_verify")
			auditRaw, _ := json.Marshal(audit)
			for _, word := range forbidden {
				if strings.Contains(strings.ToLower(string(auditRaw)), word) {
					t.Errorf("審計含粗分類字樣 %q: %s", word, auditRaw)
				}
			}
		})
	}
}

// TestLDAPTestEgressBlockedHasOwnCode 出站政策拒絕與「無法連線」分開：
// 本地判定、未發生實際連線，不揭露目標主機任何狀態
func TestLDAPTestEgressBlockedHasOwnCode(t *testing.T) {
	svc, _ := newLDAPDirectorySvc(t)
	dialer := newProbeDialer()
	dialer.dialErr = fmt.Errorf("%w: 127.0.0.1:389", ErrLDAPEgressBlocked)
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
	if err != nil {
		t.Fatalf("不應前置拒絕: %v", err)
	}
	if result.Code != LDAPTestCodeEgressBlocked || result.FailedStage != LDAPTestStageDial {
		t.Errorf("定位 = %s/%s, want dial/%s", result.FailedStage, result.Code, LDAPTestCodeEgressBlocked)
	}
}

// timeoutErrStub 供 net.Error.Timeout() 判定的替身
type timeoutErrStub struct{}

func (timeoutErrStub) Error() string { return "i/o deadline exceeded" }
func (timeoutErrStub) Timeout() bool { return true }
func (timeoutErrStub) Temporary() bool {
	return true
}

// ── diagnostic_id 三處一致 ──────────────────────────────────────────────

func TestLDAPTestDiagnosticIDAppearsInThreePlaces(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	dialer := newProbeDialer()
	dialer.conn.bindErr = ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	var buf strings.Builder
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
	if err != nil {
		t.Fatalf("不應前置拒絕: %v", err)
	}
	if result.DiagnosticID == "" {
		t.Fatal("回應缺 diagnostic_id")
	}
	// (1) 回應 (2) 審計
	audit := ldapProbeAudit(t, db, LDAPAuditEventTest)
	if audit["diagnostic_id"] != result.DiagnosticID {
		t.Errorf("審計 diagnostic_id = %v, want %s", audit["diagnostic_id"], result.DiagnosticID)
	}
	// (3) operational log，且粗分類原因只出現在這裡
	logged := buf.String()
	if !strings.Contains(logged, result.DiagnosticID) {
		t.Errorf("log 缺 diagnostic_id: %s", logged)
	}
	if !strings.Contains(logged, "class=") {
		t.Errorf("log 缺粗分類原因（它的唯一落點就是這裡）: %s", logged)
	}
}

// ── 密碼沿用三條件（缺一不可）──────────────────────────────────────────

// seedStoredDirectory 建一列既存設定（含 bind 密碼）供沿用測試使用
func seedStoredDirectory(t *testing.T, svc *LDAPDirectoryService, url string) {
	t.Helper()
	if _, err := svc.Upsert(context.Background(), ldapDirReq(func(r *LDAPDirectoryRequest) {
		r.URL = url
		r.BindPassword = "stored-secret"
	})); err != nil {
		t.Fatalf("建立既存設定: %v", err)
	}
}

func TestLDAPTestBindPasswordReuseConditions(t *testing.T) {
	const storedURL = "ldaps://dir.example:636"

	t.Run("三條件齊備才沿用", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		seedStoredDirectory(t, svc, storedURL)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			r.BindPassword = ""
		}))
		if err != nil {
			t.Fatalf("不應前置拒絕: %v", err)
		}
		if !result.Success || !result.ReusedStoredPassword {
			t.Fatalf("結果 = %+v, want 成功且沿用", result)
		}
		binds := dialer.conn.bindCalls()
		if len(binds) != 1 || binds[0].password != "stored-secret" {
			t.Fatalf("bind 記錄 = %+v, want 沿用既存密碼", binds)
		}
	})

	t.Run("同端點的不同字面仍沿用", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		seedStoredDirectory(t, svc, storedURL)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		// 省略預設埠：canonical origin 相等，不應被誤判為換了目標
		result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			r.URL = "ldaps://DIR.example"
			r.BindPassword = ""
		}))
		if err != nil {
			t.Fatalf("不應前置拒絕: %v", err)
		}
		if !result.ReusedStoredPassword {
			t.Error("同一 canonical origin 應沿用既存密碼")
		}
	})

	// **spec 明訂的斷言對象**：撥號層未收到舊密碼，不依賴遠端回應
	t.Run("改URL後留空密碼不沿用", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		seedStoredDirectory(t, svc, storedURL)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			r.URL = "ldaps://attacker.example:636"
			r.BindPassword = ""
		}))
		if err != nil {
			t.Fatalf("不應前置拒絕: %v", err)
		}
		if result.ReusedStoredPassword {
			t.Error("換端點不得沿用既存密碼")
		}
		for _, b := range dialer.conn.bindCalls() {
			if b.password == "stored-secret" {
				t.Fatalf("既存密碼被送往新位址: %+v", b)
			}
		}
		if result.FailedStage != LDAPTestStageBind || result.Code != LDAPTestCodeBindPasswordMissing {
			t.Errorf("定位 = %s/%s, want bind/%s", result.FailedStage, result.Code, LDAPTestCodeBindPasswordMissing)
		}
	})

	t.Run("勾選清除後不沿用", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		seedStoredDirectory(t, svc, storedURL)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		// URL 未變、既存有密碼，只差「已勾選清除」這一條件
		result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			r.BindPassword = ""
			r.ClearBindPassword = true
		}))
		if err != nil {
			t.Fatalf("不應前置拒絕: %v", err)
		}
		if result.ReusedStoredPassword {
			t.Error("已勾選清除時不得沿用即將被清除的密碼")
		}
		for _, b := range dialer.conn.bindCalls() {
			if b.password == "stored-secret" {
				t.Fatalf("清除旗標下仍送出既存密碼: %+v", b)
			}
		}
	})

	t.Run("請求自帶密碼即不查既存", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		seedStoredDirectory(t, svc, storedURL)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
		if err != nil {
			t.Fatalf("不應前置拒絕: %v", err)
		}
		if result.ReusedStoredPassword {
			t.Error("請求自帶密碼時不應標記沿用")
		}
		binds := dialer.conn.bindCalls()
		if len(binds) != 1 || binds[0].password != "form-secret" {
			t.Fatalf("bind 記錄 = %+v, want 使用表單密碼", binds)
		}
	})

	t.Run("無既存列時以空密碼測試", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			r.BindPassword = ""
		}))
		if err != nil {
			t.Fatalf("不應前置拒絕: %v", err)
		}
		if result.Code != LDAPTestCodeBindPasswordMissing {
			t.Errorf("碼 = %s, want %s", result.Code, LDAPTestCodeBindPasswordMissing)
		}
		if len(dialer.conn.bindCalls()) != 0 {
			t.Error("空密碼不得對目錄發出 bind 請求（部分目錄視為匿名 bind 而回成功）")
		}
	})
}

// ── 測試端點的傳輸閘（含「關掉啟用開關不能繞過」）─────────────────────

func TestLDAPTestTransmissionGate(t *testing.T) {
	plaintext := func(r *LDAPDirectoryTestRequest) { r.URL = "ldap://dir.example:389" }

	t.Run("strict 拒測且未撥號", func(t *testing.T) {
		svc, db := newLDAPGateSvc(t, policy.TransportLevelStrict)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		_, err := svc.TestConnection(context.Background(), ldapTestReq(plaintext))
		var gateErr *policy.TransmissionGateError
		if !errors.As(err, &gateErr) || gateErr.Code != policy.TransmissionGateStrictReject {
			t.Fatalf("錯誤 = %v, want strict_reject", err)
		}
		if dialer.dialCount() != 0 {
			t.Error("strict 下不得撥號（bind 密碼即隨之送出）")
		}
		audit := ldapProbeAudit(t, db, LDAPAuditEventTestRejected)
		if audit["reason"] != LDAPRejectTransmissionGate || audit["detail"] != policy.TransmissionGateStrictReject {
			t.Errorf("審計 = %v", audit)
		}
	})

	// **繞過面的守衛格**：測試閘的判定不受請求的 enabled 值限縮
	t.Run("enabled=false 仍被 strict 拒絕", func(t *testing.T) {
		svc, _ := newLDAPGateSvc(t, policy.TransportLevelStrict)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		_, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			plaintext(r)
			r.Enabled = false
		}))
		var gateErr *policy.TransmissionGateError
		if !errors.As(err, &gateErr) || gateErr.Code != policy.TransmissionGateStrictReject {
			t.Fatalf("錯誤 = %v, want strict_reject——關掉啟用開關不得成為明文外送憑證的旁路", err)
		}
		if dialer.dialCount() != 0 {
			t.Error("enabled=false 的 strict 測試仍不得撥號")
		}
	})

	t.Run("warn 缺確認即拒", func(t *testing.T) {
		svc, _ := newLDAPGateSvc(t, policy.TransportLevelWarn)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		_, err := svc.TestConnection(context.Background(), ldapTestReq(plaintext))
		var gateErr *policy.TransmissionGateError
		if !errors.As(err, &gateErr) || gateErr.Code != policy.TransmissionGateAckRequired {
			t.Fatalf("錯誤 = %v, want ack_required", err)
		}
		if dialer.dialCount() != 0 {
			t.Error("warn 缺確認時不得撥號")
		}
	})

	t.Run("warn 帶確認放行並留痕", func(t *testing.T) {
		svc, db := newLDAPGateSvc(t, policy.TransportLevelWarn)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			plaintext(r)
			r.RiskAcknowledged = true
		}))
		if err != nil {
			t.Fatalf("warn＋確認應放行: %v", err)
		}
		if !result.Success || dialer.dialCount() != 1 {
			t.Fatalf("結果 = %+v, dial=%d", result, dialer.dialCount())
		}
		audit := ldapProbeAudit(t, db, LDAPAuditEventTest)
		if audit["risk_acknowledged"] != true {
			t.Errorf("審計未留痕確認聲明: %v", audit)
		}
		if _, ok := audit["transmission_risks"]; !ok {
			t.Errorf("審計缺風險項: %v", audit)
		}
	})

	t.Run("strict 下 ldaps 正常執行", func(t *testing.T) {
		svc, _ := newLDAPGateSvc(t, policy.TransportLevelStrict)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
		if err != nil {
			t.Fatalf("無風險的 ldaps 不應被閘擋: %v", err)
		}
		if !result.Success {
			t.Errorf("結果 = %+v", result)
		}
	})
}

// ── 前置驗證（存檔規則同源，不得只存在於存檔路徑）─────────────────────

func TestLDAPTestValidationRejectsBeforeDial(t *testing.T) {
	cases := map[string]func(*LDAPDirectoryTestRequest){
		"OR 繞過型 filter":  func(r *LDAPDirectoryTestRequest) { r.UserFilter = "(|(uid=%s)(uid=svc-admin))" },
		"缺 base_dn":      func(r *LDAPDirectoryTestRequest) { r.BaseDN = "" },
		"URL 帶 userinfo": func(r *LDAPDirectoryTestRequest) { r.URL = "ldap://user:secret@dir.example" },
		"URL 非法 scheme":  func(r *LDAPDirectoryTestRequest) { r.URL = "http://dir.example" },
		"超長 bind 密碼":     func(r *LDAPDirectoryTestRequest) { r.BindPassword = strings.Repeat("x", ldapProbeBindPasswordMaxLen+1) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			svc, db := newLDAPDirectorySvc(t)
			dialer := newProbeDialer()
			installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

			if _, err := svc.TestConnection(context.Background(), ldapTestReq(mut)); err == nil {
				t.Fatal("應被前置拒絕")
			}
			if dialer.dialCount() != 0 {
				t.Error("驗證未過不得撥號")
			}
			audit := ldapProbeAudit(t, db, LDAPAuditEventTestRejected)
			if audit["reason"] != LDAPRejectValidation {
				t.Errorf("審計 reason = %v", audit["reason"])
			}
			// 原始輸入（可能含 userinfo 憑證）不得進審計
			if raw, _ := json.Marshal(audit); strings.Contains(string(raw), "secret") {
				t.Errorf("審計含使用者輸入: %s", raw)
			}
		})
	}
}

// TestLDAPTestStoredSettingsUnreadable 需沿用既存密碼但既存密文不可解時，
// 不靜默降級為空密碼測試（會讓 admin 誤以為是目錄權限問題）
func TestLDAPTestStoredSettingsUnreadable(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	seedStoredDirectory(t, svc, "ldaps://dir.example:636")
	// 破壞密文：解密必然失敗 → 解析三態的「故障」
	if err := db.Model(&model.LDAPDirectory{}).Where("1 = 1").
		Update("bind_password_enc", "not-a-valid-ciphertext").Error; err != nil {
		t.Fatalf("破壞密文: %v", err)
	}
	dialer := newProbeDialer()
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	_, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
		r.BindPassword = ""
	}))
	if !errors.Is(err, ErrLDAPTestStoredSettingsUnavailable) {
		t.Fatalf("錯誤 = %v, want ErrLDAPTestStoredSettingsUnavailable", err)
	}
	if dialer.dialCount() != 0 {
		t.Error("既存設定不可讀時不應撥號")
	}
}

// ── 資源上限 ────────────────────────────────────────────────────────────

func TestLDAPTestRateLimited(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	dialer := newProbeDialer()
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{ActorBurst: 1, ActorRefill: time.Hour})

	if _, err := svc.TestConnection(context.Background(), ldapTestReq(nil)); err != nil {
		t.Fatalf("首次應通過: %v", err)
	}
	_, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
	if !errors.Is(err, ErrLDAPTestRateLimited) {
		t.Fatalf("第二次錯誤 = %v, want ErrLDAPTestRateLimited", err)
	}
	if dialer.dialCount() != 1 {
		t.Errorf("撥號次數 = %d, want 1（被限流者不得撥號）", dialer.dialCount())
	}
	// 限流事件不入審計：審計儲存正是本界線要保護的資源之一
	var n int64
	if err := db.Model(&model.AuditLog{}).Count(&n).Error; err != nil {
		t.Fatalf("計數審計: %v", err)
	}
	if n != 1 {
		t.Errorf("審計筆數 = %d, want 1（限流事件不落審計）", n)
	}
}

func TestLDAPTestPerTargetAndInFlightLimits(t *testing.T) {
	t.Run("per-target 跨操作者生效", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		dialer := newProbeDialer()
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{TargetBurst: 1, TargetRefill: time.Hour})

		if _, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			r.Actor.ID = 11
		})); err != nil {
			t.Fatalf("首次應通過: %v", err)
		}
		// 換一個操作者、同一目標：per-target 額度已用盡
		_, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			r.Actor.ID = 22
		}))
		if !errors.Is(err, ErrLDAPTestRateLimited) {
			t.Fatalf("錯誤 = %v, want 被 per-target 限流", err)
		}
	})

	t.Run("in-flight 上限與歸還", func(t *testing.T) {
		limiter := newLDAPProbeLimiter(ldapProbeLimits{MaxInFlight: 1})
		release, _, ok := limiter.acquire("u1", "t1")
		if !ok {
			t.Fatal("首次應取得額度")
		}
		if _, reason, ok := limiter.acquire("u2", "t2"); ok || reason != ldapProbeLimitInFlight {
			t.Fatalf("第二次 = ok:%v reason:%s, want 被 in_flight 擋", ok, reason)
		}
		release()
		release() // 冪等：重複歸還不得使計數失真
		if _, _, ok := limiter.acquire("u2", "t2"); !ok {
			t.Fatal("歸還後應可再取得")
		}
		if limiter.inFlight != 1 {
			t.Errorf("in-flight = %d, want 1（release 須冪等）", limiter.inFlight)
		}
	})

	t.Run("額度隨時間回補且被拒不延後窗口", func(t *testing.T) {
		limiter := newLDAPProbeLimiter(ldapProbeLimits{ActorBurst: 1, ActorRefill: time.Minute})
		now := time.Unix(1_700_000_000, 0)
		limiter.now = func() time.Time { return now }

		if _, _, ok := limiter.acquire("u1", "t1"); !ok {
			t.Fatal("首次應通過")
		}
		if _, _, ok := limiter.acquire("u1", "t1"); ok {
			t.Fatal("額度用盡應被擋")
		}
		// 被拒後持續嘗試不得把回補窗口往後推
		now = now.Add(30 * time.Second)
		if _, _, ok := limiter.acquire("u1", "t1"); ok {
			t.Fatal("半個回補週期不應恢復")
		}
		now = now.Add(31 * time.Second)
		if _, _, ok := limiter.acquire("u1", "t1"); !ok {
			t.Fatal("超過一個回補週期後應恢復")
		}
	})
}

// TestLDAPTestStageTimeoutClosesConn 逾時主動關閉連線
// （go-ldap 的阻塞呼叫不受 handler context 中止）
func TestLDAPTestStageTimeoutClosesConn(t *testing.T) {
	prev := ldapProbeStageTimeout
	ldapProbeStageTimeout = 50 * time.Millisecond
	t.Cleanup(func() { ldapProbeStageTimeout = prev })

	svc, _ := newLDAPDirectorySvc(t)
	dialer := newProbeDialer()
	dialer.conn.bindDelay = 2 * time.Second
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	start := time.Now()
	result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
	if err != nil {
		t.Fatalf("不應前置拒絕: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("逾時未生效，耗時 %v", elapsed)
	}
	if result.FailedStage != LDAPTestStageBind || result.Code != LDAPTestCodeStageTimeout {
		t.Errorf("定位 = %s/%s, want bind/%s", result.FailedStage, result.Code, LDAPTestCodeStageTimeout)
	}
	if dialer.conn.closeCount() == 0 {
		t.Error("逾時後未主動關閉連線")
	}
}

// ── 真實撥號路徑：舊密碼確實沒離開本機 ─────────────────────────────────

// TestLDAPTestRealDialSendsNoStoredPassword 以真實 go-ldap 撥號（經出站政策）
// 對一個只讀不回應的 listener 測試，斷言**送出的位元組**不含既存密碼。
//
// 與上方的替身版互補：替身版釘住服務層分支，本格釘住「整條真實路徑串起來後
// 仍成立」——包含 DialURL 的 Control 檢查與 go-ldap 的實際編碼
func TestLDAPTestRealDialSendsNoStoredPassword(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener: %v", err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("解析埠: %v", err)
	}

	received := make(chan []byte, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			received <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf, _ := io.ReadAll(io.LimitReader(conn, 4096))
		received <- buf
	}()

	// loopback 目標須顯式放行（出站政策無關閉開關）
	t.Setenv("LDAP_ALLOWED_LOOPBACK_ENDPOINTS", net.JoinHostPort("127.0.0.1", port))

	svc, _ := newLDAPDirectorySvc(t)
	seedStoredDirectory(t, svc, "ldaps://dir.example:636")
	// 生產撥號路徑（不裝替身），但限流器換新的以免與其他案例互相干擾
	prev := ldapProbeCurrentRuntime
	ldapProbeCurrentRuntime = newLDAPProbeRuntime()
	t.Cleanup(func() { ldapProbeCurrentRuntime = prev })

	result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
		r.URL = "ldap://127.0.0.1:" + port
		r.BindPassword = ""
	}))
	if err != nil {
		t.Fatalf("不應前置拒絕: %v", err)
	}
	if result.ReusedStoredPassword {
		t.Error("換端點不得沿用既存密碼")
	}
	// 撥號成功（listener 接受了連線），停在 bind 階段
	if result.FailedStage != LDAPTestStageBind || result.Code != LDAPTestCodeBindPasswordMissing {
		t.Fatalf("定位 = %s/%s, want bind/%s", result.FailedStage, result.Code, LDAPTestCodeBindPasswordMissing)
	}

	select {
	case buf := <-received:
		if strings.Contains(string(buf), "stored-secret") {
			t.Fatalf("既存密碼被送往新位址（%d bytes）", len(buf))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener 未收到連線")
	}
}

// ── 安全與健壯性補強─────────────────────

// TestLDAPProbeBindErrorNeverReachesLog LDAP 回應的原始錯誤文字不得入日誌。
//
// # 為什麼這是 HIGH
//
// bind 的 diagnostic message 是**對端可控的自由文字**，且部分實作會在失敗訊息
// 中回顯收到的憑證。原始錯誤一路以 %v 交給 log，等於讓一個惡意或異常的目錄
// 端點只要回顯密碼，就能把 service bind 明文寫進我方伺服器日誌。
//
// **突變辨識力**：把 logLDAPProbeFailure 改回收 error 並格式化 err=%v，
// 本格立刻轉紅（假 LDAP 錯誤刻意回顯密碼字面值）
func TestLDAPProbeBindErrorNeverReachesLog(t *testing.T) {
	// 對端回顯 bind 密碼的診斷訊息（AD 風格的 LdapErr 文案）
	echoing := func(password string) error {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, fmt.Errorf(
			"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, "+
				"supplied credential %q rejected, data 52e", password))
	}

	t.Run("bind 階段", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		dialer := newProbeDialer()
		dialer.conn.bindErr = echoing("form-secret")
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})
		logged := captureLDAPLog(t)

		result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
		if err != nil {
			t.Fatalf("不應前置拒絕: %v", err)
		}
		if result.Code != LDAPTestCodeBindFailed {
			t.Fatalf("碼 = %s, want %s", result.Code, LDAPTestCodeBindFailed)
		}
		out := logged()
		if strings.Contains(out, "form-secret") {
			t.Fatalf("bind 明文落入 operational log: %s", out)
		}
		// 整段對端文字都不得出現——只擋密碼字面值等於相信對端不會換個講法
		for _, fragment := range []string{"AcceptSecurityContext", "LdapErr", "DSID", "data 52e"} {
			if strings.Contains(out, fragment) {
				t.Errorf("對端可控文字 %q 落入 log: %s", fragment, out)
			}
		}
		// 排錯所需的靜態資訊仍在（收斂不等於把可觀測性砍掉）
		if !strings.Contains(out, "class=ldap_result_49") {
			t.Errorf("log 缺 LDAP result code 數值分類: %s", out)
		}
		for _, want := range []string{"stage=" + LDAPTestStageBind, "diagnostic_id=" + result.DiagnosticID,
			"target=ldaps://dir.example:636"} {
			if !strings.Contains(out, want) {
				t.Errorf("log 缺 %q: %s", want, out)
			}
		}
	})

	t.Run("search 階段", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		dialer := newProbeDialer()
		dialer.conn.searchErr = echoing("form-secret")
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})
		logged := captureLDAPLog(t)

		if _, err := svc.TestConnection(context.Background(), ldapTestReq(nil)); err != nil {
			t.Fatalf("不應前置拒絕: %v", err)
		}
		if out := logged(); strings.Contains(out, "form-secret") || strings.Contains(out, "AcceptSecurityContext") {
			t.Fatalf("search 階段仍把對端原文寫入 log: %s", out)
		}
	})

	t.Run("dial 階段的靜態分類仍保留", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		dialer := newProbeDialer()
		// 撥號錯誤同樣不得原樣入 log；但本地分類器的靜態字串應保留
		dialer.dialErr = fmt.Errorf("dial tcp: %w", errors.New("secret-in-dial-error"))
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})
		logged := captureLDAPLog(t)

		if _, err := svc.TestConnection(context.Background(), ldapTestReq(nil)); err != nil {
			t.Fatalf("不應前置拒絕: %v", err)
		}
		out := logged()
		if strings.Contains(out, "secret-in-dial-error") {
			t.Fatalf("撥號原始錯誤落入 log: %s", out)
		}
		if !strings.Contains(out, "class=") {
			t.Errorf("log 缺本地靜態分類: %s", out)
		}
	})
}

// TestLDAPTestNilGateFailsClosed 閘未接線時測試一律拒絕且不撥號。
//
// 測試端點**當下就會把 bind 密碼送上網路**，nil 閘視為放行等於 strict 檔位在
// 此端點完全不存在。請求刻意用無風險的 ldaps——舊行為下它會照常執行完整階梯，
// 故 fail-close 改回 `if s.gate != nil` 即轉紅
func TestLDAPTestNilGateFailsClosed(t *testing.T) {
	db := newLDAPDirectoryDB(t)
	svc := NewLDAPDirectoryService(db, aesColumnCodec(t, kmTestKey(0x42)), audit.NewTxSink()) // 刻意不接閘
	dialer := newProbeDialer()
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	_, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
	if !errors.Is(err, ErrLDAPTransmissionGateUnavailable) {
		t.Fatalf("錯誤 = %v, want ErrLDAPTransmissionGateUnavailable", err)
	}
	if dialer.dialCount() != 0 {
		t.Error("閘未接線時不得撥號（bind 密碼即隨之送出）")
	}
	audit := ldapProbeAudit(t, db, LDAPAuditEventTestRejected)
	if audit["reason"] != LDAPRejectTransmissionGateUnavailable {
		t.Errorf("審計 reason = %v, want %s", audit["reason"], LDAPRejectTransmissionGateUnavailable)
	}

	// 接上明確的 allow-all 閘後同一請求即正常執行——證明拒絕出自閘缺席
	svc.SetTransmissionPolicy(ldapAllowAllGate{})
	result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
	if err != nil {
		t.Fatalf("接上閘後應可執行: %v", err)
	}
	if !result.Success || dialer.dialCount() != 1 {
		t.Errorf("結果 = %+v, dial=%d", result, dialer.dialCount())
	}
}

// TestLDAPTestPasswordClearConflictRejectedBeforeDial 密碼＋clear 併存時
// 測試路徑須與存檔路徑同樣拒絕，且**不得發生撥號**。
//
// 舊行為：測試路徑優先採用密碼並實際送出 bind——admin 勾了「清除密碼」卻看到
// 「測試成功」，存檔後該密碼已不存在，測試結果純屬誤導
func TestLDAPTestPasswordClearConflictRejectedBeforeDial(t *testing.T) {
	svc, db := newLDAPDirectorySvc(t)
	seedStoredDirectory(t, svc, "ldaps://dir.example:636")
	dialer := newProbeDialer()
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	_, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
		r.ClearBindPassword = true // BindPassword 仍為 "form-secret"
	}))
	if !errors.Is(err, ErrLDAPBindPasswordConflict) {
		t.Fatalf("錯誤 = %v, want ErrLDAPBindPasswordConflict（與存檔路徑同一判定）", err)
	}
	if dialer.dialCount() != 0 {
		t.Error("衝突請求不得撥號")
	}
	if binds := dialer.conn.bindCalls(); len(binds) != 0 {
		t.Errorf("衝突請求仍送出 bind: %+v", binds)
	}
	audit := ldapProbeAudit(t, db, LDAPAuditEventTestRejected)
	if audit["reason"] != LDAPRejectBindPasswordConflict {
		t.Errorf("審計 reason = %v, want %s", audit["reason"], LDAPRejectBindPasswordConflict)
	}
}

// TestLDAPTestCorruptCiphertextDoesNotBlockOtherEndpoint 證明同源前不解密。
//
// 既存密文損壞（金鑰事故）時，測試**另一個**端點本就不會沿用既存密碼，故不應
// 被 stored_settings_unavailable 阻斷——否則金鑰事故會連帶癱瘓「換一台目錄
// 重新設定」這條復原路徑。
//
// 兩道斷言各自獨立：(1) 測試仍可執行 (2) 解密根本沒被呼叫。把比較端點的步驟
// 移回解密之後，兩道都轉紅
func TestLDAPTestCorruptCiphertextDoesNotBlockOtherEndpoint(t *testing.T) {
	db := newLDAPDirectoryDB(t)
	var decrypts int32
	svc := NewLDAPDirectoryService(db, ldapCountingCodec{
		inner:    aesColumnCodec(t, kmTestKey(0x42)),
		decrypts: &decrypts,
	}, audit.NewTxSink())
	svc.SetTransmissionPolicy(ldapAllowAllGate{})
	seedStoredDirectory(t, svc, "ldaps://dir.example:636")
	// 破壞密文：任何解密嘗試都會失敗
	if err := db.Model(&model.LDAPDirectory{}).Where("1 = 1").
		Update("bind_password_enc", "not-a-valid-ciphertext").Error; err != nil {
		t.Fatalf("破壞密文: %v", err)
	}
	atomic.StoreInt32(&decrypts, 0)

	dialer := newProbeDialer()
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
		r.URL = "ldaps://other.example:636" // 不同 canonical origin
		r.BindPassword = ""
	}))
	if err != nil {
		t.Fatalf("測試不同端點不應被既存密文損壞阻斷: %v", err)
	}
	if n := atomic.LoadInt32(&decrypts); n != 0 {
		t.Errorf("解密被呼叫 %d 次——證明同源之前不得解密（明文亦被不必要地具現化）", n)
	}
	if result.ReusedStoredPassword {
		t.Error("換端點不得標記沿用")
	}
	// 階梯確實跑到 bind 階段並停在「無可用密碼」
	if dialer.dialCount() != 1 {
		t.Errorf("撥號次數 = %d, want 1", dialer.dialCount())
	}
	if result.FailedStage != LDAPTestStageBind || result.Code != LDAPTestCodeBindPasswordMissing {
		t.Errorf("定位 = %s/%s, want bind/%s", result.FailedStage, result.Code, LDAPTestCodeBindPasswordMissing)
	}

	// 對照：測試**同一個**端點時，損壞的密文確實阻斷（沿用本就必要，
	// 不得靜默降級為空密碼測試）——見 TestLDAPTestStoredSettingsUnreadable
	if _, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
		r.BindPassword = ""
	})); !errors.Is(err, ErrLDAPTestStoredSettingsUnavailable) {
		t.Fatalf("同端點的錯誤 = %v, want ErrLDAPTestStoredSettingsUnavailable", err)
	}
}
