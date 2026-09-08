package identity

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// 連線測試的群組屬性抽樣：只回布林不回值，且「沒設定」與「設了卻讀不到」可分辨。

// probeGroupSearchResult 首筆帶群組值、次筆不帶的搜尋結果。
func probeGroupSearchResult() *ldap.SearchResult {
	return &ldap.SearchResult{Entries: []*ldap.Entry{
		{DN: "uid=a,ou=users,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
			{Name: "mail", Values: []string{"a@example.com"}},
			{Name: "cn", Values: []string{"使用者 A"}},
			{Name: "memberOf", Values: []string{"cn=inner,ou=groups,dc=example,dc=org"}},
		}},
		{DN: "uid=b,ou=users,dc=example,dc=com", Attributes: []*ldap.EntryAttribute{
			{Name: "mail", Values: []string{"b@example.com"}},
		}},
	}}
}

// TestProbeGroupAttrSampleBooleanOnly 抽樣只回布林，回應裡不得出現任何屬性值。
//
// 回值等於讓連線測試變成免認證的目錄內容讀取管道——群組的辨識名稱本身就是
// 組織結構，比電郵更值得保護。斷言對象是**序列化後的整份回應**：
// 只檢查那一個欄位的話，日後有人多加一個「命中的群組」欄就完全看不見。
func TestProbeGroupAttrSampleBooleanOnly(t *testing.T) {
	svc, _ := newLDAPDirectorySvc(t)
	dialer := &fakeLDAPDialer{conn: &fakeLDAPConn{searchResult: probeGroupSearchResult()}}
	installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

	result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
		r.AttrGroup = "memberOf"
	}))
	if err != nil {
		t.Fatalf("測試不應被前置拒絕: %v", err)
	}
	if !result.Success {
		t.Fatalf("階梯應全過: %+v", result)
	}
	if !result.AttrSample.GroupConfigured || !result.AttrSample.GroupPresent {
		t.Fatalf("抽樣 = %+v, want 已設定且首筆有值", result.AttrSample)
	}

	// 群組屬性確實被索取（同一次搜尋，不另發）
	if n := len(dialer.conn.searchReqs); n != 1 {
		t.Fatalf("搜尋次數 = %d, want 1（群組屬性不得另發一次搜尋）", n)
	}
	attrs := dialer.conn.searchReqs[0].Attributes
	found := 0
	for _, a := range attrs {
		if a == "memberOf" {
			found++
		}
	}
	if found != 1 {
		t.Errorf("搜尋索取的屬性 = %v, want 含 memberOf 恰一次", attrs)
	}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("序列化回應: %v", err)
	}
	for _, leaked := range []string{"cn=inner", "a@example.com", "使用者 A", "uid=a"} {
		if strings.Contains(string(payload), leaked) {
			t.Errorf("回應含目錄內容 %q：連線測試不得回傳屬性值\n%s", leaked, payload)
		}
	}
}

// TestProbeGroupAttrUnsetDistinguishable 沒設定與設了卻讀不到必須分得出來。
//
// 兩者的處置完全不同：前者是「這個部署不用群組」，後者是「設定錯了，啟用之後
// 沒有人會拿到角色」。壓成一個布林就分不出來，而管理者需要的正是這個分辨。
func TestProbeGroupAttrUnsetDistinguishable(t *testing.T) {
	t.Run("未設定", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		dialer := &fakeLDAPDialer{conn: &fakeLDAPConn{searchResult: probeGroupSearchResult()}}
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		result, err := svc.TestConnection(context.Background(), ldapTestReq(nil))
		if err != nil {
			t.Fatalf("測試不應被前置拒絕: %v", err)
		}
		if result.AttrSample.GroupConfigured {
			t.Error("未填群組屬性名時 group_configured 應為 false")
		}
		if result.AttrSample.GroupPresent {
			t.Error("未填群組屬性名時 group_present 不得為 true")
		}
		// 未設定時搜尋請求逐字不變（不索取任何多餘屬性）
		if n := len(dialer.conn.searchReqs[0].Attributes); n != 2 {
			t.Errorf("索取屬性數 = %d, want 2（未設定時不多索取）", n)
		}
	})

	t.Run("設了但首筆沒有值", func(t *testing.T) {
		svc, _ := newLDAPDirectorySvc(t)
		// 首筆刻意不帶群組屬性
		res := probeGroupSearchResult()
		res.Entries = res.Entries[1:]
		dialer := &fakeLDAPDialer{conn: &fakeLDAPConn{searchResult: res}}
		installLDAPProbeRuntime(t, dialer, ldapProbeLimits{})

		result, err := svc.TestConnection(context.Background(), ldapTestReq(func(r *LDAPDirectoryTestRequest) {
			r.AttrGroup = "memberOf"
		}))
		if err != nil {
			t.Fatalf("測試不應被前置拒絕: %v", err)
		}
		if !result.AttrSample.GroupConfigured {
			t.Error("已填群組屬性名時 group_configured 應為 true")
		}
		if result.AttrSample.GroupPresent {
			t.Error("首筆沒有群組值時 group_present 應為 false")
		}
	})
}
