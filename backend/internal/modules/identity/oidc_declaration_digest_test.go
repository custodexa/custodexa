package identity

import (
	"regexp"
	"strings"
	"testing"
)

// 部署宣告指紋。
//
// 指紋的唯一用途是回答「兩個副本的宣告是否等效」，故兩個方向都要測：
// 判定上等效者 SHALL 同指紋（否則滾動更新期間會噴假分歧警報，警報一旦被視為
// 雜訊就等於沒有），判定上不等效者 SHALL 不同指紋（否則分歧被靜默吞掉）。

var digestShape = regexp.MustCompile(`^[0-9a-f]{12}$`)

func TestDeclarationDigestDiffersForDifferentDeclarations(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
	}{
		{"不同 issuer", []string{"https://a.example.com"}, []string{"https://b.example.com"}},
		{"多一項", []string{"https://a.example.com"},
			[]string{"https://a.example.com", "https://b.example.com"}},
		{"未宣告 vs 有宣告", nil, []string{"https://a.example.com"}},
		{"路徑不同（不得做前綴折疊）", []string{"https://idp.example.com/tenant-a"},
			[]string{"https://idp.example.com/tenant-b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if DedicatedIssuerDeclarationDigest(c.a) == DedicatedIssuerDeclarationDigest(c.b) {
				t.Errorf("%v 與 %v 的指紋相同——副本間的設定分歧將無法由 /health 偵測", c.a, c.b)
			}
		})
	}
}

func TestDeclarationDigestStableForEquivalentDeclarations(t *testing.T) {
	base := []string{"https://a.example.com", "https://b.example.com"}
	cases := []struct {
		name string
		in   []string
	}{
		{"順序不同", []string{"https://b.example.com", "https://a.example.com"}},
		{"尾斜線", []string{"https://a.example.com/", "https://b.example.com"}},
		{"host 大小寫", []string{"https://A.Example.com", "https://b.example.com"}},
		{"重複項", []string{"https://a.example.com", "https://b.example.com", "https://a.example.com"}},
		{"空白與空項", []string{" https://a.example.com ", "", "https://b.example.com"}},
	}
	want := DedicatedIssuerDeclarationDigest(base)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 正規化與 EffectiveIssuerKind 同源：這些差異不改變任何 issuer 的判定，
			// 若指紋因此改變，監控會在每次無害的環境檔排版調整後噴假警報
			if got := DedicatedIssuerDeclarationDigest(c.in); got != want {
				t.Errorf("指紋 = %q, want %q——判定上等效的宣告不得產生分歧信號", got, want)
			}
		})
	}
}

func TestDeclarationDigestShape(t *testing.T) {
	for _, in := range [][]string{nil, {}, {"https://a.example.com"}} {
		got := DedicatedIssuerDeclarationDigest(in)
		if !digestShape.MatchString(got) {
			t.Errorf("指紋 %q 形狀不符（應為 12 位小寫 hex）——空宣告亦須有固定值，"+
				"否則「欄位為空」與「欄位不存在」在監控端無法區分", got)
		}
	}
}

// Scenario: 指紋不得洩漏宣告原文——健康檢查端點無須認證
func TestDeclarationDigestDoesNotLeakIssuers(t *testing.T) {
	got := DedicatedIssuerDeclarationDigest([]string{"https://secret-idp.internal.corp"})
	for _, frag := range []string{"secret-idp", "internal", "corp", "https"} {
		if strings.Contains(got, frag) {
			t.Errorf("指紋 %q 含宣告原文片段 %q", got, frag)
		}
	}
}
