package policy

import (
	"errors"
	"strings"
	"testing"
)

// 文字型政策鍵的正規化與驗證。
//
// 全部經 normalizePolicyValue 這個唯一入口——測試若各自呼叫一個私有的
// 正規化步驟，就證明不了「寫入路徑存進去的與驗證通過的是同一個字串」。

func bannerBodyDef(t *testing.T) *PolicyDef {
	t.Helper()
	def := findDef(PolicyLoginBannerBody)
	if def == nil {
		t.Fatalf("政策鍵 %s 未定義", PolicyLoginBannerBody)
	}
	return def
}

func bannerTitleDef(t *testing.T) *PolicyDef {
	t.Helper()
	def := findDef(PolicyLoginBannerTitle)
	if def == nil {
		t.Fatalf("政策鍵 %s 未定義", PolicyLoginBannerTitle)
	}
	return def
}

func TestLoginBannerTextLengthBoundary(t *testing.T) {
	def := bannerBodyDef(t)

	// 補充平面字元：每個佔兩個 UTF-16 單位、四個 byte，只有以 code point 計
	// 才會得到 2000。用它才分辨得出計數口徑是否走錯
	at := strings.Repeat("\U0001F600", def.MaxLength)
	if got, err := normalizePolicyValue(def, at); err != nil || got != at {
		t.Errorf("上限值被拒: err=%v", err)
	}
	over := at + "\U0001F600"
	if _, err := normalizePolicyValue(def, over); err == nil {
		t.Errorf("超過上限一個字元仍被接受（%d code point）", def.MaxLength+1)
	}
}

func TestLoginBannerTextNormalization(t *testing.T) {
	def := bannerBodyDef(t)

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"CRLF 統一為 LF", "第一行\r\n第二行", "第一行\n第二行"},
		{"孤立 CR 統一為 LF", "第一行\r第二行", "第一行\n第二行"},
		{"首尾空白移除", "  \n 內文 \n\t ", "內文"},
		{"空字串合法", "", ""},
		{"只有空白等同未設定", "   \n  ", ""},
		{"TAB 保留於行內", "欄一\t欄二", "欄一\t欄二"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizePolicyValue(def, c.in)
			if err != nil {
				t.Fatalf("被拒: %v", err)
			}
			if got != c.want {
				t.Errorf("正規化 = %q, want %q", got, c.want)
			}
		})
	}
}

func TestLoginBannerTextRejectsControlCharacters(t *testing.T) {
	body := bannerBodyDef(t)
	title := bannerTitleDef(t)

	rejected := []struct {
		name string
		def  *PolicyDef
		in   string
	}{
		{"內文含 U+0000", body, "前\x00後"},
		{"內文含 U+0085（C1）", body, "前\u0085後"},
		{"內文含 U+001B（ESC）", body, "前\x1b[31m後"},
		{"標題含換行", title, "標題\n第二行"},
		{"標題含 CRLF（正規化後仍是換行）", title, "標題\r\n第二行"},
		{"非法 UTF-8 位元組", body, "前\xff後"},
	}
	for _, c := range rejected {
		t.Run(c.name, func(t *testing.T) {
			if _, err := normalizePolicyValue(c.def, c.in); err == nil {
				t.Error("應被拒卻通過")
			} else {
				var invalid *PolicyInvalidValueError
				if !errors.As(err, &invalid) {
					t.Fatalf("錯誤型別 = %T, want *PolicyInvalidValueError（handler 靠它指名鍵）", err)
				}
				if invalid.Key != c.def.Key {
					t.Errorf("錯誤指名的鍵 = %q, want %q", invalid.Key, c.def.Key)
				}
			}
		})
	}

	accepted := []struct {
		name string
		in   string
	}{
		{"零寬空格 U+200B", "前\u200b後"},
		{"取代字元 U+FFFD", "前\ufffd後"},
	}
	for _, c := range accepted {
		t.Run(c.name, func(t *testing.T) {
			if _, err := normalizePolicyValue(body, c.in); err != nil {
				t.Errorf("被拒: %v（Cf 與取代字元不在擋的範圍內）", err)
			}
		})
	}
}

func TestLoginBannerPolicyDefsShape(t *testing.T) {
	if err := validatePolicyDefs(); err != nil {
		t.Fatalf("validatePolicyDefs: %v", err)
	}
	for _, want := range []struct {
		key       string
		maxLength int
		multiline bool
	}{
		{PolicyLoginBannerTitle, 120, false},
		{PolicyLoginBannerBody, 2000, true},
	} {
		def := findDef(want.key)
		if def == nil {
			t.Fatalf("政策鍵 %s 未定義", want.key)
		}
		if def.Type != PolicyTypeText {
			t.Errorf("%s Type = %q, want %q", want.key, def.Type, PolicyTypeText)
		}
		if def.Default != "" {
			t.Errorf("%s Default = %q, want 空字串（出廠即未設定）", want.key, def.Default)
		}
		if def.MaxLength != want.maxLength {
			t.Errorf("%s MaxLength = %d, want %d", want.key, def.MaxLength, want.maxLength)
		}
		if def.Multiline != want.multiline {
			t.Errorf("%s Multiline = %v, want %v", want.key, def.Multiline, want.multiline)
		}
		if def.PCIValue != "" || def.EPaymentValue != "" {
			t.Errorf("%s 掛了基準建議值（內容由部署方自填，不存在通用的正確值）", want.key)
		}
		if def.Unit != "" || def.UnitKey != "" {
			t.Errorf("%s 有單位 %q/%q，文字鍵不應有", want.key, def.Unit, def.UnitKey)
		}
	}
}

func TestLoginBannerListExposesTextMetadata(t *testing.T) {
	svc, _ := setupPolicyDB(t)
	views := map[string]PolicyView{}
	for _, v := range svc.List() {
		views[v.Key] = v
	}
	for key, wantMax := range map[string]int{
		PolicyLoginBannerTitle: 120,
		PolicyLoginBannerBody:  2000,
	} {
		v, ok := views[key]
		if !ok {
			t.Fatalf("List() 未含 %s", key)
		}
		if v.Type != PolicyTypeText {
			t.Errorf("%s type = %q, want text", key, v.Type)
		}
		if v.MaxLength != wantMax {
			t.Errorf("%s max_length = %d, want %d", key, v.MaxLength, wantMax)
		}
		if v.Compliant != nil || v.EPaymentCompliant != nil {
			t.Errorf("%s 的符合性應為 nil（無基準建議值）", key)
		}
	}
	if views[PolicyLoginBannerBody].Multiline != true {
		t.Error("內文 multiline 應為 true")
	}
	if views[PolicyLoginBannerTitle].Multiline != false {
		t.Error("標題 multiline 應為 false")
	}
}

// TestLoginBannerTextRoundTripThroughUpdate 寫入路徑落庫的是終值：
// 讀回的內文換行為 LF、尾端空白已移除。
func TestLoginBannerTextRoundTrip(t *testing.T) {
	svc, _ := setupPolicyDB(t)
	if _, err := svc.Update(PolicyLoginBannerBody, "第一行\r\n第二行  ", "admin"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := svc.Get(PolicyLoginBannerBody); got != "第一行\n第二行" {
		t.Errorf("讀回 = %q, want %q", got, "第一行\n第二行")
	}
}

// TestLoginBannerOverLimitRejectsWholeBatch 批次原子：一鍵超限，同批的合法鍵也不落庫。
func TestLoginBannerOverLimitRejectsWholeBatch(t *testing.T) {
	svc, _ := setupPolicyDB(t)
	def := bannerBodyDef(t)
	_, err := svc.UpdateBatch(map[string]string{
		PolicyLockoutMaxAttempts: "5",
		PolicyLoginBannerBody:    strings.Repeat("a", def.MaxLength+1),
	}, "admin")
	if err == nil {
		t.Fatal("超限值仍被接受")
	}
	var invalid *PolicyInvalidValueError
	if !errors.As(err, &invalid) {
		t.Fatalf("錯誤型別 = %T", err)
	}
	if invalid.Key != PolicyLoginBannerBody {
		t.Errorf("錯誤指名 %q, want %q", invalid.Key, PolicyLoginBannerBody)
	}
	if got := svc.Get(PolicyLockoutMaxAttempts); got != "10" {
		t.Errorf("同批的合法鍵已落庫（現值 %q），批次原子被破壞", got)
	}
}
