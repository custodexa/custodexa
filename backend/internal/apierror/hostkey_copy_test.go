package apierror

import (
	"strings"
	"testing"
)

// TestHostKeyMismatchCopyMatchesCredentialFact 主機金鑰不符的兩個碼對「登入憑證是否已送出」的陳述
// 必須與事實一致：警示碼只用於互動連線照常建立（憑證已送出），文案維持已送出的說法；
// 拒絕碼用於不放行的路徑（憑證未送出），文案必須明示未送出、且不得出現已送出的說法。
// 後端 zh fallback 與三語前端譯文都檢查。
func TestHostKeyMismatchCopyMatchesCredentialFact(t *testing.T) {
	type phrases struct{ sent, notSent string }
	byLocale := map[string]phrases{
		"zh-TW": {sent: "已送出登入憑證", notSent: "未送出任何登入憑證"},
		"en-US": {sent: "has sent the sign-in credentials", notSent: "no sign-in credentials were sent"},
		"ja-JP": {sent: "ログイン認証情報を送信しました", notSent: "ログイン認証情報は送信していません"},
	}
	sentClaims := map[string][]string{
		"zh-TW": {"已送出"},
		"en-US": {"has sent", "have been sent", "were sent to"},
		"ja-JP": {"送信しました"},
	}

	assertCopy := func(t *testing.T, where, text string, p phrases, claims []string, code ErrCode) {
		t.Helper()
		switch code {
		case CodeSSHHostKeyChanged:
			if !strings.Contains(text, p.sent) {
				t.Errorf("%s：互動放行的警示 %s 應陳述已送出登入憑證（含 %q）: %q", where, code, p.sent, text)
			}
		case CodeSSHHostKeyMismatchRefused:
			if !strings.Contains(text, p.notSent) {
				t.Errorf("%s：拒絕碼 %s 應明示未送出登入憑證（含 %q）: %q", where, code, p.notSent, text)
			}
			for _, c := range claims {
				if strings.Contains(text, c) {
					t.Errorf("%s：拒絕碼 %s 不得出現已送出憑證的說法 %q: %q", where, code, c, text)
				}
			}
		}
	}

	codes := []ErrCode{CodeSSHHostKeyChanged, CodeSSHHostKeyMismatchRefused}
	for _, code := range codes {
		d, ok := DescriptorOf(code)
		if !ok {
			t.Fatalf("%s 未註冊", code)
		}
		assertCopy(t, "ZhFallback", d.ZhFallback, byLocale["zh-TW"], sentClaims["zh-TW"], code)
	}

	dir := localeDir(t)
	for _, l := range locales {
		m := loadAPIError(t, dir, l)
		for _, code := range codes {
			text, ok := m[string(code)]
			if !ok {
				t.Fatalf("%s 缺 apiError.%s", l, code)
			}
			assertCopy(t, l, text, byLocale[l], sentClaims[l], code)
		}
	}
}
