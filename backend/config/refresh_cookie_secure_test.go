package config

import "testing"

// refresh cookie 的 Secure 旗標推導（refresh-token-httponly-cookie 決策 2）。
//
// # 為什麼不寫死
//
// 兩個寫死方向各有一種真實且**難以歸因**的失敗：
//
//   - 寫死 true：純 HTTP 部署（真實存在）下瀏覽器直接丟棄 Set-Cookie，使用者陷入
//     「登入成功 → 十幾分鐘後被登出」的迴圈。瀏覽器丟 cookie 是靜默行為，
//     錯誤訊息無從指出成因。
//   - 寫死 false：生產 HTTPS 環境放棄降級攻擊防護。
//
// 故採推導：env 顯式覆寫 > PUBLIC_BASE_URL 的 scheme > 預設 false。
// 本檔逐格釘住這條優先序與其邊界。

func TestDeriveRefreshCookieSecure(t *testing.T) {
	cases := []struct {
		name       string
		explicit   string
		baseURL    string
		wantSecure bool
		wantSource string
	}{
		{"顯式 true 覆寫 http 的 base URL", "true", "http://bastion.example.com",
			true, RefreshCookieSecureFromEnv},
		{"顯式 false 覆寫 https 的 base URL", "false", "https://bastion.example.com",
			false, RefreshCookieSecureFromEnv},
		{"顯式值容忍前後空白", "  true  ", "", true, RefreshCookieSecureFromEnv},
		{"顯式值可為 1／0", "1", "", true, RefreshCookieSecureFromEnv},
		// 拼錯的布林**不採信**：靜默接受會讓部署者以為自己關掉（或打開）了保護，
		// 而實際生效的是另一條規則。退回下一順位並在啟動日誌標明來源才可歸因
		{"顯式值無法解析時退回下一順位", "yes-please", "https://bastion.example.com",
			true, RefreshCookieSecureFromBaseURL},
		{"未顯式設定時取 https base URL", "", "https://bastion.example.com",
			true, RefreshCookieSecureFromBaseURL},
		{"未顯式設定時取 http base URL", "", "http://bastion.example.com",
			false, RefreshCookieSecureFromBaseURL},
		{"scheme 大小寫不敏感", "", "HTTPS://BASTION.EXAMPLE.COM",
			true, RefreshCookieSecureFromBaseURL},
		{"base URL 為空即本地／開發形態", "", "", false, RefreshCookieSecureFromDefault},
		{"base URL 無 scheme 時不臆測", "", "bastion.example.com",
			false, RefreshCookieSecureFromDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DeriveRefreshCookieSecure(tc.explicit, tc.baseURL)
			if got.Secure != tc.wantSecure {
				t.Errorf("Secure = %v, want %v（explicit=%q baseURL=%q）",
					got.Secure, tc.wantSecure, tc.explicit, tc.baseURL)
			}
			// 來源是啟動日誌的歸因依據：兩個方向的誤設都要能從日誌查出「這個值是
			// 依哪一個設定推出來的」，否則警告本身也答不出該去改哪裡
			if got.Source != tc.wantSource {
				t.Errorf("Source = %q, want %q", got.Source, tc.wantSource)
			}
		})
	}
}

// TestLoadRefreshCookieSecureDefaultsToInsecure 未設任何相關 env 時的預設。
//
// 預設非安全是刻意的（本地／開發形態必須可用），代價由啟動日誌的警告承擔——
// 這一格釘住的是「預設不會意外變成 true 而讓本地開發整個登不進去」
func TestLoadRefreshCookieSecureDefaultsToInsecure(t *testing.T) {
	t.Setenv("AUTH_REFRESH_COOKIE_SECURE", "")
	t.Setenv("PUBLIC_BASE_URL", "")

	got := LoadRefreshCookieSecure()
	if got.Secure {
		t.Errorf("未設任何相關 env 時 Secure = true，本地 HTTP 開發會因瀏覽器丟棄 cookie 而登不進去")
	}
	if got.Source != RefreshCookieSecureFromDefault {
		t.Errorf("Source = %q, want %q", got.Source, RefreshCookieSecureFromDefault)
	}
}

// TestLoadRefreshCookieSecureReadsEnv Load 路徑確實接到推導函式（接線本身也會斷）
func TestLoadRefreshCookieSecureReadsEnv(t *testing.T) {
	t.Setenv("AUTH_REFRESH_COOKIE_SECURE", "true")
	t.Setenv("PUBLIC_BASE_URL", "http://bastion.example.com")

	if got := LoadRefreshCookieSecure(); !got.Secure || got.Source != RefreshCookieSecureFromEnv {
		t.Errorf("LoadRefreshCookieSecure() = %+v, want Secure=true source=%s",
			got, RefreshCookieSecureFromEnv)
	}
}
