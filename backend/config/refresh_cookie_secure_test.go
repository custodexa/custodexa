package config

import "testing"

// refresh cookie 的 Secure 旗標推導。
//
// # 這個推導現在算的是什麼
//
// **首次啟動的播種值**，不是執行期生效值：生效值由安全政策鍵
// refresh_cookie_secure 承載（發放 cookie 時現讀、管理端可調、改了即生效）。
// 推導只在部署第一次啟動、該鍵尚無政策列時決定初值。
//
// # 為什麼「兩者皆缺」取 true
//
// 兩個方向各有一種真實失敗，但**可見性不對稱**：
//
//   - 預設 false（原設計）：未設 PUBLIC_BASE_URL 的 HTTPS 部署零症狀地失去
//     降級攻擊防護。沒有人會察覺，也沒有人會去讀一個運作正常的系統的啟動日誌。
//   - 預設 true（現行）：純 HTTP 部署下瀏覽器丟棄 Set-Cookie，使用者每個
//     access token 壽命重登一次。吵鬧、當場可見，且登入頁與管理頁都會說明成因；
//     復原是管理端政策頁一個開關，不需改部署檔重啟。
//
// 把故障放在看得見的一側是使用者裁決。顯式 false 與
// http 位址兩格不變——那是明文部署的顯式訊號。
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
		// 「兩者皆缺」的兩格取安全側（決策 1 的反轉）：無任何明文部署的顯式訊號時，
		// 不得由預設值把保護關掉
		{"base URL 為空時取安全預設", "", "", true, RefreshCookieSecureFromDefault},
		{"base URL 無 scheme 時不臆測，取安全預設", "", "bastion.example.com",
			true, RefreshCookieSecureFromDefault},
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

// TestLoadRefreshCookieSecureDefaultsToSecure 未設任何相關 env 時的預設。
//
// **這一格釘住的是「保護不會因為沒人設定而消失」**。舊版此處反向釘住預設 false，
// 理由是本地 HTTP 開發必須可用；該取捨已被裁決推翻——它把故障放在最不可見的
// 一側（未設 PUBLIC_BASE_URL 的 HTTPS 部署零症狀失去防護），而本地開發要走
// 明文只需在 .env 顯式關閉一次（或於政策頁關閉），代價落在有人看得見的地方。
func TestLoadRefreshCookieSecureDefaultsToSecure(t *testing.T) {
	t.Setenv("AUTH_REFRESH_COOKIE_SECURE", "")
	t.Setenv("PUBLIC_BASE_URL", "")

	got := LoadRefreshCookieSecure()
	if !got.Secure {
		t.Errorf("未設任何相關 env 時 Secure = false：未設定的部署會靜默失去傳輸保護")
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
