package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/gin-gonic/gin"
)

// refresh cookie 的 `Secure` 屬性改由安全政策管轄：
// 發放時現讀、管理端可調、變更即生效不需重啟；政策未接線時落安全側。
//
// **本檔釘的是「值從哪裡來」與「讀不到時往哪邊倒」**，不是 cookie 的其餘屬性
//（Path／HttpOnly／SameSite 由 refresh_cookie_issue_guard_test.go 的 G1 承擔）。

// stubSecurePolicy 可變的政策佔位：測「發放時現讀」必須能在兩次發放之間改值。
type stubSecurePolicy struct {
	value bool
	// gotKey 記錄被問到的鍵——writer 問錯鍵時值會恆為佔位的零值，
	// 而「恆 false」與「政策就是 false」在斷言上無從分辨
	gotKey string
}

func (s *stubSecurePolicy) GetBool(key string) bool {
	s.gotKey = key
	return s.value
}

// issueAndClear 以指定 writer 發放與清除一次 cookie，回傳兩者
func issueAndClear(t *testing.T, w *RefreshCookieWriter) (issued, cleared *http.Cookie) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	w.Set(c, "plain-token", time.Now().Add(time.Hour))
	issued = findRefreshCookie(rec)
	if issued == nil {
		t.Fatal("Set 未下發 refresh cookie")
	}

	rec2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(rec2)
	w.Clear(c2)
	cleared = findRefreshCookie(rec2)
	if cleared == nil {
		t.Fatal("Clear 未下發清除性 refresh cookie")
	}
	return issued, cleared
}

// TestRefreshCookieSecureFollowsPolicy 政策現值即 cookie 的 Secure 屬性，
// 且 Set 與 Clear 同讀（屬性不一致的清除在部分瀏覽器不命中原 cookie）。
func TestRefreshCookieSecureFollowsPolicy(t *testing.T) {
	for _, want := range []bool{true, false} {
		stub := &stubSecurePolicy{value: want}
		writer := NewRefreshCookieWriter(stub)

		issued, cleared := issueAndClear(t, writer)
		if issued.Secure != want {
			t.Errorf("政策 = %v 時發放的 cookie Secure = %v", want, issued.Secure)
		}
		if cleared.Secure != want {
			t.Errorf("政策 = %v 時清除的 cookie Secure = %v（與發放不一致的清除可能不命中原 cookie）",
				want, cleared.Secure)
		}
		if stub.gotKey != policy.PolicyRefreshCookieSecure {
			t.Errorf("讀的政策鍵 = %q, want %q", stub.gotKey, policy.PolicyRefreshCookieSecure)
		}
	}
}

// TestRefreshCookieSecureReadAtIssueTime 政策改值後**下一次發放**即採新值：
// writer 不得快取啟動期常數，否則管理員在政策頁的修正要等重啟才生效，
// 而那正是設錯時唯一好走的復原路徑。
func TestRefreshCookieSecureReadAtIssueTime(t *testing.T) {
	stub := &stubSecurePolicy{value: true}
	writer := NewRefreshCookieWriter(stub)

	if issued, _ := issueAndClear(t, writer); !issued.Secure {
		t.Fatal("初值 true 未生效")
	}
	stub.value = false
	if issued, _ := issueAndClear(t, writer); issued.Secure {
		t.Error("政策改為 false 後仍發出 Secure cookie：writer 持了啟動期常數而非現讀")
	}
}

// TestRefreshCookieSecureFallsBackToSecure 未接線政策源時一律回安全側。
//
// **方向是本測試的全部**：Secure 改為自政策現讀後，「沒有政策源」在生產中的
// 唯一意義是接線遺漏。回 false 會讓一個接線 bug 靜默地把傳輸保護關掉且毫無症狀；
// 回 true 的代價是純 HTTP 部署下多出重新登入——看得見、改得掉。
func TestRefreshCookieSecureFallsBackToSecure(t *testing.T) {
	cases := map[string]*RefreshCookieWriter{
		"nil 接收者（未經建構函式的佔位）":    nil,
		"建構了但未注入政策源":            NewRefreshCookieWriter(nil),
		"handler 建構期的預設 writer": defaultRefreshCookieWriter(),
	}
	for name, writer := range cases {
		t.Run(name, func(t *testing.T) {
			issued, cleared := issueAndClear(t, writer)
			if !issued.Secure {
				t.Error("未接線政策源時發出非 Secure cookie：接線遺漏會靜默失去傳輸保護")
			}
			if !cleared.Secure {
				t.Error("未接線政策源時清除性 cookie 非 Secure")
			}
		})
	}
}
