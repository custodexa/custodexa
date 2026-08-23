package identity

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 綁定失敗門檻的原子性（spec oidc-auth L80「達三次即作廢」）。
//
// 遞增本身是原子的（`binding_failures + 1` 由 DB 計算），但門檻判定若用**本次
// 請求開頭讀出的陳舊值**，三個並發的錯誤綁定就會各自算出 `0+1 < 3` 而都不刪除；
// DB 的計數早已是 3，憑證卻要到第 4 次才作廢——上限被悄悄放寬。
//
// 並發交錯以 hook 製造而非靠時間競賽：競態測試若靠 goroutine 搶跑，會在「剛好
// 沒撞上」時假綠，正是本專案既有的 flaky 前科來源。
func TestExchangeBindingFailureThresholdUsesFreshCount(t *testing.T) {
	login, _, db := setupOIDCEnv(t)
	p := seedProvider(t, db, nil)
	user := seedOIDCUser(t, db, "alice")
	ticket := issueTestTicket(t, login, user, p, "browser-secret")

	// 在「本次請求已讀出 ticket、尚未遞增計數」的精確位置插入另外兩次錯誤綁定，
	// 等價於三個並發請求都讀到 binding_failures=0 的交錯
	// 旗標而非 sync.Once：hook 內的巢狀 Exchange 會再次進入 hook，
	// 重入 sync.Once.Do 會卡在它自己的互斥鎖上
	interleaved := false
	oidcTicketBindingFailureHook = func() {
		if interleaved {
			return
		}
		interleaved = true
		for i := 0; i < oidcTicketMaxBindingFailures-1; i++ {
			if _, _, err := login.Exchange(ticket, "wrong-secret"); !errors.Is(err, ErrOIDCTicketInvalid) {
				t.Errorf("交錯的第 %d 次錯誤綁定 = %v, want ErrOIDCTicketInvalid", i+1, err)
			}
		}
	}
	t.Cleanup(func() { oidcTicketBindingFailureHook = nil })

	if _, _, err := login.Exchange(ticket, "wrong-secret"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("錯誤綁定 = %v, want ErrOIDCTicketInvalid", err)
	}

	var stored model.OIDCLoginTicket
	err := db.Where("token_hash = ?", sha256Hex(ticket)).First(&stored).Error
	if err == nil {
		t.Fatalf("累計 %d 次綁定失敗（DB 現值 %d）後憑證仍存在——門檻以陳舊值判定，"+
			"並發下第 %d 次才作廢", oidcTicketMaxBindingFailures, stored.BindingFailures,
			oidcTicketMaxBindingFailures+1)
	}

	// 作廢的行為面確認：拿對 secret 也不能再兌換
	if _, _, err := login.Exchange(ticket, "browser-secret"); !errors.Is(err, ErrOIDCTicketInvalid) {
		t.Fatalf("作廢後兌換 = %v, want ErrOIDCTicketInvalid", err)
	}
}
