package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 外部帳號本地登入嘗試的審計不得成為無界寫入載體（批 14 對抗審查 L1）。
//
// `/auth/login` 是**未認證**端點，而外部帳號分支刻意不計入鎖定計數
// （計數會讓任何人用本地表單把 SSO 帳號鎖死）。兩者相加即：知道任一 OIDC 帳號
// username 的攻擊者，每送一個請求就換得一筆 audit_logs 寫入，且沒有任何節流。
// 該分支在密碼比對**之前**就返回，連 bcrypt 的天然成本都沒有。
//
// 本 change 對 callback／exchange 正是以「偵測訊號不得成為 DoS 載體」為由改成
// 聚合審計（oidc_abuse_guard.go），此處形狀相同。
//
// 聚合的形狀刻意保留「首筆即時落地」：偵測訊號延後或遺失比寫入量更糟——
// 攻擊者只要打一次就停手，純窗尾聚合會讓那一筆永遠不落地。
func TestExternalLocalLoginAttemptAuditIsAggregated(t *testing.T) {
	env := setupRegressionEnv(t)
	p := seedProvider(t, env.db, nil)
	victim := seedRegressionUser(t, env, "alice", "placeholder", func(u *model.User) {
		u.ProvisioningOrigin = model.AuthSourceOIDC
		u.ExternalCredential = true
	})
	seedIdentity(t, env.db, victim, p, "sub-alice")

	// 時間可控：窗的推進不靠 sleep
	base := time.Now()
	now := base
	env.auth.externalLoginAttempts().now = func() time.Time { return now }

	const flood = 200
	for i := 0; i < flood; i++ {
		if _, err := env.auth.Login(&LoginRequest{Username: "alice", Password: "guess"}); err == nil {
			t.Fatal("外部帳號的本地登入不得成功")
		}
		now = now.Add(10 * time.Millisecond) // 全部落在同一個聚合窗內
	}

	total := countAuditEvent(t, env.db, "external_user_local_login_attempt")
	if total != 1 {
		t.Fatalf("同一聚合窗內 %d 次嘗試落了 %d 筆審計——偵測訊號成了無界寫入載體",
			flood, total)
	}

	// 窗結束後的下一次事件結清前窗：彙總筆數含被抑制的次數，訊號不失真
	now = base.Add(2 * time.Minute)
	if _, err := env.auth.Login(&LoginRequest{Username: "alice", Password: "guess"}); err == nil {
		t.Fatal("外部帳號的本地登入不得成功")
	}
	if n := countAuditEvent(t, env.db, "external_user_local_login_attempt_aggregated"); n != 1 {
		t.Fatalf("窗結束應落一筆彙總審計，got %d", n)
	}

	var agg model.AuditLog
	if err := env.db.Where("details LIKE ?", `%external_user_local_login_attempt_aggregated%`).
		First(&agg).Error; err != nil {
		t.Fatalf("讀彙總審計: %v", err)
	}
	if agg.UserID != victim.ID || agg.Username != "alice" {
		t.Errorf("彙總審計的對象 = (id=%d, name=%q), want (%d, alice)",
			agg.UserID, agg.Username, victim.ID)
	}
	// flood 筆中的第一筆即時落地，其餘 flood-1 筆被抑制
	if want := `"suppressed_count":199`; !strings.Contains(agg.Details, want) {
		t.Errorf("彙總審計應載明被抑制的筆數 %s，實得 %s", want, agg.Details)
	}

	// 新窗的第一筆同樣即時落地（訊號不因聚合而延後）
	if n := countAuditEvent(t, env.db, "external_user_local_login_attempt"); n != 2 {
		t.Errorf("新窗首筆應即時落地，即時筆數 = %d, want 2", n)
	}
}

// TestExternalLocalLoginAttemptAggregatorIsBounded 聚合表本身不得成為無界成長點：
// 攻擊者可對大量帳號名輪流嘗試，表滿時落到共用 overflow 鍵而非繼續長大
func TestExternalLocalLoginAttemptAggregatorIsBounded(t *testing.T) {
	agg := newExternalLoginAttemptAggregator()
	agg.now = func() time.Time { return time.Unix(0, 0) }

	for i := 1; i <= externalLoginAttemptMaxKeys*3; i++ {
		agg.record(uint(i), "u", model.AuthSourceOIDC)
	}
	if n := agg.size(); n > externalLoginAttemptMaxKeys+1 {
		t.Fatalf("聚合表條目數 = %d，超過容量上限 %d（＋1 個 overflow 鍵）",
			n, externalLoginAttemptMaxKeys)
	}
}
