package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// flow state 全表容量上限（idp-oidc-integration tasks 4.8／design D13）。
//
// begin 是未認證端點且每次呼叫都產生一列持久化狀態，沒有帳號可綁。驗收有兩面，
// 缺一即為假綠：儲存量**有界**（否則洪水直接撐爆 DB），且**既有流程仍可完成**
// （否則「有界」可以用「一滿就清空全表」達成，而那是把儲存問題換成可用性攻擊）。

// TestBeginFloodBoundedAndInFlightFlowStillCompletes 洪水下儲存量有界，
// 且洪水**之前**發起的正常流程仍能走完 callback → exchange 全程
func TestBeginFloodBoundedAndInFlightFlowStillCompletes(t *testing.T) {
	login, _, idp, p := setupLiveFlow(t)
	const capacity = 8
	login.flowCapacity = capacity

	// 正常使用者先發起流程（此刻人在 IdP 頁面輸入密碼）
	state, nonce := beginFlow(t, login, p, "browser-secret", idp)

	rejected := 0
	for i := 0; i < 200; i++ {
		_, err := login.Begin(context.Background(), p.ID, sha256Hex("flood"), "/")
		if errors.Is(err, ErrOIDCFlowCapacity) {
			rejected++
			continue
		}
		if err != nil {
			t.Fatalf("洪水第 %d 次 Begin 非預期錯誤: %v", i, err)
		}
	}
	if rejected == 0 {
		t.Fatal("200 次洪水應有請求被容量上限拒絕，實際全數接受")
	}

	var cnt int64
	if err := login.db.Model(&model.OIDCFlowState{}).Count(&cnt).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if cnt > capacity {
		t.Fatalf("flow state 列數 = %d，超過容量上限 %d（儲存量無界）", cnt, capacity)
	}

	// 既有流程不得被洪水淘汰：完整走完 callback → exchange
	idp.stageCode("code-1", idp.issueIDToken(t, idTokenOpts{
		subject: "sub-1", audience: "test-client", nonce: nonce,
		extra: map[string]any{
			"hd": "corp.example", "preferred_username": "alice",
		},
	}))
	res, err := login.Callback(context.Background(), state, "code-1")
	if err != nil {
		t.Fatalf("洪水後既有流程的 callback 應仍成立，實得: %v", err)
	}
	resp, _, err := login.Exchange(res.Ticket, "browser-secret")
	if err != nil {
		t.Fatalf("洪水後既有流程的 exchange 應仍成立，實得: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("應發放正式 token")
	}
}

// TestBeginCapacityReclaimsExpiredRows 達上限時先清過期列再重數——清理排程
// 週期未到不該讓可回收的空間算進佔用，否則系統會在真正滿載前就開始拒絕
func TestBeginCapacityReclaimsExpiredRows(t *testing.T) {
	login, _, _, p := setupLiveFlow(t)
	const capacity = 4
	login.flowCapacity = capacity

	for i := 0; i < capacity; i++ {
		row := model.OIDCFlowState{
			State: "expired-" + string(rune('a'+i)), Nonce: "n", PKCEVerifier: "v",
			ProviderID: p.ID, AuthEpoch: p.AuthEpoch,
			BindingHash: sha256Hex("x"), RedirectNext: "/",
			ExpiresAt: time.Now().Add(-time.Minute),
		}
		if err := login.db.Create(&row).Error; err != nil {
			t.Fatalf("seed expired: %v", err)
		}
	}

	// 表已達上限但全為過期列：新流程應被接受（回收後仍有空間）
	if _, err := login.Begin(context.Background(), p.ID, sha256Hex("s"), "/"); err != nil {
		t.Fatalf("過期列應被回收後接受新流程，實得: %v", err)
	}
	var cnt int64
	if err := login.db.Model(&model.OIDCFlowState{}).Count(&cnt).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if cnt != 1 {
		t.Fatalf("回收後應只剩新建的 1 列，實得 %d", cnt)
	}
}

// TestBeginCapacityRejectsBeforeProviderResolution 容量拒絕須發生在任何 provider
// 解析與出站往返**之前**：否則洪水仍能把每次請求放大成一次 DB 查詢與一次對
// IdP 的連線（把 DoS 轉嫁給 IdP）。
//
// 判準取「不存在的 provider 也回容量錯誤」：若容量檢查排在 GetForAuth 之後，
// 這裡必然先看到 provider 不存在的錯誤
func TestBeginCapacityRejectsBeforeProviderResolution(t *testing.T) {
	login, _, _, p := setupLiveFlow(t)
	login.flowCapacity = 1

	// 先塞滿（未過期，不可回收）
	if _, err := login.Begin(context.Background(), p.ID, sha256Hex("s"), "/"); err != nil {
		t.Fatalf("首次 Begin: %v", err)
	}

	const missingProvider = 4242
	if _, err := login.Begin(context.Background(), missingProvider, sha256Hex("s"), "/"); !errors.Is(err, ErrOIDCFlowCapacity) {
		t.Fatalf("滿載時對不存在的 provider = %v, want ErrOIDCFlowCapacity（容量檢查須最先執行）", err)
	}
	for i := 0; i < 20; i++ {
		if _, err := login.Begin(context.Background(), p.ID, sha256Hex("s"), "/"); !errors.Is(err, ErrOIDCFlowCapacity) {
			t.Fatalf("滿載後第 %d 次 Begin = %v, want ErrOIDCFlowCapacity", i, err)
		}
	}
}
