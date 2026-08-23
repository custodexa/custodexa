package proxy

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// 未兌換 grant 的無界成長。
//
// 原本 grants map 只有一條移除路徑：以**同一把 token** 呼叫 Resolve。
// 已認證使用者只要反覆打簽發端點而從不兌換，每張 grant 就會永久留在 map 裡
//（ExpiresAt 只在 Resolve 當下才被檢查，沒人 Resolve 就沒人檢查），
// 迴圈跑久了即為行程記憶體耗盡。
//
// 修法有兩層，測試逐層釘住：
//  1. Issue 時順帶清掉逾時項（不開背景 goroutine——多一條生命週期就多一處洩漏）；
//  2. 全域與每使用者兩道容量上限。**每使用者上限不可省**：只有全域上限時，
//     單一已認證使用者灌滿全表即可讓其他所有人無法建立連線（把記憶體 DoS
//     換成可用性 DoS，並未真正解決問題）。
//
// Resolve 的熱路徑語義不變：它仍是 O(1) 查表＋刪除，不做任何全表掃描
//（TestConnectTokenResolveDoesNotSweep 釘住）。

// expireAll 把表中全部 grant 的到期時間往前推，模擬逾時而未被兌換
func expireAll(m *ConnectTokenManager) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tok, g := range m.grants {
		g.ExpiresAt = time.Now().Add(-time.Second)
		m.grants[tok] = g
	}
}

func grantCount(m *ConnectTokenManager) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.grants)
}

// TestConnectTokenIssuePurgesExpired 逾時項的全域清理路徑（G-B 主缺陷）：
// 沒有人來 Resolve 也必須被清掉
func TestConnectTokenIssuePurgesExpired(t *testing.T) {
	m := NewConnectTokenManager()
	for i := 0; i < 5; i++ {
		if _, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: uint(i + 1), AssetID: 7}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
	}
	expireAll(m)

	if _, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: 99, AssetID: 7}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if n := grantCount(m); n != 1 {
		t.Errorf("簽發後表內 %d 筆，應只剩剛簽發的 1 筆（逾時未兌換的 grant 沒被清理）", n)
	}
}

// TestConnectTokenPerUserCapacity 單一使用者的未兌換 grant 上限。
//
// 這是「一個人灌爆全表」的直接防線，也是全域上限不可單獨存在的理由
func TestConnectTokenPerUserCapacity(t *testing.T) {
	m := NewConnectTokenManager()
	const victim, attacker = uint(1), uint(2)

	for i := 0; i < connectTokenPerUserCapacity; i++ {
		if _, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: attacker, AssetID: 7}); err != nil {
			t.Fatalf("第 %d 張應可簽發: %v", i+1, err)
		}
	}

	_, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: attacker, AssetID: 7})
	if !errors.Is(err, ErrConnectTokenCapacity) {
		t.Errorf("超過每使用者上限應回 ErrConnectTokenCapacity，實得 %v", err)
	}

	// 別人不受牽連——上限是按使用者計，不是全域先到先得
	if _, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: victim, AssetID: 7}); err != nil {
		t.Errorf("其他使用者不應被牽連: %v", err)
	}
}

// TestConnectTokenGlobalCapacity 全域上限（多帳號協同時的最後一道）
func TestConnectTokenGlobalCapacity(t *testing.T) {
	m := NewConnectTokenManager()
	perUser := connectTokenPerUserCapacity
	users := connectTokenCapacity / perUser

	for u := 0; u < users; u++ {
		for i := 0; i < perUser; i++ {
			if _, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: uint(u + 1), AssetID: 7}); err != nil {
				t.Fatalf("填表階段 user=%d 第 %d 張: %v", u+1, i+1, err)
			}
		}
	}
	if n := grantCount(m); n != connectTokenCapacity {
		t.Fatalf("前提不成立：表內 %d 筆，預期填滿 %d", n, connectTokenCapacity)
	}

	// 換一個全新使用者（未觸及每使用者上限），仍須被全域上限擋下
	_, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: uint(users + 1), AssetID: 7})
	if !errors.Is(err, ErrConnectTokenCapacity) {
		t.Errorf("達全域上限後應回 ErrConnectTokenCapacity，實得 %v", err)
	}
}

// TestConnectTokenCapacityRecoversAfterExpiry 上限是「未逾時的量」，不是累計簽發量。
//
// 若清理與計數不同源（例如先數 len(map) 再清理），表一旦被灌滿就永遠回不來，
// 等於一次 DoS 造成永久停業
func TestConnectTokenCapacityRecoversAfterExpiry(t *testing.T) {
	m := NewConnectTokenManager()
	for i := 0; i < connectTokenPerUserCapacity; i++ {
		if _, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 7}); err != nil {
			t.Fatalf("填表: %v", err)
		}
	}
	if _, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 7}); !errors.Is(err, ErrConnectTokenCapacity) {
		t.Fatalf("前提不成立：應已達上限，實得 %v", err)
	}

	expireAll(m)

	if _, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 7}); err != nil {
		t.Errorf("逾時項清掉後應可再簽發: %v", err)
	}
}

// TestConnectTokenResolveDoesNotSweep 熱路徑語義守衛：清理放在 Issue 側，
// Resolve 只做 O(1) 查表＋刪除。
//
// 若把清理搬進 Resolve，兌換就變成 O(表大小) 的全表掃描——那正是本次修法
// 刻意避開的取捨（兌換在連線關鍵路徑上，簽發不是）
func TestConnectTokenResolveDoesNotSweep(t *testing.T) {
	m := NewConnectTokenManager()
	live, err := m.IssueConnectToken(context.Background(), ConnectGrant{UserID: 1, AssetID: 7})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// 另外塞入 3 筆已逾時的 grant（繞過 Issue，避免觸發清理）
	m.mu.Lock()
	for i := 0; i < 3; i++ {
		m.grants[fmt.Sprintf("stale-%d", i)] = ConnectGrant{
			UserID: uint(100 + i), AssetID: 7, ExpiresAt: time.Now().Add(-time.Second)}
	}
	m.mu.Unlock()

	if _, ok := m.RedeemConnectToken(context.Background(), live); !ok {
		t.Fatal("有效 token 應可兌換")
	}

	if n := grantCount(m); n != 3 {
		t.Errorf("Resolve 後表內 %d 筆，預期 3 筆逾時項原封不動（Resolve 不得做全表掃描）", n)
	}
}
