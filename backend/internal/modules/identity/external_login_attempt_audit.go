package identity

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 外部身分帳號的本地登入嘗試——聚合審計
//（「偵測訊號不得成為 DoS 載體」）。
//
// 背景：`/auth/login` 未認證可達，而外部帳號分支刻意**不計入鎖定計數**
//（計數會讓任何知道 username 的人把 SSO 帳號鎖死），且該分支在密碼比對之前
// 就返回——連 bcrypt 的天然成本都沒有。逐筆落審計時，「持續送已知的 SSO
// username」即等於「持續寫 DB」，無任何上界。
//
// 形狀與 internal/api/source_abuse_guard.go 的聚合一致（事件鍵＋時間窗＋容量上限），
// 但多一條規則：**每個窗的第一筆即時落地**。偵測訊號延後或遺失比寫入量更糟——
// 攻擊者打一次就停手時，純窗尾聚合會讓那唯一一筆永遠不落地（本專案沒有背景
// flush 排程，窗尾結清一律由後續事件觸發）。
//
// 每個 (使用者, 窗) 因此最多兩筆：窗首的即時筆，與窗尾的彙總筆（僅在有被抑制的
// 嘗試時才落）。條目數上界為 externalLoginAttemptMaxKeys ＋ 1 個 overflow 鍵。
//
// 本結構為 in-memory、**每副本各自聚合**——與濫用防護同樣的刻意取捨：共享狀態
// 需要外部存放，而其寫入正是這裡要保護的資源。

const (
	// externalLoginAttemptWindow 聚合時間窗
	externalLoginAttemptWindow = time.Minute
	// externalLoginAttemptMaxKeys 聚合表容量（追蹤中的帳號數上限）
	externalLoginAttemptMaxKeys = 1024
	// externalLoginAttemptOverflowKey 表滿後的共用鍵。
	// 真實使用者的 ID 不可能為 0，故不會與任何帳號相撞
	externalLoginAttemptOverflowKey uint = 0
	// externalLoginAttemptOverflowName overflow 鍵的顯示名（來源解析度已失去，
	// 但事件本身不丟棄）
	externalLoginAttemptOverflowName = "(overflow)"

	externalLoginAttemptEvent    = "external_user_local_login_attempt"
	externalLoginAttemptAggEvent = "external_user_local_login_attempt_aggregated"
)

// externalLoginAttemptAggregator (使用者, 時間窗) 維度的聚合器
type externalLoginAttemptAggregator struct {
	mu      sync.Mutex
	now     func() time.Time
	window  time.Duration
	maxKeys int
	entries map[uint]*externalLoginAttemptEntry
}

type externalLoginAttemptEntry struct {
	username   string
	origin     string
	suppressed int
	first      time.Time
	last       time.Time
	windowEnd  time.Time
}

// externalLoginAttemptEmit 一筆待落地的審計。aggregated=false 為窗首即時筆，
// true 為窗尾彙總筆
type externalLoginAttemptEmit struct {
	userID     uint
	username   string
	origin     string
	aggregated bool
	suppressed int
	first      time.Time
	last       time.Time
}

func newExternalLoginAttemptAggregator() *externalLoginAttemptAggregator {
	return &externalLoginAttemptAggregator{
		now:     time.Now,
		window:  externalLoginAttemptWindow,
		maxKeys: externalLoginAttemptMaxKeys,
		entries: make(map[uint]*externalLoginAttemptEntry),
	}
}

// size 目前追蹤中的條目數（容量上界的斷言點）
func (a *externalLoginAttemptAggregator) size() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.entries)
}

// record 記錄一次嘗試，回傳應落地的審計（可能為空）。
//
// **落地在鎖外**：呼叫端拿到回傳值後才寫 DB——持鎖跨越儲存層延遲會把登入路徑
// 卡在 DB 上（同 oidcAbuseGuard.sweepLocked 的取捨）
func (a *externalLoginAttemptAggregator) record(userID uint, username, origin string) []externalLoginAttemptEmit {
	now := a.now()

	a.mu.Lock()
	out := a.sweepLocked(now)

	key := userID
	if _, tracked := a.entries[key]; !tracked && len(a.entries) >= a.maxKeys {
		// 表滿：不 fail-open（照樣逐筆寫）、也不丟棄，改落共用 overflow 鍵——
		// 失去的是來源解析度，不是事件本身
		key = externalLoginAttemptOverflowKey
		username, origin = externalLoginAttemptOverflowName, ""
	}

	if e, ok := a.entries[key]; ok {
		e.suppressed++
		e.last = now
		a.mu.Unlock()
		return out
	}

	a.entries[key] = &externalLoginAttemptEntry{
		username: username, origin: origin,
		first: now, last: now, windowEnd: now.Add(a.window),
	}
	a.mu.Unlock()

	// 窗首即時落地
	return append(out, externalLoginAttemptEmit{
		userID: key, username: username, origin: origin,
		first: now, last: now,
	})
}

// sweepLocked 取出已到期的窗。只有「有被抑制的嘗試」才產生彙總筆——
// 窗內只有一次嘗試時，那一筆已於窗首落地，再落一筆彙總只是重複
func (a *externalLoginAttemptAggregator) sweepLocked(now time.Time) []externalLoginAttemptEmit {
	var out []externalLoginAttemptEmit
	for k, e := range a.entries {
		if now.Before(e.windowEnd) {
			continue
		}
		if e.suppressed > 0 {
			out = append(out, externalLoginAttemptEmit{
				userID: k, username: e.username, origin: e.origin,
				aggregated: true, suppressed: e.suppressed,
				first: e.first, last: e.last,
			})
		}
		delete(a.entries, k)
	}
	return out
}

// flushExpired 主動結清已到期的窗（排程／測試用；本專案目前無背景排程，
// 保留此出口使日後接上不必改動聚合器本體）
func (a *externalLoginAttemptAggregator) flushExpired() []externalLoginAttemptEmit {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sweepLocked(now)
}

// externalLoginAttempts 取得（必要時建立）本服務的聚合器。
//
// 延遲建立而非放進建構子：AuthService 有兩個建構子，且測試會直接以結構字面值
// 建構——放進建構子會讓某些路徑拿到 nil 而在登入時 panic
func (s *AuthService) externalLoginAttempts() *externalLoginAttemptAggregator {
	s.extLoginAggOnce.Do(func() {
		s.extLoginAgg = newExternalLoginAttemptAggregator()
	})
	return s.extLoginAgg
}

// writeExternalLoginAttemptAudits 把聚合結果落地（鎖外）
func writeExternalLoginAttemptAudits(emits []externalLoginAttemptEmit) {
	if len(emits) == 0 || database.DB == nil {
		return
	}
	for _, e := range emits {
		event := externalLoginAttemptEvent
		payload := map[string]interface{}{
			"event":               event,
			"provisioning_origin": e.origin,
		}
		if e.aggregated {
			event = externalLoginAttemptAggEvent
			payload["event"] = event
			// 窗內被抑制的筆數（不含已即時落地的窗首那一筆）
			payload["suppressed_count"] = e.suppressed
			payload["window_start"] = e.first.UTC().Format(time.RFC3339)
			payload["window_end"] = e.last.UTC().Format(time.RFC3339)
		}
		details, err := json.Marshal(payload)
		if err != nil {
			details = []byte(`{"event":"` + event + `"}`)
		}
		entry := &model.AuditLog{
			Action:   model.ActionLogin,
			Resource: model.ResourceUser,
			Status:   model.StatusDenied,
			UserID:   e.userID,
			Username: e.username,
			Details:  string(details),
		}
		if err := database.DB.Create(entry).Error; err != nil {
			log.Printf("[AuthService] 外部帳號本地登入嘗試審計寫入失敗: %v", err)
		}
	}
}
