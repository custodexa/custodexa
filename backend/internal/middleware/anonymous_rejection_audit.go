package middleware

// 匿名拒絕留痕與其有界機制（audit-coverage-closure 批 1，design D1／D2）。
//
// # 這個檔補的是什麼洞
//
// `middleware/auth.go` 的每一個 401 出口都在**還沒設過 userID** 的狀態下 abort，
// 而 `audit_log.go` 的審計中介層取不到 `userID`/`username` 就整筆跳過。兩者相乘的
// 結果是：**171 條掛認證中介層的路由，其拒絕路徑一列審計都不會留下**——「誰在敲門、
// 敲了幾次、敲的是哪一扇」在稽核上完全答不出來，而且沒有任何測試會因此變紅
//（批 0 的 `cmd/server/audit_rejection_coverage_guard_test.go` 實測 171／171）。
//
// # 為什麼補在這裡而不是逐 handler 補
//
// 黑洞的位置是**單一**的（認證中介層 abort → 無 userID → 審計中介層跳過），故單點
// 補寫即涵蓋全部 171 條，且新增端點自動涵蓋。逐 handler 補要改 171 處，新增端點
// 必然遺漏——那正是本 change 要根除的模式（design D1）。
//
// # 為什麼需要有界機制
//
// 未認證請求可寫庫即**洪水面**：任何人從瀏覽器就能無限灌審計表，把偵測機制本身
// 變成攻擊載體，且 audit_logs 受檢查點鏈保護（寫進去刪不掉，刪了鏈驗證即失敗）。
// 模式沿用 `openspec/specs/oidc-auth/spec.md:370-383` 已確立的聚合審計，實作形狀
// 沿用 `internal/api/source_abuse_guard.go`（令牌桶＋時間窗聚合＋不 fail-open 的
// overflow 桶），**不另創機制**。
//
// 三道界線，順序即優先序：
//
//	per-key 令牌桶 → 全域令牌桶 → 逾界者併入聚合列
//
//   - **per-key**（來源位址＋失敗原因＋方法＋路徑）：擋「反覆敲同一扇門」的洪水。
//     排第一，使被 per-key 擋下的重複**不消耗全域額度**——否則單一端點的洪水即可
//     把全域額度打空，其他來源的**首見**事件就此失去逐筆解析度。
//   - **全域**：這才是真正的上界。它不依賴任何客戶端可控輸入，故 per-key 的鍵
//     再怎麼被輪換（攻擊者換路徑即換鍵）也繞不過它。
//   - **聚合**：逾界的失敗不逐筆持久化，改以（原因, 來源）在時間窗內併為一列，
//     帶 `count`／`first_at`／`last_at`。偵測訊號可以失去單筆解析度，但不該整段消失。
//
// **最壞情況的寫入量與請求量無關**：每分鐘 ≤ 60 列（全域桶穩態 1 列／秒）
// ＋ ≤ 128 列（聚合表容量 × 每窗一列）＝ ≤ 188 列／分鐘。
//
// # 誠實的邊界
//
//   - 本結構為 in-memory、**每副本各自計數**——多副本部署下實際上界為副本數的倍數。
//     同 `oidcAbuseGuard` 的取捨：共享狀態需外部存放，而其寫入正是本防護要保護的資源。
//   - 聚合列的落地時機是「時間窗結束」，由**後續事件或 `flushExpired`** 觸發，不留
//     背景 goroutine。最後一個窗在無後續事件時會延後到下次拒絕才落——對「洪水偵測」
//     這個用途無害（洪水本身就是後續事件）。
//   - 威脅模型邊界（design Goals 段）：本檔只防「攻擊者能從 web 介面發出的請求」。
//     已取得底層 OS 或能改 code 的情境**不在範圍內**，不為其加碼。

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/sourceip"
)

// 匿名列的 details 事件名。**閉集合**：稽核端以 `details.event` 篩出這兩類列，
// 散文字串會讓篩選條件隨手改動而失效
const (
	// anonEventRejected 逐筆匿名失敗列。
	anonEventRejected = "auth_rejected"
	// anonEventRejectedAggregate 逾界後的聚合列（帶 count／first_at／last_at）。
	anonEventRejectedAggregate = "auth_rejected_aggregate"
)

// anonRejectionParams 有界機制的參數。全部可注入，使測試不必依賴真實時間 sleep
type anonRejectionParams struct {
	// PerKeyBurst 單一（來源, 原因, 方法, 路徑）可累積的逐筆留痕額度
	PerKeyBurst float64
	// PerKeyRefill 每補回一個 per-key 額度所需時間
	PerKeyRefill time.Duration
	// GlobalBurst 全域可累積的逐筆留痕額度
	GlobalBurst float64
	// GlobalRefill 每補回一個全域額度所需時間
	GlobalRefill time.Duration
	// MaxKeys per-key 表容量（無界鍵集合的記憶體保護）
	MaxKeys int
	// AggregateWindow 聚合時間窗
	AggregateWindow time.Duration
	// MaxAggregates 聚合表容量
	MaxAggregates int
}

// defaultAnonRejectionParams 預設參數。
//
// **量級的依據（不是隨手填的數字）**：
//
//   - per-key 10 突發／每 6 秒回補一次（穩態 10 次／分）：一位使用者的憑證過期後，
//     開著的分頁會對**同一個端點**連打數次才跳回登入頁；10 次涵蓋這個形態，
//     第 11 次起才併入聚合。這條同時是「正常過期逐筆留痕」那條 spec scenario 的
//     實際門檻。
//   - 全域 2000 突發／每秒回補一次：突發額度要吃得下**憑證過期風暴**——NAT 後單一
//     出口的整個辦公室在同一分鐘內 token 到期，每人數個分頁，數量級即千。穩態
//     壓到 1 列／秒，使持續洪水的逐筆留痕上限為 60 列／分鐘。
//   - 聚合表 128 鍵、窗 1 分鐘：要有 128 個活躍聚合鍵，等於同時有 128 個來源
//     正在越界——那已是分散式攻擊，而 128 列／分鐘正是該情境要留下的證據。
//     窗長沿用 `oidcAbuseGuard` 的一分鐘，不另立第二套時間語彙。
//
// **per-key 排在全域之前**是刻意的：洪水多半集中在少數端點，先由 per-key 擋下
// 才不會把全域額度耗在同一扇門上，讓其他來源的首見事件仍能逐筆留痕。
func defaultAnonRejectionParams() anonRejectionParams {
	return anonRejectionParams{
		PerKeyBurst:     10,
		PerKeyRefill:    6 * time.Second,
		GlobalBurst:     2000,
		GlobalRefill:    time.Second,
		MaxKeys:         4096,
		AggregateWindow: time.Minute,
		MaxAggregates:   128,
	}
}

// anonBucket 令牌桶（以「上次補充時間＋餘額」表示，無背景 goroutine）
type anonBucket struct {
	tokens float64
	last   time.Time
}

// allow 消費一個令牌；額度不足回 false。
//
// **被拒絕的嘗試不延後補充時間**——先算補充再判定，判定失敗時 last 已前移但額度
// 未扣，故不存在「持續送請求把窗口無限往後推、正當使用者永遠等不到額度」的形態
// （同 `oidcAbuseGuard` 與 seal limiter 的要求）
func (b *anonBucket) allow(now time.Time, burst float64, refill time.Duration) bool {
	if b.last.IsZero() {
		b.tokens = burst
		b.last = now
	}
	if elapsed := now.Sub(b.last); elapsed > 0 {
		if refill > 0 {
			b.tokens += float64(elapsed) / float64(refill)
			if b.tokens > burst {
				b.tokens = burst
			}
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// anonRateKey 逐筆留痕的節流鍵。
//
// 含**方法與路徑**而不只是來源：拒絕的稽核價值在「他敲的是哪一扇門」，把不同端點
// 的首見拒絕壓成同一個桶會讓橫向探測（逐一敲遍 171 條路由）在逐筆列上只剩前幾筆。
// 鍵集合的無界成長由 MaxKeys ＋ overflow 桶承接（見 bucketForLocked）
type anonRateKey struct {
	ip     string
	reason string
	method string
	path   string
}

// anonAggKey 聚合鍵。**刻意比節流鍵粗**：聚合要回答的是「哪個來源、因為什麼原因、
// 在這段時間內被拒了幾次」，逐路徑聚合會讓一次橫向掃描散成上百列聚合，
// 與「合併」的目的相反
type anonAggKey struct {
	reason string
	ip     string
}

type anonAggEntry struct {
	count     int
	first     time.Time
	last      time.Time
	windowEnd time.Time
}

type anonAggFlush struct {
	key   anonAggKey
	entry anonAggEntry
}

// anonAggOverflowIP 聚合表滿載後的共用鍵。**不丟棄事件**：偵測訊號可以失去來源
// 解析度，但不該整段消失
const anonAggOverflowIP = "(overflow)"

// anonRejectionAuditor 匿名拒絕留痕器。一個 AuditLogMiddleware 實例持有一個，
// 狀態（桶與聚合表）跨請求存續
type anonRejectionAuditor struct {
	mu     sync.Mutex
	params anonRejectionParams
	now    func() time.Time
	// trustProxy 是否已設定可信代理清單。未設定時**一律忽略轉送標頭**，見 sourceIP
	trustProxy bool
	// sink 落地出口。**具體型別而非介面**：介面欄位收下一個「型別化的 nil 指標」
	// 時本身不為 nil，`sink == nil` 的防呆會整條失效而在呼叫時 panic
	//（實測：路由守衛以零值 deps 建 router，審計服務就是 nil 指標）。
	// 本檔沒有任何測試需要替身 sink，介面只換來一個空手道陷阱
	sink *audit.AuditLogService

	keys     map[anonRateKey]*anonBucket
	overflow anonBucket // 鍵表滿載後的共用桶（不 fail-open，也不無界成長）
	global   anonBucket
	agg      map[anonAggKey]*anonAggEntry
}

// newAnonRejectionAuditor 建立留痕器。零值參數取預設；sink 為 nil 時不落地
// （計數與聚合仍進行，語義同「審計關閉」）
func newAnonRejectionAuditor(params anonRejectionParams, trustProxy bool, sink *audit.AuditLogService) *anonRejectionAuditor {
	return &anonRejectionAuditor{
		params:     anonRejectionDefaults(params),
		now:        time.Now,
		trustProxy: trustProxy,
		sink:       sink,
		keys:       make(map[anonRateKey]*anonBucket),
		agg:        make(map[anonAggKey]*anonAggEntry),
	}
}

// anonRejectionDefaults 零值欄位取預設。抽出成獨立函式是因為選項覆寫
// （`withAnonRejectionParams`）也要走同一套補值，兩處各補一次必然分歧
func anonRejectionDefaults(params anonRejectionParams) anonRejectionParams {
	d := defaultAnonRejectionParams()
	if params.PerKeyBurst <= 0 {
		params.PerKeyBurst = d.PerKeyBurst
	}
	if params.PerKeyRefill <= 0 {
		params.PerKeyRefill = d.PerKeyRefill
	}
	if params.GlobalBurst <= 0 {
		params.GlobalBurst = d.GlobalBurst
	}
	if params.GlobalRefill <= 0 {
		params.GlobalRefill = d.GlobalRefill
	}
	if params.MaxKeys <= 0 {
		params.MaxKeys = d.MaxKeys
	}
	if params.AggregateWindow <= 0 {
		params.AggregateWindow = d.AggregateWindow
	}
	if params.MaxAggregates <= 0 {
		params.MaxAggregates = d.MaxAggregates
	}
	return params
}

// sourceIP 取來源位址（歸戶鍵與審計列的 client_ip 同一個值）。
//
// **未設可信代理時一律採 socket 對端並忽略轉送標頭**：gin 在未呼叫
// SetTrustedProxies 時信任全部 X-Forwarded-For，此時以 ClientIP() 歸戶等同讓攻擊者
// 自選限流桶與自選審計欄位——每個請求換一個偽造標頭就得到全新額度，有界機制形同
// 虛設，且審計列上的「來源」變成攻擊者寫的字串。寧可讓同一代理後的使用者共用一個
// 桶，也不提供可繞過的假防線（同 `oidcAbuseGuard.sourceIP`）。
//
// **判定不在這裡**：本函式是 internal/sourceip（全庫唯一實作）的薄委派。本檔原本
// 自帶一份逐行相同的實作，那正是「同一條紀律分家」的形態——分家的那一份會在後續
// 演化中悄悄退回 c.ClientIP()，而不會有任何測試轉紅（audit-coverage-closure 批 8）
func (a *anonRejectionAuditor) sourceIP(c *gin.Context) string {
	return sourceip.From(c, a.trustProxy)
}

// record 記錄一次「認證中介層拒絕」。額度足夠時逐筆留痕，逾界時併入聚合。
//
// reason 是 apierror 的**機器碼**（AUTH_TOKEN_MISSING／AUTH_TOKEN_INVALID／…），
// 由 `abortUnauthenticated` 寫進 gin context。沿用既有碼而非另造散文字串：
// 稽核端篩「憑證缺失 vs 憑證無效」與前端拿到的錯誤碼是同一套語彙。
//
// **唯一的例外是 `model.AuditReasonTokenExpired`**（批 3 裁決）：它只存在於審計側，
// 對外回應仍是 AUTH_TOKEN_INVALID。例行到期若與真正的無效存取嘗試同碼，
// 每日覆核的登入失敗數會被正常流量淹沒；而若讓對外也分碼，就開出了憑證存在性探測面
func (a *anonRejectionAuditor) record(c *gin.Context, reason, requestID string, elapsed time.Duration) {
	ip := a.sourceIP(c)
	now := a.now()

	a.mu.Lock()
	pending := a.sweepLocked(now)
	allowed := a.allowLocked(anonRateKey{
		ip: ip, reason: reason,
		method: c.Request.Method, path: c.Request.URL.Path,
	}, now)
	if !allowed {
		a.aggregateLocked(anonAggKey{reason: reason, ip: ip}, now)
	}
	a.mu.Unlock()

	if allowed {
		a.writeRow(anonRow{
			clientIP:   ip,
			method:     c.Request.Method,
			path:       c.Request.URL.Path,
			statusCode: c.Writer.Status(),
			duration:   elapsed,
			requestID:  requestID,
			details: anonDetails(map[string]any{
				"event":  anonEventRejected,
				"reason": reason,
			}),
		})
	}
	// 落地在鎖外：sink 可能寫 DB，持鎖跨越儲存層延遲會把每個 401 卡在同一把鎖上
	a.emit(pending)
}

// flushExpired 主動結清已到期的時間窗（測試與排程用）
func (a *anonRejectionAuditor) flushExpired() {
	now := a.now()
	a.mu.Lock()
	pending := a.sweepLocked(now)
	a.mu.Unlock()
	a.emit(pending)
}

// allowLocked 三道界線的判定：per-key → 全域。順序不可倒置（見檔頭）
func (a *anonRejectionAuditor) allowLocked(key anonRateKey, now time.Time) bool {
	b := a.bucketForLocked(key, now)
	if !b.allow(now, a.params.PerKeyBurst, a.params.PerKeyRefill) {
		return false
	}
	return a.global.allow(now, a.params.GlobalBurst, a.params.GlobalRefill)
}

// bucketForLocked 取得（必要時建立）鍵對應的桶。表滿時先清掉已回滿的閒置條目，
// 仍滿則落到共用 overflow 桶——不 fail-open，也不無界成長
func (a *anonRejectionAuditor) bucketForLocked(key anonRateKey, now time.Time) *anonBucket {
	if b, ok := a.keys[key]; ok {
		return b
	}
	if len(a.keys) >= a.params.MaxKeys {
		a.pruneKeysLocked(now)
	}
	if len(a.keys) >= a.params.MaxKeys {
		return &a.overflow
	}
	b := &anonBucket{}
	a.keys[key] = b
	return b
}

// pruneKeysLocked 清掉額度已回滿的條目：它們與「不存在」等價，保留只是佔記憶體
func (a *anonRejectionAuditor) pruneKeysLocked(now time.Time) {
	for k, b := range a.keys {
		refilled := b.tokens
		if elapsed := now.Sub(b.last); elapsed > 0 && a.params.PerKeyRefill > 0 {
			refilled += float64(elapsed) / float64(a.params.PerKeyRefill)
		}
		if refilled >= a.params.PerKeyBurst {
			delete(a.keys, k)
		}
	}
}

// aggregateLocked 把一次逾界的拒絕併入聚合條目
func (a *anonRejectionAuditor) aggregateLocked(key anonAggKey, now time.Time) {
	e, ok := a.agg[key]
	if !ok && len(a.agg) >= a.params.MaxAggregates {
		key = anonAggKey{reason: key.reason, ip: anonAggOverflowIP}
		e, ok = a.agg[key]
	}
	if ok {
		e.count++
		e.last = now
		return
	}
	a.agg[key] = &anonAggEntry{
		count: 1, first: now, last: now,
		windowEnd: now.Add(a.params.AggregateWindow),
	}
}

// sweepLocked 取出已到期的聚合條目。**只取出、不落地**——落地會呼叫外部 sink
// （可能寫 DB），持鎖跨越它會把拒絕路徑卡在儲存層延遲上
func (a *anonRejectionAuditor) sweepLocked(now time.Time) []anonAggFlush {
	var out []anonAggFlush
	for k, e := range a.agg {
		if now.Before(e.windowEnd) {
			continue
		}
		out = append(out, anonAggFlush{key: k, entry: *e})
		delete(a.agg, k)
	}
	return out
}

// emit 把到期的聚合條目落成聚合列。
//
// 聚合列刻意**不填方法與路徑**：一個窗內的拒絕橫跨多個端點，填任何一個都是以偏概全。
// 稽核在聚合列上要答的是「何時、從何處、因為什麼、幾次」，四者都在
func (a *anonRejectionAuditor) emit(pending []anonAggFlush) {
	for _, p := range pending {
		a.writeRow(anonRow{
			clientIP:   p.key.ip,
			statusCode: http.StatusUnauthorized,
			details: anonDetails(map[string]any{
				"event":     anonEventRejectedAggregate,
				"reason":    p.key.reason,
				"client_ip": p.key.ip,
				"count":     p.entry.count,
				"first_at":  p.entry.first.UTC().Format(time.RFC3339),
				"last_at":   p.entry.last.UTC().Format(time.RFC3339),
			}),
		})
	}
}

// anonRow 匿名列的可變欄位。固定欄位（user_id／username／action／resource／status）
// 由 writeRow 一處決定，不開放呼叫端各自填——那是 spec 釘死的契約
type anonRow struct {
	clientIP   string
	method     string
	path       string
	statusCode int
	duration   time.Duration
	requestID  string
	details    string
}

// writeRow 匿名列的**唯一**產生點（manifest AP-71）。
//
// 固定欄位即 spec「拒絕路徑必留痕」的契約：`user_id=0`、`username` 空——**不是**
// 拿某個佔位帳號冒充，匿名就該看得出是匿名；`resource=auth`、`status=failure`
// （認證失敗＝憑證不成立，與授權拒絕的 `denied` 分流，見 design D3）。
//
// `action=login` 沿用本庫既有的認證事件語彙（`auditLogin`、OIDC 的 writeAudit
// 皆同）——這一列記的就是一次不成立的身分認定；「他想做什麼」不因此遺失，
// method 與 path 兩欄原樣保留
func (a *anonRejectionAuditor) writeRow(r anonRow) {
	if a.sink == nil {
		return
	}
	a.sink.Log(&audit.AuditLogEntry{
		UserID:     0,
		Username:   "",
		Action:     model.ActionLogin,
		Resource:   model.ResourceAuth,
		Status:     model.StatusFailure,
		Method:     r.method,
		Path:       r.path,
		ClientIP:   r.clientIP,
		StatusCode: r.statusCode,
		Duration:   r.duration,
		RequestID:  r.requestID,
		Details:    r.details,
	})
}

// anonDetails 序列化 details；失敗時退為最小可用內容（審計不得因序列化而遺失，
// 同 oidc_login_service.go 的 mustJSON）
func anonDetails(v map[string]any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"event":"serialize_failed"}`
	}
	return string(b)
}
