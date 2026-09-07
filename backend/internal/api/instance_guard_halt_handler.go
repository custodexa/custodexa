package api

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
)

// 單實例守衛「攔下模式」的兩個未認證端點（preservice-pages）。
//
//	GET  /api/v1/instance-guard/halt  攔下狀態與持鎖者指紋（含本次確認碼）
//	POST /api/v1/instance-guard/ack   三要件確認送出
//
// **可達條件與封印期解封頁相同**：同一份來源網段限制（SEAL_UNSEAL_ALLOWED_CIDRS）、
// 不需登入。理由與解封端點一致——服務尚未上線，JWT 不可能存在；把它擋在登入後
// 等於讓這條救援路徑永遠用不到。
//
// **兩端點在完整路由樹上恆註冊**（比照 /seal/status 與 /seal/unseal）：
// 只在攔下模式註冊會使路由 golden、審計分類守衛與 API 索引都看不見它們，
// 而「監控分不出 503 與 404」正是封印閘刻意消滅的形態。非攔下狀態下
// GET 回 state=running、POST 回 409＋INSTANCE_GUARD_NOT_HALTED，
// 兩者都在觸碰任何憑證之前返回。

// InstanceGuardHaltState 攔下端點的狀態列舉（對外契約）。
const (
	// InstanceGuardHaltStateHalted 停在攔下模式，攔下頁應顯示確認表單。
	InstanceGuardHaltStateHalted = "halted"
	// InstanceGuardHaltStateRunning 已取得鎖或已以確認啟動；攔下頁應轉為「已啟動」。
	InstanceGuardHaltStateRunning = "running"
)

// InstanceGuardHaltView 攔下狀態的回應形狀。
//
// Holder 只在攔下期間有值，且**與 InstanceGuardView.Holder 共用型別**——
// 攔下頁與管理介面橫幅顯示的是同一份指紋，兩份形狀分開漂移毫無好處。
type InstanceGuardHaltView struct {
	State  string               `json:"state"`
	Since  string               `json:"since"`
	Holder *InstanceGuardHolder `json:"holder"`
	// RetryIntervalSeconds watchdog 重取週期；頁面據此告知「鎖被釋放後多久自動接手」。
	RetryIntervalSeconds int `json:"retry_interval_seconds"`
}

// InstanceGuardAckOutcome 確認送出的判定結果（由組裝根的 confirm 函式回報）。
type InstanceGuardAckOutcome string

const (
	// AckOutcomeAccepted 三要件相符，本實例將繼續啟動。
	AckOutcomeAccepted InstanceGuardAckOutcome = "accepted"
	// AckOutcomeHolderChanged 重打的碼不等於當下持鎖者的碼。
	AckOutcomeHolderChanged InstanceGuardAckOutcome = "holder_changed"
	// AckOutcomeInvalidCredential 管理員帳密驗證失敗。
	AckOutcomeInvalidCredential InstanceGuardAckOutcome = "invalid_credential"
	// AckOutcomeUsersUnavailable 使用者表讀取失敗（schema 不相容或連線問題）。
	AckOutcomeUsersUnavailable InstanceGuardAckOutcome = "users_unavailable"
	// AckOutcomeNotHalted 本實例已不在攔下模式。
	AckOutcomeNotHalted InstanceGuardAckOutcome = "not_halted"
)

// InstanceGuardAckRequest 確認送出的請求體。
//
// 密碼以 string 承載：本路徑的秘密不進入任何長期保存的結構，且憑證驗證器
// （identity）以 []byte 為介面，轉換發生在組裝根的單一位置。解封路徑的
// 可覆寫 buffer 紀律不套用於此——那條紀律保護的是**會成為部署主 KEK 的材料**，
// 密碼在此只用於一次比對，另造一套自訂解析只會多一份可分歧的實作。
type InstanceGuardAckRequest struct {
	ConfirmedPrimaryDown bool   `json:"confirmed_primary_down"`
	Code                 string `json:"code"`
	Username             string `json:"username"`
	Password             string `json:"password"`
}

// InstanceGuardAckResult 確認送出的結果；Holder 為送出當下重查的持鎖者指紋。
type InstanceGuardAckResult struct {
	Outcome InstanceGuardAckOutcome
	Holder  *InstanceGuardHolder
}

// InstanceGuardHaltProbe 攔下狀態的現讀函式（由組裝根注入）。
type InstanceGuardHaltProbe func() InstanceGuardHaltView

// InstanceGuardAckFunc 確認送出的處理函式（由組裝根注入）。
//
// **憑證驗證與守衛狀態變更都在組裝根側**：api 層不 import identity，
// 也不 import database；本 handler 只負責請求形狀、來源限制與狀態碼映射。
type InstanceGuardAckFunc func(req InstanceGuardAckRequest) InstanceGuardAckResult

// haltAckMaxFailures 同一來源在冷卻窗內可累積的憑證失敗次數上限。
// haltAckLockWindow 為達上限後的冷卻時長。
//
// **刻意是行程內計數而非既有的帳號鎖定閘**：既有閘（AuthService）寫
// `users.failed_login_attempts`／`locked_until` 並依賴段 2 才建構的安全政策服務，
// 而攔下模式的硬不變式是「不產生任何資料庫寫入」。兩者不可兼得時以不變式為準；
// 界線在此明說，免得被誤讀為已享有帳號鎖定保護——**它擋的是自動化爆破，
// 不是有主機存取權的人**，且隨行程結束歸零。
const (
	haltAckMaxFailures = 5
	haltAckLockWindow  = 5 * time.Minute
)

// InstanceGuardHaltHandler 攔下端點的承載體。
type InstanceGuardHaltHandler struct {
	probe   InstanceGuardHaltProbe
	confirm InstanceGuardAckFunc

	trustedProxyConfigured bool
	allowedSources         []*net.IPNet

	// now 取現在時刻；生產恆為 time.Now，**僅測試**覆寫。
	// 抽出來是為了讓 haltAckLockWindow 的到期行為（暫拒→期滿受理→計數歸零）
	// 測得到——否則那條 spec scenario 只能靠等 5 分鐘，等於沒有守衛。
	now func() time.Time

	mu       sync.Mutex
	failures map[string]*haltAckCounter
}

type haltAckCounter struct {
	count int
	until time.Time
}

// NewInstanceGuardHaltHandler 建立 handler；probe／confirm 為 nil 時
// 回「非攔下」（僅單測與段 1 佔位）。
func NewInstanceGuardHaltHandler(probe InstanceGuardHaltProbe, confirm InstanceGuardAckFunc) *InstanceGuardHaltHandler {
	return &InstanceGuardHaltHandler{probe: probe, confirm: confirm,
		now: time.Now, failures: map[string]*haltAckCounter{}}
}

// SetSourceControls 注入可信代理與允許網段組態（與解封端點同一份組態）。
func (h *InstanceGuardHaltHandler) SetSourceControls(trustedProxyConfigured bool, allowed []*net.IPNet) {
	h.trustedProxyConfigured = trustedProxyConfigured
	h.allowedSources = allowed
}

// RegisterRoutes 註冊兩條攔下端點（不掛認證中介層——服務未起時 JWT 不存在）。
func (h *InstanceGuardHaltHandler) RegisterRoutes(v1 *gin.RouterGroup) {
	v1.GET("/instance-guard/halt", h.Halt)
	v1.POST("/instance-guard/ack", h.Ack)
}

// Halt 回傳攔下狀態與持鎖者指紋。唯讀、無副作用、無資料庫寫入。
func (h *InstanceGuardHaltHandler) Halt(c *gin.Context) {
	if !h.sourceAllowed(c) {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSealSourceNotAllowed, nil)
		return
	}
	c.JSON(http.StatusOK, h.view())
}

// Ack 受理三要件確認。
//
// 順序為「來源 → 攔下狀態 → 三要件齊備 → 退避 → 委派驗證」：由便宜到昂貴，
// 且**任何憑證比對之前**已先擋掉非攔下狀態的呼叫者。
func (h *InstanceGuardHaltHandler) Ack(c *gin.Context) {
	if !h.sourceAllowed(c) {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSealSourceNotAllowed, nil)
		return
	}
	view := h.view()
	if view.State != InstanceGuardHaltStateHalted {
		apierror.Respond(c, http.StatusConflict, apierror.CodeInstanceGuardNotHalted, nil)
		return
	}

	var req InstanceGuardAckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInstanceGuardAckIncomplete, nil)
		return
	}
	// 三要件缺一即拒——在觸碰資料庫之前。
	if !req.ConfirmedPrimaryDown || req.Code == "" || req.Username == "" || req.Password == "" {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInstanceGuardAckIncomplete, nil)
		return
	}

	if h.confirm == nil {
		apierror.Respond(c, http.StatusConflict, apierror.CodeInstanceGuardNotHalted, nil)
		return
	}

	// 准入在互斥內**預留**（不是事後計數）：見 reserveAttempt 的註解。
	key := h.sourceKey(c)
	if !h.reserveAttempt(key) {
		apierror.Respond(c, http.StatusTooManyRequests, apierror.CodeInstanceGuardAckLocked, nil)
		return
	}

	res := h.confirm(req)
	switch res.Outcome {
	case AckOutcomeAccepted:
		h.clearFailures(key)
		c.JSON(http.StatusOK, InstanceGuardHaltView{
			State:                InstanceGuardHaltStateRunning,
			RetryIntervalSeconds: view.RetryIntervalSeconds,
		})
	case AckOutcomeHolderChanged:
		// 憑證是對的，錯的是碼：這一次不算憑證失敗，退回預留的名額。
		h.releaseAttempt(key)
		// 回新的持鎖者指紋與確認碼：操作者才有東西可以重打。
		// 走 apierror.Write 的 Meta 而非自拼 JSON——後者會成為一個新的裸文字
		// 錯誤出口（同一個碼從此有兩份可各自漂移的文案）。
		apierror.Write(c, http.StatusConflict, apierror.ErrorResponse{
			Code: apierror.CodeInstanceGuardHolderChanged,
			Meta: map[string]any{
				"state":                  InstanceGuardHaltStateHalted,
				"holder":                 res.Holder,
				"retry_interval_seconds": view.RetryIntervalSeconds,
			},
		})
	case AckOutcomeInvalidCredential:
		h.noteFailure(key)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeInstanceGuardAckUnauthorized, nil)
	case AckOutcomeUsersUnavailable:
		// 使用者表讀不到＝未知狀態，不是「這個人打錯密碼」，不得計入退避。
		h.releaseAttempt(key)
		apierror.Respond(c, http.StatusServiceUnavailable, apierror.CodeInstanceGuardAckUnavailable, nil)
	default:
		h.releaseAttempt(key)
		apierror.Respond(c, http.StatusConflict, apierror.CodeInstanceGuardNotHalted, nil)
	}
}

// view 現讀攔下狀態；probe 未注入時回「非攔下」。
func (h *InstanceGuardHaltHandler) view() InstanceGuardHaltView {
	if h.probe == nil {
		return InstanceGuardHaltView{State: InstanceGuardHaltStateRunning}
	}
	return h.probe()
}

func (h *InstanceGuardHaltHandler) sourceIP(c *gin.Context) string {
	return requestSourceIP(c, h.trustedProxyConfigured)
}

// sourceAllowed 與解封端點同一判定（未設允許網段即不限制）。
func (h *InstanceGuardHaltHandler) sourceAllowed(c *gin.Context) bool {
	if len(h.allowedSources) == 0 {
		return true
	}
	ip := net.ParseIP(h.sourceIP(c))
	if ip == nil {
		return false
	}
	for _, n := range h.allowedSources {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// sourceKey 退避計數的分組鍵；未約定可信代理時全部來源共用一個鍵
// （與解封端點同一降級語義：轉送標頭在此不可信，per-source 分組會被偽造繞過）。
func (h *InstanceGuardHaltHandler) sourceKey(c *gin.Context) string {
	if !h.trustedProxyConfigured {
		return globalSourceKey
	}
	if ip := h.sourceIP(c); ip != "" {
		return ip
	}
	return globalSourceKey
}

// clock 現在時刻；未注入（例如以零值結構建立）時退回 time.Now。
func (h *InstanceGuardHaltHandler) clock() time.Time {
	if h.now == nil {
		return time.Now()
	}
	return h.now()
}

// reserveAttempt 在互斥內**預留**一個准入名額：達上限即拒（false＝回 429）。
//
// **為什麼是預留而非事後計數**：先前的形態是「locked() 讀計數 → 釋放互斥 →
// 驗憑證 → 失敗才 noteFailure()」。讀與寫之間沒有任何互斥，N 個併發請求會同時
// 讀到同一個尚未達上限的計數，於是全部通過准入、全部打到憑證驗證——上限對
// 併發爆破完全無效（單執行緒逐次送才擋得住，而那不是攻擊者的送法）。
//
// 改法是把「名額」在互斥內先扣掉：計數在**驗證之前**就加，故任一時刻真正走到
// 憑證驗證的請求數（含在途）不超過 haltAckMaxFailures。驗證結果若不是憑證失敗
// （受理、碼過期、使用者表讀不到），再由 releaseAttempt 把名額退回去——只有
// 真正的憑證失敗留在計數裡，時窗語義因而與先前完全相同。
func (h *InstanceGuardHaltHandler) reserveAttempt(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failures == nil {
		h.failures = map[string]*haltAckCounter{}
	}
	e := h.failures[key]
	if e != nil && !e.until.IsZero() {
		if h.clock().Before(e.until) {
			return false
		}
		// 冷卻已過：計數一併歸零，否則下一次失敗立刻再鎖（死循環）。
		delete(h.failures, key)
		e = nil
	}
	if e == nil {
		e = &haltAckCounter{}
		h.failures[key] = e
	}
	if e.count >= haltAckMaxFailures {
		return false
	}
	e.count++
	return true
}

// releaseAttempt 退回一個預留名額（本次不是憑證失敗）。
func (h *InstanceGuardHaltHandler) releaseAttempt(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.failures[key]
	if e == nil || e.count <= 0 {
		return
	}
	e.count--
	if e.count == 0 && e.until.IsZero() {
		delete(h.failures, key)
	}
}

// noteFailure 把預留的名額**確認**成一次真正的憑證失敗；達上限即開始冷卻。
func (h *InstanceGuardHaltHandler) noteFailure(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failures == nil {
		h.failures = map[string]*haltAckCounter{}
	}
	e := h.failures[key]
	if e == nil {
		// 沒有預留紀錄（理論上不可達；保守補計一次，不讓失敗白白消失）
		e = &haltAckCounter{count: 1}
		h.failures[key] = e
	}
	if e.count >= haltAckMaxFailures && e.until.IsZero() {
		// 只在跨過上限的那一次設到期；鎖定期內的請求在 reserveAttempt() 就被擋下，
		// 不會再走到這裡，故**時窗不會被後續嘗試延長**（期滿即受理）。
		e.until = h.clock().Add(haltAckLockWindow)
	}
}

func (h *InstanceGuardHaltHandler) clearFailures(key string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.failures, key)
}
