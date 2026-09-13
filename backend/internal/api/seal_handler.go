package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/middleware"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/seal"
)

// SealJournalStatus 為 /seal/status 需要的 journal 面向（由 sealjournal 提供實作）。
// 以介面注入而非直接依賴具體型別，使 handler 可單測且不牽動 journal 的生命週期。
type SealJournalStatus interface {
	// Faulted 為真代表 journal 處於 I/O 故障態，已 fail-close 拒收新嘗試。
	Faulted() bool
}

// SealAdmitFunc 取得一次 admission 資格（固定最小 admission 間隔）。
//
// 回傳的 release SHALL 於本次嘗試結束時呼叫，並以 receivedLanded 表達
// 「journal 的 received 是否真的落地」——**基準只在落地後才推進**，
// 被拒的嘗試因此不會把下一次可受理時點往後推（否則可耗盡配額的語義即回流）。
//
// 以 func 注入而非介面：sealjournal.Journal.Admit 回傳具體的 *Ticket，
// 直接宣告介面會逼 internal/api 依賴 sealjournal 的型別；一個閉包即可解耦，
// 且使單測不需要真的開一個定長檔。
type SealAdmitFunc func(ctx context.Context) (release func(receivedLanded bool), err error)

// SealHandler 封印狀態查詢與解封端點。
//
// **不要求 JWT**：要求 JWT 會在「admin 已開 MFA」時死鎖——TOTP secret 是信封
// 加密欄，封印期解不開，管理員無法登入來解封。授權改以「知道 KEK」承擔
// （一般解封）；空金鑰表的初始化解封沒有這個證明，故另行要求初始管理員憑證，
// 該要求由 VerifyFunc 在臨界區內執行。
type SealHandler struct {
	authorize func(context.Context, string) (uint, error)
	mode      string
	machine   *seal.Machine
	journal   SealJournalStatus

	// trustedProxyConfigured 為 false 時，per-source 退避 SHALL 保守降級為全域退避
	// （可信來源契約：寧可影響可用性，也不提供可被轉送標頭污染而繞過的假防線）。
	trustedProxyConfigured bool
	// allowedSources 為解封端點允許的來源網段；空集合＝不限制。
	allowedSources []*net.IPNet
	// bindAddr 為解封端點的獨立監聽位址（空＝與主服務共用監聽）。僅供 status 呈現。
	bindAddr string
	// unsealRelocated 為真代表**本 handler 掛在主監聽**，而解封端點已另行繫結
	// 到管理監聽。此時主監聽上的解封一律硬拒——否則獨立監聽只是多開
	// 一個入口，網段隔離完全沒有發生。
	unsealRelocated bool
	// initRequired 回報目前是否為「空金鑰表」（初始化解封路徑）。
	// 供 status 告知前端該顯示哪一種畫面；判定失敗時回 error 而非以 false 頂替。
	initRequired func() (bool, error)
	// admit 為 admission 資格取得函式；nil 代表未接線（僅單測情境）。
	admit SealAdmitFunc
	// onUnsealed 於解封成功**之後**呼叫，參數為**本次已發佈**的服務圖
	// （SUCCESS 已 durable 且 publish CAS 已成功）。段 2 的完整 router 於此換手
	// ——任何提前換手都會在 SUCCESS 未 durable 時放行服務。
	//
	// 服務圖以參數傳入而非由呼叫端自行保存：逾時後才返回的殭屍段 2 會寫入
	// 同一份共享狀態，用共享變數承接等於自造一個資料競賽。
	onUnsealed func(seal.ServiceGraph)
	// instanceGuard 單實例守衛的粗狀態探針。
	// 狀態查詢已是「行程當下狀態」的公開出口，且不寫審計列，故供橫幅輪詢；
	// 回應**不含**持鎖者指紋、確認碼、主機名／pid（那些走管理者限定端點）。
	// nil＝未注入（僅單測），此時省略欄位。
	instanceGuard func() InstanceGuardStatus

	// ── 解封授權脈絡（自本版起三模式一律先驗帳密）────────────────────
	//
	// grants 為行程記憶體內的短效脈絡表；verifyCredential 為封存期可用的帳密
	// 驗證器。兩者任一未注入時 /seal/authorize 一律回拒——缺驗證器不得退化為
	// 免驗證，而解封端點缺脈絡即拒。
	grants           *SealGrantStore
	verifyCredential SealCredentialVerifier
	// authLimiter 授權端點自己的退避與冷卻。
	//
	// **與解封端點各自一份而非共用**：兩者的失敗語義不同（帳密錯 vs 憑證錯），
	// 共用計數會讓一方的失敗把另一方鎖住，而管理者在憑證階段的重試是正常操作。
	// 兩者用同一份 LimiterConfig，「沿既有退避與鎖定」指的是同一套規則而非同一份計數。
	authLimiter   *seal.Limiter
	authLimiterMu sync.Mutex
	authCooldown  time.Time
	// topologyProbe 供給解封頁核對用的唯讀拓撲；非委託模式回 ok=false。
	topologyProbe func() (SealTopologyView, bool)
}

// SealTopologyView 解封頁的唯讀拓撲呈現。
//
// **在提供任何秘密之前就要能讀到**：操作者要在交出憑證前判斷目的地是否與機構的
// 部署紀錄一致。全部欄位皆為非秘密。
//
// 誠實界定：唯讀呈現使可達解封頁者讀得到內部拓撲，這是「交出憑證前先核對目的地」
// 這項能力的代價，由既有的來源網段限制承擔；它 SHALL NOT 被宣稱能防止具資料庫
// 寫入權者篡改所顯示的內容。
type SealTopologyView struct {
	// Provider 保管處服務商（唯讀；由部署檔宣告，解封頁不提供切換）。
	Provider string `json:"provider"`
	// Configured 拓撲是否已設定（全新安裝在設定之前為 false）。
	Configured bool `json:"configured"`
	// Address／TransitKeyName／RoleID Vault 分支的拓撲。
	Address        string `json:"address"`
	TransitKeyName string `json:"transit_key_name"`
	RoleID         string `json:"role_id"`
	// Region 服務區域（AWS 分支）。
	Region string `json:"region"`
	// KeyRef 金鑰識別（沿金鑰列的 KEK 引用；尚無金鑰列時為空）。
	KeyRef string `json:"key_ref"`
	// Digest 拓撲快照摘要，供核對綁定（送出憑證時帶回比對）。
	Digest string `json:"digest"`
}

// SetTopologyProbe 注入唯讀拓撲探針。
func (h *SealHandler) SetTopologyProbe(fn func() (SealTopologyView, bool)) { h.topologyProbe = fn }

// SetAuthLimiter 注入授權端點的退避器（沿解封端點的同一份組態）。
func (h *SealHandler) SetAuthLimiter(l *seal.Limiter) { h.authLimiter = l }

// authorizeLimiter 取得授權端點的退避器；未注入時以預設組態就地建一份
//（僅單測情境；正式路徑一律由組裝根注入與解封端點相同的組態）。
func (h *SealHandler) authorizeLimiter() *seal.Limiter {
	h.authLimiterMu.Lock()
	defer h.authLimiterMu.Unlock()
	if h.authLimiter == nil {
		h.authLimiter = seal.NewLimiter(seal.LimiterConfig{})
	}
	return h.authLimiter
}

// authorizeCooldownUntil 全域冷卻是否生效。
func (h *SealHandler) authorizeCooldownUntil(now time.Time) (time.Time, bool) {
	h.authLimiterMu.Lock()
	defer h.authLimiterMu.Unlock()
	if h.authCooldown.IsZero() || !now.Before(h.authCooldown) {
		return time.Time{}, false
	}
	return h.authCooldown, true
}

// recordAuthorizeFailure 記一次帳密失敗並在達門檻時武裝全域冷卻。
func (h *SealHandler) recordAuthorizeFailure(key string, now time.Time) {
	until, arm := h.authorizeLimiter().RecordMaterialFailure(key, now)
	if !arm {
		return
	}
	h.authLimiterMu.Lock()
	defer h.authLimiterMu.Unlock()
	if until.After(h.authCooldown) {
		h.authCooldown = until
	}
}

// topologyView 取得唯讀拓撲（非委託模式回 ok=false）。
func (h *SealHandler) topologyView() (SealTopologyView, bool) {
	if h.topologyProbe == nil {
		return SealTopologyView{}, false
	}
	return h.topologyProbe()
}

// NewSealHandler 建立解封端點 handler。
func NewSealHandler(m *seal.Machine, j SealJournalStatus) *SealHandler {
	return &SealHandler{machine: m, journal: j}
}

// SetSourceControls 注入可信代理與允許網段組態。
func (h *SealHandler) SetSourceControls(trustedProxyConfigured bool, allowed []*net.IPNet, bindAddr string) {
	h.trustedProxyConfigured = trustedProxyConfigured
	h.allowedSources = allowed
	h.bindAddr = bindAddr
}

// SetUnsealRelocated 宣告「解封端點已移至獨立監聽」，本 handler 自此硬拒解封。
//
// 由組裝根在設定 SEAL_UNSEAL_BIND_ADDR 時對**主監聽**的 handler 呼叫；
// 管理監聽上的 handler 不呼叫本方法，故仍可解封。狀態查詢兩邊都保留——
// 監控需要能在業務網段讀到「服務尚未解封」。
func (h *SealHandler) SetUnsealRelocated(relocated bool) { h.unsealRelocated = relocated }

// SetInitRequiredProbe 注入「金鑰表是否為空」的探針。
func (h *SealHandler) SetInitRequiredProbe(fn func() (bool, error)) { h.initRequired = fn }

// SetAdmitter 注入 admission 資格取得函式。
func (h *SealHandler) SetAdmitter(fn SealAdmitFunc) { h.admit = fn }

// SetOnUnsealed 注入解封成功後的放行回呼（段 2 router 換手）。
func (h *SealHandler) SetOnUnsealed(fn func(seal.ServiceGraph)) { h.onUnsealed = fn }

// SetInstanceGuardProbe 注入單實例守衛的粗狀態探針（組裝根於兩種模式各呼叫一次）。
func (h *SealHandler) SetInstanceGuardProbe(fn func() InstanceGuardStatus) { h.instanceGuard = fn }

// globalSourceKey 是「未設可信代理」時全部來源共用的退避鍵。
// 常數而非空字串：空字串在 map 中與「未設鍵」難以辨識，具名值使降級在
// 日誌與測試中都是可見的事實。
const globalSourceKey = "__global__"

// RegisterRoutes 註冊封印期白名單端點。
//
// 兩條路徑都必須在封印閘的白名單內，否則管理員無法查狀態、亦無法解封。
func (h *SealHandler) RegisterRoutes(v1 *gin.RouterGroup) {
	v1.GET("/seal/status", h.Status)
	v1.POST("/seal/authorize", h.Authorize)
	v1.POST("/seal/unseal", h.Unseal)
	v1.POST("/seal/seal", h.Seal)
}

// Status 暴露當前態、generation、失敗機器碼、冷卻到期時間、待收束、journal 狀態
// 與逾時提示，使管理員與監控無須猜測。
func (h *SealHandler) Status(c *gin.Context) {
	// 網段限制涵蓋**整個 seal 端點群**：狀態同樣暴露部署形態
	// （是否待初始化、繫結位址、冷卻到期時間），只擋解封而放行狀態，
	// 等於把偵察面留在網段之外。
	if !h.sourceAllowed(c) {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSealSourceNotAllowed, nil)
		return
	}
	snap := h.machine.Snapshot()

	body := gin.H{
		"state":             string(snap.State),
		"mode":              h.mode,
		"generation":        snap.Generation,
		"cleanup_pending":   snap.CleanupPending,
		"journal_faulted":   h.journalFaulted(),
		"timeout_total":     h.machine.TimeoutTotal(),
		"trusted_proxy":     h.trustedProxyConfigured,
		"source_restricted": len(h.allowedSources) > 0,
		// 三模式一律先經管理者帳密驗證才顯示材料或憑證欄位。恆為 true——
		// 這是契約而非旋鈕，前端據此決定第一步畫什麼。
		"authorization_required": true,
	}
	// 委託模式：唯讀拓撲與該服務商的憑證欄形態。**先於任何秘密輸入**，
	// 使操作者在交出憑證之前即可核對目的地。
	if view, ok := h.topologyView(); ok {
		body["topology"] = view
		body["credential_form"] = view.Provider
	}
	// **只有 env 保留這條指引**：委託模式自本版起沒有「重讀部署來源」這條路
	// ——憑證只存在於解封世代，重啟後無處可取，恢復一律經解封頁重新提供。
	// 留著它會讓操作者以為重啟就能自動恢復。
	if h.mode == "env" {
		body["restore_guidance"] = "Use the existing administrator session to restore. If it is unavailable or invalid, restart the backend with the configured key source."
	}
	if h.bindAddr != "" {
		body["bind_addr"] = h.bindAddr
	}
	// 守衛粗狀態：對未認證呼叫者多揭露一個狀態列舉，
	// 與本端點已揭露的封印狀態、bind_addr 同級；持鎖者細節不在此。
	if h.instanceGuard != nil {
		body["instance_guard"] = h.instanceGuard()
	}
	if snap.State == seal.StateSealedFaulted && snap.FaultCode != "" {
		body["fault_code"] = snap.FaultCode
	}
	if !snap.CooldownUntil.IsZero() {
		body["cooldown_until"] = snap.CooldownUntil.UTC().Format(time.RFC3339)
	}
	if snap.CleanupPending {
		body["cleanup_generation"] = snap.CleanupGeneration
		body["cleanup_reason"] = snap.CleanupReason
		if !snap.CleanupStartedAt.IsZero() {
			body["cleanup_started_at"] = snap.CleanupStartedAt.UTC().Format(time.RFC3339)
		}
	}

	// 逾時 × 初始化解封的重試指引：逾時回 sourceState 時
	// bootstrap 可能已完成，改用新材料重試將使第一把材料成為無人知曉的部署主
	// KEK，等同資料永久不可解。故只要發生過逾時就明示此提示。
	if h.machine.TimeoutTotal() > 0 {
		body["timeout_retry_hint_code"] = string(apierror.CodeSealStage2Timeout)
	}

	// 初始化 vs 一般解封的判定 fail-close：讀不到就不以 false 頂替未知狀態。
	if h.initRequired != nil && snap.State != seal.StateUnsealed {
		required, err := h.initRequired()
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeSealStatusUnavailable, err)
			return
		}
		body["initialization_required"] = required
	}

	c.JSON(http.StatusOK, body)
}

func (h *SealHandler) journalFaulted() bool {
	if h.journal == nil {
		return false
	}
	return h.journal.Faulted()
}

// Unseal 執行一次解封嘗試。
//
// 本方法本身**不做任何材料判斷**：整個請求體原樣成為 seal.UnsealRequest.Material，
// 由狀態機在臨界區內交給 VerifyFunc。這是「CAS 取得持有權發生在任何驗證
// 開始之前」的直接落實——handler 若先解析並預檢，那份預檢就落在獨佔之外。
func (h *SealHandler) Unseal(c *gin.Context) {
	// 解封端點已另行繫結時，主監聽上的解封在**讀請求體之前**即被拒：
	// 不進限速、不進 CAS、不觸及任何材料。回應與網段不符共用同一機器碼——
	// 兩者都是「這個入口不受理解封」，且不新增可被列舉的碼。
	if h.unsealRelocated {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSealSourceNotAllowed, nil)
		return
	}
	if !h.sourceAllowed(c) {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSealSourceNotAllowed, nil)
		return
	}

	// **所有模式一律要求解封授權脈絡**（改前只有 mode != "ui" 要求 Bearer）。
	// 脈絡證明送出者剛通過管理員帳密驗證；`ui` 的「知道材料」自本版起是驗證
	// 之後的第二道，SHALL NOT 再單獨承擔授權。
	//
	// **全新安裝不例外**：初始管理員於段 1 的種子即已建立（`database.SeedDatabase`
	// 在解封之前執行），故「驗證一個不存在的帳號」這個顧慮在本產品不成立——
	// 全新安裝的第一步就是以那組憑證換一個脈絡，其後三步帶著它走。
	// 請求本文仍帶同一組帳密：那一份在**臨界區之內**驗證，是「誰有權宣告本部署
	// 的主金鑰」的證明；脈絡則是「在看到秘密欄位之前已通過驗證」的證明。
	// 兩者的時點與用途不同，故不互相代償。
	grantToken, _, gerr := h.grantFromRequest(c)
	if gerr != nil {
		code := apierror.CodeSealGrantRequired
		if c.GetHeader("Authorization") != "" {
			// 帶了脈絡但不成立：過期、已撤銷或格式不符，與「根本沒帶」分開回報，
			// 否則操作者無從判斷該重驗還是先驗。兩者都不洩漏帳號是否存在。
			code = apierror.CodeSealGrantInvalid
		}
		log.Printf("[SealAudit] unseal rejected code=%s", code)
		apierror.Respond(c, http.StatusUnauthorized, code, nil)
		return
	}

	// 輸入大小上限：讀取本身即有界，超過即截斷後交由材料驗證拒絕
	//（超長內容不另給專屬碼，維持回應內容不可區分）。
	body := make([]byte, MaxSealUnsealBodyBytes+1)
	defer material.Wipe(body)
	n, err := io.ReadFull(c.Request.Body, body)
	body = body[:n]
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		err = nil
	}
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSealMaterialInvalid, nil)
		return
	}

	req := seal.UnsealRequest{
		Material:     body,
		SourceKey:    h.sourceKey(c),
		SourceDigest: sourceDigest(h.sourceIP(c)),
	}

	// admission 資格：CAS 勝出前先取得，用畢依「received 是否落地」釋放。
	release := func(bool) {}
	if h.admit != nil {
		rel, aerr := h.admit(c.Request.Context())
		if aerr != nil {
			apierror.Respond(c, http.StatusServiceUnavailable, apierror.CodeSealJournalIOFailure, nil)
			return
		}
		release = rel
	}

	res, uerr := h.machine.Unseal(c.Request.Context(), req)
	release(receivedLanded(uerr))
	if uerr != nil {
		// **可區分性的判準是成因本身，不是請求帶了什麼**：四個可辨識成因
		// （拓撲已變動、保管處不可達、憑證被拒、金鑰不符）在建構上只可能產生於
		// 管理者身分驗證通過**之後**——既有部署經授權脈絡驗證，全新安裝經同一
		// 請求內的初始管理員憑證驗證。匿名探測拿不到它們：帳密未過的請求在更早
		// 一步就收斂為材料無效，與改前逐字相同。
		//
		// 以成因判定而非以「有無脈絡」判定，使全新安裝的四步流程同樣拿得到可
		// 行動的錯誤，而這不放寬任何一分匿名可見性。
		code, status := SealErrorResponseFor(uerr, true)
		apierror.Respond(c, status, code, nil)
		return
	}
	// 解封成功即撤銷全部脈絡：新的世代已成立，任何在舊狀態下取得的核對結果
	// 都不該再能送出。
	if h.grants != nil {
		h.grants.RevokeAll()
	}
	_ = grantToken
	// 放行在回應之前：拿到 200 的呼叫端下一個請求就必須打得到完整服務。
	if h.onUnsealed != nil {
		h.onUnsealed(res.Services)
	}
	c.JSON(http.StatusOK, gin.H{
		"state":      string(res.State),
		"generation": res.Generation,
	})
}

// receivedLanded 依終局所屬的遷移格判定 journal 的 received 是否已落地。
//
// 只有兩格未落地：格 3（未取得持有權，根本沒進臨界區）與格 3b（received 落地
// **前**的一切終止）。其餘各格——材料失敗（4）、post-PREPARE 中止（4b）、
// 發佈（5）、未發佈（5b）、初始化失敗（6）、逾時（7）——皆已消耗過一次
// received 寫入與其兩次 fdatasync，故 SHALL 推進 admission 基準。
func receivedLanded(err error) bool {
	if err == nil {
		return true
	}
	switch seal.CellOf(err) {
	case "3", "3b":
		return false
	default:
		// 非本套件錯誤（CellOf 回空字串）保守視為未落地：把不確定的情形算成
		// 「已消耗資源」會讓非解封類錯誤替攻擊者延後正當管理員的下一次受理。
		return seal.CellOf(err) != ""
	}
}

// sourceKey 決定 per-source 退避鍵。
//
// 未設定可信代理時，per-IP 退避 SHALL 保守降級為全域退避——經 ingress 時
// 限速鍵可被轉送標頭污染而誤歸戶或繞過，寧可影響可用性也不提供可繞過的假防線。
func (h *SealHandler) sourceKey(c *gin.Context) string {
	if !h.trustedProxyConfigured {
		return globalSourceKey
	}
	ip := h.sourceIP(c)
	if ip == "" {
		return globalSourceKey
	}
	return ip
}

// sourceIP 決定本請求的來源 IP。
//
// **未約定可信代理鏈時只採信 socket peer IP**（RemoteAddr），不採 c.ClientIP()：
// 後者會依 X-Forwarded-For／X-Real-IP 等轉送標頭改寫來源，而那些標頭在沒有
// 可信代理約定時完全由呼叫端控制——任何以它為判準的網段白名單，攻擊者送一個
// 標頭即可自稱位於管理網段。gin 的預設是信任全部代理，因此「未設定」正是
// 最需要收窄的組態，而不是可以沿用預設的組態。
//
// 已約定可信代理時才用 c.ClientIP()：此時轉送標頭經 gin 的可信代理鏈判定，
// 且該鏈由部署方顯式宣告（TRUSTED_PROXIES，非法即拒絕啟動）。
func (h *SealHandler) sourceIP(c *gin.Context) string {
	return requestSourceIP(c, h.trustedProxyConfigured)
}

// sourceAllowed 判定來源是否落在允許網段內（網段繫結組態）。
// 未設定允許網段即不限制——是否啟用由部署方決定，但產品必須提供此控制。
func (h *SealHandler) sourceAllowed(c *gin.Context) bool {
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

// sourceDigest 產生寫入 journal 的來源摘要。
// 只送十六進位摘要：journal 的自由字串欄位只接受十六進位，原始 IP 與任何
// 請求內容在建構上無法寫入（內容白名單）。
func sourceDigest(clientIP string) string {
	sum := sha256.Sum256([]byte(clientIP))
	return hex.EncodeToString(sum[:])
}

// sealErrorStatus 把狀態機的機器碼映射為 HTTP 狀態碼與 apierror 註冊碼。
//
// 映射表是對外契約的一部分：狀態必須可被外部監控正確辨識，故衝突類一律 409、
// 限速類 429、材料類 400，而不是籠統的 500。
var sealErrorStatus = map[string]struct {
	code   apierror.ErrCode
	status int
}{
	seal.CodeUnsealInProgress:   {apierror.CodeSealUnsealInProgress, http.StatusConflict},
	seal.CodeCleanupPending:     {apierror.CodeSealCleanupPending, http.StatusConflict},
	seal.CodeAlreadyUnsealed:    {apierror.CodeSealAlreadyUnsealed, http.StatusConflict},
	seal.CodeCooldownActive:     {apierror.CodeSealCooldownActive, http.StatusTooManyRequests},
	seal.CodeBackoffActive:      {apierror.CodeSealBackoffActive, http.StatusTooManyRequests},
	seal.CodeMaterialInvalid:    {apierror.CodeSealMaterialInvalid, http.StatusBadRequest},
	seal.CodeAborted:            {apierror.CodeSealAborted, http.StatusBadRequest},
	seal.CodeJournalIOFailure:   {apierror.CodeSealJournalIOFailure, http.StatusServiceUnavailable},
	seal.CodeSealCleanupFailed:  {apierror.CodeSealInitFailed, http.StatusInternalServerError},
	seal.CodeInitFailed:         {apierror.CodeSealInitFailed, http.StatusInternalServerError},
	seal.CodeStage2Timeout:      {apierror.CodeSealStage2Timeout, http.StatusGatewayTimeout},
	seal.CodePublishUnconfirmed: {apierror.CodeSealPublishUnconfirmed, http.StatusInternalServerError},
}

// SealErrorResponse 取得解封錯誤對應的 apierror 碼與 HTTP 狀態。
// 未登記的碼一律退回「材料無效」而非 500：不可辨識的失敗不得因此洩漏出
// 一個可區分的回應形狀（回應內容不可區分）。
func SealErrorResponse(err error) (apierror.ErrCode, int) {
	return SealErrorResponseFor(err, false)
}

// distinguishableCauses 憑證階段的可辨識成因對應表。
//
// 順序無關（成因互斥），但 ErrTopologyChanged 先於其餘：核對已失效時根本
// 不該去判斷保管處的回應。
var distinguishableCauses = []struct {
	cause  error
	code   apierror.ErrCode
	status int
}{
	{seal.ErrTopologyChanged, apierror.CodeSealTopologyChanged, http.StatusConflict},
	{seal.ErrCustodyUnreachable, apierror.CodeSealCustodyUnreachable, http.StatusBadGateway},
	{seal.ErrCredentialRejected, apierror.CodeSealCredentialRejected, http.StatusBadRequest},
	{seal.ErrKeyMismatch, apierror.CodeSealKeyMismatch, http.StatusBadRequest},
}

// SealErrorResponseFor 取得解封錯誤對應的 apierror 碼與 HTTP 狀態。
//
// distinguishable 為真（請求帶有效授權脈絡）時，憑證階段的三類成因與「核對已
// 失效」各回專屬碼；為假時一律沿既有行為——未登記的碼退回「材料無效」而非
// 500，使不可辨識的失敗不洩漏出可區分的回應形狀。
func SealErrorResponseFor(err error, distinguishable bool) (apierror.ErrCode, int) {
	if distinguishable {
		for _, d := range distinguishableCauses {
			if errors.Is(err, d.cause) {
				return d.code, d.status
			}
		}
	}
	if m, ok := sealErrorStatus[seal.CodeOf(err)]; ok {
		return m.code, m.status
	}
	return apierror.CodeSealMaterialInvalid, http.StatusBadRequest
}

// SetAuthorizer uses the existing identity verifier for control-plane requests.
func (h *SealHandler) SetAuthorizer(mode string, authorize func(context.Context, string) (uint, error)) {
	h.mode = mode
	h.authorize = authorize
}
func (h *SealHandler) authorizeRequest(c *gin.Context) (uint, bool) {
	if h.authorize == nil {
		h.rejectAuthorization(c, apierror.CodeTokenInvalid)
		return 0, false
	}
	parts := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		h.rejectAuthorization(c, apierror.CodeTokenMissing)
		return 0, false
	}
	actor, err := h.authorize(c.Request.Context(), parts[1])
	if err != nil {
		h.rejectAuthorization(c, apierror.CodeTokenInvalid)
		return 0, false
	}
	return actor, true
}
func (h *SealHandler) Seal(c *gin.Context) {
	if h.unsealRelocated || !h.sourceAllowed(c) {
		apierror.Respond(c, http.StatusForbidden, apierror.CodeSealSourceNotAllowed, nil)
		return
	}
	actor, ok := h.authorizeRequest(c)
	if !ok {
		return
	}
	result, err := h.machine.Seal(c.Request.Context(), seal.SealRequest{Actor: actor, Mode: h.mode, SourceDigest: sourceDigest(h.sourceIP(c))})
	if err != nil {
		code, status := SealErrorResponse(err)
		apierror.Respond(c, status, code, nil)
		return
	}
	c.JSON(http.StatusOK, gin.H{"state": result.State, "generation": result.Generation})
}

// rejectAuthorization leaves a bounded-field log even when the business audit sink is sealed.
func (h *SealHandler) rejectAuthorization(c *gin.Context, code apierror.ErrCode) {
	log.Printf("[SealAudit] authorization rejected code=%s", code)
	middleware.AbortControlAuthentication(c, code)
}
