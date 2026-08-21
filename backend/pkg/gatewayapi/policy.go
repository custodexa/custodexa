package gatewayapi

import (
	"context"
	"time"
)

// Stage 判定發生的閘序位置。四值不可增刪而不同步 W10 的逐閘等價表。
//
// 為何要拆 RedeemTerminal／RedeemGraphical（R3.1 §4.1，坐實 R4-B F9）：兩個兌換入口
// 的閘集合本就不同——SSH 側有 `Protocol.IsTextTerminal`（sshproxy/handler.go:255）與
// K8s 單一預設帳號限制（:296），guacd 側有 `protocol == "ssh"` 拒（proxy/handler.go:196）。
// 單一 StageRedeem 表達不了這個差異。
type Stage string

const (
	// StageIssue connect-token 簽發點。
	StageIssue Stage = "issue"
	// StageRedeemTerminal SSH 兌換入口（HandleSSH）。
	StageRedeemTerminal Stage = "redeem_terminal"
	// StageRedeemGraphical guacd 兌換入口（HandleConnect）。
	StageRedeemGraphical Stage = "redeem_graphical"
	// StageData 資料面（SFTP 等）。
	StageData Stage = "data"
)

// ConnectSubject 連線主體。**全部欄位皆為 caller-asserted 的溯源脈絡**。
type ConnectSubject struct {
	UserID uint

	// ClaimedRole 呼叫端自陳的角色。
	//
	// **SHALL NOT 作為判定依據**——僅供溯源與顯示。判定一律以服務端現查為準，
	// 現查結果回填 `Decision.ResolvedRole`，審計亦只採信 ResolvedRole（D-11）。
	//
	// 為何是 SHALL NOT 而不是「盡量不要」：跨行程的 caller-asserted role 是提權面，
	// 直接撞專案紅線 CPG-010-01（internal/service/auth_service.go:945-950 明文
	// 「不得憑 JWT/token 攜帶的角色快照」判定）；且即使不用於判定，只要寫進審計就是
	// 稽核脈絡偽造面（S4 codex 採納項 #7）。欄位保留是為了讓「呼叫端聲稱的」與
	// 「服務端查到的」可以被比對出落差，不是為了讓它變成判定輸入。
	ClaimedRole string

	AuthMethod string
	ProviderID uint

	// AuthEpoch／CredEpoch 同 ClaimedRole 紀律：實作 SHALL 現查，caller 值僅溯源。
	AuthEpoch int
	CredEpoch int

	ClientIP string
}

// ConnectObjectRef 連線客體的**請求側**指涉：憑證解封之前就已知的部分。
type ConnectObjectRef struct {
	AssetID   uint
	AccountID uint
	Protocol  string
	Channel   string
}

// ResolvedConnectObject 憑證解封之後才完整的客體。
type ResolvedConnectObject struct {
	ConnectObjectRef

	// Username 已解析出的實際連線帳號名，**非請求參數**
	//（語義同 internal/service/account_scope_service.go:118 第 5 參數的註解自陳）。
	// 它是帳號範圍閘的輸入，而它要到憑證解封後才存在——這正是政策閘必須拆兩階段的原因。
	Username string
}

// RiskDetail 傳輸閘風險項。具名機器欄，不得退化為 map[string]string
// （對齊 model.TransmissionRisk 的形狀，但為值型、去 model 相依）。
type RiskDetail struct {
	Key   string
	Label string
}

// SessionLimits 會話層限制。
//
// **刻意不含 RecordingRequired**（D-6 未拍板，F16）：兌換側現況零強制，本 change 內
// 無生產者亦無消費者，寫進契約即固化未定案行為。拍板後另立行為修復 change 再加。
type SessionLimits struct {
	IdleTimeout time.Duration
	MaxDuration time.Duration
}

// Decision 一次判定的完整結果。欄位以具名機器欄承載，不塞 map
// （R4-B F10：現況前端 connect.js 依 Reason／Policy／risks 陣列分支彈框，
// 塞進 Hints 會讓契約無法表達現況行為）。
type Decision struct {
	Allowed        bool
	AdminExemption bool

	// Code apierror 機器碼；HTTP 狀態由邊界 adapter 對映，判定層不吃 net/http 語義。
	//
	// **同一失敗在不同 Stage 回不同碼是刻意的防探測設計，不是不一致**（D-9）：
	// 簽發側對「帳號不在授權範圍」回 404 CodeAssetAccountNotFound
	//（internal/sshproxy/handler.go:1118,1130，註解自陳分流回應會使端點成為
	// 帳號存在性探測器），兌換側回 403 CodeAssetConnectDenied（:309、
	// internal/proxy/handler.go:225）。將來看到此不對稱時 SHALL NOT 逕行「修掉」。
	Code   string
	Params map[string]string

	// Reason／Policy 為機器欄（非顯示字串），供呼叫端分支。
	Reason string
	Policy string

	Risks []RiskDetail

	// MaxDurationMinutes 攔截時的容許時長（語義為攔截值，非放行限制）。
	MaxDurationMinutes int

	// PendingRequestID 在途申請 ID；無在途申請時為 nil（值型 uint 無法辨 NULL/0）。
	PendingRequestID *uint

	Limits SessionLimits

	// ResolvedRole 本次判定實際採用的（服務端現查）角色。
	// **審計唯一可信的角色來源**——不得改用 ConnectSubject.ClaimedRole（D-11）。
	ResolvedRole string

	Hints map[string]string
}

// Denial 一次判定為「拒絕」時的完整結果：判定本體＋**邊界對映**。
//
// # 為何回傳型別是 *Denial 而非 (Decision, error)（W10.2 接線時訂正 R3.1 §4.1）
//
// 三處入口的判定結果一律要能寫成一則 HTTP 回應，而 Decision 表達不了其中三件事：
//
//	(1) HTTP 狀態碼——同一個機器碼在不同閘回不同狀態（存取政策閘的 403／428 由
//	    政策判定給出，見 access-policy-approval D4），無法由碼反推；
//	(2) 回應機器欄的**平鋪形狀**——前端 connect.js 依 `risks`／`reason`／`policy`
//	    等 top-level 欄分支，`Decision.Params map[string]string` 承載不了 `risks` 陣列；
//	(3)「內部故障」分支——須以 RespondInternal 寫出（伺服端記原始成因、對外只回碼），
//	    與「判定為拒」是兩種處置，(Decision, error) 的 error 位無法同時表達
//	    「這是拒絕、且拒絕理由是內部故障」。
//
// Decision 本體維持不吃 net/http 語義（見 Decision.Code）：狀態碼與平鋪機器欄
// 由本型別在邊界側承載，判定層只填 Decision。
//
// **nil 代表通過**；非 nil 即拒絕，故 Decision.Allowed 恆為 false。
type Denial struct {
	// Gate 拒絕者的閘編號（同行程實作填入；跨行程實作可留空）。
	// 供 failure-injection 測試斷言「是哪一道閘拒的」——只驗碼不足以區分兩道回同一個碼的閘。
	Gate string

	Decision Decision

	// Status HTTP 狀態碼。
	Status int

	// Meta 回應機器欄（邊界 adapter 會平鋪回封套 top-level）；無則為 nil。
	Meta map[string]any

	// Internal 非 nil 時，呼叫端 SHALL 以「伺服端記原始成因、對外只回碼」的方式寫出，
	// 而非一般回應。
	Internal error
}

// PolicyGate 政策閘。**兩階段契約**（S4 codex 採納項 #5，訂正 R3.1 §4.1 的單一 Authorize）。
//
// # 為何非拆兩階段不可
//
// 帳號範圍閘吃的是 `ResolvedConnectObject.Username`＝「已解析出的實際連線帳號名」，
// 它憑證解封後才存在；而其餘閘（政策段位、資產 Active、協議適配、授權查詢、票證與破窗）
// 在解封前就該擋下。單一 Authorize 只有兩條出路，兩條都不可接受：
//
//	(a) 讓 policy 自行解封憑證 → 破「憑證唯一產生地」的連線收口紅線；
//	(b) 丟掉吃 Username 的帳號範圍閘 → 拆閘，防線淨減少。
//
// # 呼叫骨架（W10 收斂的形狀）
//
// 每個入口固定跑「AuthorizePreResolve → 憑證解封 → AuthorizeResolvedAccount」三段，
// 三處入口的差異只由 Stage 表達。守衛據此收緊：解封出口只允許出現在兩階段之間的
// 那個固定位置，其餘位置一律紅。
//
// 附帶收益：跨行程消費者只需做純政策判定，永遠不碰憑證。
type PolicyGate interface {
	// AuthorizePreResolve 憑證解封／帳號身分解析「之前」可判定的閘。
	//
	// **本階段刻意不吃客體**（W10.2 接線時訂正 R3.1 §4.1 的
	// `AuthorizePreResolve(ctx, s, o ConnectObjectRef, stage)`）：簽發入口的客體
	// （asset_id／account_id）是由**本階段之內**的請求解析閘產生的
	// （`internal/sshproxy/connect_gates.go` G-I3 `ShouldBindJSON`，位於 G-I2
	// 角色現查之後）。要把它入參化就得把請求解析前移到閘序之前——那會改變閘序，
	// 使「壞 JSON ＋ 已停用使用者」的回應由認證類碼翻轉為 400，是行為變更。
	// 客體在本階段仍為判定輸入，只是由實作於閘內取得，不由契約規定取得時機。
	//
	// 回傳 nil 代表通過。
	AuthorizePreResolve(ctx context.Context, s ConnectSubject, stage Stage) *Denial

	// AuthorizeResolvedAccount 憑證解封／帳號身分解析「之後」才可判定的閘：
	// 帳號範圍（吃 Username）、零帳號 fail-close、K8s 單一預設帳號限制。
	//
	// 客體於本階段已解析完成，故以 ResolvedConnectObject 入參。回傳 nil 代表通過。
	AuthorizeResolvedAccount(ctx context.Context, s ConnectSubject, o ResolvedConnectObject, stage Stage) *Denial
}
