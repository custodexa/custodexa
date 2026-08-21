// Package connectgate 是 connect-token 三處入口的**兩階段閘序骨架**
// （modular-architecture W10，design.md D-C 訂正後的形狀）。
//
// # 契約
//
// 每個入口固定跑三段：
//
//	AuthorizePreResolve(stage, …)  →  憑證解封／帳號身分解析  →  AuthorizeResolvedAccount(stage, …)
//
// 三處入口（簽發／SSH 兌換／guacd 兌換）的差異只由 `Stage` 與各自宣告的閘序表達，
// 骨架本身逐字相同。閘序＝有序的 []Gate，由各入口的守衛測試逐位比對
// ——**閘序自此是可被機器檢查的資料，不再是散落在 handler 裡的一串 if**。
//
// # 閘編號（G-I* ／ G-S* ／ G-G*）
//
// 編號沒有另一份字典，**定義就在宣告閘序與矩陣的程式碼裡**：
//
//	G-I*  簽發側      internal/sshproxy/connect_gates.go
//	                  （issuePreResolveGates／issueResolvedAccountGates）
//	G-S*  SSH 兌換側   internal/sshproxy/connect_gates.go
//	                  （redeemPreResolveGates／redeemResolvedAccountGates）
//	G-G*  圖形兌換側   internal/proxy/connect_gates.go
//	                  （redeemPreResolveGates／redeemResolvedAccountGates）
//
// 每個 `{Name: "G-…", Eval: …}` 之後緊接該閘的實作與「為何是這一道」的註解，
// 那就是該編號的權威定義；每個閘序建構函式的前導註解另標出該段涵蓋的編號區間。
//
// **編號在閘序中不連續是正常的**（如 G-I8 之後接 G-I10）：它們是穩定識別碼而非
// 連續序號，且並非每一個編號都由本骨架承擔。完整編號集合與「哪些刻意不涵蓋、
// 為什麼」逐條登記在 `internal/sshproxy/w10_characterization_matrix_test.go` 與
// `internal/proxy/w10_characterization_matrix_test.go` 的 `TestW10MatrixCoverageIsDeclared`
// ——該測試對「少一道閘」與「多一道閘」兩個方向都會紅，是這套編號的機器可檢登記表。
//
// 閘序骨架與兩階段語義的規範來源為 `openspec/specs/gateway-interfaces/spec.md`
// 的「政策閘兩階段判定契約」與 `openspec/specs/connection-gating/spec.md` 的「簽發閘序」。
//
// # 為何拆兩階段（不可退回單一 Authorize）
//
// 帳號範圍閘吃的是「已解析出的實際連線帳號名」，它憑證解封後才存在，故必然屬於後階段；
// **其餘閘的歸屬依各入口的現況位置而定，不依閘的種類**（兌換側的資產 Active／協議適配／
// 授權查詢／存取政策現況都在解封之後——它們吃的是解封當下那一份資產列，前移會多讀一次
// 資產並製造新的 TOCTOU 窗口；見 design.md D-C 訂正 2 與等價表 K-1）。
// 單一 Authorize 只有兩條出路，兩條都不可接受：(a) 讓判定層自行解封憑證，
// 破「憑證唯一產生地」的連線收口紅線；(b) 丟掉吃 Username 的帳號範圍閘＝拆閘。
//
// # 與 pkg/gatewayapi.PolicyGate 的關係（誠實邊界）
//
// `Sequence` **是** `gatewayapi.PolicyGate` 的同行程實作（W10.2 接線，`var _` 釘住）。
// 契約參數（主體、已解析客體）是閘的真實輸入，逐處讀取點見 `Sequence` 註解；
// 其餘 per-request 脈絡（資產列、已解封憑證、gin 請求脈絡、審計標記合併）仍以閉包捕獲
// ——**這是同行程 orchestration 的本質，不是待補的缺口**：兌換側的解封後閘吃的是
// 解封當下那一份資產列，把它塞進契約參數就得在判定層重讀一次資產，那是額外的 DB 讀取
// 與新的 TOCTOU 窗口（design.md D-C 訂正 2、等價表 K-1）。
//
// 因此可以誠實宣稱的是：**兩階段閘序骨架可以以 PolicyGate 的形狀被消費**。
// 不可宣稱的是「跨行程消費者已可直接接上」——那還需要把上述脈絡也搬進契約，
// 屬另一波工作。
//
// # 副作用留在閘內
//
// 閘以閉包形式宣告，審計標記合併（admin 豁免）、失效事件回報、log 一律**留在原處**，
// 由閉包捕獲 handler 的 gin.Context。本包不碰 gin、不寫回應——回應由呼叫端依
// Outcome 寫出，故「先寫審計再拒」與「先拒再寫審計」的次序在收斂前後逐字不變。
package connectgate

import (
	"context"

	"github.com/custodexa/backend/pkg/gatewayapi"
)

// Stage 判定發生的閘序位置，直接沿用 gatewayapi 的四值（不另立一套）。
type Stage = gatewayapi.Stage

// Outcome 一道閘的拒絕結果＋邊界對映，**即 `gatewayapi.Denial`**（型別別名）。
//
// W10.2 接線前本包自持一份同形結構；接線時上移為契約型別，因為 PolicyGate 的
// 回傳型別非它不可（Decision 表達不了狀態碼、平鋪機器欄與內部故障分支，
// 理由逐條見 `gatewayapi.Denial` 的註解）。別名而非重新宣告，是為了讓
// `internal/proxy`／`internal/sshproxy` 既有的兩百餘處 `*connectgate.Outcome`
// 逐字不動——這波是結構接線，不是閘內容變更。
//
// **回傳 nil 代表本閘通過**；非 nil 即拒絕，故 Decision.Allowed 恆為 false。
type Outcome = gatewayapi.Denial

// Gate 一道閘：Eval 回傳 nil 代表通過。
//
// **不得在 Eval 之外做判定**——閘序的唯一事實來源是 []Gate 的順序，
// 在骨架外多加一個 if 會讓守衛測試看不到它。
type Gate struct {
	// Name 閘編號，對應等價表 §1。
	Name string
	Eval func() *Outcome
}

// PreResolveGates 依主體造出「解封之前」的閘序。
type PreResolveGates func(s gatewayapi.ConnectSubject) []Gate

// ResolvedAccountGates 依主體與已解析客體造出「解封之後」的閘序。
type ResolvedAccountGates func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []Gate

// Sequence 一次連線判定的兩階段閘序繫結，是 `gatewayapi.PolicyGate` 的**同行程實作**。
//
// # 為何是「繫結」而不是無狀態服務
//
// 閘的輸入遠多於契約參數所能承載：資產列、已解封憑證、gin 請求脈絡、審計標記合併。
// 同行程實作把這些以閉包捕獲，契約參數（主體、已解析客體）則**真的被閘讀取**
// ——現況讀取點：
//
//	s.UserID                       G-I2／G-S3／G-S9／G-S13／G-G4
//	s.AuthMethod／ProviderID／AuthEpoch／CredEpoch   G-S4／G-G5（憑證世代複查）
//	o.AssetID                      G-S9／G-S13
//	o.AccountID（選擇器，0＝預設）    G-S12
//	o.Username                     G-I10／G-S13（帳號授權範圍閘）
//
// 跨行程實作要把其餘脈絡也塞進契約參數才成立——那是 backlog，不是本波。
// 本型別的存在證明的是：**兩階段閘序骨架確實可以以 PolicyGate 的形狀被消費**。
type Sequence struct {
	pre  PreResolveGates
	post ResolvedAccountGates
}

var _ gatewayapi.PolicyGate = (*Sequence)(nil)

// NewSequence 繫結一次判定的兩階段閘序。任一階段可傳 nil（該階段視為零閘、恆通過）。
func NewSequence(pre PreResolveGates, post ResolvedAccountGates) *Sequence {
	return &Sequence{pre: pre, post: post}
}

// AuthorizePreResolve 憑證解封／帳號身分解析「之前」的閘序（各 Stage 涵蓋哪些閘
// 見 design.md D-C 的介面註解，簽發側與兌換側不同）。
//
// 逐一評估，第一個非 nil 即回傳並停止——**短路語義是契約的一部分**：
// 後面的閘不得被執行，否則會產生現況沒有的副作用（多餘的 DB 讀、多餘的審計列）。
//
// ctx 未被使用：閘各自捕獲自己的脈絡（例如兩道 authz 閘共用的 authzCtx）。
// **刻意保留參數**而不改契約——同 `gatewayapi.AsyncSink.Submit` 的既定紀律，
// 跨行程實作必然需要 ctx。
func (s *Sequence) AuthorizePreResolve(_ context.Context,
	sub gatewayapi.ConnectSubject, stage Stage) *Outcome {
	if s == nil || s.pre == nil {
		return nil
	}
	return run(stage, s.pre(sub))
}

// AuthorizeResolvedAccount 憑證解封／帳號身分解析「之後」的閘序。
// **下界**（必然屬於本階段者）＝所有吃 Username／creds 的閘：帳號範圍、零帳號 fail-close、
// K8s 單一預設帳號；兌換側另有依現況位置歸屬於此的資產 Active／協議／授權／政策等閘。
//
// ctx 未被使用，理由同 AuthorizePreResolve。
func (s *Sequence) AuthorizeResolvedAccount(_ context.Context,
	sub gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject, stage Stage) *Outcome {
	if s == nil || s.post == nil {
		return nil
	}
	return run(stage, s.post(sub, o))
}

func run(stage Stage, gates []Gate) *Outcome {
	for _, g := range gates {
		if g.Eval == nil {
			continue
		}
		if out := g.Eval(); out != nil {
			if out.Gate == "" {
				out.Gate = g.Name
			}
			out.Decision.Allowed = false
			return out
		}
	}
	// stage 目前**不參與判定**：它是敘述性參數（標示判定發生在哪個入口，供審計與
	// 將來的跨行程消費者分流），不是機器約束——本骨架不會因為某道閘「登記在別的
	// Stage」而拒絕執行它。**唯一被機器強制的不變式是解封位置**（夾在兩次呼叫之間，
	// 由 cmd/server 的 AST 守衛與執行期零解密測試釘住）。
	// 要讓 Stage 真的產生約束需一份 Stage→閘 登記表＋執行期比對：backlog B-44。
	// 在那之前，文件與 round-log SHALL NOT 把 Stage 的歸屬寫成「保證」。
	_ = stage
	return nil
}

// Deny 造一個拒絕結果。
func Deny(status int, code string, meta map[string]any) *Outcome {
	return &Outcome{
		Decision: gatewayapi.Decision{Code: code},
		Status:   status,
		Meta:     meta,
	}
}

// DenyInternal 造一個「內部故障」拒絕：呼叫端以 RespondInternal 寫出。
func DenyInternal(status int, code string, cause error) *Outcome {
	return &Outcome{
		Decision: gatewayapi.Decision{Code: code},
		Status:   status,
		Internal: cause,
	}
}

// Names 取閘序的名稱清單，供守衛測試與等價表逐位比對。
func Names(gates []Gate) []string {
	names := make([]string, 0, len(gates))
	for _, g := range gates {
		names = append(names, g.Name)
	}
	return names
}
