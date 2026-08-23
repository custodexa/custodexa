package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 兩階段閘序宣告（圖形側）
//
// 骨架與文字側（internal/sshproxy/connect_gates.go）逐字相同：`AuthorizePreResolve → 憑證解封 → AuthorizeResolvedAccount`，差異只由 Stage 與各自宣告的閘序表達。
// 閘編號（G-G*）的定義即本檔的閘序表——每個 `{Name: "G-…"}` 之後緊接該閘的實作與理由；完整登記表（含刻意不涵蓋者與其逐條理由）見 `characterization_matrix_test.go` 的 `TestGuacMatrixCoverageIsDeclared`。
//
// **判定邏輯、拒絕碼與副作用次序逐字未改**——每個 Eval 的內容即原 HandleConnect
// 對應段落的程式碼（含 log 前綴）。

// graphicsRedeemState 圖形兌換側閘序的共享中間狀態
type graphicsRedeemState struct {
	grant       ConnectGrant
	currentRole string
	authzCtx    context.Context
	creds       *asset.AssetCredentials
}

// contractSubject／contractObject 由兌換側狀態造出 `gatewayapi.PolicyGate` 的契約入參。
//
// **單一事實源**：HandleConnect 與閘序守衛測試共用同一份構造。兩處各造一份，
// 守衛驗的就會是另一組輸入，閘序等價的證明當場失效。
//
// ClaimedRole 留空是實質：grant 刻意不攜帶角色，兌換側角色一律由 G-G4 現查。
func (st *graphicsRedeemState) contractSubject(clientIP string) gatewayapi.ConnectSubject {
	return gatewayapi.ConnectSubject{
		UserID:     st.grant.UserID,
		AuthMethod: st.grant.AuthMethod,
		ProviderID: st.grant.ProviderID,
		AuthEpoch:  st.grant.AuthEpoch,
		CredEpoch:  st.grant.CredEpoch,
		ClientIP:   clientIP,
	}
}

// contractObject 已解析客體：AccountID 維持 grant 帶的**選擇器**值（0＝預設帳號），
// Username 為解封後實際會用的帳號名——後者是帳號範圍閘（G-G12）的判定對象。
func (st *graphicsRedeemState) contractObject() gatewayapi.ResolvedConnectObject {
	o := gatewayapi.ResolvedConnectObject{
		ConnectObjectRef: gatewayapi.ConnectObjectRef{
			AssetID:   st.grant.AssetID,
			AccountID: st.grant.AccountID,
		},
	}
	if st.creds != nil {
		o.Protocol = string(st.creds.Asset.Protocol)
		o.Username = st.creds.Username
	}
	return o
}

// redeemPreResolveGates 圖形兌換側「憑證解封之前」的閘序（G-G4…G-G5）。
// s＝票證所帶的主體脈絡（`gatewayapi.PolicyGate` 的契約入參），值逐欄取自 grant
func (h *ConnectionHandler) redeemPreResolveGates(
	s gatewayapi.ConnectSubject, st *graphicsRedeemState) []connectgate.Gate {
	return []connectgate.Gate{
		{Name: "G-G4", Eval: func() *connectgate.Outcome {
			// AUTH-1＋角色現況：connect_token 消費時重載
			// 用戶狀態並取 DB 現查有效角色（停用/鎖定/降權前簽發者於殘窗內須擋）
			currentRole, connErr := h.AuthService.CurrentConnectRole(s.UserID)
			if connErr != nil {
				status, code := connectionAuthCode(connErr)
				return connectgate.Deny(status, string(code), nil)
			}
			st.currentRole = currentRole
			return nil
		}},
		{Name: "G-G5", Eval: func() *connectgate.Outcome {
			// 憑證世代複查（1.9）：簽發後、兌換前若 provider 被停用或使用者世代被推進，
			// 這張一次性 token 必須失效。角色現查擋不到這一類——帳號可能仍啟用、角色未變，
			// 但其外部身分已被解綁或該 provider 已停用
			if genErr := h.AuthService.VerifyCredentialGenerationByUserID(crypto.AuthContext{
				AuthMethod: s.AuthMethod, ProviderID: s.ProviderID,
				AuthEpoch: s.AuthEpoch, CredEpoch: s.CredEpoch,
			}, s.UserID); genErr != nil {
				return connectgate.Deny(http.StatusUnauthorized,
					string(apierror.CodeConnectTokenInvalid), nil)
			}
			return nil
		}},
	}
}

// redeemResolvedAccountGates 圖形兌換側「憑證解封之後」的閘序（G-G7…G-G12）。
// s／o＝`gatewayapi.PolicyGate` 的契約入參；o.Username 是解封後實際會用的帳號名，
// 也就是帳號範圍閘（G-G12）的判定對象
func (h *ConnectionHandler) redeemResolvedAccountGates(
	s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject,
	st *graphicsRedeemState) []connectgate.Gate {
	return []connectgate.Gate{
		{Name: "G-G7", Eval: func() *connectgate.Outcome {
			// 停用硬擋兌換點重查（與 AUTH-1 對稱的 assetRow 側）：token 於資產停用前
			// 簽發者，殘窗（60s TTL）內兌換須擋；語義同簽發點（403+asset_disabled）
			if !st.creds.Asset.Active {
				return connectgate.Deny(http.StatusForbidden, string(apierror.CodeAssetDisabled),
					map[string]any{"reason": "asset_disabled"})
			}
			return nil
		}},
		{Name: "G-G8", Eval: func() *connectgate.Outcome {
			// 兌換點授權與政策重查（與簽發點對稱）：簽發後、兌換前遭撤銷之
			// 連線授權/ticket/存取政策/角色於此即時生效——撤權殘窗（原 60s TTL）歸零。
			// role 用 DB 現查 currentRole，不憑角色快照授予 admin 特權
			hasPerm, aerr := h.AuthorizationService.CheckPermission(
				st.authzCtx, s.UserID, o.AssetID, model.PermissionConnect)
			if aerr != nil {
				log.Printf("[Handler] 兌換點權限檢查失敗: userID=%d assetID=%d err=%v",
					s.UserID, o.AssetID, aerr)
				return connectgate.DenyInternal(http.StatusInternalServerError,
					string(apierror.CodeInternalPermissionCheck), aerr)
			}
			if !hasPerm {
				return connectgate.Deny(http.StatusForbidden,
					string(apierror.CodeAssetConnectDenied), nil)
			}
			return nil
		}},
		{Name: "G-G9", Eval: func() *connectgate.Outcome {
			if h.AccessPolicy == nil {
				return nil
			}
			decision, derr := h.AccessPolicy.CheckConnect(s.UserID, st.currentRole, st.creds.Asset)
			if derr != nil {
				log.Printf("[Handler] 兌換點政策閘判定失敗: userID=%d assetID=%d err=%v",
					s.UserID, o.AssetID, derr)
				return connectgate.DenyInternal(http.StatusInternalServerError,
					string(apierror.CodeInternalAccessPolicyCheck), derr)
			}
			if !decision.Allowed {
				// reason/policy 是前端 connect.js 的控制流機器欄，經 Meta 平鋪回
				// 封套 top-level，欄位名與值不變；散文降為碼的 ZhFallback
				code := apierror.CodeAccessApprovalRequired
				if decision.Reason == policy.AccessGateReasonRequired {
					code = apierror.CodeAccessReasonRequired
				}
				return connectgate.Deny(decision.Status, string(code),
					map[string]any{"reason": decision.Reason, "policy": decision.Policy})
			}
			return nil
		}},
		{Name: "G-G10", Eval: func() *connectgate.Outcome {
			// SSH 已退出 guacd 圖像串流路徑：
			// 原生文字流走 GET /api/v1/ssh（xterm.js 直連）
			if o.Protocol == "ssh" {
				log.Println("[Handler] 拒絕 guacd SSH 連線請求：請改用 /api/v1/ssh")
				return connectgate.Deny(http.StatusBadRequest,
					string(apierror.CodeSSHEndpointMoved), nil)
			}
			return nil
		}},
		{Name: "G-G11", Eval: func() *connectgate.Outcome {
			// 零帳號資產 fail-close：空 username＋空密碼交給 guacd 會變成
			// 對 RDP／VNC 等目標的匿名或免密嘗試——受管連線的前提是有受管憑證。
			// 置於停用／授權／政策閘之後：那些閘的回應語義是既有契約，順序不動
			if st.creds.AccountID == 0 {
				log.Printf("[Handler] 資產無可用帳號憑證，拒絕連線: assetID=%d", o.AssetID)
				return connectgate.Deny(http.StatusNotFound,
					string(apierror.CodeAccountNoneUsable), nil)
			}
			return nil
		}},
		{Name: "G-G12", Eval: func() *connectgate.Outcome {
			// 帳號授權範圍兌換複查（強制點 2／3，圖形側）：
			// 與 SSH 兌換點同語義——判定 creds 實際解析出的帳號（grant.AccountID=0＝預設），
			// 簽發後帳號被移出授權範圍者在此即時拒絕，不因 token 未過期而放行。
			//
			// **必須排在零帳號 fail-close 之後**：零帳號資產的
			// `creds.Username == ""`，在具名授權範圍下 `Allows("")` 為 false，範圍複查若在前
			// 會搶先回 403「無連線權限」——同一個「這台沒設帳號」的狀態，SSH 側回
			// 404 RULE_ACCOUNT_NONE_USABLE、圖形側卻回 403，管理員會照著訊息去查權限而非補帳號。
			// 順序與 sshproxy/handler.go 對齊（政策閘 → 零帳號 → 範圍複查），
			// 且不動政策閘既有的回應契約
			if aerr := h.AuthorizationService.AuthorizeConnectAccount(
				st.authzCtx, s.UserID, o.AssetID,
				model.ProtocolType(o.Protocol), o.Username); aerr != nil {
				if errors.Is(aerr, authz.ErrAccountNotAuthorized) {
					log.Printf("[Handler] 帳號已移出授權範圍，拒絕建線: userID=%d assetID=%d accountID=%d",
						s.UserID, o.AssetID, st.creds.AccountID)
					return connectgate.Deny(http.StatusForbidden,
						string(apierror.CodeAssetConnectDenied), nil)
				}
				log.Printf("[Handler] 兌換點帳號授權判定失敗: userID=%d assetID=%d err=%v",
					s.UserID, o.AssetID, aerr)
				return connectgate.DenyInternal(http.StatusInternalServerError,
					string(apierror.CodeInternalPermissionCheck), aerr)
			}
			return nil
		}},
	}
}

// writeOutcome 把閘序判定結果寫成 HTTP 回應（語義與 sshproxy 側同源），
// 並為該次拒絕留痕。
//
// **回應與留痕綁在同一個出口**是刻意的：閘序表往後只會增列，若留痕散在各閘的
// Eval 裡，新增一道閘忘了寫審計不會有任何東西轉紅——那正是本 change 要根除的模式。
// st 提供主體與客體（票證所帶的 userID／assetID）；閘序尚未跑到時 st.grant 為零值，
// 留痕仍成立（來源位址與拒絕原因才是這類事件的主要證據）。
func (h *ConnectionHandler) writeOutcome(c *gin.Context, out *connectgate.Outcome, st *graphicsRedeemState) {
	code := apierror.ErrCode(out.Decision.Code)
	h.auditConnectDenied(c, ConnectDenial{
		UserID: st.grant.UserID, AssetID: st.grant.AssetID,
		Reason: string(code), HTTPStatus: out.Status,
	})
	if out.Internal != nil {
		apierror.RespondInternal(c, out.Status, code, out.Internal)
		return
	}
	apierror.Write(c, out.Status, apierror.ErrorResponse{Code: code, Meta: out.Meta})
}

// ConnectDenial 兌換拒絕的審計輸入。
//
// **匯出是實質**：文字側（`GET /api/v1/ssh`，`internal/sshproxy`）與圖形側
// （`GET /api/v1/connect`）共用下方唯一的寫入實作。
// 兩包各寫一份的話，欄位集會各自演化——「某一側少填來源位址」不會讓任何測試轉紅，
// 而 spec 的「兌換拒絕留痕」本來就沒有端點限定。
type ConnectDenial struct {
	UserID uint
	// AssetID 票證指向的資產；票證本身不成立時為 0（寫入 NULL）
	AssetID uint
	// Reason 拒絕原因的機器碼：票證類為 `ticket_missing`／`ticket_invalid`／
	// `ticket_expired`，閘序類為該閘的 apierror 碼（協議不符即 SSH_ENDPOINT_MOVED）
	Reason     string
	HTTPStatus int
	// Via 兌換入口（`ViaConnect`／`ViaSSH`）：兩條入口的拒絕列在同一張表裡，
	// 沒有這個欄位就分不出「有人在探測圖形入口」與「有人在探測終端入口」
	Via string
}

// 兌換入口標記（`details.via`）。兩側各寫字面量就會出現 `ssh` 與 `SSH` 這種
// 分家，稽核的分組查詢當場漏一半。
const (
	ViaConnect = "connect"
	ViaSSH     = "ssh"
)

// viaUnknown 呼叫端漏填 Via 時的落地值。**不留空**：空字串在 details 裡與
// 「這個欄位還不存在」無從分辨，而具名的 unknown 至少讓漏填看得出來
const viaUnknown = "unknown"

// AuditConnectDenied 為連線票證兌換拒絕寫審計列（connection-gating spec）。
//
// **兩條兌換入口的唯一寫入點**：`GET /api/v1/connect`（圖形）與 `GET /api/v1/ssh`
// （文字）都經此。svc 為 nil 時記 log 不靜默——這兩條路由都沒有中介層兜底。
//
// # 缺口形狀
//
// 拒絕路徑原本純 HTTP 回應、零留痕，使「反覆嘗試兌換偽造票證」這類探測在稽核上
// 完全不可見——與「沒有人試過」不可分辨。中介層在此路徑亦幫不上忙：兌換失敗時
// `userID` 從未寫進 gin context，`AuditLogMiddleware` 整筆跳過。
//
// # status 的分流規則
//
// 依 HTTP 狀態機械分流，不逐案判斷：
//
//	401 → StatusFailure：憑證本身不成立（票不存在／已用過／過期／憑證世代已失效）。
//	其餘 → StatusDenied：身分成立但不准（資產停用、無連線權限、存取政策、
//	       協議不符、帳號已移出授權範圍）。
//
// 機械規則的價值在於新增閘時不需要有人再判一次；逐案判斷遲早會出現兩道語義相同
// 的閘拿到不同狀態值，而稽核報表就此無法解釋。
//
// # AssetID 填實
//
// 「有人試圖連這台機器但被擋下」必須出現在資產樞紐上——資產樞紐只讀 asset_id，
// 不填即該事實在資產視角消失（同 AP-66 的論證）。票證不成立時無從得知目標資產，
// 該情形寫 NULL 而非 0：0 會被讀成「編號 0 的資產」。
func AuditConnectDenied(svc *audit.AuditLogService, c *gin.Context, ev ConnectDenial) {
	if svc == nil {
		// 這兩條路由都沒有中介層兜底，審計服務缺席即回到零留痕的缺陷態，不得靜默
		log.Printf("[Handler] 審計服務未注入，%s 的兌換拒絕未留痕（reason=%s）",
			c.Request.URL.Path, ev.Reason)
		return
	}
	status := model.StatusDenied
	if ev.HTTPStatus == http.StatusUnauthorized {
		status = model.StatusFailure
	}
	var assetID *uint
	if ev.AssetID != 0 {
		id := ev.AssetID
		assetID = &id
	}
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	via := ev.Via
	if via == "" {
		log.Printf("[Handler] 兌換拒絕留痕未標記入口：%s（reason=%s）",
			c.Request.URL.Path, ev.Reason)
		via = viaUnknown
	}
	svc.Log(&audit.AuditLogEntry{
		UserID:     ev.UserID,
		Username:   ev.username(c),
		Action:     model.ActionCreate,
		Resource:   model.ResourceSession,
		AssetID:    assetID,
		Status:     status,
		Method:     c.Request.Method,
		Path:       path,
		ClientIP:   sourceip.Of(c),
		StatusCode: ev.HTTPStatus,
		RequestID:  c.GetString("request_id"),
		ErrorMsg:   ev.Reason,
		Details: fmt.Sprintf(`{"asset_id":%d,"reason":%q,"via":%q}`,
			ev.AssetID, ev.Reason, via),
	})
}

// auditConnectDenied 圖形側的薄包裝：把 `Via` 釘死在 `ViaConnect`。
// 讓入口標記由包裝決定而非逐呼叫點填寫——三個呼叫點各填一次字串，遲早有一個填錯
func (h *ConnectionHandler) auditConnectDenied(c *gin.Context, ev ConnectDenial) {
	ev.Via = ViaConnect
	AuditConnectDenied(h.AuditService, c, ev)
}

// username 兌換點的使用者名稱：grant 不攜帶 username（刻意的最小快照），
// 中介層亦未跑，故僅在有身分脈絡時取得；取不到留空由 user_id 承擔歸屬
func (ev ConnectDenial) username(c *gin.Context) string {
	if v, ok := c.Get("username"); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
