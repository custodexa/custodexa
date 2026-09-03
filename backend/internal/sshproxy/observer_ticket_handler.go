package sshproxy

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 唯讀觀看的兩條 WebSocket 入口一律以一次性觀看票認證，與終端連線同一形態：
// 掛認證中介層的簽發端點做完全部准入判定，WS 端只兌換即焚的票。
//
// **為何 WS 端不再收 session JWT**：query 參數會逐字進入前端可及的 URL、
// 瀏覽器歷程與各層存取日誌，而 session JWT 的壽命以分鐘計、射程是整個 API。
// 一次性票的壽命以秒計、只能開這一條連線、用過即失效，外洩的代價不可同日而語。
// 這也讓「認證中介層不得自 query 收 JWT」這條規則在 WebSocket 路徑上不再有例外。

// HandleCreateMonitorTicket 處理 POST /api/v1/sessions/:id/monitor-token：
// 簽發即時監看用的一次性觀看票。
//
// 准入判定全部在此完成（角色、目標會話存在且為進行中的文字終端），
// WS 端不重複判定——判定散在兩處就會分化，而分化的那一側沒有任何測試會轉紅。
//
// **角色現查而非採信 JWT 快照**：與連線閘序同一條紀律（降權即時生效）。
// 原先的判定讀的是 token 內的角色快照，其壽命以分鐘計。該現查**寫成閘序宣告**
// （`connect_gates.go` 的 G-M1）而非此處的 if：判定散在 handler 裡就不進等價表，
// 閘序守衛也看不到它。
func (h *Handler) HandleCreateMonitorTicket(c *gin.Context) {
	userID, claimedRole, ok := h.authenticate(c)
	if !ok {
		return
	}

	// 主體：ClaimedRole＝呼叫端自陳的角色（JWT 快照），僅供溯源，
	// SHALL NOT 作判定依據——閘序用的角色一律是 G-M1 現查後寫進 st.role 的那一份
	st := &observerIssueState{}
	var gate gatewayapi.PolicyGate = connectgate.NewSequence(
		func(s gatewayapi.ConnectSubject) []connectgate.Gate {
			return h.monitorTicketPreResolveGates(s, st)
		}, nil)
	subj := gatewayapi.ConnectSubject{
		UserID: userID, ClaimedRole: claimedRole, ClientIP: sourceip.Of(c),
	}
	if out := gate.AuthorizePreResolve(c.Request.Context(), subj,
		gatewayapi.StageIssue); out != nil {
		h.writeOutcome(c, out)
		return
	}

	sessionID, parsed := parseMonitorSessionID(c)
	if !parsed {
		return
	}
	sess, err := h.SessionService.GetByID(sessionID)
	if err != nil {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeSessionNotFound, nil)
		return
	}
	if !sess.Protocol.IsTextTerminal() || sess.Status != model.SessionStatusActive {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeSessionMonitorNotActive, nil)
		return
	}

	h.issueObserverTicket(c, proxy.ObserverGrant{
		UserID: userID, Purpose: proxy.ObserverPurposeMonitor, SessionID: sessionID,
	})
}

// HandleCreateShareTicket 處理 POST /api/v1/sessions/share/token：
// 簽發分享觀看用的一次性觀看票。任何已登入者皆可取得，票綁定該碼與該人。
//
// **分享碼走請求本體而非路徑**：本端點掛認證與審計中介層，而中介層以原始路徑
// 寫入審計列——碼放在路徑上就會逐字落進長期保存的審計表，且該表受檢查點鏈保護、
// 寫進去刪不掉。請求本體的欄位走白名單遮蔽（非白名單欄一律遮成固定字串），
// 故碼不會留下。加入端的路徑以路由樣板寫入，同樣不含碼。
//
// **分享碼的有效性刻意不在此判定**，一律留給加入端（`HandleShareJoin`）：
//
//   - 留痕形狀不變。碼無效的拒絕列是「反覆試碼」這個猜測攻擊訊號的唯一證據，
//     它由 `auditObserverJoin` 以 `status=denied` 寫在加入路徑上。本端點掛認證
//     中介層，在此再寫一列會讓同一次嘗試變成兩列——稽核報表的「被擋下幾次」翻倍。
//   - 判定本來就得在加入端做一次（簽票與加入之間分享可能被撤銷），
//     兩處各判一次只是多一份會分化的判定。
//
// 對外回應維持 404、不洩漏碼的存在性：拒絕面在加入端，與改動前逐字相同。
func (h *Handler) HandleCreateShareTicket(c *gin.Context) {
	userID, _, ok := h.authenticate(c)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}

	h.issueObserverTicket(c, proxy.ObserverGrant{
		UserID: userID, Purpose: proxy.ObserverPurposeShare, ShareCode: req.Code,
	})
}

// issueObserverTicket 兩支簽發端點共用的末段：補齊認證脈絡與帳號名後簽票並回應。
//
// 認證脈絡於簽發階段取得——兌換點只剩票證，屆時已無從得知「當初經哪個 provider
// 認證」，而那正是 provider 停用時要按 provider 收線的依據。
func (h *Handler) issueObserverTicket(c *gin.Context, grant proxy.ObserverGrant) {
	authCtx := middleware.GetAuthContext(c)
	grant.AuthMethod = authCtx.EffectiveMethod()
	grant.ProviderID = authCtx.ProviderID
	grant.AuthEpoch = authCtx.AuthEpoch
	grant.CredEpoch = authCtx.CredEpoch
	grant.Username, _ = middleware.GetCurrentUsername(c)

	token, err := h.observerTickets().IssueObserverTicket(c.Request.Context(), grant)
	if err != nil {
		// 容量拒絕與內部故障分開處置：前者是可預期的暫時性狀態（503／稍後再試），
		// 混進 500 會讓「有人在灌未兌換票證」淹沒在一般故障告警裡
		if errors.Is(err, proxy.ErrObserverTicketCapacity) {
			log.Printf("[ObserverTicket] 容量拒發: userID=%d %v", grant.UserID, err)
			apierror.Respond(c, http.StatusServiceUnavailable, apierror.CodeConnectTokenCapacity, nil)
			return
		}
		log.Printf("[ObserverTicket] 簽發失敗: %v", err)
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalConnectTokenIssue, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"connect_token": token, "expires_in": 60})
}

// parseMonitorSessionID 自路徑取監看目標會話 id；失敗時已寫入回應
func parseMonitorSessionID(c *gin.Context) (uint, bool) {
	idU64, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || idU64 == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidSessionID, nil)
		return 0, false
	}
	return uint(idU64), true
}

// redeemObserverTicket 兩條唯讀觀看 WS 的認證入口：兌換一次性觀看票，
// 成功時把認證脈絡與帳號名寫進 gin context 並回傳票證脈絡。失敗時已寫入回應。
//
// **對外一律同一則「token 無效」**：缺票、偽票、過期票、重放票、用途或客體錯置
// 五者不分流——分流即票證存在性與用途探測面。審計則以 `reason` 分得出成因：
// 反覆拿不存在的票試是探測訊號，過期多半只是慢了一步，而用途錯置是越權嘗試。
//
// **authContext 必寫**：這兩條路由不掛認證中介層，本函式是 authContext 的唯一
// 寫入者。不寫則下游 `middleware.GetAuthContext(c)` 恆回零值，造成兩個後果——
// ObserverContext.ProviderID=0 使 provider 停用收線一筆都匹配不到（外部身分使用者
// 的訂閱在其身分來源已停用後仍讀得到他人終端內容），且 CredEpoch=0 會讓
// JoinWithGenerationGuard 對 credential_epoch > 0 的使用者恆拒。
//
// **只寫 username、刻意不寫 userID**：`AuditLogMiddleware` 以兩鍵皆存在為記錄
// 條件，補上 userID 會讓這幾條路由同時由中介層與 handler 各寫一列（重複計數），
// 而中介層那一列反而缺少會話與資產脈絡。
func (h *Handler) redeemObserverTicket(c *gin.Context, purpose proxy.ObserverPurpose,
	via string) (proxy.ObserverGrant, bool) {
	raw := c.Query("connect_token")
	if raw == "" {
		h.auditObserverRedeemDenied(c, proxy.RedeemDenyMissing, via)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenMissing, nil)
		return proxy.ObserverGrant{}, false
	}
	grant, reason := h.observerTickets().RedeemObserverTicketWithReason(c.Request.Context(), raw)
	if reason != proxy.RedeemDenyNone {
		h.auditObserverRedeemDenied(c, reason, via)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenInvalid, nil)
		return proxy.ObserverGrant{}, false
	}
	if grant.Purpose != purpose {
		h.auditObserverRedeemDenied(c, proxy.RedeemDenyPurpose, via)
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenInvalid, nil)
		return proxy.ObserverGrant{}, false
	}

	c.Set("authContext", crypto.AuthContext{
		AuthMethod: grant.AuthMethod, ProviderID: grant.ProviderID,
		AuthEpoch: grant.AuthEpoch, CredEpoch: grant.CredEpoch,
	})
	c.Set("username", grant.Username)
	return grant, true
}

// denyObserverTicketObject 票證有效但客體與本次請求不符（為別的會話或別的分享碼
// 簽的票）：與用途錯置同一則對外回應、同一個審計原因。
// 客體不比對的話，一張為 A 簽的票就能開 B——票證的客體綁定形同虛設
func (h *Handler) denyObserverTicketObject(c *gin.Context, via string) {
	h.auditObserverRedeemDenied(c, proxy.RedeemDenyPurpose, via)
	apierror.Respond(c, http.StatusUnauthorized, apierror.CodeConnectTokenInvalid, nil)
}

// auditObserverRedeemDenied 觀看票兌換拒絕留痕。
//
// 與終端票的兌換拒絕共用 `proxy.AuditConnectDenied` 這一個寫入點：spec 的
// 「兌換拒絕留痕」沒有端點限定，兩份實作就會各自演化欄位集，而「某一側少填來源
// 位址」不會讓任何測試轉紅。`via` 區分入口，資產未知故留白（寫 NULL 而非 0）。
func (h *Handler) auditObserverRedeemDenied(c *gin.Context, reason proxy.RedeemDenyReason, via string) {
	h.auditRedeemDenied(c, proxy.ConnectDenial{
		Reason: string(reason), HTTPStatus: http.StatusUnauthorized,
	}, via)
}
