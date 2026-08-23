package sshproxy

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/proxy"
	"github.com/custodexa/backend/internal/recorder"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 兩階段閘序宣告
//
// 本檔只做一件事：把原本散在 handler 裡的一串 if 改寫成**有序的閘序表**，
// 使閘序成為可被守衛測試逐位比對的資料。**閘的判定邏輯、拒絕碼、副作用與其
// 發生次序逐字未改**——每個 Eval 的內容即原處的程式碼（含 log 前綴與審計標記合併）。
//
// 閘編號（G-I*／G-S*）的定義即本檔的閘序表——每個 `{Name: "G-…"}` 之後緊接
// 該閘的實作與理由；完整登記表（含刻意不涵蓋者與其逐條理由）見
// `characterization_matrix_test.go` 的 `TestMatrixCoverageIsDeclared`。
// 骨架＝`AuthorizePreResolve → 解封／解析 → AuthorizeResolvedAccount`，
// 三個入口逐字相同，差異只由 Stage 與各自的閘序表達。
//
// **認證面不在骨架內**（conventions §3「WS 入口與 middleware 是兩套認證面」）：
// 簽發側的 `authenticate`、兌換側的 connect_token 缺失／無效判定產生的是**主體本身**，
// 必須先於任何授權判定完成；骨架涵蓋的是授權與政策面。

// connectTokenRequest 簽發請求體（原為 HandleCreateConnectToken 內的匿名結構，
// 因閘序需跨閘傳遞而具名，欄位與 tag 逐字未改）
type connectTokenRequest struct {
	AssetID uint `json:"asset_id" binding:"required"`
	// AccountID 選填的連線帳號：省略／0＝預設帳號，
	// 語義與多帳號前的行為完全一致
	AccountID uint `json:"account_id"`
}

// issueState 簽發側閘序的共享中間狀態：前一道閘算出、後面的閘要用的東西
type issueState struct {
	role     string
	req      connectTokenRequest
	assetRow *model.Asset
	identity asset.AccountIdentity
}

// contractObject 簽發側的已解析客體：AccountID 為請求帶的**選擇器**值（0＝預設帳號），
// Username 為 ResolveAccountIdentity 解析出的帳號名——後者是帳號範圍閘（G-I10）的
// 判定對象，**不是請求參數**。
//
// **單一事實源**：HandleCreateConnectToken 與閘序守衛測試共用同一份構造。
func (st *issueState) contractObject() gatewayapi.ResolvedConnectObject {
	o := gatewayapi.ResolvedConnectObject{
		ConnectObjectRef: gatewayapi.ConnectObjectRef{
			AssetID:   st.req.AssetID,
			AccountID: st.req.AccountID,
		},
		Username: st.identity.Username,
	}
	if st.assetRow != nil {
		o.Protocol = string(st.assetRow.Protocol)
	}
	return o
}

// issuePreResolveGates 簽發側「帳號身分解析之前」的閘序（G-I2…G-I8）。
// s＝`gatewayapi.PolicyGate` 的主體入參；**s.ClaimedRole 在本階段零讀取**
// ——角色一律由 G-I2 現查後寫入 st.role
func (h *Handler) issuePreResolveGates(c *gin.Context,
	s gatewayapi.ConnectSubject, st *issueState) []connectgate.Gate {
	return []connectgate.Gate{
		{Name: "G-I2", Eval: func() *connectgate.Outcome {
			// AUTH-1＋角色現況覆蓋：簽發前重載用戶，
			// 並以 DB 現查有效角色覆蓋 JWT role——AuthMiddleware 不查 DB，停用/鎖定者持停用前
			// 的正式 JWT 仍能走到此處，降權 admin 亦然。不覆蓋則其後所有 admin 短路（授權/錄影
			// fail-close 例外/政策豁免/簽發）皆憑 JWT 角色快照放行。CheckUserConnectable
			// 的可連線複查併入本次查詢，不多查一趟
			role, connErr := h.AuthService.CurrentConnectRole(s.UserID)
			if connErr != nil {
				status, code := connectionAuthError(connErr)
				return connectgate.Deny(status, string(code), nil)
			}
			st.role = role
			return nil
		}},
		{Name: "G-I3", Eval: func() *connectgate.Outcome {
			if err := c.ShouldBindJSON(&st.req); err != nil {
				return connectgate.Deny(http.StatusBadRequest, string(apierror.CodeBadParams), nil)
			}
			return nil
		}},
		{Name: "G-I4", Eval: func() *connectgate.Outcome {
			// 簽發前驗資產存在：admin 經 checkPermission 直接放行，
			// 不在此驗證會對不存在的資產簽出註定失敗的 token
			assetRow, err := h.AssetService.GetByID(st.req.AssetID)
			if err != nil {
				return connectgate.Deny(http.StatusNotFound, string(apierror.CodeAssetNotFound), nil)
			}
			st.assetRow = assetRow
			return nil
		}},
		{Name: "G-I5", Eval: func() *connectgate.Outcome {
			return h.connectPermissionOutcome(c, s.UserID, st.role, st.req.AssetID)
		}},
		{Name: "G-I6", Eval: func() *connectgate.Outcome {
			// 停用資產連線硬擋：授權檢查之後（保未授權
			// 404 不洩漏語義）、政策閘之前；admin 不豁免——停用是資產態非權限態，
			// 要連先重新啟用留審計軌跡。後端強制，不受功能開關旁路
			if !st.assetRow.Active {
				return assetDisabledOutcome()
			}
			return nil
		}},
		{Name: "G-I7", Eval: func() *connectgate.Outcome {
			// K8s 固定單一預設帳號：帶 account_id 即拒，不靜默忽略
			if st.req.AccountID != 0 && st.assetRow.Protocol == model.ProtocolK8s {
				return connectgate.Deny(http.StatusBadRequest,
					string(apierror.CodeAccountK8sDefaultOnly), nil)
			}
			return nil
		}},
		{Name: "G-I8", Eval: func() *connectgate.Outcome {
			// 帳號客體綁定：授權閘之後
			//（不對未授權者洩漏帳號存在性）、政策閘之前（無效客體不該觸發審批流／
			// 建 access_request）。跨資產或已刪的 account_id 一律拒發——connect token
			// 不承載未經 DB 現查的客體，兌換點另有一次重查（fail-close 兩道）
			if st.req.AccountID == 0 {
				return nil
			}
			if err := h.AssetService.VerifyAccountBinding(st.req.AssetID, st.req.AccountID); err != nil {
				if errors.Is(err, asset.ErrAssetAccountNotFound) {
					// 404＋通用碼：不區分「不存在」與「屬於別的資產」，否則成為帳號探測器
					return connectgate.Deny(http.StatusNotFound,
						string(apierror.CodeAssetAccountNotFound), nil)
				}
				log.Printf("[ConnectToken] 帳號綁定驗證失敗: assetID=%d accountID=%d err=%v",
					st.req.AssetID, st.req.AccountID, err)
				return connectgate.DenyInternal(http.StatusInternalServerError,
					string(apierror.CodeInternalAssetAccountResolve), err)
			}
			return nil
		}},
	}
}

// issueResolvedAccountGates 簽發側「帳號身分解析之後」的閘序（G-I10…G-I13）。
// s／o＝`gatewayapi.PolicyGate` 的契約入參；o.Username 是解析出的實際連線帳號名，
// 即帳號範圍閘（G-I10）的判定對象——**不是請求參數**
func (h *Handler) issueResolvedAccountGates(c *gin.Context,
	s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject,
	st *issueState) []connectgate.Gate {
	return []connectgate.Gate{
		{Name: "G-I10", Eval: func() *connectgate.Outcome {
			// 帳號授權範圍（強制點 1／3）：客體綁定之後——
			// 「這個帳號屬於這台」與「你被授權用這個帳號」是兩件事。
			// **判定對象是實際會用的帳號、不是請求參數**：req.AccountID=0 時解析出預設
			// 帳號再判定，否則授權範圍收緊為 ["app"] 的使用者只要省略 account_id
			// 就能以預設的 root 建線，整個維度形同虛設。
			// 零帳號資產（Found=false）不在此擋——那是憑證路徑的 fail-close 職責
			//（兌換點 CodeAccountNoneUsable），在此擋會把「資產沒設帳號」誤報成「未授權」
			if !st.identity.Found {
				return nil
			}
			if aerr := h.AuthorizationService.AuthorizeConnectAccount(
				authorizationContext(c, st.role), s.UserID, o.AssetID,
				model.ProtocolType(o.Protocol), o.Username); aerr != nil {
				if errors.Is(aerr, authz.ErrAccountNotAuthorized) {
					// 與「帳號不存在」共用一碼：分流回應會讓端點成為「哪些帳號存在」的探測器
					return connectgate.Deny(http.StatusNotFound,
						string(apierror.CodeAssetAccountNotFound), nil)
				}
				log.Printf("[ConnectToken] 帳號授權判定失敗: userID=%d assetID=%d err=%v", s.UserID, o.AssetID, aerr)
				return connectgate.DenyInternal(http.StatusInternalServerError,
					string(apierror.CodeInternalAssetAccountResolve), aerr)
			}
			return nil
		}},
		{Name: "G-I11", Eval: func() *connectgate.Outcome {
			// 錄影前置檢查：停用硬擋後、政策閘前
			//（錄影儲存壞了不該讓使用者走完申請流才發現連不上）。probe 以共用
			// volume 代理 guacd（全協議唯一入口）；偵測/告警恆做，政策開啟時
			// 才擋簽發——admin 為唯一例外（嚴重事故仍需能處理），豁免留審計標記
			if probeErr := recorder.ProbeWritable(h.RecordingPath); probeErr != nil {
				if failure := audit.GetAuditFailure(); failure != nil {
					failure.Report(model.MechanismRecordingProbe, model.CauseRecordingProbeFailed,
						map[string]string{model.CauseParamDetail: probeErr.Error()})
				}
				if h.RecordingFailClose != nil && h.RecordingFailClose() {
					if st.role != model.RoleAdmin {
						return connectgate.Deny(http.StatusForbidden,
							string(apierror.CodeRecordingUnavailable),
							map[string]any{"reason": "recording_unavailable"})
					}
					mergeAuditDetails(c, map[string]string{"recording_exemption": "admin"})
				}
			} else if failure := audit.GetAuditFailure(); failure != nil {
				// 恢復僅配對自己的信號流（probe 成功≠他路錄製恢復，機制族分列）
				failure.Resolve(model.MechanismRecordingProbe)
			}
			return nil
		}},
		{Name: "G-I12", Eval: func() *connectgate.Outcome {
			// 存取政策閘：授權檢查之後、傳輸閘之前——
			// 先確認「可不可以連」再談「怎麼連安全」。非 open 段位蓋過常設 connect，
			// 僅時窗內核准流臨時授權放行；admin 豁免放行＋審計獨立標記（決議 3）；
			// 攔截恆 403＋機器可辨 reason（428 為傳輸閘專用）。後端強制——直呼 API 同受此閘
			if h.AccessPolicy == nil {
				return nil
			}
			decision, err := h.AccessPolicy.CheckConnect(s.UserID, st.role, st.assetRow)
			if err != nil {
				log.Printf("[AccessPolicy] 政策閘判定失敗: userID=%d assetID=%d err=%v", s.UserID, o.AssetID, err)
				return connectgate.DenyInternal(http.StatusInternalServerError,
					string(apierror.CodeInternalAccessPolicyCheck), err)
			}
			if !decision.Allowed {
				meta := map[string]any{
					"reason":               decision.Reason,
					"policy":               decision.Policy,
					"max_duration_minutes": decision.MaxDurationMinutes,
				}
				if decision.PendingRequestID != nil {
					meta["pending_request_id"] = *decision.PendingRequestID
				}
				return connectgate.Deny(decision.Status, string(accessGateCode(decision.Reason)), meta)
			}
			if decision.AdminExemption {
				// admin 豁免留痕：審計中介層將此標記合併進該筆日誌的 details
				mergeAuditDetails(c, map[string]string{"policy_exemption": "admin", "policy": decision.Policy})
				log.Printf("[AccessPolicy] admin 豁免政策閘連線: userID=%d assetID=%d policy=%s", s.UserID, o.AssetID, decision.Policy)
			}
			return nil
		}},
		{Name: "G-I13", Eval: func() *connectgate.Outcome {
			// 傳輸安全閘：授權之後、簽發之前。
			// strict＝400＋不符項；warn 無有效同意＝428＋風險項（前端據此彈同意對話框）；
			// off 或無風險＝零影響。後端強制——繞前端直呼 API 同受此閘
			if h.TransmissionConsent == nil {
				return nil
			}
			decision := h.TransmissionConsent.CheckConnect(s.UserID, st.assetRow, s.ClientIP)
			if !decision.Allowed {
				// channel/level/risks 是前端 connect.js 的機器欄（428＋risks 驅動同意
				// 對話框），經 Meta 平鋪回封套 top-level，欄位名與值不變
				return connectgate.Deny(decision.Status, string(transmissionGateCode(decision.Level)),
					map[string]any{
						"channel": decision.Channel,
						"level":   decision.Level,
						"risks":   decision.Risks,
					})
			}
			return nil
		}},
	}
}

// redeemState SSH 兌換側閘序的共享中間狀態
type redeemState struct {
	grant       proxy.ConnectGrant
	currentRole string
	cols, rows  int
	creds       *asset.AssetCredentials
}

// contractSubject／contractObject SSH 兌換側的契約入參（構造與職責同圖形側，
// 見 internal/proxy/connect_gates.go 的同名方法）。
// ClaimedRole 留空是實質：grant 刻意不攜帶角色，角色一律由 G-S3 現查。
func (st *redeemState) contractSubject(clientIP string) gatewayapi.ConnectSubject {
	return gatewayapi.ConnectSubject{
		UserID:     st.grant.UserID,
		AuthMethod: st.grant.AuthMethod,
		ProviderID: st.grant.ProviderID,
		AuthEpoch:  st.grant.AuthEpoch,
		CredEpoch:  st.grant.CredEpoch,
		ClientIP:   clientIP,
	}
}

// contractObject AccountID 維持 grant 帶的選擇器值（G-S12 判的正是它），
// Username 為解封後實際會用的帳號名（G-S13 的判定對象）。
func (st *redeemState) contractObject() gatewayapi.ResolvedConnectObject {
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

// redeemPreResolveGates SSH 兌換側「憑證解封之前」的閘序（G-S3…G-S5）。
// s＝票證所帶的主體脈絡（`gatewayapi.PolicyGate` 入參），值逐欄取自 grant
func (h *Handler) redeemPreResolveGates(c *gin.Context,
	s gatewayapi.ConnectSubject, st *redeemState) []connectgate.Gate {
	return []connectgate.Gate{
		{Name: "G-S3", Eval: func() *connectgate.Outcome {
			// AUTH-1＋角色現況：connect_token 於停用/鎖定/
			// 降權前簽發者，兌換時重載用戶狀態並取 DB 現查有效角色（即時撤權殘窗 = 60s TTL；
			// 不重載＝停用/降權者仍可開新 shell）。currentRole 供下方授權/政策重查判定 admin 特權
			currentRole, connErr := h.AuthService.CurrentConnectRole(s.UserID)
			if connErr != nil {
				status, code := connectionAuthError(connErr)
				return connectgate.Deny(status, string(code), nil)
			}
			st.currentRole = currentRole
			return nil
		}},
		{Name: "G-S4", Eval: func() *connectgate.Outcome {
			// 憑證世代複查：簽發後、兌換前若該 provider 被停用／
			// 刪除／輪替 secret，或使用者憑證世代被推進（解綁外部身分、改為僅外部登入、改密、
			// 停用），這張一次性 token 必須失效。上方角色現查擋不到這一類——帳號可能仍啟用、
			// 角色也沒變，但其外部身分已被解綁或該 provider 已停用。
			// 語義與 guacd 路徑（proxy/handler.go）一致：一律收斂為 401＋token 無效，不分述成因
			if genErr := h.AuthService.VerifyCredentialGenerationByUserID(crypto.AuthContext{
				AuthMethod: s.AuthMethod, ProviderID: s.ProviderID,
				AuthEpoch: s.AuthEpoch, CredEpoch: s.CredEpoch,
			}, s.UserID); genErr != nil {
				log.Printf("[SSHProxy] 兌換點憑證世代複查拒絕: userID=%d providerID=%d err=%v",
					s.UserID, s.ProviderID, genErr)
				return connectgate.Deny(http.StatusUnauthorized,
					string(apierror.CodeConnectTokenInvalid), nil)
			}
			return nil
		}},
		{Name: "G-S5", Eval: func() *connectgate.Outcome {
			cols, rows, out := parseSizeOutcome(c)
			if out != nil {
				return out
			}
			st.cols, st.rows = cols, rows
			return nil
		}},
	}
}

// redeemResolvedAccountGates SSH 兌換側「憑證解封之後」的閘序（G-S7…G-S13）。
// s／o＝`gatewayapi.PolicyGate` 的契約入參；o.AccountID 是 grant 帶的**選擇器**值
// （0＝預設帳號，G-S12 判的正是它），o.Username 是解封後實際會用的帳號名（G-S13 的判定對象）
func (h *Handler) redeemResolvedAccountGates(c *gin.Context,
	s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject,
	st *redeemState) []connectgate.Gate {
	return []connectgate.Gate{
		{Name: "G-S7", Eval: func() *connectgate.Outcome {
			// 停用硬擋兌換點重查（與 AUTH-1 對稱的 assetRow 側）：token 於資產停用前
			// 簽發者，殘窗（60s TTL）內兌換須擋；語義同簽發點（403+asset_disabled）
			if !st.creds.Asset.Active {
				return assetDisabledOutcome()
			}
			return nil
		}},
		{Name: "G-S8", Eval: func() *connectgate.Outcome {
			if !st.creds.Asset.Protocol.IsTextTerminal() {
				return connectgate.Deny(http.StatusBadRequest,
					string(apierror.CodeAssetNotTextTerminal), nil)
			}
			return nil
		}},
		{Name: "G-S9", Eval: func() *connectgate.Outcome {
			// 兌換點授權與政策重查（與簽發點對稱）：connect_token 於簽發後、
			// 兌換前，其連線授權/ticket/存取政策/角色若遭撤銷或收緊，於此即時生效——撤權
			// 殘窗（原以 60s TTL 為上界）歸零。role 用 DB 現查 currentRole，不憑角色快照
			// 授予 admin 特權
			return h.connectPermissionOutcome(c, s.UserID, st.currentRole, o.AssetID)
		}},
		{Name: "G-S10", Eval: func() *connectgate.Outcome {
			if h.AccessPolicy == nil {
				return nil
			}
			decision, perr := h.AccessPolicy.CheckConnect(s.UserID, st.currentRole, st.creds.Asset)
			if perr != nil {
				log.Printf("[SSHProxy] 兌換點政策閘判定失敗: userID=%d assetID=%d err=%v",
					s.UserID, o.AssetID, perr)
				return connectgate.DenyInternal(http.StatusInternalServerError,
					string(apierror.CodeInternalAccessPolicyCheck), perr)
			}
			if !decision.Allowed {
				return connectgate.Deny(decision.Status, string(accessGateCode(decision.Reason)),
					map[string]any{"reason": decision.Reason, "policy": decision.Policy})
			}
			return nil
		}},
		{Name: "G-S11", Eval: func() *connectgate.Outcome {
			// 零帳號資產 fail-close：空 token／空密碼交給 k8s client 或
			// DB CLI 會變成匿名 ServiceAccount／trust 認證／互動式提示——SSH 靠
			// authMethods 空集擋得住，其餘協議沒有這道網，統一在此擋。
			// 置於停用／授權／政策閘之後：那些閘的回應語義是既有契約，順序不動
			if st.creds.AccountID == 0 {
				log.Printf("[SSHProxy] 資產無可用帳號憑證，拒絕連線: assetID=%d", o.AssetID)
				return connectgate.Deny(http.StatusNotFound,
					string(apierror.CodeAccountNoneUsable), nil)
			}
			return nil
		}},
		{Name: "G-S12", Eval: func() *connectgate.Outcome {
			// K8s 固定單一預設帳號：簽發點已擋，此處為兌換點的對稱防線
			//（簽發／兌換之間資產協議被改為 k8s 亦涵蓋）。拒而非忽略——靜默忽略會讓
			// 使用者以為連的是所選帳號、實際用的是預設憑證
			if model.ProtocolType(o.Protocol) == model.ProtocolK8s && o.AccountID != 0 {
				log.Printf("[SSHProxy] K8s 資產不支援指定連線帳號，拒絕連線: assetID=%d accountID=%d",
					o.AssetID, o.AccountID)
				return connectgate.Deny(http.StatusBadRequest,
					string(apierror.CodeAccountK8sDefaultOnly), nil)
			}
			return nil
		}},
		{Name: "G-S13", Eval: func() *connectgate.Outcome {
			// 帳號授權範圍兌換複查：與既有授權／政策重查同處、同哲學
			//（DB 現查，簽發後遭收緊者於此即時生效，token 效期不構成放行理由）。
			// 判定對象是 creds 實際解析出的帳號 username——grant.AccountID=0 時即預設帳號
			if aerr := h.AuthorizationService.AuthorizeConnectAccount(
				authorizationContext(c, st.currentRole), s.UserID, o.AssetID,
				model.ProtocolType(o.Protocol), o.Username); aerr != nil {
				if errors.Is(aerr, authz.ErrAccountNotAuthorized) {
					log.Printf("[SSHProxy] 帳號已移出授權範圍，拒絕建線: userID=%d assetID=%d accountID=%d",
						s.UserID, o.AssetID, st.creds.AccountID)
					return connectgate.Deny(http.StatusForbidden,
						string(apierror.CodeAssetConnectDenied), nil)
				}
				log.Printf("[SSHProxy] 兌換點帳號授權判定失敗: userID=%d assetID=%d err=%v",
					s.UserID, o.AssetID, aerr)
				return connectgate.DenyInternal(http.StatusInternalServerError,
					string(apierror.CodeInternalPermissionCheck), aerr)
			}
			return nil
		}},
	}
}

// assetDisabledOutcome 資產停用硬擋的判定結果：**本包（簽發點 G-I6 與 SSH 兌換點 G-S7）
// 唯一的來源**，語義必須一致。原先的 `writeAssetDisabled` 收斂後已無呼叫者，已刪。
//
// **跨包不是單一事實源**：`internal/proxy` 的 G-G7 仍 inline 一份同形回應
// （403＋`RULE_ASSET_DISABLED`＋`reason=asset_disabled`）。要共用得跨包匯出，屬重構外溢，
// 同 K-7 類，目前不做（等價表 §3.1 R-4 已以此措辭誠實記載）。
func assetDisabledOutcome() *connectgate.Outcome {
	return connectgate.Deny(http.StatusForbidden, string(apierror.CodeAssetDisabled),
		map[string]any{"reason": "asset_disabled"})
}
