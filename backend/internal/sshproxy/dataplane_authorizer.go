package sshproxy

import (
	"errors"
	"log"
	"net/http"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/connectgate"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"github.com/gin-gonic/gin"
)

// 資料面裁決（DataPlaneAuthorizer）
//
// K8s 容器檔案進出（`kubectl cp` 上傳與下載）不產生連線票證，卻是對容器的讀寫：
// 它必須與連線簽發走**同一組閘函式**，而不是另寫一份判定。本檔以簽發側閘序
// （connect_gates.go 的 issuePreResolveGates／issueResolvedAccountGates）為唯一來源，
// 依名稱挑出資料面需要的閘，逐字重用其 Eval——**不重寫任何判定、不新增拒絕碼**。
//
// 閘序：G-I2（重載主體、可連線複查）→ G-I15（來源限定）→ G-I4（資產存在）→
// G-I5（連線授權，含超管短路與稽核員不具 connect）→ G-I6（停用資產）→ G-D1（協定
// 須為 K8s）→ G-I7（K8s 固定預設帳號）→ 解析預設帳號 → G-I10（帳號範圍）→
// G-I12（存取政策，含核准時窗與超管豁免標記）→ G-I13（傳輸安全）。
//
// 刻意不納入：G-I3（請求綁定；資料面的客體由路由參數給定）、G-I8（帳號客體綁定；
// 資料面固定預設帳號，選擇器恆為 0）、G-I11（錄影前置探測；檔案進出不產生錄影會話，
// 納入會新增未經裁決的阻擋）、G-I16（申請單封套與 token 簽發；本段不新增請求參數）。
//
// 管理權限點（asset:update、asset:test 等）**不出現在本裁決的任何輸入**：持任何管理
// 能力而無連線授權者在 G-I5 被拒，與連線簽發的結論一致。

// dataPlanePreGateNames 資料面裁決自簽發側前置閘序挑出的閘（順序即簽發側順序）；
// dataPlanePostGateNames 自解析後閘序挑出的閘。以函式回傳集合而非包級變數：
// 這兩組名單沒有初始化時序語義，不進 lifecycle manifest。
func dataPlanePreGateNames() map[string]bool {
	return map[string]bool{"G-I2": true, "G-I15": true, "G-I4": true, "G-I5": true, "G-I6": true, "G-I7": true}
}

func dataPlanePostGateNames() map[string]bool {
	return map[string]bool{"G-I10": true, "G-I12": true, "G-I13": true}
}

// DataPlaneAction 資料面動作的名稱（只進 log，不參與判定）。
const (
	DataPlaneActionK8sUpload   = "k8s_file_upload"
	DataPlaneActionK8sDownload = "k8s_file_download"
)

// AuthorizeDataPlane 對 (subject, assetID) 做資料面裁決；回 nil 代表通過，
// 否則回該閘既有的拒絕結果（狀態碼、碼、Meta 與簽發側逐字相同）。
// 通過前**不解封憑證、不連叢集**：本函式只讀資產列與授權狀態。
// 超管豁免存取政策時，`policy_exemption` 審計標記由 G-I12 合併進請求脈絡，與簽發側同源。
func (h *Handler) AuthorizeDataPlane(c *gin.Context, subject gatewayapi.ConnectSubject, assetID uint, action string) *gatewayapi.Denial {
	if assetID == 0 {
		return connectgate.Deny(http.StatusBadRequest, string(apierror.CodeBadParams), nil)
	}
	input := &ConnectTokenRequest{AssetID: assetID}
	st := &issueState{input: input, req: *input}
	gate := connectgate.NewSequence(
		func(s gatewayapi.ConnectSubject) []connectgate.Gate {
			return h.dataPlanePreResolveGates(c, s, st)
		},
		func(s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject) []connectgate.Gate {
			return h.dataPlaneResolvedAccountGates(c, s, o, st)
		},
	)
	ctx := c.Request.Context()
	if out := gate.AuthorizePreResolve(ctx, subject, gatewayapi.StageIssue); out != nil {
		log.Printf("[DataPlane] 裁決拒絕: action=%s userID=%d assetID=%d gate=%s code=%s",
			action, subject.UserID, assetID, out.Gate, out.Decision.Code)
		return out
	}
	identity, err := h.AssetService.ResolveAccountIdentity(assetID, 0)
	if err != nil {
		if errors.Is(err, asset.ErrAssetAccountNotFound) {
			return connectgate.Deny(http.StatusNotFound, string(apierror.CodeAssetAccountNotFound), nil)
		}
		return connectgate.DenyInternal(http.StatusInternalServerError, string(apierror.CodeInternalAssetAccountResolve), err)
	}
	st.identity = identity
	if out := gate.AuthorizeResolvedAccount(ctx, subject, st.contractObject(), gatewayapi.StageIssue); out != nil {
		log.Printf("[DataPlane] 裁決拒絕: action=%s userID=%d assetID=%d gate=%s code=%s",
			action, subject.UserID, assetID, out.Gate, out.Decision.Code)
		return out
	}
	return nil
}

// dataPlanePreResolveGates 簽發側前置閘序的資料面子集，並在 G-I6 之後插入協定閘 G-D1：
// 資料面入口只服務 K8s 資產，其他協定的資產在此以既有的協定驗證碼拒絕，
// 不走到 K8s 專屬的 G-I7 與後續解析。
func (h *Handler) dataPlanePreResolveGates(c *gin.Context,
	s gatewayapi.ConnectSubject, st *issueState) []connectgate.Gate {
	gates := filterGates(h.issuePreResolveGates(c, s, st), dataPlanePreGateNames())
	protocol := connectgate.Gate{Name: "G-D1", Eval: func() *connectgate.Outcome {
		if st.assetRow == nil || st.assetRow.Protocol != model.ProtocolK8s {
			return connectgate.Deny(http.StatusBadRequest, string(apierror.CodeInvalidProtocol), nil)
		}
		return nil
	}}
	out := make([]connectgate.Gate, 0, len(gates)+1)
	for _, g := range gates {
		if g.Name == "G-I7" {
			out = append(out, protocol)
		}
		out = append(out, g)
	}
	return out
}

// dataPlaneResolvedAccountGates 簽發側解析後閘序的資料面子集。與 dataPlanePreResolveGates
// 同為 AuthorizeDataPlane 與閘序守衛測試共用的唯一組裝點：測試鎖定的是實際組出的清單。
func (h *Handler) dataPlaneResolvedAccountGates(c *gin.Context,
	s gatewayapi.ConnectSubject, o gatewayapi.ResolvedConnectObject, st *issueState) []connectgate.Gate {
	return filterGates(h.issueResolvedAccountGates(c, s, o, st), dataPlanePostGateNames())
}

// filterGates 依名稱挑出閘，保留原順序；閘的 Eval 逐字重用。
func filterGates(gates []connectgate.Gate, keep map[string]bool) []connectgate.Gate {
	out := make([]connectgate.Gate, 0, len(keep))
	for _, g := range gates {
		if keep[g.Name] {
			out = append(out, g)
		}
	}
	return out
}
