package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/k8sproxy"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/gin-gonic/gin"
)

// AssetServiceInterface 資產服務接口（用於測試注入）
type AssetServiceInterface interface {
	List(filter *asset.AssetFilter) (*asset.AssetListResponse, error)
	GetByID(id uint) (*model.Asset, error)
	Create(ctx context.Context, req *asset.CreateAssetRequest) (*model.Asset, error)
	Update(ctx context.Context, id uint, req *asset.UpdateAssetRequest) (*model.Asset, error)
	Delete(ctx context.Context, id uint) error
	TestConnection(ctx context.Context, id uint, timeout int) (*asset.ConnectionTestResult, error)
	ListK8sPods(ctx context.Context, id uint) ([]k8sproxy.PodInfo, error)
	K8sCopyToPod(ctx context.Context, id uint, pod, container, destPath, localPath string) error
	K8sCopyFromPod(ctx context.Context, id uint, pod, container, srcPath, localPath string) error
	AssetIDsForNodeFilter(nodeID *uint, includeSubtree, ungrouped bool) (map[uint]bool, error)
	ListTags() ([]asset.TagCount, error)
	ListTagsForAssetIDs(ids []uint) ([]asset.TagCount, error)
	RenameTag(ctx context.Context, from, to string) (int64, error)
	DeleteTag(ctx context.Context, name string) (int64, error)
	PreviewImport(ctx context.Context, batch *asset.ImportBatch) (*asset.ImportPreview, error)
	ImportAssets(ctx context.Context, batch *asset.ImportBatch, createdBy uint, createdByName string) (*asset.ImportResult, error)
	BatchMove(ctx context.Context, ids []uint, targetNodeID uint) (asset.BatchResult, error)
	BatchAddTags(ctx context.Context, ids []uint, tags []string) (asset.BatchResult, error)
	BatchDelete(ctx context.Context, ids []uint) (asset.BatchResult, error)
}

// AssetAuthorizationServiceInterface 資產授權服務接口（用於測試注入）
type AssetAuthorizationServiceInterface interface {
	CheckPermission(ctx context.Context, userID, assetID uint, perm model.PermissionType) (bool, error)
	GetAuthorizedAssets(ctx context.Context, userID uint, perm model.PermissionType) ([]*authz.AuthorizedAssetDTO, error)
	ExplicitAuthorizedAssetIDs(userID uint, perm model.PermissionType) (map[uint]bool, error)
	// FillNodeInfoForDTOs 授權分支 DTO 的節點資訊填充。
	// **自 AssetServiceInterface 移來**：DTO 是授權服務的型別，
	// 填充是授權列表流程的一步；asset 只提供「一批資產的節點資訊」的能力。
	FillNodeInfoForDTOs(dtos []*authz.AuthorizedAssetDTO) error
}

// AccessStateAnnotator 連線入口三態標註
type AccessStateAnnotator interface {
	AnnotateConnectStates(userID uint, assets []*authz.AuthorizedAssetDTO) error
}

// AssetHandler 資產 API handler
type AssetHandler struct {
	assetService         AssetServiceInterface
	authorizationService AssetAuthorizationServiceInterface
	// accessState 一般 user 列表的連線入口三態標註；nil＝不標註
	//（既有測試路徑，前端沿 permission 欄渲染）
	accessState AccessStateAnnotator
	// auditSink k8s 檔案操作審計的投遞面（AP-04）。同 file_tap，
	// 本點現況直寫 database.DB 且不看 AuditLogEnabled，故注入的是 DirectSink
	auditSink gatewayapi.AsyncSink
	// dataTransfer 資料傳輸閘（data-transfer-control 4.3）：K8s 檔案進出與 SFTP
	// 面**同碼同語義**。nil＝不套閘（既有測試路徑，等同五鍵全允許）。
	// 次序固定為：資料面裁決 → 傳輸控管 → `kubectl cp` → 審計
	dataTransfer *policy.DataTransferService
	// dataPlane K8s 檔案進出的資料面裁決：與連線簽發同一組閘函式（主體可連線與來源
	// 限定、資產存在與啟用、連線授權、K8s 固定預設帳號與帳號範圍、存取政策、傳輸安全）。
	// 管理權限點不是放行條件。**未注入即拒絕**（fail-close，不回退為放行）
	dataPlane DataPlaneAuthorizer
	// scopeGate 登錄閘的目標範圍判定依賴（建構參數，組裝端傳入）；nil 時宣告了目標的登錄項不放行
	scopeGate *middleware.ScopeGate
	// assetScope 資產頁的範圍化投影來源；nil＝不帶範圍化欄位、只見連線可視（不擴大資料）
	assetScope AssetScopeSource
}

// DataPlaneAuthorizer 資料面裁決器（由 sshproxy 以簽發側閘序實作，組裝端注入）。
// 回 nil 代表通過；否則回該閘既有的拒絕結果，handler 原樣寫出、不另加判斷。
type DataPlaneAuthorizer interface {
	AuthorizeDataPlane(c *gin.Context, subject gatewayapi.ConnectSubject, assetID uint, action string) *gatewayapi.Denial
}

// SetDataPlaneAuthorizer 注入資料面裁決器（組裝端呼叫）
func (h *AssetHandler) SetDataPlaneAuthorizer(a DataPlaneAuthorizer) {
	h.dataPlane = a
}

// requireK8sDataPlane K8s 檔案端點的資料面裁決。被拒時已寫入該閘的既有回應，回傳 false。
// 未通過裁決的請求不建暫存檔、不解封 token、不打叢集；通過後才進資料傳輸控管閘。
func (h *AssetHandler) requireK8sDataPlane(c *gin.Context, userID, assetID uint, action string) bool {
	if h.dataPlane == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionCheck,
			errors.New("資料面裁決器未注入，K8s 檔案進出一律拒絕"))
		return false
	}
	authCtx := middleware.GetAuthContext(c)
	subject := gatewayapi.ConnectSubject{
		UserID: userID, AuthMethod: authCtx.EffectiveMethod(), ProviderID: authCtx.ProviderID,
		AuthEpoch: authCtx.AuthEpoch, CredEpoch: authCtx.CredEpoch, ClientIP: sourceip.Of(c),
	}
	out := h.dataPlane.AuthorizeDataPlane(c, subject, assetID, action)
	if out == nil {
		return true
	}
	code := apierror.ErrCode(out.Decision.Code)
	if out.Internal != nil {
		apierror.RespondInternal(c, out.Status, code, out.Internal)
		return false
	}
	apierror.Write(c, out.Status, apierror.ErrorResponse{Code: code, Meta: out.Meta})
	return false
}

// SetDataTransfer 注入資料傳輸閘（組裝端呼叫）
func (h *AssetHandler) SetDataTransfer(dt *policy.DataTransferService) {
	h.dataTransfer = dt
}

// requireK8sTransferAllowed K8s 檔案端點的資料傳輸閘。被拒時已寫入 403 回應與
// StatusDenied 審計，回傳 false。與 SFTP 面同碼（apierror.CodeTransferDenied）
func (h *AssetHandler) requireK8sTransferAllowed(c *gin.Context, userID, assetID uint, action string, detail string) bool {
	if h.dataTransfer == nil {
		return true
	}
	allowed, err := h.dataTransfer.AllowsAction(c.Request.Context(), userID, assetID,
		policy.TransferChannelWeb, action)
	if err != nil {
		// fail-close：傳輸控制的失敗方向必須是擋住而非放行
		log.Printf("[AssetHandler] 傳輸能力解析失敗（fail-close 拒絕）: userID=%d assetID=%d action=%s err=%v",
			userID, assetID, action, err)
		allowed = false
	}
	if allowed {
		return true
	}
	auditAction := model.ActionFileUpload
	if action == policy.TransferActionFileDownload {
		auditAction = model.ActionFileDownload
	}
	// 被拒留痕：現行兩端點的審計皆在成功路徑，拒絕分支直接 return
	// 會讓「有沒有人試著把資料帶出去」無法回答
	h.auditK8sFileDenied(c, userID, assetID, auditAction, detail)
	apierror.Respond(c, http.StatusForbidden, apierror.CodeTransferDenied, map[string]any{
		"action": action,
		"reason": "global_policy",
	})
	return false
}

// SetAccessStateAnnotator 注入三態標註服務（組裝端呼叫）
func (h *AssetHandler) SetAccessStateAnnotator(a AccessStateAnnotator) {
	h.accessState = a
}

// NewAssetHandler 創建資產 handler
func NewAssetHandler(
	assetService AssetServiceInterface,
	authorizationService AssetAuthorizationServiceInterface,
	auditSink gatewayapi.AsyncSink,
	scopeGate ...*middleware.ScopeGate, // 至多一個：登錄閘的目標範圍判定依賴
) *AssetHandler {
	return &AssetHandler{
		assetService:         assetService,
		authorizationService: authorizationService,
		auditSink:            auditSink,
		scopeGate:            firstScopeGate(scopeGate),
	}
}

// firstScopeGate 建構參數中的登錄閘範圍判定依賴；未傳入回 nil。
func firstScopeGate(gs []*middleware.ScopeGate) *middleware.ScopeGate {
	if len(gs) == 0 {
		return nil
	}
	return gs[0]
}

// tagValidationCode 標籤驗證 sentinel → 機器碼。
// 第二回傳值 false＝非標籤驗證錯誤，交由呼叫端續判。
// 註：舊碼 Create/Update 對 ErrTagEmpty/ErrTagContainsComma 落 500、RenameTag 卻
// 落 400——同 sentinel 異狀態屬既有不一致；本表統一為語義正確的 400（刻意的
// 小幅正規化）。
func tagValidationCode(err error) (apierror.ErrCode, bool) {
	switch {
	case errors.Is(err, asset.ErrTagEmpty):
		return apierror.CodeTagEmpty, true
	case errors.Is(err, asset.ErrTagContainsComma):
		return apierror.CodeTagContainsComma, true
	case errors.Is(err, asset.ErrTagTooLong):
		return apierror.CodeTagTooLong, true
	case errors.Is(err, asset.ErrTooManyTags):
		return apierror.CodeTooManyTags, true
	case errors.Is(err, asset.ErrTagsTotalTooLong):
		return apierror.CodeTagsTotalTooLong, true
	}
	return "", false
}

// respondPrivateKeyInvalid 私鑰無法解析的共用出口（資產、資產帳號、憑證庫）。
// 回應頂層帶 field 指出出錯的是私鑰欄，表單據此把錯誤掛在該欄下方，
// 不必猜是哪一區。field 走 Meta 而非 params：params 只承載訊息模板的插值，
// 這句訊息沒有插值位置。
func respondPrivateKeyInvalid(c *gin.Context) {
	apierror.Write(c, http.StatusBadRequest, apierror.ErrorResponse{
		Code: apierror.CodeCredentialPrivateKeyInvalid,
		Meta: map[string]any{"field": "private_key"},
	})
}

// respondAssetError 資產寫入端點的統一錯誤出口：已知 sentinel 依 errors.Is 映射
// 到機器碼（狀態碼與遷移前逐一相同），未知一律 RespondInternal（成因只落日誌）。
// internalCode 為該端點的 INTERNAL_ASSET_<VERB> 碼。
func respondAssetError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	if respondTxScopeError(c, err) {
		return
	}
	if respondAssetWriteScopeError(c, err) {
		return
	}
	if code, ok := tagValidationCode(err); ok {
		apierror.Respond(c, http.StatusBadRequest, code, nil)
		return
	}
	switch {
	case errors.Is(err, asset.ErrAssetNotFound):
		middleware.RespondTargetNotFound(c, authz.ScopeTargetAsset, authz.ScopeLayerAsset)
	case errors.Is(err, asset.ErrFieldCapabilityDenied),
		// 表單內嵌密碼／私鑰是 SetSecret 的同義入口：缺 credential:set-secret 與欄位能力不足
		// 同一出口。資產本身已通過可見性判定，403 不構成憑證存在性探測
		errors.Is(err, asset.ErrCredentialBindForbidden):
		// 不帶權限名或角色名；依據只存進請求脈絡
		respondAssetCapabilityDenial(c, err)
	case errors.Is(err, asset.ErrAssetNoUsableAccount):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoneUsable, nil)
	case errors.Is(err, asset.ErrAssetAccountNotFound):
		middleware.RespondTargetNotFound(c, authz.ScopeTargetAssetAccount, authz.ScopeLayerAccount)
	case errors.Is(err, asset.ErrAssetAccountUsernameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountUsernameExists, nil)
	case errors.Is(err, asset.ErrAssetAccountDefaultConflict):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountDefaultConflict, nil)
	case errors.Is(err, asset.ErrAssetAccountDefaultMissing):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountDefaultMissing, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameInvalid, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameTooLong, nil)
	case errors.Is(err, asset.ErrAssetNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAssetNameExists, nil)
	case errors.Is(err, asset.ErrPrivateKeyInvalid):
		// 原始解析錯誤不帶出：可能含金鑰格式細節
		respondPrivateKeyInvalid(c)
	case errors.Is(err, asset.ErrInvalidProtocol):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidProtocol, nil)
	case errors.Is(err, asset.ErrInvalidRDPSecurity):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidRDPSecurity, nil)
	case errors.Is(err, asset.ErrInvalidDBTLSMode):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidDBTLSMode, nil)
	case errors.Is(err, asset.ErrInvalidAllowedDatabases):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAllowedDatabases, nil)
	case errors.Is(err, asset.ErrMSSQLHostComma):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeMSSQLHostComma, nil)
	case errors.Is(err, asset.ErrInvalidAccessPolicy):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccessPolicy, nil)
	case errors.Is(err, asset.ErrInvalidRotationChannel):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidRotationChannel, nil)
	case errors.Is(err, asset.ErrInvalidRotationChannelParams):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidRotationChannelParams, nil)
	// 建資產的登入憑證區：來源二擇一、已退場的複製參數，與所選共用憑證本身的狀態
	case errors.Is(err, asset.ErrCredentialSourceAmbiguous):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialSourceAmbiguous, nil)
	case errors.Is(err, asset.ErrAccountCopyFromRemoved):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountCopyFromRemoved, nil)
	case errors.Is(err, asset.ErrAccountSharedCredentialSecret):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountSharedCredentialSecret, nil)
	case errors.Is(err, asset.ErrCredentialNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCredentialNotFound, nil)
	case errors.Is(err, asset.ErrCredentialDedicatedSingleBinding):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialDedicatedSingle, nil)
	case errors.Is(err, asset.ErrCredentialProtocolMismatch):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialProtocolMismatch, nil)
	case errors.Is(err, asset.ErrCredentialRotationActive):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialRotationActive, nil)
	case errors.Is(err, asset.ErrCredentialUsernameImmutable):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialUsernameImmutable, nil)
	case errors.Is(err, asset.ErrCredentialOutOfSync):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialOutOfSync, nil)
	// 建立／更新的欄位規則：原本未映射而落到 500
	case errors.Is(err, asset.ErrUsernameRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAssetUsernameRequired, nil)
	case errors.Is(err, asset.ErrK8sTargetRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAssetK8sNamespaceRequired, nil)
	case errors.Is(err, asset.ErrSftpUsernameRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAssetSftpUsernameRequired, nil)
	case errors.Is(err, asset.ErrNodeNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNodeNotFound, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

// isPrivilegedRole 判斷請求者是否具管理視圖資格（內建超管或稽核員身分；
// 主體缺失視為非特權，安全預設）
func isPrivilegedRole(c *gin.Context) bool {
	return middleware.PrincipalFrom(c).ViewShortcut()
}

// assetListUsesAuthorizedSet 資產列表走授權集合還是全量：非檢視捷徑主體一律走授權集合，
// 不信任客戶端的 authorized_only；儀表板資產卡以同一函式選分支。
func assetListUsesAuthorizedSet(p *authz.Principal, authorizedOnlyParam bool) bool {
	return authorizedOnlyParam || !p.ViewShortcut()
}

// authorizedAssetsOf 主體在 view 權限下的已授權資產集合（已去重）。
// 資產列表的授權分支與儀表板資產卡共用，兩邊的總數因此同源。
func authorizedAssetsOf(ctx context.Context, svc AssetAuthorizationServiceInterface, p *authz.Principal, userID uint) ([]*authz.AuthorizedAssetDTO, error) {
	return svc.GetAuthorizedAssets(authz.ContextWithPrincipal(ctx, p), userID, model.PermissionView)
}

// isAuditorRole 判斷請求者的舊主角色是否為 auditor（保留例外：依舊主角色選擇回應形狀，非授權判斷）：
// 全量分支僅 auditor 需要入口判定欄，admin 回應形狀凍結
func isAuditorRole(c *gin.Context) bool {
	return middleware.PrincipalFrom(c).IsAuditor()
}

// assetWithEntryPermission auditor 全量列表的入口判定包裝：permission 僅供
// 連線入口判定（connect＝顯式 grant 命中／view＝其餘），非授權狀態欄資料
type assetWithEntryPermission struct {
	model.Asset
	Permission model.PermissionType `json:"permission"`
}

// filterAuthorizedAssets 在授權集合內套用 search/protocol/active 篩選——
// 收斂後一般 user 走授權分支，前端的搜尋/協議/狀態控制項須在伺服端於授權集合內
// 生效，否則參數被忽略、篩選對一般 user 全面失效。
func filterAuthorizedAssets(assets []*authz.AuthorizedAssetDTO, search, protocol, active string) []*authz.AuthorizedAssetDTO {
	search = strings.ToLower(strings.TrimSpace(search))
	out := make([]*authz.AuthorizedAssetDTO, 0, len(assets))
	for _, a := range assets {
		if search != "" &&
			!strings.Contains(strings.ToLower(a.Name), search) &&
			!strings.Contains(strings.ToLower(a.Host), search) {
			continue
		}
		if protocol != "" && string(a.Protocol) != protocol {
			continue
		}
		if active != "" && a.Active != (active == "true") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// List 列出資產
func (h *AssetHandler) List(c *gin.Context) {
	// 分頁參數（授權分支與全量分支共用）
	page, pageSize := 1, 20
	if p, err := strconv.Atoi(c.Query("page")); err == nil && p > 0 {
		page = p
	}
	if ps, err := strconv.Atoi(c.Query("page_size")); err == nil && ps > 0 {
		pageSize = ps
	}

	// 伺服端強制授權收斂：非 admin/auditor 一律走授權
	// 資產集合，不信任客戶端 authorized_only 參數；管理角色保留參數自查行為
	authorizedOnly := assetListUsesAuthorizedSet(middleware.PrincipalFrom(c), c.Query("authorized_only") == "true")

	// 節點過濾參數：node_id 點選節點、include_subtree
	// 預設含子樹（顯式 false 關）、ungrouped 僅未分組
	var nodeID *uint
	if raw := c.Query("node_id"); raw != "" {
		id64, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			// 非法值明確拒絕，不得靜默退化為無過濾
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidNodeID, nil)
			return
		}
		id := uint(id64)
		nodeID = &id
	}
	includeSubtree := c.Query("include_subtree") != "false"
	ungrouped := c.Query("ungrouped") == "true"

	// 範圍化檢視者的判定先於篩選參數：標籤與待配憑證篩選都依它開放
	scopeView, err := h.assetScopeView(c)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
		return
	}
	scopedNonPrivileged := scopeView != nil && !isPrivilegedRole(c)

	// 標籤篩選參數：admin/auditor 全量分支與範圍化檢視者（在其可視集合內、分頁之前）；
	// 其他主體帶參數明確拒 400——不得靜默忽略（同型教訓：
	// 參數被忽略＝篩選對一般 user 全面失效）
	var tagFilters []string
	if raw := c.Query("tags"); raw != "" {
		if !isPrivilegedRole(c) && !scopedNonPrivileged {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeTagFilterPrivilegedOnly, nil)
			return
		}
		parsed, err := asset.ParseTagsQuery(raw)
		if err != nil {
			// ParseTagsQuery 目前僅回 ErrTooManyTags；未知錯誤仍維持 400
			// （與遷移前 err.Error() 同狀態碼），以通用參數碼呈現
			code, ok := tagValidationCode(err)
			if !ok {
				code = apierror.CodeBadParams
			}
			apierror.Respond(c, http.StatusBadRequest, code, nil)
			return
		}
		tagFilters = parsed
	}

	// 待配憑證篩選：僅 admin/auditor 全量分支；一般使用者帶參數明確拒 400
	//（比照標籤篩選：參數被靜默忽略＝篩選對一般 user 失效而無人察覺）
	credentialPending := false
	if raw := c.Query("credential_pending"); raw != "" {
		if !isPrivilegedRole(c) && !scopedNonPrivileged {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
			return
		}
		credentialPending = raw == "true"
	}

	// 範圍化檢視者（非檢視捷徑）：管理可視 ∪ 連線可視，篩選在聯集內、分頁之前；
	// 明示 authorized_only=true 時候選集縮為連線可視，其餘（遮罩、旗標、摘要）沿用
	if scopedNonPrivileged {
		h.scopedList(c, scopeView, scopedListQuery{
			page: page, pageSize: pageSize, nodeID: nodeID, includeSubtree: includeSubtree,
			ungrouped: ungrouped, credentialPending: credentialPending, tags: tagFilters,
			connectionOnly: c.Query("authorized_only") == "true",
		})
		return
	}

	if authorizedOnly {
		// 獲取目前用戶
		userID, exists := middleware.GetCurrentUserID(c)
		if !exists {
			apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
			return
		}

		// 獲取用戶已授權的資產（至少需要 view 權限）
		// 將 Gin Context 中的主體傳遞到 Go context
		assets, err := authorizedAssetsOf(c.Request.Context(), h.authorizationService, middleware.PrincipalFrom(c), userID)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAuthorizedAssetQuery, err)
			return
		}

		// 授權集合內套用篩選與分頁（P2-1）：前端篩選/分頁控制項須在此生效
		filtered := filterAuthorizedAssets(assets, c.Query("search"), c.Query("protocol"), c.Query("active"))

		// 節點過濾在授權集合內生效（收斂樹點選同樣過濾右表）
		if nodeID != nil || ungrouped {
			nodeSet, err := h.assetService.AssetIDsForNodeFilter(nodeID, includeSubtree, ungrouped)
			if err != nil {
				apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetNodeFilter, err)
				return
			}
			kept := make([]*authz.AuthorizedAssetDTO, 0, len(filtered))
			for _, dto := range filtered {
				if nodeSet[dto.ID] {
					kept = append(kept, dto)
				}
			}
			filtered = kept
		}
		total := len(filtered)
		start := (page - 1) * pageSize
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		pageRows := filtered[start:end]

		// 連線入口三態標註：僅一般 user
		// 分支、僅當頁列。標註失敗不擋列表（按鈕退回 permission 欄渲染，
		// 行為仍以簽發點政策閘為準）
		if h.accessState != nil && !isPrivilegedRole(c) {
			if err := h.accessState.AnnotateConnectStates(userID, pageRows); err != nil {
				log.Printf("[AssetList] 三態標註失敗（列表照常回傳）: %v", err)
			}
		}

		// 節點掛載資訊：僅當頁列，失敗不擋列表
		if err := h.authorizationService.FillNodeInfoForDTOs(pageRows); err != nil {
			log.Printf("[AssetList] 節點資訊填充失敗（列表照常回傳）: %v", err)
		}

		if kind, _ := middleware.GetPrincipalKind(c); kind == model.KindAgent {
			recorder, ok := h.authorizationService.(interface {
				RecordAgentVisibilityExposures(context.Context, uint, []uint) error
			})
			if !ok {
				apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, errors.New("agent visibility recorder not configured"))
				return
			}
			ids := make([]uint, 0, len(pageRows))
			for _, row := range pageRows {
				ids = append(ids, row.ID)
			}
			if err := recorder.RecordAgentVisibilityExposures(c.Request.Context(), userID, ids); err != nil {
				apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"data":      pageRows,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		})
		return
	}

	// admin/auditor 全量分支（帶過濾），分頁參數已於函式開頭解析
	filter := &asset.AssetFilter{
		Search:         c.Query("search"),
		Protocol:       model.ProtocolType(c.Query("protocol")),
		Page:           page,
		PageSize:       pageSize,
		NodeID:         nodeID,
		IncludeSubtree: includeSubtree,
		Ungrouped:      ungrouped,
		Tags:           tagFilters,

		CredentialPending: credentialPending,
	}

	// 解析啟用狀態
	if activeStr := c.Query("active"); activeStr != "" {
		active := activeStr == "true"
		filter.Active = &active
	}

	// 查詢資產
	result, err := h.assetService.List(filter)
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
		return
	}

	// auditor 連線入口判定欄：當頁列標
	// permission——顯式 connect grant 命中標 connect、餘標 view。集合查詢失敗
	// 不擋列表、當頁全標 view（寧缺勿假，行為以簽發點為準）。admin 回應形狀凍結
	if isAuditorRole(c) {
		var connectable map[uint]bool
		if userID, ok := middleware.GetCurrentUserID(c); ok {
			ids, err := h.authorizationService.ExplicitAuthorizedAssetIDs(userID, model.PermissionConnect)
			if err != nil {
				log.Printf("[AssetList] auditor 顯式授權集合查詢失敗（當頁標 view）: %v", err)
			} else {
				connectable = ids
			}
		}
		rows := make([]assetWithEntryPermission, len(result.Data))
		for i, a := range result.Data {
			perm := model.PermissionView
			if connectable[a.ID] {
				perm = model.PermissionConnect
			}
			rows[i] = assetWithEntryPermission{Asset: a, Permission: perm}
		}
		if scopeView != nil {
			decorated, err := decorateFullRows(rows, func(i int) []uint { return rows[i].NodeIDs }, scopeView)
			if err != nil {
				apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"data": decorated, "total": result.Total, "page": result.Page, "page_size": result.PageSize,
				assetFieldManagementScope: managementScopeOf(scopeView),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"data":      rows,
			"total":     result.Total,
			"page":      result.Page,
			"page_size": result.PageSize,
		})
		return
	}

	if scopeView != nil {
		decorated, err := decorateFullRows(result.Data, func(i int) []uint { return result.Data[i].NodeIDs }, scopeView)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"data": decorated, "total": result.Total, "page": result.Page, "page_size": result.PageSize,
			assetFieldManagementScope: managementScopeOf(scopeView),
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get 取得資產詳情
func (h *AssetHandler) Get(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}

	// 逐資產授權由 RequireAssetVisible 中介層守門

	// 查詢資產
	assetRow, err := h.assetService.GetByID(uint(id))
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			middleware.RespondTargetNotFound(c, authz.ScopeTargetAsset, authz.ScopeLayerAsset)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
		return
	}

	// 範圍化檢視者：歸屬依管理可視遮蔽並附旗標；其餘主體回應不變
	if h.assetScope != nil {
		row, served, err := h.scopedDetail(c, assetRow, true)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetQuery, err)
			return
		}
		if served {
			c.JSON(http.StatusOK, row)
			return
		}
	}

	c.JSON(http.StatusOK, assetRow)
}

// ListTags 標籤清單：canonical 去重＋使用數，
// 供篩選下拉、表單自動完成與治理介面共用
func (h *AssetHandler) ListTags(c *gin.Context) {
	// 全表彙整含未授權資產的標籤詞彙，一般 user 拒絕（洩漏面，
	// 與「404 不洩漏資產存在性」紅線同源）
	if !isPrivilegedRole(c) {
		h.scopedListTags(c)
		return
	}
	tags, err := h.assetService.ListTags()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTagListQuery, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": tags})
}

// requireAdminRole 標籤治理端點守衛：僅內建超管（超管保留能力，不是權限點；auditor 亦拒）。
//
// 登錄項為 BaseAuthenticated，故不具資產寫入能力者也會走到這裡。兩種拒絕回應同形（能力拒絕單一形狀），
// 只在審計依據上區分：缺資產寫入能力者記該權限點，其餘非超管者記超管保留條件。
func requireAdminRole(c *gin.Context) bool {
	p := middleware.PrincipalFrom(c)
	if p.IsSuperAdmin() {
		return true
	}
	if !p.Has(authz.PermAssetUpdate) {
		middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(authz.PermAssetUpdate))
		return false
	}
	middleware.WriteCapabilityDenial(c, middleware.ReservedCapabilityDenial(authz.ReservedSuperAdmin))
	return false
}

// withFieldCapability 把「主體是否持有某請求欄位的額外能力」綁進 ctx，
// 供資產服務在載入目標之後、寫入之前以實際會變更的欄位判定。
// 判定取自本路由登錄項上宣告的欄位條件，並回報經權限點或經相容並列能力通過；未宣告的欄位一律不通過。
func withFieldCapability(c *gin.Context, ctx context.Context) context.Context {
	principal := middleware.PrincipalFrom(c)
	method, fullPath := c.Request.Method, c.FullPath()
	ctx = asset.WithFieldCapabilityKey(ctx, func(field string) string {
		return fieldPermissionKey(method, fullPath, field)
	})
	return asset.WithFieldCapability(ctx, func(field string) asset.FieldCapGrant {
		switch authz.FieldCapabilityGrantOf(method, fullPath, field, principal) {
		case authz.FieldGrantCompat:
			return asset.FieldCapViaCompat
		case authz.FieldGrantPerm:
			return asset.FieldCapViaPerm
		}
		return asset.FieldCapDenied
	})
}

// tagGovernanceContext 將操作者身分注入 ctx（審計 hook 取用）
func tagGovernanceContext(c *gin.Context) context.Context {
	return operatorRequestContext(c)
}

// operatorRequestContext 將已驗證的操作者身分（userID／username）注入請求 ctx，
// 供服務層交易與 GORM 稽核 hook 取用
func operatorRequestContext(c *gin.Context) context.Context {
	ctx := c.Request.Context()
	if userID, exists := middleware.GetCurrentUserID(c); exists {
		ctx = context.WithValue(ctx, "userID", userID)
	}
	if username, exists := c.Get("username"); exists {
		ctx = context.WithValue(ctx, "username", username)
	}
	return ctx
}

// RenameTagRequest 標籤改名/合併請求
type RenameTagRequest struct {
	From string `json:"from" binding:"required"`
	To   string `json:"to" binding:"required"`
}

// RenameTag 標籤全面改名/合併
func (h *AssetHandler) RenameTag(c *gin.Context) {
	if !requireAdminRole(c) {
		return
	}
	var req RenameTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	affected, err := h.assetService.RenameTag(tagGovernanceContext(c), req.From, req.To)
	if err != nil {
		if code, ok := tagValidationCode(err); ok {
			apierror.Respond(c, http.StatusBadRequest, code, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTagRename, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"affected": affected})
}

// DeleteTagRequest 標籤刪除請求（POST body 避免 URL 編碼 unicode 標籤名）
type DeleteTagRequest struct {
	Name string `json:"name" binding:"required"`
}

// DeleteTag 標籤全面刪除
func (h *AssetHandler) DeleteTag(c *gin.Context) {
	if !requireAdminRole(c) {
		return
	}
	var req DeleteTagRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	affected, err := h.assetService.DeleteTag(tagGovernanceContext(c), req.Name)
	if err != nil {
		// 統一改走 tagValidationCode：全部標籤驗證 sentinel 一律 400
		//（與 Create/Update/RenameTag 一致，不再只映 ErrTagEmpty）
		if code, ok := tagValidationCode(err); ok {
			apierror.Respond(c, http.StatusBadRequest, code, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTagDelete, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"affected": affected})
}

// Create 創建資產
func (h *AssetHandler) Create(c *gin.Context) {
	var req asset.CreateAssetRequest

	// 綁定 JSON
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	// 從 JWT token 取得目前用戶 ID
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		apierror.Respond(c, http.StatusUnauthorized, apierror.CodeUnauthenticated, nil)
		return
	}
	req.CreatedBy = userID
	if name, ok := c.Get("username"); ok {
		if n, ok := name.(string); ok {
			req.CreatedByName = n
		}
	}

	// 創建資產：ctx 帶已驗證的操作者，建立稽核列記到操作者而非 system
	// ctx 另帶主體：服務在建立交易內重解並判定初始歸屬的範圍
	assetRow, err := h.assetService.Create(withFieldCapability(c, assetWriteContext(c, operatorRequestContext(c))), &req)
	if err != nil {
		respondAssetError(c, apierror.CodeInternalAssetCreate, err)
		return
	}

	// POST /assets 路徑上沒有 :id，中介層推導不出主體；資產 id 建立完才存在，
	// 只有此處知道（auditor-workbench）
	setAuditAssetIDValue(c, assetRow.ID)

	// 範圍化檢視者的回應與詳情同遮蔽
	h.writeScopedAssetResponse(c, http.StatusCreated, assetRow)
}

// maxUpdateGateBody 欄位閘讀取本文的上限；超過視為不可解析（需資產編輯能力，後續綁定自會拒絕）
const maxUpdateGateBody = 32 << 20

// requireUpdateFieldGate PUT /assets/:id 的欄位閘（handler 第一步，先於路徑參數驗證、資產查詢與本文綁定）。
// 路由登錄為「僅需登入」，能力由本文頂層鍵決定：只含 access_policy 者需存取政策權限點；
// 含其他鍵、空本文或不可解析者需資產編輯能力；兩個權限點皆無時一律 403，審計依據記資產編輯能力，
// 與原守衛同序（不存在的資產 ID 也是 403）。回應為能力拒絕單一形狀，不帶缺的權限點。本文讀完後放回，供後續綁定使用。
func requireUpdateFieldGate(c *gin.Context) bool {
	var raw []byte
	if c.Request.Body != nil {
		raw, _ = io.ReadAll(io.LimitReader(c.Request.Body, maxUpdateGateBody+1))
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	}
	var obj map[string]json.RawMessage
	parsed := len(raw) <= maxUpdateGateBody && json.Unmarshal(raw, &obj) == nil && obj != nil
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	ok, missing := authz.BodyKeyGate(c.Request.Method, c.FullPath(), middleware.PrincipalFrom(c), keys, parsed)
	if ok {
		return true
	}
	if missing == "" {
		missing = authz.PermAssetUpdate
	}
	middleware.WriteCapabilityDenial(c, middleware.AllOfCapabilityDenial(missing))
	return false
}

// Update 更新資產
func (h *AssetHandler) Update(c *gin.Context) {
	if !requireUpdateFieldGate(c) {
		return
	}
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}

	var req asset.UpdateAssetRequest

	// 綁定 JSON
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}

	// 提取用戶資訊並放入 context
	ctx := c.Request.Context()
	if userID, exists := c.Get("userID"); exists {
		ctx = context.WithValue(ctx, "userID", userID)
	}
	if username, exists := c.Get("username"); exists {
		ctx = context.WithValue(ctx, "username", username)
	}

	// 登錄閘判過範圍時，服務在寫入交易內以同一組判定重判（掛載改動後目標可能已不在範圍內）
	ctx = asset.WithTxScopeRecheck(ctx, middleware.TxScopeRecheck(c))
	// 帶主體：服務在更新交易內重解並判定編輯、停用與節點合併的範圍
	ctx = assetWriteContext(c, ctx)

	// 更新資產（傳遞 context 以記錄審計）
	assetRow, err := h.assetService.Update(withFieldCapability(c, ctx), uint(id), &req)
	if err != nil {
		respondAssetError(c, apierror.CodeInternalAssetUpdate, err)
		return
	}

	// 只含存取政策者：經節點範圍持有該權限點時，回應依該權限點投影（與覆寫清單同形），不依資產檢視範圍
	if asset.AccessPolicyOnlyUpdate(&req) && h.writeAccessPolicyUpdateResponse(c, assetRow.ID) {
		return
	}
	// 範圍化檢視者的回應與詳情同遮蔽（範圍外歸屬不出）
	h.writeScopedAssetResponse(c, http.StatusOK, assetRow)
}

// Delete 刪除資產
func (h *AssetHandler) Delete(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}

	// 刪除資產：服務在刪除交易內取序列化鎖、重解主體並判定範圍與刪停歸屬規則
	if err := h.assetService.Delete(assetWriteContext(c, operatorRequestContext(c)), uint(id)); err != nil {
		respondAssetError(c, apierror.CodeInternalAssetDelete, err)
		return
	}

	// 成功回應不攜帶 UI 文案：前端以 $t('assets.deleted') 自有文案提示。
	// 仍回空 JSON 物件而非空 body，維持「200 一律是 JSON」的回應形狀慣例。
	c.JSON(http.StatusOK, gin.H{})
}

// TestConnectionRequest 測試連線請求
type TestConnectionRequest struct {
	Timeout int `json:"timeout"` // 超時秒數，可選，默認 10
}

// TestConnection 測試連線
func (h *AssetHandler) TestConnection(c *gin.Context) {
	// 解析 ID
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}

	// 解析請求參數（可選）
	var req TestConnectionRequest
	req.Timeout = 10 // 默認 10 秒

	// 嘗試綁定 JSON，如果失敗則使用默認值
	_ = c.ShouldBindJSON(&req)

	// 調用 Service 層執行連線測試
	// 帶入操作者與來源位址：SSH 撥測的主機金鑰不符審計與告警以測試發起者為連線使用者
	result, err := h.assetService.TestConnection(asset.ContextWithClientIP(operatorRequestContext(c), sourceip.Of(c)), uint(id), req.Timeout)
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			middleware.RespondTargetNotFound(c, authz.ScopeTargetAsset, authz.ScopeLayerAsset)
			return
		}
		// err 僅來自憑證讀取（撥接結果在 result 內），屬內部錯誤不外洩
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalAssetTestConnection, err)
		return
	}

	// 返回測試結果
	c.JSON(http.StatusOK, result)
}

// ListK8sPods GET /assets/:id/k8s/pods — 列 namespace 內活 pod 供連線時選擇器
func (h *AssetHandler) ListK8sPods(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	// 逐資產授權由 RequireAssetVisible 中介層守門；只經管理可視者另需測試連線能力涵蓋該資產
	if middleware.AssetVisibleViaManagement(c) && !h.requireManagedTest(c, uint(id)) {
		return
	}
	pods, err := h.assetService.ListK8sPods(c.Request.Context(), uint(id))
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			middleware.RespondTargetNotFound(c, authz.ScopeTargetAsset, authz.ScopeLayerAsset)
			return
		}
		// 零帳號資產（空 token）於服務層即擋，不以匿名身分打叢集
		if errors.Is(err, asset.ErrAssetNoUsableAccount) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoneUsable, nil)
			return
		}
		// k8sproxy 的六類分類（不可達/TLS/401/403/404/unknown）逐類配碼——
		// 與 WS 撥號路徑共用 k8sproxy.ErrCodeOf（原本此處
		// 一律回泛碼 RULE_K8S_POD_UNAVAILABLE，同一分類在兩條路徑上碼不同）。
		// 機器欄 kind 仍經 Meta 保留（既有前端契約）。
		var ke *k8sproxy.K8sError
		if errors.As(err, &ke) {
			log.Printf("[ListK8sPods] k8s 錯誤: kind=%s err=%v", ke.Kind, ke)
			apierror.Write(c, http.StatusBadGateway, apierror.ErrorResponse{
				Code: k8sproxy.ErrCodeOf(err),
				Meta: map[string]any{"kind": ke.Kind},
			})
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalK8sPodList, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"pods": pods})
}

// auditK8sFile 直接落 audit_log（kubectl cp 檔名/大小/方向，k8s-exec）
func (h *AssetHandler) auditK8sFile(c *gin.Context, userID, assetID uint, action model.AuditAction, detail string) {
	username, _ := middleware.GetCurrentUsername(c)
	aid := assetID
	if h.auditSink == nil {
		log.Printf("[AssetHandler] 稽核投遞面未注入，k8s 檔案操作留痕已丟失 (asset=%d action=%s)", assetID, action)
		return
	}
	// 收口（AP-04）：改經 AsyncSink，繞過 AuditLogEnabled 分支。
	// **error 仍然完全不檢查**——那是既有缺陷，修它是行為變更，不在等價搬遷範圍
	//（現況 database.DB.Create 的回傳同樣被丟棄）
	_ = h.auditSink.Submit(c.Request.Context(), gatewayapi.AuditEvent{
		Action:     string(action),
		Resource:   string(model.ResourceFile),
		ResourceID: &aid,
		// ResourceID 維持既有語義（resource=file 的既有查詢靠它），主體鍵另記：
		// 工作台的檔案傳輸類只讀 asset_id（auditor-workbench）
		AssetID: &aid,
		Status:  string(model.StatusSuccess),
		Actor:   gatewayapi.Actor{UserID: userID, Username: username},
		Request: gatewayapi.RequestMeta{
			Method:     c.Request.Method,
			Path:       c.FullPath(),
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusOK,
			Body:       detail,
		},
	})
}

// auditK8sFileDenied 記錄被資料傳輸閘擋下的 K8s 檔案操作（status=denied）
func (h *AssetHandler) auditK8sFileDenied(c *gin.Context, userID, assetID uint, action model.AuditAction, detail string) {
	username, _ := middleware.GetCurrentUsername(c)
	aid := assetID
	if h.auditSink == nil {
		log.Printf("[AssetHandler] 稽核投遞面未注入，k8s 檔案拒絕留痕已丟失 (asset=%d action=%s)", assetID, action)
		return
	}
	_ = h.auditSink.Submit(c.Request.Context(), gatewayapi.AuditEvent{
		Action:     string(action),
		Resource:   string(model.ResourceFile),
		ResourceID: &aid,
		// 同成功路徑：被拒的傳輸企圖同樣是「對這台資產做的事」，
		// 主體鍵缺了工作台就看不到它（auditor-workbench）
		AssetID: &aid,
		Status:  string(model.StatusDenied),
		Actor:   gatewayapi.Actor{UserID: userID, Username: username},
		Request: gatewayapi.RequestMeta{
			Method:     c.Request.Method,
			Path:       c.FullPath(),
			ClientIP:   sourceip.Of(c),
			StatusCode: http.StatusForbidden,
			Body:       detail,
		},
	})
}

// UploadK8sFile POST /assets/:id/k8s/upload — 上傳檔到選定 pod/container（kubectl cp）
func (h *AssetHandler) UploadK8sFile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	// 資料面裁決先於一切：被拒的請求不解析上傳內容、不建暫存檔
	if !h.requireK8sDataPlane(c, userID, uint(id), policy.TransferActionFileUpload) {
		return
	}
	pod := c.PostForm("pod")
	container := c.PostForm("container")
	destDir := c.PostForm("dest_path")
	if destDir == "" {
		destDir = "/tmp"
	}
	fileHeader, err := c.FormFile("file")
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeUploadFileMissing, nil)
		return
	}
	tmp, err := os.CreateTemp("", "k8scp-*")
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTempFileCreate, err)
		return
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)
	if err := c.SaveUploadedFile(fileHeader, tmpPath); err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalUploadFileSave, err)
		return
	}
	// 本文已完整暫存。本文的送達時間由客戶端控制，撤權、停用資產、核准時窗到期都可能落在
	// 早期裁決與此刻之間；解封憑證與遠端寫入之前以此刻的授權事實再完整裁決一次。
	// 早期裁決保留：被拒的請求不解析本文、不建暫存檔。
	//（下載沒有本文，裁決與 `kubectl cp` 之間沒有客戶端可控的窗口，維持單次裁決；
	// 裁決通過後傳輸進行中的撤銷或到期不中斷傳輸，為本版已知限制。）
	if !h.requireK8sDataPlane(c, userID, uint(id), policy.TransferActionFileUpload) {
		return
	}
	destPath := path.Join(destDir, path.Base(fileHeader.Filename))
	if !h.requireK8sTransferAllowed(c, userID, uint(id), policy.TransferActionFileUpload,
		fmt.Sprintf(`{"direction":"upload","pod":%q,"container":%q,"path":%q}`, pod, container, destPath)) {
		return
	}
	if err := h.assetService.K8sCopyToPod(c.Request.Context(), uint(id), pod, container, destPath, tmpPath); err != nil {
		if errors.Is(err, asset.ErrAssetNoUsableAccount) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoneUsable, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusBadGateway, apierror.CodeK8sCopy, err)
		return
	}
	h.auditK8sFile(c, userID, uint(id), model.ActionFileUpload,
		fmt.Sprintf(`{"direction":"upload","pod":%q,"container":%q,"path":%q,"size":%d}`, pod, container, destPath, fileHeader.Size))
	c.JSON(http.StatusOK, gin.H{"path": destPath, "size": fileHeader.Size})
}

// DownloadK8sFile GET /assets/:id/k8s/download?pod=&container=&path= — 從容器下載檔
func (h *AssetHandler) DownloadK8sFile(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidID, map[string]any{"resource": "asset"})
		return
	}
	userID, _ := middleware.GetCurrentUserID(c)
	if !h.requireK8sDataPlane(c, userID, uint(id), policy.TransferActionFileDownload) {
		return
	}
	pod := c.Query("pod")
	container := c.Query("container")
	srcPath := c.Query("path")
	if srcPath == "" {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeFilePathMissing, nil)
		return
	}
	if !h.requireK8sTransferAllowed(c, userID, uint(id), policy.TransferActionFileDownload,
		fmt.Sprintf(`{"direction":"download","pod":%q,"container":%q,"path":%q}`, pod, container, srcPath)) {
		return
	}
	tmp, err := os.CreateTemp("", "k8scp-*")
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalTempFileCreate, err)
		return
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	// 先刪預建檔，讓 kubectl cp 自己建：kubectl cp 對「容器內不存在的來源」會 exit 0
	// 但不產生本地檔，故以「是否建出檔案」判斷來源是否真的存在（否則會把失敗的下載
	// 偽裝成 200 空檔，誤導使用者）。
	_ = os.Remove(tmpPath)
	defer os.Remove(tmpPath)
	if err := h.assetService.K8sCopyFromPod(c.Request.Context(), uint(id), pod, container, srcPath, tmpPath); err != nil {
		if errors.Is(err, asset.ErrAssetNoUsableAccount) {
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoneUsable, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusBadGateway, apierror.CodeK8sCopy, err)
		return
	}
	info, statErr := os.Stat(tmpPath)
	if statErr != nil {
		// 請求方自帶的 path 不再回填訊息（apierror params 僅收受控 enum/int）；
		// 前端已有該路徑，可自行組字
		apierror.Respond(c, http.StatusNotFound, apierror.CodeK8sFileNotFound, nil)
		return
	}
	if info.IsDir() {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeK8sPathIsDir, nil)
		return
	}
	h.auditK8sFile(c, userID, uint(id), model.ActionFileDownload,
		fmt.Sprintf(`{"direction":"download","pod":%q,"container":%q,"path":%q,"size":%d}`, pod, container, srcPath, info.Size()))
	c.FileAttachment(tmpPath, path.Base(srcPath))
}

// RegisterRoutes 註冊資產相關路由
func (h *AssetHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	assets := r.Group("/assets")
	assets.Use(middleware.AuthMiddleware(authService))

	// 逐資產可視性守門：無條件生效（權限旗標已退場；讀取端點無條件
	// 守門紅線），故在兩分支皆掛，且置於 RequirePermission 之後
	visible := middleware.RequireAssetVisibleOrManaged(h.authorizationService, h.managementVisibility())

	assets.GET("", middleware.EnforceRegistry(h.scopeGate), h.List)
	// 標籤清單/治理：/tags 與 /:id 共存已實測；
	// 角色細分（清單 admin/auditor、治理僅 admin）在 handler 內守衛
	assets.GET("/tags", middleware.EnforceRegistry(h.scopeGate), h.ListTags)
	assets.POST("/tags/rename", middleware.EnforceRegistry(h.scopeGate), h.RenameTag)
	assets.POST("/tags/delete", middleware.EnforceRegistry(h.scopeGate), h.DeleteTag)
	assets.POST("", middleware.EnforceRegistry(h.scopeGate), h.Create)
	// 批次新增：預檢（唯讀）與整批寫入，權限同單筆建立
	assets.POST("/import/preview", middleware.EnforceRegistry(h.scopeGate), h.PreviewImport)
	assets.POST("/import", middleware.EnforceRegistry(h.scopeGate), h.Import)
	// 單台存取政策覆寫清單：依存取政策權限點的範圍投影（靜態段，與 /:id 不衝突）
	assets.GET("/access-policy-overrides", middleware.EnforceRegistry(h.scopeGate), h.ListAccessPolicyOverrides)
	assets.GET("/:id", middleware.EnforceRegistry(h.scopeGate), visible, h.Get)
	assets.PUT("/:id", middleware.EnforceRegistry(h.scopeGate), h.Update)
	assets.DELETE("/:id", middleware.EnforceRegistry(h.scopeGate), h.Delete)
	assets.POST("/:id/test-connection", middleware.EnforceRegistry(h.scopeGate), h.TestConnection)
	assets.GET("/:id/k8s/pods", middleware.EnforceRegistry(h.scopeGate), visible, h.ListK8sPods)
	// 容器檔案進出是資料面：登錄為已認證（資料面類別），授權在 handler 內經
	// DataPlaneAuthorizer 走與連線簽發同一組閘序；管理權限點不是放行條件
	assets.POST("/:id/k8s/upload", middleware.EnforceRegistry(h.scopeGate), h.UploadK8sFile)
	assets.GET("/:id/k8s/download", middleware.EnforceRegistry(h.scopeGate), h.DownloadK8sFile)
	// 批次搬移、加標籤、刪除（見 asset_batch_handler.go）
	h.registerBatchRoutes(assets)
}
