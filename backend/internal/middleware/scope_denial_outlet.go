package middleware

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
)

// 範圍拒絕的共用出口與目標種類「不存在」對照。
//
// 判準：範圍化主體對範圍外目標得到的回應，必須等於全域主體對同一請求、在未通過範圍的
// 那個目標不存在時得到的回應。對照表是兩條路徑共用的唯一來源——handler 的真不存在分支
// 以 RespondTargetNotFound 寫出，範圍拒絕以 RespondScopeDenied 寫出，兩者查同一張表，
// 因此不會各自演變。
//
// 能力先於範圍與存在性：能力拒絕一律走 WriteCapabilityDenial 的 403 單一形狀，不查本表。
// 未登記的（種類, 層）不放行：回能力拒絕的 403 單一形狀、記伺服端日誌，脈絡標記的原因為
// kind_unmapped。批次整批無法操作另有 RespondBatchUnavailable，只帶筆數。

// 本段新增的範圍拒絕原因（在既有的三個範圍拒絕原因之外）。
const (
	ScopeReasonKindUnmapped          = "kind_unmapped"
	ScopeReasonBatchItemsUnavailable = "batch_items_unavailable"
)

// scopeDenialContextKey 範圍拒絕標記在請求脈絡中的鍵。
const scopeDenialContextKey = "authz_scope_denial"

// ScopeDenial 範圍拒絕的標記。Reason 為受控原因碼；HasCount 為真時 Count 是整批無法操作的筆數。
// 不帶目標、節點、使用者或群組的名稱或識別碼。
type ScopeDenial struct {
	Reason   string
	Count    int
	HasCount bool
}

// AuditDetails 本標記對應的審計細節鍵值（denial、scope_reason，整批另加 count）。
// 合併進 audit_details 的規則由審計中介層負責，本函式只產出鍵值。
func (d ScopeDenial) AuditDetails() map[string]string {
	m := map[string]string{"denial": "scope", "scope_reason": d.Reason}
	if d.HasCount {
		m["count"] = strconv.Itoa(d.Count)
	}
	return m
}

// ScopeDenialFrom 取本請求經範圍拒絕出口存下的標記；未經出口拒絕回 false。
func ScopeDenialFrom(c *gin.Context) (ScopeDenial, bool) {
	v, ok := c.Get(scopeDenialContextKey)
	if !ok {
		return ScopeDenial{}, false
	}
	d, ok := v.(ScopeDenial)
	return d, ok
}

// setScopeDenial 存範圍拒絕標記並設拒絕分類標記（審計狀態為 denied）。
func setScopeDenial(c *gin.Context, d ScopeDenial) {
	c.Set(scopeDenialContextKey, d)
	markAuthzDenial(c, denialKindScope)
}

// ScopeNotFoundRegistration 對照表的一列：（種類, 層）→ 該目標「不存在」的 404 碼與受控 params。
type ScopeNotFoundRegistration struct {
	Kind   authz.ScopeTargetKind
	Layer  authz.ScopeDeniedLayer
	Code   apierror.ErrCode
	Params map[string]any
}

// ScopeNotFoundRegistrations 回傳對照表全部列（每次新建，呼叫端修改不影響出口）。
//
// 登記資產、資產帳號與節點；資產帳號依不成立的層分兩列，資產層不成立等於「資產不存在」，
// 不得統一成帳號層。後段種類（憑證、授權規則與授權客體）由各段在此登記。
// 複製來源帳號不是目標種類，不在此表。
func ScopeNotFoundRegistrations() []ScopeNotFoundRegistration {
	return []ScopeNotFoundRegistration{
		{Kind: authz.ScopeTargetAsset, Layer: authz.ScopeLayerAsset, Code: apierror.CodeAssetNotFound},
		{Kind: authz.ScopeTargetAssetAccount, Layer: authz.ScopeLayerAsset, Code: apierror.CodeAssetNotFound},
		{Kind: authz.ScopeTargetAssetAccount, Layer: authz.ScopeLayerAccount, Code: apierror.CodeAssetAccountNotFound},
		// 節點：寫入的目標節點與建立、搬移的目的父節點同屬節點種類，不存在即「節點不存在」
		{Kind: authz.ScopeTargetNode, Layer: authz.ScopeLayerNode, Code: apierror.CodeAssetNodeNotFound},
		// 憑證：範圍外與不存在同為「憑證不存在」
		{Kind: authz.ScopeTargetCredential, Layer: authz.ScopeLayerTarget, Code: apierror.CodeCredentialNotFound},
		// 改密候選：範圍外（所屬資產不在範圍內）與不存在同為「候選不存在」
		{Kind: authz.ScopeTargetChangeSecretCandidate, Layer: authz.ScopeLayerTarget, Code: apierror.CodeCandidateNotFound},
		// 授權規則面：既有規則範圍外與不存在同為規則不存在；建立時的客體範圍外與不存在同為引用不存在
		// （單筆建立的 entity 與客體實際種類一致，資產分組即節點）
		{Kind: authz.ScopeTargetAuthorizationRule, Layer: authz.ScopeLayerTarget, Code: apierror.CodeAuthorizationNotFound},
		{Kind: authz.ScopeTargetAuthorizationObject, Layer: authz.ScopeLayerAsset, Code: apierror.CodeGrantReferenceNotFound, Params: map[string]any{"entity": "asset"}},
		{Kind: authz.ScopeTargetAuthorizationObject, Layer: authz.ScopeLayerNode, Code: apierror.CodeGrantReferenceNotFound, Params: map[string]any{"entity": "asset_group"}},
		// 審核範圍面：既有列範圍外、申請人型列對不具全域管理者、不存在，三者同為審核範圍不存在
		{Kind: authz.ScopeTargetApproverScope, Layer: authz.ScopeLayerTarget, Code: apierror.CodeApproverScopeNotFound},
	}
}

func lookupScopeNotFound(kind authz.ScopeTargetKind, layer authz.ScopeDeniedLayer) (ScopeNotFoundRegistration, bool) {
	for _, r := range ScopeNotFoundRegistrations() {
		if r.Kind == kind && r.Layer == layer {
			return r, true
		}
	}
	return ScopeNotFoundRegistration{}, false
}

func copyParams(p map[string]any) map[string]any {
	if len(p) == 0 {
		return nil
	}
	out := make(map[string]any, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// writeKindUnmapped 未登記（種類, 層）：不放行，回能力拒絕的 403 單一形狀並記伺服端日誌。
func writeKindUnmapped(c *gin.Context, kind authz.ScopeTargetKind, layer authz.ScopeDeniedLayer) {
	log.Printf("[authz] target kind not registered in not-found table: kind=%q layer=%q (path=%s)",
		string(kind), string(layer), c.FullPath())
	setScopeDenial(c, ScopeDenial{Reason: ScopeReasonKindUnmapped})
	writeCapabilityShape(c)
	c.Abort()
}

// RespondTargetNotFound handler 真不存在分支的寫出：查對照表回該（種類, 層）的 404，
// 不留範圍拒絕標記（全域主體對不存在目標的審計維持 failure）。kind 與 layer 須傳 authz 的具名常數。
func RespondTargetNotFound(c *gin.Context, kind authz.ScopeTargetKind, layer authz.ScopeDeniedLayer) {
	r, ok := lookupScopeNotFound(kind, layer)
	if !ok {
		writeKindUnmapped(c, kind, layer)
		return
	}
	apierror.Respond(c, http.StatusNotFound, r.Code, copyParams(r.Params))
}

// RespondScopeDenied 範圍拒絕的寫出：回應與該目標「不存在」相同，並留範圍拒絕標記。
// denied 為 nil 視為呼叫端錯誤，回 500 而不放行。
func RespondScopeDenied(c *gin.Context, denied *authz.ErrScopeDenied) {
	if denied == nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionCheck,
			errors.New("authz: scope denial outlet called without denial value"))
		c.Abort()
		return
	}
	r, ok := lookupScopeNotFound(denied.Kind, denied.Layer)
	if !ok {
		writeKindUnmapped(c, denied.Kind, denied.Layer)
		return
	}
	setScopeDenial(c, ScopeDenial{Reason: string(denied.Reason)})
	apierror.Respond(c, http.StatusNotFound, r.Code, copyParams(r.Params))
	c.Abort()
}

// RespondAuthzDecision 範圍判定結果的共用出口。回傳 true 表示已寫出回應，呼叫端應立即返回；
// false 表示放行，呼叫端繼續。
//
//   - 放行（且無拒絕值）→ false。
//   - 能力拒絕 → WriteCapabilityDenial(basis)；basis 由呼叫端依該操作實際要求的權限點或保留條件組出，
//     出口不從判定結果或路由判定讀取。
//   - 範圍拒絕 → RespondScopeDenied(denied)，依（種類, 層）查對照表。
//   - 其他（結果零值、範圍拒絕卻無拒絕值、放行卻帶拒絕值）→ 500，不放行。
func RespondAuthzDecision(c *gin.Context, res authz.ScopeResult, denied *authz.ErrScopeDenied, basis CapabilityDenial) bool {
	switch {
	case res.Outcome == authz.ScopeAllow && denied == nil:
		return false
	case res.Outcome == authz.ScopeDenyCapability && denied == nil:
		WriteCapabilityDenial(c, basis)
		return true
	case res.Outcome == authz.ScopeDenyScope && denied != nil:
		RespondScopeDenied(c, denied)
		return true
	}
	apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionCheck,
		errors.New("authz: inconsistent scope decision ("+res.Outcome.String()+")"))
	c.Abort()
	return true
}

// RespondBatchUnavailable 整批中有項目無法操作時的唯一寫出函式：404、只帶筆數。
// 無權、範圍外與不存在三種原因不可區分；呼叫端只傳筆數，不傳 ID。
func RespondBatchUnavailable(c *gin.Context, count int) {
	setScopeDenial(c, ScopeDenial{Reason: ScopeReasonBatchItemsUnavailable, Count: count, HasCount: true})
	apierror.Respond(c, http.StatusNotFound, apierror.CodeBatchItemsUnavailable, map[string]any{"count": count})
	c.Abort()
}
