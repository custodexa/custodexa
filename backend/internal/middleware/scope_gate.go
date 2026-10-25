package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 登錄閘的目標範圍判定。
//
// 登錄項在範圍宣告表（authz.RouteScopeDecl）宣告了目標解析時，登錄閘在能力判定通過後，
// 從路徑參數解析出目標、交範圍判定器判定，結果交 RespondAuthzDecision 寫出：
// 範圍外、已刪除與不存在對範圍化主體為同一個「不存在」回應。未宣告的登錄項不經本檔，行為不變。
//
// 判定器、讀取連線與宣告表由組裝端建構 ScopeGate 後經 handler 的建構參數交給登錄閘，
// 不經套件層狀態。沒有拿到 ScopeGate 的登錄閘遇到宣告了目標的登錄項一律回 500，不放行。

// ScopeGate 登錄閘的範圍判定依賴；建構後不可變。
type ScopeGate struct {
	db    *gorm.DB
	eval  *authz.ScopeEvaluator
	decls map[string][]authz.RouteScopeDecl // 鍵同 RouteEntry.Key()；只收 Kind == target
}

// NewScopeGate 建構登錄閘的範圍判定依賴。decls 只取目標解析宣告（列表投影與批次集合由各自的
// handler 處理），建構時複製。
func NewScopeGate(db *gorm.DB, eval *authz.ScopeEvaluator, decls []authz.RouteScopeDecl) *ScopeGate {
	return &ScopeGate{db: db, eval: eval, decls: indexTargetDecls(decls)}
}

func indexTargetDecls(decls []authz.RouteScopeDecl) map[string][]authz.RouteScopeDecl {
	m := map[string][]authz.RouteScopeDecl{}
	for _, d := range decls {
		if d.Kind != authz.ScopeDeclTarget {
			continue
		}
		k := d.Method + " " + d.Path
		m[k] = append(m[k], d)
	}
	return m
}

// targetDeclsFor 本請求登錄項的目標解析宣告。沒有 ScopeGate 時查正式宣告表，
// 使「宣告了卻沒注入判定器」可被偵測而不是被略過。
func targetDeclsFor(g *ScopeGate, method, fullPath string) []authz.RouteScopeDecl {
	k := method + " " + fullPath
	if g != nil {
		return g.decls[k]
	}
	return productTargetDecls[k]
}

// productTargetDecls 正式宣告表的目標解析索引；宣告表建構後不變，套件初始化時建一次，
// 不在每個請求重建。
var productTargetDecls = indexTargetDecls(authz.RouteScopeDeclarations())

// enforceRegistry 登錄閘本體：能力判定（authz.DecideRoute）通過後，宣告了目標的登錄項再做範圍判定。
func enforceRegistry(c *gin.Context, g *ScopeGate) {
	p := PrincipalFrom(c)
	d := authz.DecideRoute(c.Request.Method, c.FullPath(), p)
	switch {
	case d.Allowed:
		if enforceTargetScope(c, g, p) {
			return
		}
		c.Next()
	case d.Unauthenticated:
		abortUnauthenticated(c, apierror.CodeUnauthenticated)
	default:
		WriteCapabilityDenial(c, RouteCapabilityDenial(d))
	}
}

// enforceTargetScope 對本請求生效的每一條目標宣告呼叫判定器；回 true 表示已寫出回應。
// 能力先於範圍：任一宣告為能力拒絕即以能力拒絕寫出；否則任一為範圍拒絕即以範圍拒絕寫出；
// 判定結果不一致時交出口回 500。
func enforceTargetScope(c *gin.Context, g *ScopeGate, p *authz.Principal) bool {
	decls := targetDeclsFor(g, c.Request.Method, c.FullPath())
	if len(decls) == 0 {
		return false
	}
	if g == nil || g.eval == nil || g.db == nil {
		return respondScopeGateInternal(c, "declared target route without scope evaluator")
	}
	active, err := declsInEffect(c, decls)
	if err != nil {
		return respondScopeGateInternal(c, err.Error())
	}
	type outcome struct {
		res    authz.ScopeResult
		denied *authz.ErrScopeDenied
		basis  CapabilityDenial
	}
	var capDeny, scopeDeny *outcome
	var checks []txScopeCheck
	tx := g.db.WithContext(c.Request.Context())
	for _, d := range active {
		target, ok := scopeTargetFromParams(c, d.Target)
		if !ok {
			return respondScopeGateInternal(c, "declared target kind cannot be resolved from route params: "+string(d.Target))
		}
		res, denied, err := g.eval.DecideWithDenial(tx, p, d.Perm, target)
		if err != nil {
			apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionCheck, err)
			c.Abort()
			return true
		}
		checks = append(checks, txScopeCheck{perm: d.Perm, target: target})
		o := &outcome{res: res, denied: denied, basis: AllOfCapabilityDenial(d.Perm)}
		switch {
		case res.Outcome == authz.ScopeAllow && denied == nil:
		case res.Outcome == authz.ScopeDenyCapability && denied == nil:
			if capDeny == nil {
				capDeny = o
			}
		case res.Outcome == authz.ScopeDenyScope && denied != nil:
			if scopeDeny == nil {
				scopeDeny = o
			}
		default:
			return RespondAuthzDecision(c, o.res, o.denied, o.basis) // 不一致：出口回 500
		}
	}
	switch {
	case capDeny != nil:
		return RespondAuthzDecision(c, capDeny.res, capDeny.denied, capDeny.basis)
	case scopeDeny != nil:
		return RespondAuthzDecision(c, scopeDeny.res, scopeDeny.denied, scopeDeny.basis)
	}
	rememberTxScopeRecheck(c, g, p, checks) // 服務在寫入交易內重判（scope_tx_recheck.go）
	return false
}

// respondScopeGateInternal 宣告與接線不一致（呼叫端錯誤）：500、不放行，成因只落伺服端日誌。
func respondScopeGateInternal(c *gin.Context, cause string) bool {
	apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalPermissionCheck,
		errors.New("authz: scope gate: "+cause))
	c.Abort()
	return true
}

// declsInEffect 本請求生效的目標宣告：基本要求恆生效；欄位條件依本文頂層鍵決定
// （具名欄位在本文出現時生效，萬用欄位的判準見 wildcardFieldInEffect）。
// 並列進入能力（AnyOf）的目標宣告尚未支援，回錯誤使登錄閘不放行。
func declsInEffect(c *gin.Context, decls []authz.RouteScopeDecl) ([]authz.RouteScopeDecl, error) {
	var keys []string
	parsed, read := false, false
	out := make([]authz.RouteScopeDecl, 0, len(decls))
	for _, d := range decls {
		switch d.Source {
		case authz.ReqSourcePerm:
			out = append(out, d)
		case authz.ReqSourceFields:
			if !read {
				keys, parsed = requestBodyKeys(c)
				read = true
			}
			if fieldInEffect(d.Field, keys, parsed) {
				out = append(out, d)
			}
		default:
			return nil, errors.New("unsupported requirement source for target declaration: " + string(d.Source))
		}
	}
	return out, nil
}

// fieldInEffect 一條欄位條件對本文是否生效。
func fieldInEffect(field string, keys []string, parsed bool) bool {
	if field == authz.FieldWildcard {
		return wildcardFieldInEffect(keys, parsed)
	}
	for _, k := range keys {
		if strings.EqualFold(k, field) { // JSON 綁定不分大小寫，比對同樣不分
			return true
		}
	}
	return false
}

// wildcardAlternativeField 只含此鍵的本文不需萬用條件的權限點（與 authz.BodyKeyGate 同一判準）。
const wildcardAlternativeField = "access_policy"

// wildcardFieldInEffect 萬用欄位條件是否生效：本文為空、不可解析，或含 access_policy 以外的鍵。
// 與 authz.BodyKeyGate 要求萬用條件權限點的判準相同。
func wildcardFieldInEffect(keys []string, parsed bool) bool {
	if !parsed || len(keys) == 0 {
		return true
	}
	for _, k := range keys {
		if !strings.EqualFold(k, wildcardAlternativeField) {
			return true
		}
	}
	return false
}

// maxScopeGateBody 讀取本文判定欄位條件的上限；超過視為不可解析。
const maxScopeGateBody = 32 << 20

// requestBodyKeys 讀本文頂層鍵，讀完放回供後續綁定。parsed 為 false 表示本文為空或不是 JSON 物件。
func requestBodyKeys(c *gin.Context) (keys []string, parsed bool) {
	var raw []byte
	if c.Request.Body != nil {
		raw, _ = io.ReadAll(io.LimitReader(c.Request.Body, maxScopeGateBody+1))
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	}
	var obj map[string]json.RawMessage
	parsed = len(raw) <= maxScopeGateBody && json.Unmarshal(raw, &obj) == nil && obj != nil
	for k := range obj {
		keys = append(keys, k)
	}
	return keys, parsed
}

// scopeTargetFromParams 依目標種類從路徑參數組出判定目標。資產取 :id，資產帳號另取 :accountId。
// 參數不是合法 ID 時以 0 代入（不對應任何列）：範圍化主體得到與不存在相同的回應，
// 全域主體由判定器放行、交 handler 照舊驗參數。路由樣板缺參數或種類不支援回 false（不放行）。
func scopeTargetFromParams(c *gin.Context, kind authz.ScopeTargetKind) (authz.ScopeTarget, bool) {
	switch kind {
	case authz.ScopeTargetAsset:
		id, ok := routeIDParam(c, "id")
		return authz.AssetTarget(id), ok
	case authz.ScopeTargetAssetAccount:
		assetID, okA := routeIDParam(c, "id")
		accountID, okB := routeIDParam(c, "accountId")
		return authz.AssetAccountTarget(assetID, accountID), okA && okB
	}
	return authz.ScopeTarget{}, false
}

// routeIDParam 路徑參數的 ID；樣板沒有該參數回 false，值不合法回 (0, true)。
func routeIDParam(c *gin.Context, name string) (uint, bool) {
	if !hasPathParam(c.FullPath(), name) {
		return 0, false
	}
	v, err := strconv.ParseUint(c.Param(name), 10, 32)
	if err != nil {
		return 0, true
	}
	return uint(v), true
}

// hasPathParam 路由樣板是否有名為 name 的路徑參數（逐段精確比對）。
func hasPathParam(fullPath, name string) bool {
	for _, seg := range strings.Split(fullPath, "/") {
		if seg == ":"+name {
			return true
		}
	}
	return false
}
