package authz

import (
	"sort"
	"strings"
)

// 路由登錄。
//
// 登錄項＝(method, 路由樣板) → 基本要求 + 依請求欄位決定的額外能力。
// 登錄內容由產生器自路由清冊推導並寫入 route_registry_data.go；登錄表與路由清冊的一致性由 TestAuthzRegistryCoversRouteInventory 比對。
//
// 本檔不 import apierror（模組邊界守衛）：判定只回放行、未認證或拒絕依據；能力拒絕一律由
// internal/middleware 的單一寫出函式回應同一形狀，拒絕依據只進審計。

// BaseKind 路由的基本要求種類。
type BaseKind string

const (
	// BasePerm 需要一個權限點。
	BasePerm BaseKind = "perm"
	// BasePublic 無 AuthMiddleware 的公開端點（登入前或 scoped token 端點，由 handler 自行驗證）。
	BasePublic BaseKind = "public"
	// BaseAuthenticated 僅需登入。
	BaseAuthenticated BaseKind = "authenticated"
	// BaseSelf 只對本人資源生效；判定沿用 handler 內既有的本人比對，登錄只標記類別。
	BaseSelf BaseKind = "self"
	// BaseManual 手動認證入口（WebSocket／代理）：無 AuthMiddleware，由 handler 自行認證，
	// 以現查主體加資產授權判定；登錄只標記。
	BaseManual BaseKind = "manual"
)

// DenialBasis 能力拒絕的依據種類。只進審計細節，不進回應：回應對所有能力拒絕同形，
// 不讓操作者從回應得知缺哪個權限點或誰持有。
type DenialBasis string

const (
	// DenialAllOf 所列權限點都要持有（登錄項只有 Perm；欄位閘的缺漏鍵）。
	DenialAllOf DenialBasis = "all_of"
	// DenialAnyOf 所列權限點持其一即可（登錄項有 AnyOf：Perm 與 AnyOf 依登錄順序）。
	DenialAnyOf DenialBasis = "any_of"
	// DenialReserved 保留給特定內建身分或資格的條件（服務層提供受控條件值，非權限點）。
	DenialReserved DenialBasis = "reserved"
	// DenialUnregistered 路由未登錄（預設拒絕），無所列鍵。
	DenialUnregistered DenialBasis = "unregistered"
)

// 保留條件的受控值（DenialReserved 的所列鍵）。清單封閉：新增保留條件須先在此新增常數，
// 寫出點只能引用這些常數，不得自行拼字串。
const (
	// ReservedSuperAdmin 僅內建超管（Principal.IsSuperAdmin）。
	ReservedSuperAdmin = "superadmin"
	// ReservedSuperAdminOrAuditor 內建超管或稽核員（Principal.ViewShortcut）。
	ReservedSuperAdminOrAuditor = "superadmin_or_auditor"
	// ReservedApproverEligibility 審核資格（EvaluateApproverRouteEligibility）。
	ReservedApproverEligibility = "approver_eligibility"
	// ReservedRevokeEligibility 撤銷資格（EvaluateRevokeRouteEligibility）。
	ReservedRevokeEligibility = "revoke_eligibility"
)

// credentialWriteCapabilities 憑證寫入路由的並列進入能力：憑證語義管理能力任一。
// 服務層對每個動作逐項判定所需能力與影響集合，路由層只擋下毫無憑證管理能力的主體；
// 檢視能力不在其中（只能讀，不能進寫入路由）。
func credentialWriteCapabilities() []Permission {
	return []Permission{
		PermCredentialCreate, PermCredentialUpdate, PermCredentialSetSecret, PermCredentialRotate,
		PermCredentialConvertScope, PermCredentialDetach, PermCredentialDelete, PermCredentialBind,
	}
}

// FieldCondition 依請求欄位決定的額外能力：請求或回應含該欄位集合時，另需該權限點。
type FieldCondition struct {
	Field string
	Perm  Permission
	// AnyOf 與 Perm 並列的相容能力：持有 Perm 或其中任一即通過欄位層。持有其中任一時一律回報
	// 經相容能力通過（不論是否另持 Perm），服務層據此決定是否另做語義目標判定；空＝只看 Perm。
	AnyOf []Permission
}

// RouteEntry 一條路由的登錄項。
type RouteEntry struct {
	Method string
	Path   string // 完整樣板，與 gin 的 c.FullPath() 相同
	Base   BaseKind
	Perm   Permission // Base == BasePerm 時有值
	// AnyOf 與 Perm 並列的進入能力：持有 Perm 或其中任一即通過路由層（只給「服務層逐項判定」的
	// 路由用，路由層只確認主體有任何相關能力；空＝只看 Perm）。
	AnyOf  []Permission
	Fields []FieldCondition
	// DataPlane 資料面路由：登錄只要求已認證，授權在 handler 內走與連線簽發同一組閘序
	// （DataPlaneAuthorizer）。資料面路由 SHALL NOT 帶任何管理權限點，
	// 由 TestK8sDataPlaneAdjudication 的登錄案例釘住。
	DataPlane bool
}

// Key 登錄鍵 "METHOD path"。
func (e RouteEntry) Key() string { return e.Method + " " + e.Path }

var routeRegistry = buildRouteRegistry()

func buildRouteRegistry() map[string]RouteEntry {
	m := make(map[string]RouteEntry, len(routeRegistryEntries()))
	for _, e := range routeRegistryEntries() {
		if _, dup := m[e.Key()]; dup {
			panic("authz: 路由登錄鍵重複: " + e.Key())
		}
		if e.Base == BasePerm {
			if _, ok := LookupPermission(e.Perm); !ok {
				panic("authz: 路由登錄引用目錄外的權限點: " + e.Key() + " " + string(e.Perm))
			}
		}
		for _, ap := range e.AnyOf {
			if _, ok := LookupPermission(ap); !ok || e.Base != BasePerm {
				panic("authz: 路由登錄的並列進入能力無效: " + e.Key() + " " + string(ap))
			}
		}
		for _, f := range e.Fields {
			if _, ok := LookupPermission(f.Perm); !ok {
				panic("authz: 欄位條件引用目錄外的權限點: " + e.Key())
			}
			for _, ap := range f.AnyOf {
				if _, ok := LookupPermission(ap); !ok {
					panic("authz: 欄位條件的並列能力引用目錄外的權限點: " + e.Key() + " " + string(ap))
				}
			}
		}
		m[e.Key()] = e
	}
	return m
}

// LookupRoute 查登錄項；查不到即未登錄（呼叫端一律拒絕）。
func LookupRoute(method, fullPath string) (RouteEntry, bool) {
	e, ok := routeRegistry[method+" "+fullPath]
	return e, ok
}

// RegistryKeys 全部登錄鍵（排序）。
func RegistryKeys() []string {
	out := make([]string, 0, len(routeRegistry))
	for k := range routeRegistry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RegistryEntries 全部登錄項的副本（依鍵排序）。
func RegistryEntries() []RouteEntry {
	keys := RegistryKeys()
	out := make([]RouteEntry, len(keys))
	for i, k := range keys {
		out[i] = routeRegistry[k]
	}
	return out
}

// Decision 路由判定結果。
type Decision struct {
	Allowed bool
	// Unauthenticated 需要主體但沒有（呼叫端回 401，而不是 403）。
	Unauthenticated bool
	// Basis 拒絕依據種類（Allowed 為 false 且非 Unauthenticated 時有值）。
	Basis DenialBasis
	// Required 拒絕依據所列的權限點鍵：all_of 為登錄項的 Perm；any_of 為 Perm 與 AnyOf，
	// 依登錄順序、持其一即可；unregistered 為空。每次判定新建，不與登錄表共用底層陣列。
	Required []Permission
}

// DecideRoute 登錄執行中介層呼叫的判定函式。手動認證入口（連線兌換、WebSocket）不經過它，
// 改以現查主體加資產授權（ACL）判定。
// 查不到登錄項一律拒絕（預設拒絕）。
func DecideRoute(method, fullPath string, p *Principal) Decision {
	e, ok := LookupRoute(method, fullPath)
	if !ok {
		return Decision{Basis: DenialUnregistered}
	}
	return DecideEntry(e, p)
}

// DecideEntry 對一個登錄項判定。
func DecideEntry(e RouteEntry, p *Principal) Decision {
	switch e.Base {
	case BasePublic, BaseManual:
		return Decision{Allowed: true}
	case BaseAuthenticated, BaseSelf:
		if p == nil {
			return Decision{Unauthenticated: true}
		}
		return Decision{Allowed: true}
	case BasePerm:
		if p == nil {
			return Decision{Unauthenticated: true}
		}
		if p.Has(e.Perm) {
			return Decision{Allowed: true}
		}
		for _, ap := range e.AnyOf {
			if p.Has(ap) {
				return Decision{Allowed: true}
			}
		}
		return permDenial(e)
	}
	return Decision{Basis: DenialUnregistered}
}

// permDenial 權限點路由的拒絕依據：只有 Perm 為 all_of，有 AnyOf 為 any_of。
func permDenial(e RouteEntry) Decision {
	if len(e.AnyOf) == 0 {
		return Decision{Basis: DenialAllOf, Required: []Permission{e.Perm}}
	}
	req := make([]Permission, 0, 1+len(e.AnyOf))
	req = append(req, e.Perm)
	return Decision{Basis: DenialAnyOf, Required: append(req, e.AnyOf...)}
}

// FieldCapability 欄位條件能力的共用輔助函式：路由登錄項宣告了 field 的額外能力時，
// 回傳主體是否持有；未宣告或路由未登錄時回傳 false（宣告缺漏不得放行）。
func FieldCapability(method, fullPath, field string, p *Principal) bool {
	return FieldCapabilityGrantOf(method, fullPath, field, p) != FieldGrantNone
}

// FieldGrant 欄位條件經哪一條路通過。
type FieldGrant int

const (
	// FieldGrantNone 未通過（含未宣告的欄位、未登錄的路由、無主體）。
	FieldGrantNone FieldGrant = iota
	// FieldGrantPerm 經欄位宣告的權限點通過（未持該欄宣告的任何相容能力）。
	FieldGrantPerm
	// FieldGrantCompat 經該欄宣告的相容並列能力通過；持有相容能力者一律回此值，不論是否另持權限點。
	FieldGrantCompat
)

// FieldCapabilityGrantOf 與 FieldCapability 同一判定，另回報經哪一條路通過。
// 相容優先只看該欄實際宣告的 AnyOf：未宣告並列能力的欄位只有權限點一條路。
func FieldCapabilityGrantOf(method, fullPath, field string, p *Principal) FieldGrant {
	e, ok := LookupRoute(method, fullPath)
	if !ok || p == nil {
		return FieldGrantNone
	}
	for _, f := range e.Fields {
		if f.Field != field {
			continue
		}
		for _, ap := range f.AnyOf {
			if p.Has(ap) {
				return FieldGrantCompat
			}
		}
		if p.Has(f.Perm) {
			return FieldGrantPerm
		}
		return FieldGrantNone
	}
	return FieldGrantNone
}

// FieldWildcard 欄位條件的萬用欄位名：僅需登入的路由用它宣告「請求含任何其他欄位、
// 或本文為空／不可解析時」另需的權限點（原本由基本要求承擔，改由欄位條件承擔）。
const FieldWildcard = "*"

// BodyKeyGate 僅需登入、由請求頂層鍵決定能力的路由判定（欄位閘）。
// keys 為本文頂層鍵；parsed 為 false 表示本文為空或不是 JSON 物件，視同含其他欄位。
// 只含 access_policy 者只需該欄位的權限點；含其他鍵者需萬用條件的權限點，
// 出現 access_policy 鍵者另需該欄位的權限點。兩個權限點皆無時回萬用條件的權限點，
// 只缺其一時回缺的那個；回傳的缺漏鍵即能力拒絕的 all_of 依據。路由未登錄或無主體一律拒絕。
func BodyKeyGate(method, fullPath string, p *Principal, keys []string, parsed bool) (allowed bool, missing Permission) {
	e, ok := LookupRoute(method, fullPath)
	if !ok || p == nil {
		return false, ""
	}
	var wild, ap Permission
	for _, f := range e.Fields {
		switch f.Field {
		case FieldWildcard:
			wild = f.Perm
		case "access_policy":
			ap = f.Perm
		}
	}
	if wild == "" || ap == "" {
		return false, wild
	}
	needAP, needOther := false, !parsed || len(keys) == 0
	for _, k := range keys {
		// JSON 綁定不分大小寫，閘的比對同樣不分，避免變體鍵名繞過
		if strings.EqualFold(k, "access_policy") {
			needAP = true
		} else {
			needOther = true
		}
	}
	missWild, missAP := needOther && !p.Has(wild), needAP && !p.Has(ap)
	switch {
	case !missWild && !missAP:
		return true, ""
	case !p.Has(wild) && !p.Has(ap):
		return false, wild
	case missWild:
		return false, wild
	default:
		return false, ap
	}
}
