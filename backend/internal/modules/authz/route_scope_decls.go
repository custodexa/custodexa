package authz

// 路由的範圍宣告表。
//
// 一個權限點改標 scoped-enforced 之後，凡以它為要求的登錄項（不論經基本要求、並列進入能力
// 或欄位條件，含萬用欄位）都必須宣告「怎麼從請求解析出判定目標」或「列表怎麼投影範圍」；
// 沒有宣告的登錄項會在沒有目標的情況下判定。宣告放在這張獨立表，不改 RouteEntry 與登錄資料，
// 因此不影響路由快照與端點索引。宣告與登錄表的一致性由 cmd/server 的
// TestScopedEnforcedRequiresTargetResolution 逐列比對。

// RequirementSource 登錄項以哪個來源要求權限點。
type RequirementSource string

const (
	// ReqSourcePerm 基本要求（Base == BasePerm 的 Perm）。
	ReqSourcePerm RequirementSource = "Perm"
	// ReqSourceAnyOf 並列進入能力（AnyOf 任一）。
	ReqSourceAnyOf RequirementSource = "AnyOf"
	// ReqSourceFields 欄位條件（含萬用欄位 FieldWildcard）。
	ReqSourceFields RequirementSource = "Fields"
)

// ScopeDeclKind 宣告種類。守衛只認登記過的值；後續新增種類時同步登記到守衛。
type ScopeDeclKind string

const (
	// ScopeDeclTarget 從請求解析出單一判定目標。
	ScopeDeclTarget ScopeDeclKind = "target"
	// ScopeDeclListProjection 列表依有效範圍投影。
	ScopeDeclListProjection ScopeDeclKind = "list_projection"
	// ScopeDeclBatchSet 批次請求逐項以目標集合判定。
	ScopeDeclBatchSet ScopeDeclKind = "batch_set"
	// ScopeDeclServiceTx 服務在寫入交易內、取得拓撲序列化鎖之後判定（目標或目的在本文、或規則
	// 不只「目標在範圍內」時）。登錄閘不處理此種類；判定點只有服務交易內一處。
	ScopeDeclServiceTx ScopeDeclKind = "service_tx"
	// ScopeDeclRouteGuard 逐資源讀取由該路由掛的守門判定：放行條件不只「目標在權限點範圍內」
	// （例如連線可視或管理可視任一成立，皆否經共用出口），故不交登錄閘以目標判定。
	// 登錄閘不處理此種類；判定點只有該守門一處。
	ScopeDeclRouteGuard ScopeDeclKind = "route_guard"
	// ScopeDeclServiceRead 逐資源讀取由服務以目標解析判定（範圍外、已刪除與不存在同形），不在寫入交易內。
	// 登錄閘不處理此種類；判定點只有服務讀取一處。
	ScopeDeclServiceRead ScopeDeclKind = "service_read"
	// ScopeDeclSubjectDirectory 主體目錄：不依節點範圍過濾，只要求主體至少有一筆含該權限點的
	// 有效指派（空範圍或全刪的指派不算）。登錄閘不處理此種類；判定點只有該目錄的 handler 一處。
	// 目前只有授權畫面的主體選擇器使用，守衛斷言不得擴散到其他路由。
	ScopeDeclSubjectDirectory ScopeDeclKind = "subject_directory"
)

// RouteScopeDecl 一條登錄項上一個要求來源的範圍宣告。
// (Method, Path, Source, Perm, Field) 對應登錄表的一個要求；Method 與 Path 與 RouteEntry 相同。
type RouteScopeDecl struct {
	Method, Path string
	Source       RequirementSource
	Perm         Permission
	// Field Source == ReqSourceFields 時的欄位名（含 FieldWildcard）；其他來源為空。
	Field string
	Kind  ScopeDeclKind
	// Target Kind == ScopeDeclTarget 時必填，須是已登記的目標種類。
	Target ScopeTargetKind
	// Owner 負責實作此宣告的段落。
	Owner string
}

// RouteScopeDeclarations 全部範圍宣告。權限點逐一啟用 scoped-enforced 時，同一次變更補上以它為要求的全部宣告。
func RouteScopeDeclarations() []RouteScopeDecl {
	const nodeWrites = "節點寫入服務（交易內判定）"
	const assetWrites = "資產寫入服務（交易內判定）"
	const assetTarget = "資產（登錄閘以路徑資產判定）"
	const accountWrites = "資產帳號寫入服務（交易內判定，隨所屬資產）"
	const assetList = "資產列表（管理可視與連線可視的聯集投影）"
	const tagDictionary = "標籤字典（以資產列表同一可視聯集彙整）"
	const assetRead = "逐資產讀取守門（連線可視或管理可視）"
	const accountList = "資產帳號列表（隨所屬資產的可視來源投影）"
	const credList = "憑證列表（檢視集合投影：節點歸屬在子樹內，或專用憑證的掛載資產在子樹內）"
	const credRead = "憑證讀取服務（以憑證歸屬判定）"
	const credWrites = "憑證管理服務（交易內以憑證歸屬與明確目標資產判定）"
	const credOwnershipBatch = "憑證批次改歸（逐筆以歸屬判定，整批原子）"
	const assetMountSource = "資產建立的掛載來源（交易內以憑證歸屬判定）"
	const assetImportRows = "資產批次新增的逐列範圍（預檢逐列判定，提交於交易內重算）"
	const assetBatch = "資產批次服務（批次交易內逐列判定，搬移另判目的節點）"
	const ruleWrites = "授權規則寫入服務（交易內重解主體並判定）"
	const ruleList = "授權規則列表（檢視者可見節點的集合述詞投影）"
	const ruleView = "授權有效權限檢視（隨檢視者可見節點投影）"
	const ruleTargets = "授權客體候選（資產、節點、標籤皆依檢視者可見節點投影）"
	const ruleSubjects = "授權主體目錄（不依節點範圍，要求至少一筆有效指派）"
	const importEntry = "資產批次新增的進入（預檢逐列判定節點範圍，提交於交易內重算）"
	const csList = "改密列表（批次、目標、帳號名、候選與計畫皆以集合述詞投影範圍內資產）"
	const csRead = "改密逐筆讀取服務（批次詳情與計畫記錄只含範圍內目標，不可見與不存在同形）"
	const csWrites = "改密寫入服務（交易內取拓撲序列化鎖後判定目標範圍）"
	const csBatchSet = "改密批次集合（逐項以目標集合判定，任一不可操作整批拒絕；一鍵重新授權只承接可見計畫）"
	const approverWrites = "審核範圍寫入服務（交易內判定；申請人型另需全域申請人型管理鍵）"
	const approverList = "審核範圍列表（管理者可見節點的集合述詞投影，申請人型列只給全域兩鍵持有者）"
	const approverTargets = "審核範圍客體候選（資產、節點依管理者可見節點投影）"
	const approverSubjects = "審核方目錄（不依節點範圍，要求至少一筆有效指派）"
	const policyUpdate = "存取政策覆寫的更新（交易內取拓撲序列化鎖後依存取政策權限點判定資產）"
	const policyCreate = "存取政策覆寫的建立（交易內判定目的節點至少一個在存取政策範圍內）"
	const policyImport = "存取政策覆寫的批次新增（逐列判定目的節點，任一列不符整批拒絕；提交於交易內重算）"
	const policyList = "單台覆寫清單（存取政策權限點的集合述詞投影）"
	decls := []RouteScopeDecl{
		{Method: "GET", Path: "/api/v1/approver-scopes", Source: ReqSourcePerm, Perm: PermApproverScopeManage, Kind: ScopeDeclListProjection, Owner: approverList},
		{Method: "POST", Path: "/api/v1/approver-scopes", Source: ReqSourcePerm, Perm: PermApproverScopeManage, Kind: ScopeDeclServiceTx, Owner: approverWrites},
		{Method: "DELETE", Path: "/api/v1/approver-scopes/:id", Source: ReqSourcePerm, Perm: PermApproverScopeManage, Kind: ScopeDeclServiceTx, Owner: approverWrites},
		{Method: "GET", Path: "/api/v1/approver-scopes/approver-options", Source: ReqSourcePerm, Perm: PermApproverScopeManage, Kind: ScopeDeclSubjectDirectory, Owner: approverSubjects},
		{Method: "GET", Path: "/api/v1/approver-scopes/target-options", Source: ReqSourcePerm, Perm: PermApproverScopeManage, Kind: ScopeDeclListProjection, Owner: approverTargets},
		{Method: "GET", Path: "/api/v1/authorizations", Source: ReqSourcePerm, Perm: PermAuthorizationManage, Kind: ScopeDeclListProjection, Owner: ruleList},
		{Method: "POST", Path: "/api/v1/authorizations", Source: ReqSourcePerm, Perm: PermAuthorizationManage, Kind: ScopeDeclServiceTx, Owner: ruleWrites},
		{Method: "DELETE", Path: "/api/v1/authorizations/:id", Source: ReqSourcePerm, Perm: PermAuthorizationManage, Kind: ScopeDeclServiceTx, Owner: ruleWrites},
		{Method: "PUT", Path: "/api/v1/authorizations/:id/accounts", Source: ReqSourcePerm, Perm: PermAuthorizationManage, Kind: ScopeDeclServiceTx, Owner: ruleWrites},
		{Method: "POST", Path: "/api/v1/authorizations/batch", Source: ReqSourcePerm, Perm: PermAuthorizationManage, Kind: ScopeDeclServiceTx, Owner: ruleWrites},
		{Method: "GET", Path: "/api/v1/authorizations/effective-assets", Source: ReqSourcePerm, Perm: PermAuthorizationManage, Kind: ScopeDeclListProjection, Owner: ruleView},
		{Method: "GET", Path: "/api/v1/authorizations/effective-users", Source: ReqSourcePerm, Perm: PermAuthorizationManage, Kind: ScopeDeclListProjection, Owner: ruleView},
		{Method: "GET", Path: "/api/v1/authorizations/target-options", Source: ReqSourcePerm, Perm: PermAuthorizationManage, Kind: ScopeDeclListProjection, Owner: ruleTargets},
		{Method: "GET", Path: "/api/v1/authorizations/subject-options", Source: ReqSourcePerm, Perm: PermAuthorizationManage, Kind: ScopeDeclSubjectDirectory, Owner: ruleSubjects},
		{Method: "GET", Path: "/api/v1/assets", Source: ReqSourcePerm, Perm: PermAssetView, Kind: ScopeDeclListProjection, Owner: assetList},
		{Method: "GET", Path: "/api/v1/assets/:id", Source: ReqSourcePerm, Perm: PermAssetView, Kind: ScopeDeclRouteGuard, Owner: assetRead},
		{Method: "GET", Path: "/api/v1/assets/:id/k8s/pods", Source: ReqSourcePerm, Perm: PermAssetView, Kind: ScopeDeclRouteGuard, Owner: assetRead},
		{Method: "GET", Path: "/api/v1/assets/:id/accounts", Source: ReqSourcePerm, Perm: PermAssetView, Kind: ScopeDeclListProjection, Owner: accountList},
		{Method: "GET", Path: "/api/v1/assets/tags", Source: ReqSourcePerm, Perm: PermAssetView, Kind: ScopeDeclListProjection, Owner: tagDictionary},
		{Method: "POST", Path: "/api/v1/assets", Source: ReqSourcePerm, Perm: PermAssetCreate, Kind: ScopeDeclServiceTx, Owner: assetWrites},
		{Method: "PUT", Path: "/api/v1/assets/:id", Source: ReqSourceFields, Perm: PermAssetUpdate, Field: FieldWildcard, Kind: ScopeDeclServiceTx, Owner: assetWrites},
		{Method: "DELETE", Path: "/api/v1/assets/:id", Source: ReqSourcePerm, Perm: PermAssetDelete, Kind: ScopeDeclServiceTx, Owner: assetWrites},
		{Method: "POST", Path: "/api/v1/assets/batch/move", Source: ReqSourcePerm, Perm: PermAssetUpdate, Kind: ScopeDeclServiceTx, Owner: assetBatch},
		{Method: "POST", Path: "/api/v1/assets/batch/tags", Source: ReqSourcePerm, Perm: PermAssetUpdate, Kind: ScopeDeclServiceTx, Owner: assetBatch},
		{Method: "POST", Path: "/api/v1/assets/batch/delete", Source: ReqSourcePerm, Perm: PermAssetDelete, Kind: ScopeDeclServiceTx, Owner: assetBatch},
		{Method: "POST", Path: "/api/v1/assets/:id/accounts", Source: ReqSourcePerm, Perm: PermAssetUpdate, Kind: ScopeDeclServiceTx, Owner: accountWrites},
		{Method: "PUT", Path: "/api/v1/assets/:id/accounts/:accountId", Source: ReqSourcePerm, Perm: PermAssetUpdate, Kind: ScopeDeclServiceTx, Owner: accountWrites},
		{Method: "DELETE", Path: "/api/v1/assets/:id/accounts/:accountId", Source: ReqSourcePerm, Perm: PermAssetUpdate, Kind: ScopeDeclServiceTx, Owner: accountWrites},
		{Method: "POST", Path: "/api/v1/assets/:id/accounts/:accountId/set-default", Source: ReqSourcePerm, Perm: PermAssetUpdate, Kind: ScopeDeclServiceTx, Owner: accountWrites},
		{Method: "POST", Path: "/api/v1/assets/:id/test-connection", Source: ReqSourcePerm, Perm: PermAssetTest, Kind: ScopeDeclTarget, Target: ScopeTargetAsset, Owner: assetTarget},
		{Method: "POST", Path: "/api/v1/asset-groups", Source: ReqSourcePerm, Perm: PermAssetGroupManage, Kind: ScopeDeclServiceTx, Owner: nodeWrites},
		{Method: "PUT", Path: "/api/v1/asset-groups/:id", Source: ReqSourcePerm, Perm: PermAssetGroupManage, Kind: ScopeDeclServiceTx, Owner: nodeWrites},
		{Method: "PUT", Path: "/api/v1/asset-groups/:id/move", Source: ReqSourcePerm, Perm: PermAssetGroupManage, Kind: ScopeDeclServiceTx, Owner: nodeWrites},
		{Method: "DELETE", Path: "/api/v1/asset-groups/:id", Source: ReqSourcePerm, Perm: PermAssetGroupManage, Kind: ScopeDeclServiceTx, Owner: nodeWrites},
		{Method: "GET", Path: "/api/v1/credentials", Source: ReqSourcePerm, Perm: PermCredentialView, Kind: ScopeDeclListProjection, Owner: credList},
		{Method: "GET", Path: "/api/v1/credentials/:id", Source: ReqSourcePerm, Perm: PermCredentialView, Kind: ScopeDeclServiceRead, Owner: credRead},
		{Method: "GET", Path: "/api/v1/credentials/:id/rotations/:rid", Source: ReqSourcePerm, Perm: PermCredentialView, Kind: ScopeDeclServiceRead, Owner: credRead},
		{Method: "POST", Path: "/api/v1/assets", Source: ReqSourceFields, Perm: PermCredentialBind, Field: "credential_id", Kind: ScopeDeclServiceTx, Owner: assetMountSource},
		{Method: "POST", Path: "/api/v1/assets/import/preview", Source: ReqSourceFields, Perm: PermCredentialBind, Field: "credential_id", Kind: ScopeDeclServiceRead, Owner: assetImportRows},
		{Method: "POST", Path: "/api/v1/assets/import", Source: ReqSourceFields, Perm: PermCredentialBind, Field: "credential_id", Kind: ScopeDeclServiceTx, Owner: assetImportRows},
		{Method: "POST", Path: "/api/v1/assets/import/preview", Source: ReqSourcePerm, Perm: PermAssetCreate, Kind: ScopeDeclServiceRead, Owner: importEntry},
		{Method: "POST", Path: "/api/v1/assets/import", Source: ReqSourcePerm, Perm: PermAssetCreate, Kind: ScopeDeclServiceTx, Owner: importEntry},
		{Method: "PUT", Path: "/api/v1/assets/:id", Source: ReqSourceFields, Perm: PermAccessPolicyManage, Field: "access_policy", Kind: ScopeDeclServiceTx, Owner: policyUpdate},
		{Method: "POST", Path: "/api/v1/assets", Source: ReqSourceFields, Perm: PermAccessPolicyManage, Field: "access_policy", Kind: ScopeDeclServiceTx, Owner: policyCreate},
		{Method: "POST", Path: "/api/v1/assets/import/preview", Source: ReqSourceFields, Perm: PermAccessPolicyManage, Field: "access_policy", Kind: ScopeDeclServiceRead, Owner: policyImport},
		{Method: "POST", Path: "/api/v1/assets/import", Source: ReqSourceFields, Perm: PermAccessPolicyManage, Field: "access_policy", Kind: ScopeDeclServiceTx, Owner: policyImport},
		{Method: "GET", Path: "/api/v1/assets/access-policy-overrides", Source: ReqSourcePerm, Perm: PermAccessPolicyManage, Kind: ScopeDeclListProjection, Owner: policyList},
	}
	// 改密路由：基本要求皆為 changesecret:manage，範圍由各服務判定
	for _, c := range []struct {
		method, path string
		kind         ScopeDeclKind
		owner        string
	}{
		{"GET", "/api/v1/change-secret-batches", ScopeDeclListProjection, csList},
		{"POST", "/api/v1/change-secret-batches", ScopeDeclBatchSet, csBatchSet},
		{"GET", "/api/v1/change-secret-batches/:id", ScopeDeclServiceRead, csRead},
		{"GET", "/api/v1/change-secret-batches/targets", ScopeDeclListProjection, csList},
		{"GET", "/api/v1/change-secret-batches/usernames", ScopeDeclListProjection, csList},
		{"GET", "/api/v1/change-secret-candidates", ScopeDeclListProjection, csList},
		{"DELETE", "/api/v1/change-secret-candidates/:id", ScopeDeclServiceTx, csWrites},
		{"POST", "/api/v1/change-secret-candidates/:id/retry", ScopeDeclServiceTx, csWrites},
		{"GET", "/api/v1/change-secret-plans", ScopeDeclListProjection, csList},
		{"POST", "/api/v1/change-secret-plans", ScopeDeclServiceTx, csWrites},
		{"DELETE", "/api/v1/change-secret-plans/:id", ScopeDeclServiceTx, csWrites},
		{"PUT", "/api/v1/change-secret-plans/:id", ScopeDeclServiceTx, csWrites},
		{"GET", "/api/v1/change-secret-plans/:id/records", ScopeDeclServiceRead, csRead},
		{"POST", "/api/v1/change-secret-plans/:id/run", ScopeDeclServiceTx, csWrites},
		{"POST", "/api/v1/change-secret-plans/reauthorize", ScopeDeclBatchSet, csBatchSet},
	} {
		decls = append(decls, RouteScopeDecl{Method: c.method, Path: c.path, Source: ReqSourcePerm,
			Perm: PermChangeSecretManage, Kind: c.kind, Owner: c.owner})
	}
	// 憑證寫入路由：路由級入口 credential:manage 與並列進入的語義鍵，皆由服務逐項判定
	for _, w := range []struct {
		method, path string
		anyOf        []Permission
		kind         ScopeDeclKind
		owner        string
	}{
		{"POST", "/api/v1/credentials", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
		{"PUT", "/api/v1/credentials/:id", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
		{"DELETE", "/api/v1/credentials/:id", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
		{"POST", "/api/v1/credentials/ownership", []Permission{PermCredentialUpdate}, ScopeDeclBatchSet, credOwnershipBatch},
		{"POST", "/api/v1/credentials/:id/bindings", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
		{"DELETE", "/api/v1/credentials/:id/bindings/:accountId", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
		{"POST", "/api/v1/credentials/:id/bindings/:accountId/detach", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
		{"POST", "/api/v1/credentials/:id/impact-confirmations", []Permission{PermCredentialSetSecret, PermCredentialRotate}, ScopeDeclServiceTx, credWrites},
		{"POST", "/api/v1/credentials/:id/rotations", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
		{"POST", "/api/v1/credentials/:id/rotations/:rid/abandon", []Permission{PermCredentialRotate}, ScopeDeclServiceTx, credWrites},
		{"POST", "/api/v1/credentials/:id/rotations/:rid/members/:mid/retry", []Permission{PermCredentialRotate}, ScopeDeclServiceTx, credWrites},
		{"POST", "/api/v1/credentials/:id/scope", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
		{"POST", "/api/v1/credentials/:id/secret", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
		{"PUT", "/api/v1/assets/:id/accounts/:accountId/credential", credentialWriteCapabilities(), ScopeDeclServiceTx, credWrites},
	} {
		decls = append(decls, RouteScopeDecl{Method: w.method, Path: w.path, Source: ReqSourcePerm, Perm: PermCredentialManage,
			Kind: w.kind, Owner: w.owner})
		for _, p := range w.anyOf {
			decls = append(decls, RouteScopeDecl{Method: w.method, Path: w.path, Source: ReqSourceAnyOf, Perm: p,
				Kind: w.kind, Owner: w.owner})
		}
	}
	// 資產與帳號表單的憑證欄位：欄位權限點（憑證語義鍵）與相容並列能力各一條宣告。經語義鍵通過者由服務
	// 在交易內以資產或送出節點為目標判定，帳號列表由投影以重解主體決定形狀與可見集合
	for _, f := range []struct {
		method, path, field string
		perm                Permission
		kind                ScopeDeclKind
		owner               string
	}{
		{"POST", "/api/v1/assets", "username", PermCredentialCreate, ScopeDeclServiceTx, assetWrites},
		{"POST", "/api/v1/assets", "password", PermCredentialCreate, ScopeDeclServiceTx, assetWrites},
		{"POST", "/api/v1/assets", "private_key", PermCredentialCreate, ScopeDeclServiceTx, assetWrites},
		{"POST", "/api/v1/assets", "sftp_username", PermCredentialCreate, ScopeDeclServiceTx, assetWrites},
		{"POST", "/api/v1/assets", "sftp_password", PermCredentialCreate, ScopeDeclServiceTx, assetWrites},
		{"POST", "/api/v1/assets", "credential", PermCredentialCreate, ScopeDeclServiceTx, assetWrites},
		{"PUT", "/api/v1/assets/:id", "username", PermCredentialUpdate, ScopeDeclServiceTx, assetWrites},
		{"PUT", "/api/v1/assets/:id", "password", PermCredentialSetSecret, ScopeDeclServiceTx, assetWrites},
		{"PUT", "/api/v1/assets/:id", "private_key", PermCredentialSetSecret, ScopeDeclServiceTx, assetWrites},
		{"PUT", "/api/v1/assets/:id", "sftp_username", PermCredentialUpdate, ScopeDeclServiceTx, assetWrites},
		{"PUT", "/api/v1/assets/:id", "sftp_password", PermCredentialSetSecret, ScopeDeclServiceTx, assetWrites},
		{"GET", "/api/v1/assets/:id/accounts", "credential_identity_fields", PermCredentialView, ScopeDeclListProjection, accountList},
		{"POST", "/api/v1/assets/:id/accounts", "username", PermCredentialCreate, ScopeDeclServiceTx, accountWrites},
		{"PUT", "/api/v1/assets/:id/accounts/:accountId", "username", PermCredentialUpdate, ScopeDeclServiceTx, accountWrites},
	} {
		for _, perm := range []Permission{f.perm, PermCredentialManage} {
			decls = append(decls, RouteScopeDecl{Method: f.method, Path: f.path, Source: ReqSourceFields, Perm: perm,
				Field: f.field, Kind: f.kind, Owner: f.owner})
		}
	}
	return decls
}
