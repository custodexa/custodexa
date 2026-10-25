package api

// 範圍化輸出的登錄表：結構性守衛（cmd/server 的 TestScopedOutputProjectionGuard）以此判讀 internal/api。
// 函式識別一律為「[套件.]接收者型別.方法」或「[套件.]函式」；internal/api 內的名稱不帶套件前綴。
// 新增出口、投影、取得 gin.Context 的輔助函式，都要在此登記並寫明理由，守衛會雙向核對。

// ScopedOutputExit 一個受管出口（成功回應必須是 respondScoped 寫出的投影結果）。
type ScopedOutputExit struct {
	Fn    string
	Group string
	// Via 非空時，出口經此登錄函式間接呼叫 respondScoped（該函式必須存在且呼叫 respondScoped）。
	Via string
}

// ScopedOutputExits 18 個登錄出口：帳號列 6、輪替 5、改密 7。
func ScopedOutputExits() []ScopedOutputExit {
	return []ScopedOutputExit{
		{Fn: "AssetAccountHandler.List", Group: "account"},
		{Fn: "AssetAccountHandler.Create", Group: "account"},
		{Fn: "AssetAccountHandler.Update", Group: "account"},
		{Fn: "AssetAccountHandler.SetDefault", Group: "account"},
		{Fn: "CredentialHandler.Bind", Group: "account", Via: "CredentialHandler.respondAccountRow"},
		{Fn: "CredentialHandler.RebindAccount", Group: "account", Via: "CredentialHandler.respondAccountRow"},
		{Fn: "CredentialHandler.StartRotation", Group: "rotation"},
		{Fn: "CredentialHandler.GetRotation", Group: "rotation"},
		{Fn: "CredentialHandler.RetryMember", Group: "rotation"},
		{Fn: "CredentialHandler.AbandonRotation", Group: "rotation"},
		{Fn: "CredentialHandler.Detach", Group: "rotation"},
		{Fn: "ChangeSecretHandler.BatchTargets", Group: "changesecret"},
		{Fn: "ChangeSecretHandler.GetBatch", Group: "changesecret"},
		{Fn: "ChangeSecretHandler.Records", Group: "changesecret"},
		{Fn: "ChangeSecretHandler.ListCandidates", Group: "changesecret"},
		{Fn: "ChangeSecretHandler.List", Group: "changesecret"},
		{Fn: "ChangeSecretHandler.Create", Group: "changesecret"},
		{Fn: "ChangeSecretHandler.Update", Group: "changesecret"},
	}
}

// ScopedOutputProjection 投影集合的成員。Kind 為 entry 者必須回傳 scopedOutput（respondScoped 例外）；
// helper 為投影內部輔助，只處理受保護型別的換形，不對外寫出。
type ScopedOutputProjection struct {
	Fn     string
	Kind   string
	Reason string
}

const (
	ProjectionEntry  = "entry"
	ProjectionHelper = "helper"
)

// ScopedOutputProjections 投影集合，逐函式列名。
func ScopedOutputProjections() []ScopedOutputProjection {
	return []ScopedOutputProjection{
		{"CredentialHandler.projectRotation", ProjectionEntry, "輪替回應：成員只含請求主體可見者"},
		{"accountRowProjector.rows", ProjectionEntry, "帳號列表回應"},
		{"accountRowProjector.one", ProjectionEntry, "帳號寫入回應（單列）"},
		{"ChangeSecretHandler.projectBatchTargets", ProjectionEntry, "批次目標回應"},
		{"ChangeSecretHandler.projectRecords", ProjectionEntry, "改密紀錄回應（批次明細與計畫紀錄共用）"},
		{"ChangeSecretHandler.projectCandidates", ProjectionEntry, "候選回應（來源計畫參照依可見性輸出）"},
		{"ChangeSecretHandler.projectPlanList", ProjectionEntry, "計畫列表回應"},
		{"ChangeSecretHandler.projectPlan", ProjectionEntry, "計畫建立與更新回應（單筆）"},
		{"respondScoped", ProjectionEntry, "唯一寫出點；讀取密封欄位，不回傳 scopedOutput"},
		{"newRotationDTO", ProjectionHelper, "輪替對外型別的組裝，只被 projectRotation 呼叫"},
		{"newCandidateDTO", ProjectionHelper, "候選對外型別的組裝，只被 projectCandidates 呼叫"},
		{"accountRowProjector.shape", ProjectionHelper, "決定帳號列形狀與範圍內憑證，只被 rows、one 呼叫"},
		{"accountRowProjector.row", ProjectionHelper, "單列依形狀轉換，只被 rows、one 呼叫"},
		{"withOutOfScopeCount", ProjectionHelper, "於輪替對外型別加範圍外台數，只被 projectRotation 呼叫"},
		{"accountRowActions", ProjectionHelper, "範圍外帳號列的動作判定轉換，只被 row 呼叫"},
		{"ChangeSecretHandler.maskPlans", ProjectionHelper, "計畫列的遮蔽判定，只被 projectPlanList、projectPlan 呼叫"},
		{"maskPlanRow", ProjectionHelper, "單一計畫列的遮蔽轉換，只被 maskPlans 呼叫"},
		{"newChangeSecretRecordDTO", ProjectionHelper, "改密紀錄對外型別的組裝，只被 projectRecords 呼叫"},
		{"CredentialHandler.respondAccountRow", ProjectionHelper, "掛載與更換憑證的回應轉接：把帳號列交給 one 投影後經 respondScoped 寫出，本體自己不呼叫任何寫出方法"},
	}
}

// ScopedOutputOwnTypes 投影專屬的輸出型別：複合字面值、轉換與密封欄位存取只能出現在投影集合內。
func ScopedOutputOwnTypes() []string {
	return []string{"scopedOutput", "changeSecretRecordDTO"}
}

// ScopedOutputProtectedTypes 受保護型別（套件.型別）；含有它們的型別（指標、slice、陣列、map、struct 欄位遞迴）亦受保護。
func ScopedOutputProtectedTypes() []string {
	return []string{
		"api.credentialRotationDTO",
		"api.credentialRotationMemberDTO",
		"asset.AssetAccountDTO",
		"model.ChangeSecretRecord",
		"asset.BatchTarget",
		"asset.AccountRow",
		"api.changeSecretCandidateDTO",
		"model.CredentialRotationMember",
		"model.ChangeSecretCandidate",
		"model.ChangeSecretPlan",
	}
}

// ScopedOutputSources 來源方法：呼叫它們的函式必須是登錄出口、投影集合成員或豁免。
func ScopedOutputSources() []string {
	return []string{
		"AssetAccountServiceInterface.Create",
		"AssetAccountServiceInterface.Update",
		"AssetAccountServiceInterface.SetDefault",
		"AssetAccountServiceInterface.List",
		"CredentialServiceInterface.Bind",
		"CredentialServiceInterface.Rebind",
		"CredentialRotationServiceInterface.Members",
		"RotationMemberProjection.MembersInView",
		"asset.ChangeSecretBatchService.TargetsFor",
		"asset.ChangeSecretBatchService.DetailFor",
		"asset.ChangeSecretBatchService.Targets",
		"asset.ChangeSecretBatchService.Records",
		"asset.ChangeSecretPlanService.RecordsFor",
		"asset.ChangeSecretPlanService.Records",
		"asset.ChangeSecretCandidateService.ListFor",
		"asset.ChangeSecretCandidateService.List",
		"asset.ChangeSecretPlanService.ListFor",
		"asset.ChangeSecretPlanService.Create",
		"asset.ChangeSecretPlanService.Update",
	}
}

// ContextConsumer 受檢函式可以把 gin.Context 交給的函式。
// Mode 為 write 者本體不套允許清單（它們就是寫出者）；read 者定義在 internal/api 時，本體同樣套允許清單與去向規則。
type ContextConsumer struct {
	Fn     string
	Mode   string
	Reason string
}

const (
	ConsumerWrite = "write"
	ConsumerRead  = "read"
)

// ContextConsumers 逐函式列名。
func ContextConsumers() []ContextConsumer {
	return []ContextConsumer{
		{"respondScoped", ConsumerWrite, "唯一的成功回應寫出點"},
		{"apierror.Respond", ConsumerWrite, "既有錯誤出口"},
		{"apierror.RespondInternal", ConsumerWrite, "既有錯誤出口（內部錯誤）"},
		{"respondAccountError", ConsumerWrite, "帳號端點錯誤映射"},
		{"respondCredentialError", ConsumerWrite, "憑證端點錯誤映射"},
		{"respondHostIdentityMemberError", ConsumerWrite, "主機身分補跑錯誤映射"},
		{"respondBatchError", ConsumerWrite, "批次端點錯誤映射"},
		{"respondPlanError", ConsumerWrite, "計畫端點錯誤映射"},
		{"accountParams", ConsumerRead, "解析路徑參數"},
		{"credentialParam", ConsumerRead, "解析路徑參數"},
		{"credentialAccountParam", ConsumerRead, "解析路徑參數"},
		{"credentialRotationParam", ConsumerRead, "解析路徑參數"},
		{"credentialMemberParam", ConsumerRead, "解析路徑參數"},
		{"accountContext", ConsumerRead, "由請求建立服務層脈絡"},
		{"accountAuthzContext", ConsumerRead, "由請求建立授權脈絡"},
		{"credentialContext", ConsumerRead, "由請求建立服務層脈絡"},
		{"credentialFieldsVisible", ConsumerRead, "讀取欄位能力"},
		{"withFieldCapability", ConsumerRead, "於脈絡掛欄位能力"},
		{"batchViewer", ConsumerRead, "取得改密檢視者脈絡"},
		{"operatorRequestContext", ConsumerRead, "由請求建立操作者脈絡"},
		{"assetWriteContext", ConsumerRead, "由請求建立資產寫入脈絡"},
		{"currentUser", ConsumerRead, "讀取目前使用者"},
		{"setAuditAssetIDValue", ConsumerRead, "寫審計鍵，不進回應本文"},
		{"setAuditAssetID", ConsumerRead, "寫審計鍵，不進回應本文"},
		{"parseHostIdentityConfirmBody", ConsumerRead, "解析確認請求本文"},
		{"CredentialHandler.confirmMember", ConsumerRead, "確認成員歸屬，不輸出"},
		{"AssetAccountHandler.managedVisible", ConsumerRead, "判定資產管理可視，不輸出"},
		{"middleware.PrincipalFrom", ConsumerRead, "讀取主體（套件外，只列名）"},
		{"middleware.GetCurrentUserID", ConsumerRead, "讀取目前使用者識別（套件外，只列名）"},
		{"middleware.GetCurrentUsername", ConsumerRead, "讀取目前使用者名稱（套件外，只列名）"},
		{"middleware.AssetVisibleViaManagement", ConsumerRead, "判定管理可視（套件外，只列名）"},
	}
}

// ScopedOutputContextAllow gin.Context 唯讀選擇子允許清單（共 7 個）。其餘選擇子一律視為寫出。
type ScopedOutputContextAllowEntry struct {
	Name  string
	Field bool
}

func ScopedOutputContextAllow() []ScopedOutputContextAllowEntry {
	return []ScopedOutputContextAllowEntry{
		{Name: "Param"},
		{Name: "Query"},
		{Name: "DefaultQuery"},
		{Name: "ShouldBindJSON"},
		{Name: "Get"},
		{Name: "FullPath"},
		{Name: "Request", Field: true},
	}
}

// ScopedOutputContextException 逐函式例外（共 2 列）。
type ScopedOutputContextException struct {
	Fn     string
	Name   string
	Reason string
	// OnlyArgOf 非空時，該選擇子只能作為此函式的第一個引數。
	OnlyArgOf string
}

func ScopedOutputContextExceptions() []ScopedOutputContextException {
	return []ScopedOutputContextException{
		{Fn: "setAuditAssetID", Name: "Set", Reason: "只寫 c.Keys 供審計中介層讀取，不進回應本文"},
		{Fn: "parseHostIdentityConfirmBody", Name: "Writer", OnlyArgOf: "http.MaxBytesReader",
			Reason: "只用來限制請求本文大小"},
	}
}

// ScopedOutputExemption 逐函式豁免（SR1、SR4、SR5）。
type ScopedOutputExemption struct {
	Fn     string
	Reason string
}

func ScopedOutputExemptions() []ScopedOutputExemption {
	return []ScopedOutputExemption{
		{"CredentialHandler.confirmMember", "以輪替成員判定歸屬，不輸出"},
		{"ChangeSecretHandler.RetryCandidate", "候選只作為重試引數交給執行器，回應只含 promoted 旗標與主機身分檢視，不含候選欄位"},
		{"ChangeSecretHandler.Run", "計畫只作為引數交給執行器，回應為空物件，不含計畫欄位"},
		{"RotationReportHandler.Dataset", "輪替報告資料集由稽核檢視權限與報告範圍自行授權，形狀為既有契約；不在 15 個登錄出口之內，後續另案評估"},
	}
}
