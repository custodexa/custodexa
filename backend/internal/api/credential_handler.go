package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/authz/disclosure"
	"github.com/custodexa/backend/internal/modules/identity"
)

// 帳號憑證庫 API。
//
// # 兩件事在這一層決定
//
// **回應的收斂**：憑證不存在、已軟刪、對操作者不可見三者回同一個碼。分流即製造
// 存在性探測器——請求方以回應差異就能問出「這個識別後面有沒有東西」，而憑證識別
// 是連號的。錯誤回應同樣不回填憑證名、帳號名與資產名（見 apierror 的憑證碼檔頭）。
//
// **同步與非同步的界線**：動遠端主機的動作分兩類。整組改密要跑 n 台、每台各自
// 連線與驗證，同步等待會讓請求掛在那裡直到逾時，故回 202 與輪替識別、由進度端點
// 輪詢；單台補跑與單台脫離只動一台，操作者需要當下的結果才知道下一步，故同步回。
//
// # 掛載與卸載的審計主體
//
// 路徑上的識別是憑證，中介層據此把 resource 記為憑證分類；受影響的資產由 handler
// 顯式注入（setAuditAssetIDValue），使同一個動作在資產樞紐上也查得到——掛載改變的
// 是秘密在哪些主機上生效，只掛在憑證下會讓「這台機器的登入身分被誰換掉」查不出來。

// CredentialServiceInterface 憑證管理服務（介面化供測試注入）。
type CredentialServiceInterface interface {
	List(ctx context.Context, filter asset.CredentialFilter) ([]*asset.CredentialDTO, error)
	Get(ctx context.Context, id uint) (*asset.CredentialDetailDTO, error)
	Create(ctx context.Context, req *asset.CreateCredentialRequest) (*asset.CredentialDTO, error)
	Update(ctx context.Context, id uint, req *asset.UpdateCredentialRequest) (*asset.CredentialDTO, error)
	Delete(ctx context.Context, id uint) error
	Bind(ctx context.Context, credentialID uint, req *asset.BindCredentialRequest) (*asset.AssetAccountDTO, error)
	Unbind(ctx context.Context, credentialID, accountID uint) error
	Rebind(ctx context.Context, assetID, accountID, credentialID uint) (*asset.AssetAccountDTO, error)
	ConvertScope(ctx context.Context, id uint, req *asset.ConvertCredentialScopeRequest) (*asset.CredentialDTO, error)
	ReassignOwnership(ctx context.Context, req *asset.ReassignCredentialOwnershipRequest) (*asset.ReassignCredentialOwnershipResult, error)
	SetSecret(ctx context.Context, id uint, req *asset.SetCredentialSecretRequest) (*asset.CredentialDTO, error)
	ConfirmImpact(ctx context.Context, id uint, req *asset.ConfirmCredentialImpactRequest) (*asset.ConfirmCredentialImpactResult, error)
	// BindingAssetID 掛載所屬資產識別（審計主體鍵用，不經讀取能力，只回識別）。
	BindingAssetID(credentialID, accountID uint) uint
}

// CredentialRotationServiceInterface 憑證輪替引擎（介面化供測試注入）。
type CredentialRotationServiceInterface interface {
	Start(ctx context.Context, credentialID uint, req asset.StartRotationRequest) (*model.CredentialRotation, error)
	StartSplit(ctx context.Context, credentialID uint, req asset.StartRotationRequest) (*model.CredentialRotation, error)
	Detach(ctx context.Context, credentialID, accountID uint, req asset.DetachCredentialRequest) (*model.CredentialRotation, error)
	Run(ctx context.Context, rotationID uint) error
	RunMember(ctx context.Context, rotationID, memberID uint) error
	RunMemberResult(ctx context.Context, rotationID, memberID uint,
		origin asset.RotationRecordOrigin) (*asset.MemberRunResult, error)
	Abandon(ctx context.Context, rotationID uint) error
	// RequireRotationTarget 補跑與放棄的憑證層判定，須先於 Rotation 與任何輪次狀態檢查
	RequireRotationTarget(ctx context.Context, credentialID uint) error
	Rotation(credentialID, rotationID uint) (*model.CredentialRotation, error)
	Members(rotationID uint) ([]model.CredentialRotationMember, error)
	AggregateState(credentialID uint) (string, error)
	UnsettledRotationID(credentialID uint) (uint, error)
	CandidateKeptMembers(rotationID uint) (map[uint]bool, error)
}

// CredentialRotationStatusResolver 一筆憑證的輪替合規狀態（其全部掛載的狀態桶取最嚴）。
//
// 窄介面而非直接持有報告建構者：列表只需要「這一筆現在算哪一桶」，
// 併入既有介面會逼輪替引擎的既有測試替身補一個它不負責的方法。
type CredentialRotationStatusResolver interface {
	CredentialRotationStatus(credentialID uint, asOf time.Time) (string, error)
}

// CredentialHandler 憑證庫 API。
type CredentialHandler struct {
	credentials CredentialServiceInterface
	rotations   CredentialRotationServiceInterface
	// rotationStatus 列表的輪替狀態篩選。**建構期必填**：設為可選欄位＋nil 時
	// 不過濾，等於讓「只看逾期的那幾筆」靜默回成全部——而畫面上看不出差別
	rotationStatus CredentialRotationStatusResolver
	// takeover 主機身分人工承接服務。組裝根在啟動時確認它完整就緒才注入
	takeover *asset.HostIdentityTakeoverService
	// confirmer 帶確認的補跑所呼叫的動作；由 SetHostIdentityTakeover 設為 takeover
	confirmer hostIdentityConfirmer
}

// SetHostIdentityTakeover 注入人工承接服務。
func (h *CredentialHandler) SetHostIdentityTakeover(s *asset.HostIdentityTakeoverService) {
	h.takeover = s
	h.confirmer = nil
	if s != nil {
		h.confirmer = s
	}
}

// HostIdentityTakeoverWired 承接服務已注入且依賴完整（組裝自檢用）。
func (h *CredentialHandler) HostIdentityTakeoverWired() bool {
	return h != nil && h.takeover != nil && len(h.takeover.WiringGaps()) == 0
}

// NewCredentialHandler 建立 handler。三個相依皆為建構期必填：
// 缺輪替服務時改密端點會在執行期 nil panic，而那是使用者按下按鈕才會發現的失敗。
func NewCredentialHandler(credentials CredentialServiceInterface,
	rotations CredentialRotationServiceInterface,
	rotationStatus CredentialRotationStatusResolver) *CredentialHandler {

	return &CredentialHandler{
		credentials: credentials, rotations: rotations, rotationStatus: rotationStatus,
	}
}

// --- 對外形狀 ---

// credentialRotationDTO 一次輪替的對外表示（不含任何秘密材料）。
type credentialRotationDTO struct {
	ID           uint  `json:"id"`
	CredentialID uint  `json:"credential_id"`
	Epoch        int64 `json:"epoch"`
	// Mode 見 model.CredentialRotationMode* 常數
	Mode string `json:"mode"`
	// Status 見 model.CredentialRotation* 狀態常數
	Status          string `json:"status"`
	RequestedBy     uint   `json:"requested_by"`
	RequestedByName string `json:"requested_by_name"`
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at,omitempty"`
	// AggregateState 憑證當下的聚合態（見 model.CredentialAggregate* 常數）
	AggregateState string `json:"aggregate_state,omitempty"`
	// Unsettled 本輪已放棄、但仍是憑證要逐台補跑至收斂的那一輪（見憑證詳情的
	// unsettled_rotation_id）；呈現面據此決定放棄後還給哪些成員補跑
	Unsettled bool                          `json:"unsettled,omitempty"`
	Members   []credentialRotationMemberDTO `json:"members"`
}

// credentialRotationMemberDTO 輪替的逐掛載成員。
//
// LastError 是機器可讀原因碼，文案由前端三語對照——遠端回應原文一律不外露
// （它可能含主機名、路徑與帳號枚舉）。
type credentialRotationMemberDTO struct {
	ID        uint   `json:"id"`
	AccountID uint   `json:"account_id"`
	AssetID   uint   `json:"asset_id"`
	AssetName string `json:"asset_name"`
	Username  string `json:"username"`
	// State 見 model.CredentialMember* 常數
	State         string `json:"state"`
	AttemptCount  int    `json:"attempt_count"`
	NextAttemptAt string `json:"next_attempt_at,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	AppliedAt     string `json:"applied_at,omitempty"`
	// CandidateKept 該掛載的候選仍在（只在已放棄、仍待逐台補跑的那一輪帶出）：拆分模式
	// 已收束的成員有候選才給補跑——那台可能已在用候選裡的新秘密
	CandidateKept bool `json:"candidate_kept,omitempty"`
	// HostIdentity 本次補跑被主機身分守衛擋下時的唯讀檢視；只在補跑的回應中出現於被補跑的那一台
	HostIdentity *asset.HostIdentityView `json:"host_identity,omitempty"`
	// Reason 帶確認的補跑因授權目標已改變而未執行時的既有原因碼；其他情形不帶
	Reason string `json:"reason,omitempty"`
}

const credentialTimeLayout = "2006-01-02T15:04:05Z07:00"

func newRotationDTO(rot *model.CredentialRotation, members []model.CredentialRotationMember,
	aggregate string) credentialRotationDTO {

	out := credentialRotationDTO{
		ID:              rot.ID,
		CredentialID:    rot.CredentialID,
		Epoch:           rot.Epoch,
		Mode:            rot.Mode,
		Status:          rot.Status,
		RequestedBy:     rot.RequestedBy,
		RequestedByName: rot.RequestedByName,
		StartedAt:       rot.StartedAt.Format(credentialTimeLayout),
		AggregateState:  aggregate,
		Members:         make([]credentialRotationMemberDTO, 0, len(members)),
	}
	if rot.FinishedAt != nil {
		out.FinishedAt = rot.FinishedAt.Format(credentialTimeLayout)
	}
	for i := range members {
		m := &members[i]
		dto := credentialRotationMemberDTO{
			ID: m.ID, AccountID: m.AccountID, AssetID: m.AssetID,
			AssetName: m.AssetName, Username: m.Username, State: m.State,
			AttemptCount: m.AttemptCount, LastError: m.LastError,
		}
		if m.NextAttemptAt != nil {
			dto.NextAttemptAt = m.NextAttemptAt.Format(credentialTimeLayout)
		}
		if m.AppliedAt != nil {
			dto.AppliedAt = m.AppliedAt.Format(credentialTimeLayout)
		}
		out.Members = append(out.Members, dto)
	}
	return out
}

// startRotationBody 發起改密的請求形狀。
type startRotationBody struct {
	// Mode group＝整組換到同一組新秘密；split＝每台各自隨機並解除共用
	Mode string `json:"mode"`
	// Policy 密碼生成策略（語義與改密計劃相同）
	Policy asset.PasswordPolicy `json:"policy"`
	// ImpactConfirmationID 範圍外影響確認識別（範圍外集合為空時不看）
	ImpactConfirmationID string `json:"impact_confirmation_id"`
}

// --- 錯誤出口 ---

// respondCredentialError 憑證端點的統一錯誤出口。
//
// 已知哨兵依 errors.Is 映射到機器碼，未知一律 RespondInternal（成因只落伺服端
// 日誌）。**「不存在」與「不可見」在同一個 case 上**：兩者必須產生位元相同的回應。
func respondCredentialError(c *gin.Context, internalCode apierror.ErrCode, err error) {
	if respondCredentialOwnershipError(c, err) {
		return
	}
	var inUse *asset.CredentialInUseError
	if errors.As(err, &inUse) {
		// 名單走回應 body 而非錯誤 params：params 只收受控值域，資產名是自由字串。
		// 名單本身只對具憑證管理權限者可見，而本端點已在該授權點之後
		body := gin.H{"code": string(apierror.CodeCredentialInUse), "assets": inUse.Assets}
		if inUse.Scoped {
			// 範圍化檢視者：名單只含範圍內資產名，範圍外只給台數（揭露登錄固定欄名與函式）
			body[disclosure.FieldOutOfScopeAssetCount] = disclosure.Count(disclosure.OutOfScopeAssetCount, inUse.OutOfScopeAssets)
		}
		c.JSON(http.StatusConflict, body)
		return
	}
	var impactRequired *asset.CredentialImpactConfirmationRequiredError
	if errors.As(err, &impactRequired) {
		// 台數經揭露登錄的範圍外台數轉出；零變更、零遠端（交易已回滾）
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialImpactConfirmationRequired, map[string]any{
			"count": disclosure.Count(disclosure.OutOfScopeAssetCount, impactRequired.Count),
		})
		return
	}
	if errors.Is(err, asset.ErrCredentialImpactOperationInvalid) {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	var detachFailed *asset.CredentialDetachFailedError
	if errors.As(err, &detachFailed) {
		// 終態與原因碼是**機器碼的封閉集合**（成員狀態常數與原因碼），非遠端原文
		c.JSON(http.StatusConflict, gin.H{
			"code":   string(apierror.CodeCredentialDetachFailed),
			"state":  detachFailed.State,
			"reason": detachFailed.Reason,
		})
		return
	}

	// 範圍化檢視者的能力拒絕（判定先於目標解析，與目標存在與否無關）：單一 forbidden
	if asset.IsForbiddenCapabilityDenial(err) {
		respondAssetCapabilityDenial(c, err)
		return
	}
	switch {
	case errors.Is(err, asset.ErrCredentialNotFound),
		// 對受影響資產無權限與憑證不存在共用收斂回應：分流即成為存在性探測器
		errors.Is(err, asset.ErrCredentialBindForbidden):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCredentialNotFound, nil)
	case errors.Is(err, asset.ErrCredentialBindingNotFound),
		errors.Is(err, asset.ErrAssetAccountNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCredentialBindingNotFound, nil)
	case errors.Is(err, asset.ErrCredentialRotationNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCredentialRotationNotFound, nil)
	case errors.Is(err, asset.ErrCredentialRotationMemberNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCredentialRotationMemberNotFound, nil)
	case errors.Is(err, asset.ErrAssetNotFound):
		apierror.Respond(c, http.StatusNotFound, apierror.CodeAssetNotFound, nil)

	case errors.Is(err, asset.ErrCredentialNameRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialNameRequired, nil)
	case errors.Is(err, asset.ErrCredentialNameTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialNameTooLong, nil)
	case errors.Is(err, asset.ErrCredentialNameInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialNameInvalid, nil)
	case errors.Is(err, asset.ErrCredentialScopeInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialScopeInvalid, nil)
	case errors.Is(err, asset.ErrCredentialSecretTypeInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialSecretTypeInvalid, nil)
	case errors.Is(err, asset.ErrCredentialSecretRequired):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialSecretRequired, nil)
	case errors.Is(err, asset.ErrCredentialUsernameImmutable):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialUsernameImmutable, nil)
	case errors.Is(err, asset.ErrCredentialProtocolFamilyInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialProtocolFamily, nil)
	case errors.Is(err, asset.ErrCredentialDetachSourceInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialDetachSourceInvalid, nil)
	// 人工輸入的私鑰無法解析：與資產、資產帳號入口同碼；原始解析錯誤不帶出
	case errors.Is(err, asset.ErrPrivateKeyInvalid):
		respondPrivateKeyInvalid(c)
	// 帳號名的既有檢核在憑證上沿用同一套規則，故沿用既有帳號名碼
	case errors.Is(err, asset.ErrAssetAccountUsernameInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameInvalid, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameTooLong, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameReserved):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountUsernameReserved, nil)
	case errors.Is(err, asset.ErrAssetAccountNoteTooLong):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountNoteTooLong, nil)
	// auth_method 值域＝sql｜domain（資料庫協定族的認證類型），非 secret_type；
	// 沿用帳號碼，送錯值是請求錯誤，不得漏成 500
	case errors.Is(err, asset.ErrAssetAccountAuthMethodInvalid):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountAuthMethod, nil)
	case errors.Is(err, asset.ErrAssetAccountAuthMethodUnsupported):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeAccountAuthMethodUnsupported, nil)

	case errors.Is(err, asset.ErrCredentialNameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialNameExists, nil)
	case errors.Is(err, asset.ErrCredentialBindingExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialBindingExists, nil)
	case errors.Is(err, asset.ErrAssetAccountUsernameExists):
		apierror.Respond(c, http.StatusConflict, apierror.CodeAccountUsernameExists, nil)

	case errors.Is(err, asset.ErrCredentialHasPendingCandidate):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialPendingCandidate, nil)
	case errors.Is(err, asset.ErrCredentialRotationActive):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialRotationActive, nil)
	case errors.Is(err, asset.ErrCredentialOutOfSync):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialOutOfSync, nil)
	case errors.Is(err, asset.ErrCredentialSharedRequiresName):
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialSharedRequiresName, nil)
	case errors.Is(err, asset.ErrCredentialToDedicatedMultiBinding):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialToDedicatedMulti, nil)
	case errors.Is(err, asset.ErrCredentialToDedicatedNoBinding):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialToDedicatedNoBinding, nil)
	case errors.Is(err, asset.ErrCredentialDedicatedSingleBinding):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialDedicatedSingle, nil)
	case errors.Is(err, asset.ErrCredentialProtocolMismatch):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialProtocolMismatch, nil)
	case errors.Is(err, asset.ErrCredentialNotShared):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialNotShared, nil)
	case errors.Is(err, asset.ErrCredentialRotationNotRunning):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialRotationNotRunning, nil)
	case errors.Is(err, asset.ErrCredentialRotationNoBinding):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialRotationNoBinding, nil)
	case errors.Is(err, asset.ErrMemberTransitionNotAllowed):
		apierror.Respond(c, http.StatusConflict, apierror.CodeCredentialMemberNotRetryable, nil)
	default:
		apierror.RespondInternal(c, http.StatusInternalServerError, internalCode, err)
	}
}

// credentialParam 解析 :id（憑證）。第二回傳值 false＝已寫錯誤回應。
func credentialParam(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidCredentialID, nil)
		return 0, false
	}
	return uint(id), true
}

// credentialAccountParam 解析 :accountId（掛載列）。
func credentialAccountParam(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("accountId"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidAccountID, nil)
		return 0, false
	}
	return uint(id), true
}

// credentialRotationParam 解析 :rid（輪替）。
func credentialRotationParam(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("rid"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidRotationID, nil)
		return 0, false
	}
	return uint(id), true
}

// credentialMemberParam 解析 :mid（輪替成員）。
func credentialMemberParam(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("mid"), 10, 32)
	if err != nil || id == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidRotationMemberID, nil)
		return 0, false
	}
	return uint(id), true
}

// credentialContext 把操作者身分與角色帶入 ctx（審計與跨資產權限判定都需要）。
func credentialContext(c *gin.Context) context.Context {
	return accountContext(c)
}

// --- 端點 ---

// List 憑證清單（範圍、秘密型別、協定相容性、輪替狀態、帳號名與顯示名搜尋、分頁）。
// 讀取留痕由審計中介層承擔。
//
// **分頁是選用的**：不帶 page 即回全部（既有呼叫端的行為不變），帶了才切頁。
// `total` 恆為套用全部篩選後的筆數，而不是本頁筆數——否則畫面算不出有幾頁。
//
// 輪替狀態的篩選在取回之後於此層做，不下推成 SQL：狀態是逐掛載狀態桶取最嚴的
// **計算值**，沒有可篩的欄位；下推等於在 DB 裡再實作一次那套優先序，而兩份口徑
// 遲早分岔，分岔出來的就是同一筆憑證在兩個畫面上顯示成兩種合規狀態。
func (h *CredentialHandler) List(c *gin.Context) {
	filter := asset.CredentialFilter{
		Scope:      c.Query("scope"),
		Username:   c.Query("username"),
		Search:     c.Query("search"),
		SecretType: c.Query("secret_type"),
	}
	family, ok := parseCredentialProtocolFamilyQuery(c)
	if !ok {
		return
	}
	filter.ProtocolFamily = family
	filter.Ownership = c.Query("ownership")
	if filter.Ownership != "" && filter.Ownership != model.CredentialOwnerGlobal &&
		filter.Ownership != model.CredentialOwnerAsset && filter.Ownership != model.CredentialOwnerNode {
		respondInvalidQueryParam(c, "ownership")
		return
	}
	if raw := c.Query("owner_node_id"); raw != "" {
		nodeID, perr := strconv.ParseUint(raw, 10, 32)
		if perr != nil || nodeID == 0 {
			respondInvalidQueryParam(c, "owner_node_id")
			return
		}
		n := uint(nodeID)
		filter.OwnerNodeID = &n
	}
	rotationState := c.Query("rotation_state")
	if rotationState != "" && !asset.IsRotationBucket(rotationState) {
		respondInvalidQueryParam(c, "rotation_state")
		return
	}
	page, ok := parsePositiveIntQuery(c, "page", 0)
	if !ok {
		return
	}
	pageSize, ok := parsePositiveIntQuery(c, "page_size", credentialDefaultPageSize)
	if !ok {
		return
	}
	if pageSize > credentialMaxPageSize {
		pageSize = credentialMaxPageSize
	}

	items, err := h.credentials.List(credentialContext(c), filter)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialList, err)
		return
	}
	if rotationState != "" {
		items, err = h.filterByRotationState(items, rotationState)
		if err != nil {
			respondCredentialError(c, apierror.CodeInternalCredentialList, err)
			return
		}
	}
	total := len(items)
	if page > 0 {
		items = credentialPageSlice(items, page, pageSize)
	}
	rows, err := credentialRowsJSON(items)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialList, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows, "total": total})
}

// 列表分頁的預設與上限。上限是為了讓「一次要一萬筆」這種請求不必逐筆投影。
const (
	credentialDefaultPageSize = 20
	credentialMaxPageSize     = 200
)

// parseCredentialProtocolFamilyQuery 由「資產協定＋Windows OpenSSH 開關」推導要篩的
// 協定族；回傳空字串＝不以協定族篩選。第二個回傳值為 false 時回應已寫出。
//
// **推導在後端做，不由呼叫端傳族別**：協定族是協定與改密通道共同決定的計算值
// （model.ProtocolFamilyForAsset），在畫面上複製一份判準，會在通道規則改變的那一刻
// 開始說謊——而說謊的方向正好是「挑得到的憑證其實掛不上去」。
//
// **兩個參數缺一不擋**：只帶協定＝Windows 開關視為關；只帶開關而沒有協定不構成
// 篩選條件（沒有協定就沒有可推導的族別），回全部。
func parseCredentialProtocolFamilyQuery(c *gin.Context) (string, bool) {
	windowsOpenSSH := false
	if raw := c.Query("windows_openssh"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			respondInvalidQueryParam(c, "windows_openssh")
			return "", false
		}
		windowsOpenSSH = parsed
	}
	raw := c.Query("protocol")
	if raw == "" {
		return "", true
	}
	protocol := model.ProtocolType(raw)
	if !asset.IsAssetProtocol(protocol) {
		respondInvalidQueryParam(c, "protocol")
		return "", false
	}
	probe := model.Asset{Protocol: protocol}
	if windowsOpenSSH {
		// 開關描述的是「這台機器的改密走 Windows OpenSSH」。與協定不相容時，
		// 它描述的是一台本系統建不出來的資產——回錯而非靜默忽略：靜默忽略會回一份
		// 看起來正常、實際上族別不對的清單，而畫面上看不出來
		if !model.RotationChannelCompatibleWith(protocol, model.RotationChannelWindowsSSH) {
			respondInvalidQueryParam(c, "windows_openssh")
			return "", false
		}
		probe.RotationChannel = model.RotationChannelWindowsSSH
	}
	return model.ProtocolFamilyForAsset(&probe), true
}

// filterByRotationState 只留下輪替狀態等於指定桶的憑證。
//
// 判定器缺席時回錯而非略過篩選：靜默回成未篩選的全部，使用者看不出自己拿到的
// 不是他要的那幾筆。
func (h *CredentialHandler) filterByRotationState(items []*asset.CredentialDTO,
	want string) ([]*asset.CredentialDTO, error) {

	if h.rotationStatus == nil {
		return nil, errCredentialRotationStatusUnavailable
	}
	asOf := time.Now()
	out := make([]*asset.CredentialDTO, 0, len(items))
	for _, item := range items {
		state, err := h.rotationStatus.CredentialRotationStatus(item.ID, asOf)
		if err != nil {
			return nil, err
		}
		if state == want {
			out = append(out, item)
		}
	}
	return out, nil
}

// errCredentialRotationStatusUnavailable 輪替狀態判定器缺席（裝配缺陷）。
// 對外收斂為一般內部錯誤，成因只落伺服端日誌。
var errCredentialRotationStatusUnavailable = errors.New("輪替狀態判定不可用")

// credentialPageSlice 取第 page 頁（1 起算）；超出範圍回空片而非錯誤——
// 「翻到沒有資料的那一頁」是正常操作，不是請求有問題。
func credentialPageSlice(items []*asset.CredentialDTO, page, pageSize int) []*asset.CredentialDTO {
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []*asset.CredentialDTO{}
	}
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

// Get 憑證詳情（含掛載清單與逐台就位版本）。
func (h *CredentialHandler) Get(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	detail, err := h.credentials.Get(credentialContext(c), id)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialGet, err)
		return
	}
	// 聚合態併入詳情：憑證庫的動作區要據它決定哪些動作此刻可執行，
	// 讓前端再打一次改密端點才問得到會多出一個可能不一致的中間狀態
	data, derr := credentialDetailJSON(detail)
	if derr != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialGet, derr)
		return
	}
	if state, serr := h.rotations.AggregateState(id); serr == nil {
		c.JSON(http.StatusOK, gin.H{"data": data, "aggregate_state": state})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": data})
}

// Create 建立共用憑證（零掛載的待用狀態）。
func (h *CredentialHandler) Create(c *gin.Context) {
	var req asset.CreateCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	dto, err := h.credentials.Create(credentialContext(c), &req)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialCreate, err)
		return
	}
	c.JSON(http.StatusCreated, dto)
}

// Update 改名稱、備註；專用憑證另可改帳號名。
func (h *CredentialHandler) Update(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	var req asset.UpdateCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	dto, err := h.credentials.Update(credentialContext(c), id, &req)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialUpdate, err)
		return
	}
	c.JSON(http.StatusOK, dto)
}

// Delete 刪除憑證（仍有掛載時拒絕並回受影響資產名單）。
func (h *CredentialHandler) Delete(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	if err := h.credentials.Delete(credentialContext(c), id); err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialDelete, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Bind 掛到資產（對目標主機零寫入）。
func (h *CredentialHandler) Bind(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	var req asset.BindCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	// 受影響資產的主體鍵：路徑上只有憑證識別，中介層推導不出這個動作動到哪台機器。
	// 失敗時同樣要留（那也是一次針對該台的嘗試），故在呼叫服務之前就注入
	setAuditAssetIDValue(c, req.AssetID)
	dto, err := h.credentials.Bind(credentialContext(c), id, &req)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialBind, err)
		return
	}
	c.JSON(http.StatusCreated, dto)
}

// Unbind 卸載（只移除掛載列，不更動目標主機上的秘密）。
func (h *CredentialHandler) Unbind(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	accountID, ok := credentialAccountParam(c)
	if !ok {
		return
	}
	// 主體鍵取自掛載列所屬資產：卸載後該掛載即不存在，事後回查不到
	setAuditAssetIDValue(c, h.bindingAssetID(id, accountID))
	if err := h.credentials.Unbind(credentialContext(c), id, accountID); err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialUnbind, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Detach 單台脫離共用（改密後改綁專用憑證）。**同步**：只動一台，
// 而操作者需要當下的結果——脫離失敗與遠端結果不明對他的下一步完全不同。
func (h *CredentialHandler) Detach(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	accountID, ok := credentialAccountParam(c)
	if !ok {
		return
	}
	var req asset.DetachCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	setAuditAssetIDValue(c, h.bindingAssetID(id, accountID))
	rot, err := h.rotations.Detach(credentialContext(c), id, accountID, req)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialDetach, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": h.rotationView(rot)})
}

// ConvertScope 轉專用／轉共用（不動任何密文版本與遠端主機）。
func (h *CredentialHandler) ConvertScope(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	var req asset.ConvertCredentialScopeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	dto, err := h.credentials.ConvertScope(credentialContext(c), id, &req)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialScope, err)
		return
	}
	c.JSON(http.StatusOK, dto)
}

// ReassignOwnership 批次改歸共用憑證的管理歸屬（整批原子；任一筆不可操作只回筆數）。
func (h *CredentialHandler) ReassignOwnership(c *gin.Context) {
	var req asset.ReassignCredentialOwnershipRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	res, err := h.credentials.ReassignOwnership(credentialContext(c), &req)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialUpdate, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

// SetSecret 直接寫入新密文（建新版本，不動遠端；供補登既有密碼）。
func (h *CredentialHandler) SetSecret(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	var req asset.SetCredentialSecretRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	dto, err := h.credentials.SetSecret(credentialContext(c), id, &req)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialSecret, err)
		return
	}
	c.JSON(http.StatusOK, dto)
}

// ConfirmImpact 建立範圍外影響確認：宣告新秘密或遠端輪替提交前，先取得範圍外台數與不透明確認識別。
// 範圍外集合為空回 required=false；回應不含任何範圍外資產識別、名稱或節點。
func (h *CredentialHandler) ConfirmImpact(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	var req asset.ConfirmCredentialImpactRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	res, err := h.credentials.ConfirmImpact(credentialContext(c), id, &req)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialSecret, err)
		return
	}
	body, err := withOutOfScopeCount(res, res.OutOfScopeAssets)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialSecret, err)
		return
	}
	if res.OutOfScopeAssets == 0 {
		delete(body, disclosure.FieldOutOfScopeAssetCount)
	}
	c.JSON(http.StatusOK, body)
}

// StartRotation 發起改密（整組或拆分）。**非同步**：n 台各自連線與驗證，
// 同步等待會讓請求掛到逾時。回 202 與輪替識別，進度由 GET 進度端點輪詢。
func (h *CredentialHandler) StartRotation(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	var body startRotationBody
	if err := c.ShouldBindJSON(&body); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	req := asset.StartRotationRequest{Policy: body.Policy, ImpactConfirmationID: body.ImpactConfirmationID}
	ctx := credentialContext(c)

	var rot *model.CredentialRotation
	var err error
	switch body.Mode {
	case model.CredentialRotationModeGroup, "":
		rot, err = h.rotations.Start(ctx, id, req)
	case model.CredentialRotationModeSplit:
		rot, err = h.rotations.StartSplit(ctx, id, req)
	default:
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeCredentialRotationModeInvalid, nil)
		return
	}
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationStart, err)
		return
	}
	h.runRotationAsync(rot.ID)
	c.JSON(http.StatusAccepted, gin.H{"data": h.rotationView(rot)})
}

// GetRotation 改密進度（聚合態＋成員逐列）。
func (h *CredentialHandler) GetRotation(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	rid, ok := credentialRotationParam(c)
	if !ok {
		return
	}
	// 進度查詢與詳情同一道檢視裁決：範圍外與不存在的憑證在此收斂為同形回應
	if _, err := h.credentials.Get(credentialContext(c), id); err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationGet, err)
		return
	}
	rot, err := h.rotations.Rotation(id, rid)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationGet, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": h.rotationView(rot)})
}

// RetryMember 逐台補跑。**同步**：只動一台，操作者要當下的結果。
// 選用 body：{"confirm_host_identity": {...}} 明示承接主機身分停止的成員；
// 不帶 body 時行為與回應形狀不變，只在成員被主機身分守衛擋下時該成員多帶 host_identity。
func (h *CredentialHandler) RetryMember(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	rid, ok := credentialRotationParam(c)
	if !ok {
		return
	}
	mid, ok := credentialMemberParam(c)
	if !ok {
		return
	}
	// 形狀先於一切查詢與服務呼叫：不合法的 body 不會觸及任何狀態
	confirm, err := parseHostIdentityConfirmBody(c)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	// 憑證層判定先於輪替歸屬查詢：範圍外憑證與不存在同形，輪替識別不得用來探測範圍外的輪次
	if err := h.rotations.RequireRotationTarget(credentialContext(c), id); err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationRetry, err)
		return
	}
	// 憑證識別是判定的一部分：先確認該輪替屬於路徑上的憑證，再推進成員
	if _, err := h.rotations.Rotation(id, rid); err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationRetry, err)
		return
	}
	var (
		hostIdentity *asset.HostIdentityView
		reason       string
	)
	if confirm != nil {
		switch cerr := h.confirmMember(c, rid, mid, *confirm); {
		case cerr == nil, errors.Is(cerr, asset.ErrHostIdentityVerifyFailed):
			// 驗證沒有通過：成員保留、可再次確認，失敗原因在成員的最近錯誤
		case isHostIdentityTargetChanged(cerr):
			reason = model.ChangeSecretReasonAuthzTargetChanged
		default:
			respondHostIdentityMemberError(c, cerr)
			return
		}
	} else {
		res, err := h.rotations.RunMemberResult(credentialContext(c), rid, mid, asset.RotationRecordOrigin{})
		if err != nil {
			respondCredentialError(c, apierror.CodeInternalCredentialRotationRetry, err)
			return
		}
		if res != nil {
			hostIdentity = res.HostIdentity
		}
	}
	rot, err := h.rotations.Rotation(id, rid)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationRetry, err)
		return
	}
	view := h.rotationView(rot)
	for i := range view.Members {
		if view.Members[i].ID == mid {
			view.Members[i].HostIdentity = hostIdentity
			view.Members[i].Reason = reason
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": view})
}

// confirmMember 帶確認的補跑：先確認成員屬於該輪替（不存在與不屬於同一回應），再交給承接服務。
func (h *CredentialHandler) confirmMember(c *gin.Context, rid, mid uint, req asset.HostIdentityConfirmRequest) error {
	members, err := h.rotations.Members(rid)
	if err != nil {
		return err
	}
	found := false
	for i := range members {
		found = found || members[i].ID == mid
	}
	if !found {
		return asset.ErrCredentialRotationMemberNotFound
	}
	if h.confirmer == nil {
		return errors.New("人工承接服務未注入")
	}
	return h.confirmer.ConfirmHostIdentityAndVerify(credentialContext(c), "member", mid, req)
}

// respondHostIdentityMemberError 承接錯誤的出口：成員不存在走憑證端點既有的 404，其餘與候選共用同一組對映。
func respondHostIdentityMemberError(c *gin.Context, err error) {
	if errors.Is(err, asset.ErrCredentialRotationMemberNotFound) {
		apierror.Respond(c, http.StatusNotFound, apierror.CodeCredentialRotationMemberNotFound, nil)
		return
	}
	respondHostIdentityConfirmError(c, apierror.CodeInternalCredentialRotationRetry, err)
}

// AbandonRotation 放棄本輪（不回滾已動過的遠端；未動過的成員標為放棄）。
func (h *CredentialHandler) AbandonRotation(c *gin.Context) {
	id, ok := credentialParam(c)
	if !ok {
		return
	}
	rid, ok := credentialRotationParam(c)
	if !ok {
		return
	}
	// 憑證層判定先於輪替歸屬與「已結束」的狀態檢查：範圍外憑證與不存在同形
	if err := h.rotations.RequireRotationTarget(credentialContext(c), id); err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationAbandon, err)
		return
	}
	if _, err := h.rotations.Rotation(id, rid); err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationAbandon, err)
		return
	}
	if err := h.rotations.Abandon(credentialContext(c), rid); err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationAbandon, err)
		return
	}
	rot, err := h.rotations.Rotation(id, rid)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRotationAbandon, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": h.rotationView(rot)})
}

// RebindAccount 更換此掛載使用的憑證（PUT /assets/:id/accounts/:accountId/credential）。
func (h *CredentialHandler) RebindAccount(c *gin.Context) {
	assetID, accountID, ok := accountParams(c, true)
	if !ok {
		return
	}
	var req struct {
		CredentialID uint `json:"credential_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadRequestFormat, nil)
		return
	}
	if req.CredentialID == 0 {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeInvalidCredentialID, nil)
		return
	}
	dto, err := h.credentials.Rebind(credentialContext(c), assetID, accountID, req.CredentialID)
	if err != nil {
		respondCredentialError(c, apierror.CodeInternalCredentialRebind, err)
		return
	}
	c.JSON(http.StatusOK, dto)
}

// --- 內部 ---

// rotationView 組出輪替的對外形狀（成員與聚合態取不到時不因此把回應翻成失敗：
// 那是進度的補充資訊，缺它仍答得出「這一輪是哪一輪、現在什麼狀態」）。
func (h *CredentialHandler) rotationView(rot *model.CredentialRotation) credentialRotationDTO {
	members, err := h.rotations.Members(rot.ID)
	if err != nil {
		log.Printf("[Credential] 查詢輪替成員失敗: rotation=%d err=%v", rot.ID, err)
		members = nil
	}
	aggregate, err := h.rotations.AggregateState(rot.CredentialID)
	if err != nil {
		log.Printf("[Credential] 查詢聚合態失敗: credential=%d err=%v", rot.CredentialID, err)
		aggregate = ""
	}
	out := newRotationDTO(rot, members, aggregate)
	if rot.Status == model.CredentialRotationAbandoned {
		unsettled, uerr := h.rotations.UnsettledRotationID(rot.CredentialID)
		if uerr != nil {
			log.Printf("[Credential] 查詢未收束輪替失敗: credential=%d err=%v", rot.CredentialID, uerr)
		}
		out.Unsettled = uerr == nil && unsettled == rot.ID
		if out.Unsettled {
			kept, kerr := h.rotations.CandidateKeptMembers(rot.ID)
			if kerr != nil {
				log.Printf("[Credential] 查詢成員候選失敗: rotation=%d err=%v", rot.ID, kerr)
			}
			for i := range out.Members {
				out.Members[i].CandidateKept = kept[out.Members[i].ID]
			}
		}
	}
	return out
}

// bindingAssetID 取掛載列所屬的資產識別，供審計主體鍵注入。
//
// 取不到時回 0（`setAuditAssetIDValue` 對 0 是空操作）：主體鍵是查詢的便利，
// 不該讓一次合法的卸載因為多查一次失敗而被拒。
func (h *CredentialHandler) bindingAssetID(credentialID, accountID uint) uint {
	return h.credentials.BindingAssetID(credentialID, accountID)
}

// runRotationAsync 於背景推進整輪。
//
// **必須攔 panic**：Go 的 goroutine panic 直接終止行程——一次改密的遠端例外
// 不該有把整個閘道帶下線的權力，而閘道下線會把全部進行中的連線一起切斷。
// ctx 用 Background 而非請求 ctx：請求回應之後那個 ctx 即被取消，
// 沿用它會讓每一輪改密在回 202 的瞬間全部中止。
func (h *CredentialHandler) runRotationAsync(rotationID uint) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[Credential] 輪替推進 panic: rotation=%d panic=%v", rotationID, r)
			}
		}()
		if err := h.rotations.Run(context.Background(), rotationID); err != nil {
			log.Printf("[Credential] 輪替推進失敗: rotation=%d err=%v", rotationID, err)
		}
	}()
}

// RegisterRoutes 註冊憑證庫路由。
//
// 讀取路由認憑證檢視能力；寫入路由在路由層只確認主體持有任一憑證語義管理能力
// （補跑與放棄只認遠端輪替能力），各動作所需的能力與影響集合由服務層逐項裁決。
// 憑證是登入身分的本體，掛載清單與拓撲同受這組授權保護（見 credential_handler 檔頭）。
//
// 單台脫離只有這一支端點（`/credentials/:id/bindings/:accountId/detach`）：
// 編輯資產抽屜與憑證庫掛載列都打它——兩支端點的規則會漂移，而漂移的方向是
// 其中一支忘了某一道檢核。
func (h *CredentialHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	g := r.Group("/credentials")
	g.Use(middleware.AuthMiddleware(authService))
	g.Use(middleware.EnforceRegistry())
	{
		g.GET("", h.List)
		g.POST("", h.Create)
		g.POST("/ownership", h.ReassignOwnership)
		g.GET("/:id", h.Get)
		g.PUT("/:id", h.Update)
		g.DELETE("/:id", h.Delete)
		g.POST("/:id/bindings", h.Bind)
		g.DELETE("/:id/bindings/:accountId", h.Unbind)
		g.POST("/:id/bindings/:accountId/detach", h.Detach)
		g.POST("/:id/scope", h.ConvertScope)
		g.POST("/:id/secret", h.SetSecret)
		g.POST("/:id/impact-confirmations", h.ConfirmImpact)
		g.POST("/:id/rotations", h.StartRotation)
		g.GET("/:id/rotations/:rid", h.GetRotation)
		g.POST("/:id/rotations/:rid/members/:mid/retry", h.RetryMember)
		g.POST("/:id/rotations/:rid/abandon", h.AbandonRotation)
	}

	// 更換掛載憑證掛在資產帳號路徑下：它改的是**那一台**的登入身分，
	// 路徑上的主體是資產而非憑證，審計主體鍵因此由路由層即可推導
	rebind := r.Group("/assets/:id/accounts/:accountId")
	rebind.Use(middleware.AuthMiddleware(authService))
	rebind.Use(middleware.EnforceRegistry())
	{
		rebind.PUT("/credential", h.RebindAccount)
	}
}
