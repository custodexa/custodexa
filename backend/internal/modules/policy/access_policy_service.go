package policy

import (
	"net/http"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// ConnectSourceResolver 連線授權來源解析（**policy 自宣告的窄介面**，authz 側實作）。
//
// **存在理由是 §4.8 環拆解**（modular-architecture W3 3.1／R3.1 §3.1）：政策閘原本
// 直接持有 `*database.AssetAuthorizationRepository` 並自行查 `access_requests`，
// 使 policy→authz 成為真出向邊；而 authz→policy 又因申請核准流讀政策鍵而必然存在
// （`access_request_service.go:131,132` 同時持 `*SecurityPolicyService` 與
// `*AccessPolicyService`），兩者合成環。介面由消費方（policy）宣告、實作留在 authz、
// 注入在 `cmd/server/stage2.go`，方向即翻轉為 authz→policy 單向。
//
// **簽名刻意只回布林與 ID，不回 authz 的 `ConnectSources` 結構**：政策閘只用得到
// 「是否有票證來源的 connect」與「在途單 ID」兩件事，讓介面承載更多等於把 authz 的
// 內部資料形狀複製進 policy，環拆掉了但耦合面沒縮。
type ConnectSourceResolver interface {
	// HasTicketConnect 使用者對資產在 at 時點是否具**核准流臨時授權**（source=ticket）
	// 的 connect 權限。非 open 段位只認這一種來源放行（決議 2/B）。
	HasTicketConnect(userID, assetID uint, at time.Time) (bool, error)
	// PendingConnectRequestID 使用者對資產的在途申請單 ID；無在途單回 (nil, nil)。
	// **僅供前端顯示**（`Decision.PendingRequestID`），不參與攔截判定。
	PendingConnectRequestID(userID, assetID uint) (*uint, error)
}

// 政策閘攔截原因（機器可辨，前端據此分流：reason 段彈事由框、approval 段導向申請）
const (
	AccessGateReasonRequired   = "reason_required"
	AccessGateApprovalRequired = "approval_required"
)

// AccessPolicyDecision 政策閘判定結果（access-policy-approval D4）
type AccessPolicyDecision struct {
	Allowed bool
	// AdminExemption 本次放行屬 admin 豁免（決議 3）：呼叫端必須寫入審計獨立標記
	AdminExemption bool
	// Policy 資產解析後的政策段位（open/reason/approval）
	Policy string
	// 以下僅攔截時有值。Status 恆 403——與傳輸閘 strict 400／warn 428 語義區隔
	Status             int
	Reason             string
	MaxDurationMinutes int
	// PendingRequestID 在途申請識別（前端顯示「申請中」而非再送新單）
	PendingRequestID *uint
}

// AccessPolicyService 存取政策解析與政策閘（access-policy-approval D1/D4）
type AccessPolicyService struct {
	db       *gorm.DB
	policies *SecurityPolicyService
	// sources 授權來源解析：型別是 policy 自宣告的窄介面，非 authz 的具體 repository
	// （§4.8 拆環）。SHALL NOT 為 nil——政策閘沒有它就無法分辨常設與票證來源，
	// 靜默降級等同把非 open 段位放行成 open
	sources ConnectSourceResolver
}

// NewAccessPolicyService 建立存取政策服務。
// sources 為窄介面（§4.8 拆環）：呼叫端 SHALL 傳入非 nil 實作
func NewAccessPolicyService(db *gorm.DB, policies *SecurityPolicyService, sources ConnectSourceResolver) *AccessPolicyService {
	return &AccessPolicyService{
		db:       db,
		policies: policies,
		sources:  sources,
	}
}

// isValidAccessPolicy 段位值合法性（open/reason/approval）
func isValidAccessPolicy(v string) bool {
	return v == model.AccessPolicyOpen || v == model.AccessPolicyReason || v == model.AccessPolicyApproval
}

// AccessPolicyOf 資產政策段位解析（asset-level-access-policy D1）：
// 資產欄位非 NULL 且合法用之，否則全域預設鍵。政策掛資產本身，
// 組織結構（分組/節點）不影響解析。欄位值非法（手動改庫等）視同未設定。
// 回傳恆為合法段位（政策鍵層 Get 對非法列值退回出廠預設）
func (s *AccessPolicyService) AccessPolicyOf(asset *model.Asset) string {
	if asset.AccessPolicy != nil && isValidAccessPolicy(*asset.AccessPolicy) {
		return *asset.AccessPolicy
	}
	v := s.policies.Get(PolicyAccessPolicyDefault)
	if !isValidAccessPolicy(v) {
		return model.AccessPolicyOpen
	}
	return v
}

// 連線入口三態值（D7 補充二；reason_required/approval_required 沿閘常數）
const (
	AccessStateConnectable = "connectable"
	AccessStatePending     = "pending"
)

// ResolveSegments 批次段位解析（bulk 標註專用；modular-architecture W3 3.1）。
//
// **唯一消費者＝authz 的 `AccessRequestService.AnnotateConnectStates`**。該方法原本
// 是 `AccessPolicyService` 的方法（`AnnotateConnectStates`），但它做的是「對 authz
// 自己的 `AuthorizedAssetDTO` 做標註、順帶查 authz 自己的在途單與票證表」——方向
// 本就該是 authz→policy（R3.1 §4.8(a)）。方法整個搬到 authz 後，policy 這側只需
// 提供段位解析。
//
// **回傳切片而非逐列查詢**：全域預設鍵在整批中**只讀一次**，與搬遷前逐位相同——
// 改成逐列呼叫 `AccessPolicyOf` 會讓同一頁的資產在政策剛好被改動時得到兩種段位。
// 入參是各資產的 `access_policy` 欄位值（nil＝未設定），輸出與輸入同長同序。
func (s *AccessPolicyService) ResolveSegments(assetPolicies []*string) []string {
	globalPolicy := s.policies.Get(PolicyAccessPolicyDefault)
	if !isValidAccessPolicy(globalPolicy) {
		globalPolicy = model.AccessPolicyOpen
	}
	out := make([]string, len(assetPolicies))
	for i, v := range assetPolicies {
		if v != nil && isValidAccessPolicy(*v) {
			out[i] = *v
			continue
		}
		out[i] = globalPolicy
	}
	return out
}

// CheckConnectByAssetID 依 assetID 載入資產後套政策閘（codex 審查 #1）：
// SFTP 檔案資料面與 connect-token 共用此閘，非 open 段位同樣蓋常設 connect——
// 否則強制審核只保護終端、不保護同資產的檔案傳輸。資產不存在回 gorm.ErrRecordNotFound，
// 呼叫端據此回 404（不洩漏存在性）
func (s *AccessPolicyService) CheckConnectByAssetID(userID uint, role string, assetID uint) (AccessPolicyDecision, error) {
	var asset model.Asset
	if err := s.db.Select("id", "access_policy").First(&asset, assetID).Error; err != nil {
		return AccessPolicyDecision{}, err
	}
	return s.CheckConnect(userID, role, &asset)
}

// CheckConnect 政策閘判定（D4）：connect-token 簽發點第三道閘，
// 於授權檢查之後、傳輸安全閘之前呼叫。語義鐵則（決議 2/B）：
// 非 open 段位蓋過常設 connect——僅時窗內核准流（source=ticket）授權放行；
// reason 與 approval 的差別只在申請將被即時自動核准，不是攔不攔。
// admin 豁免放行（呼叫端寫審計獨立標記）；auditor 與一般 user 同攔
func (s *AccessPolicyService) CheckConnect(userID uint, role string, asset *model.Asset) (AccessPolicyDecision, error) {
	policy := s.AccessPolicyOf(asset)
	if policy == model.AccessPolicyOpen {
		return AccessPolicyDecision{Allowed: true, Policy: policy}, nil
	}

	ticket, err := s.sources.HasTicketConnect(userID, asset.ID, time.Now())
	if err != nil {
		return AccessPolicyDecision{}, err
	}
	if ticket {
		return AccessPolicyDecision{Allowed: true, Policy: policy}, nil
	}
	if role == model.RoleAdmin {
		return AccessPolicyDecision{Allowed: true, AdminExemption: true, Policy: policy}, nil
	}

	reason := AccessGateApprovalRequired
	if policy == model.AccessPolicyReason {
		reason = AccessGateReasonRequired
	}
	decision := AccessPolicyDecision{
		Policy:             policy,
		Status:             http.StatusForbidden,
		Reason:             reason,
		MaxDurationMinutes: s.policies.GetInt(PolicyAccessRequestMaxDurationMinutes),
	}

	// 在途單識別（僅供前端顯示，查失敗不影響攔截判定）。
	// 經 ConnectSourceResolver 取得：`access_requests` 是 authz 的表，policy 不直查（§4.8(c)）
	pendingID, err := s.sources.PendingConnectRequestID(userID, asset.ID)
	if err != nil {
		return AccessPolicyDecision{}, err
	}
	decision.PendingRequestID = pendingID
	return decision, nil
}
