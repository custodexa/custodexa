package authz

import (
	"fmt"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 資產列表連線入口三態 bulk 標註（authz 側）。
//
// **為何在 authz 而非 policy**：本方法對 authz 自己的 `AuthorizedAssetDTO` 做標註，
// 且所讀的三份資料（`access_requests` 在途單、`asset_authorizations` 票證時窗、
// 常設 connect 命中）全部是 authz 自有表。它消費 policy 的段位判定，方向本就是
// authz→policy。原掛在 `AccessPolicyService` 上使 policy 反向依賴 authz 的
// `AuthorizedAssetDTO` 與 repository，是 §4.8 環的一半。
//
// **搬遷為零行為變更**：邏輯逐行未改，只有三處限定名調整——段位解析改呼叫
// `policy.AccessPolicyService.ResolveSegments`（全域鍵仍只讀一次）、破窗開關
// 改由本服務既有的 `s.policies` 讀、常設命中改用本服務既有的 `s.authzRepo`。
// 掛在 `AccessRequestService` 上是因為它已同時持有 db／policies／accessPolicy／
// authzRepo 四者，改掛他型別會需要新增建構子參數。

// 連線入口三態值（reason_required/approval_required 沿 policy 的閘常數）。
// 值本體定義在 policy（`AccessStateConnectable`／`AccessStatePending`），此處不另立複本。

// AnnotateConnectStates 資產列表連線入口三態 bulk 標註：
// 伺服端單一事實源——政策解析（資產欄位直讀）＋一次查 pending 集合＋
// 一次查 ticket 集合，前端零推導。僅供顯示提示；行為以簽發點政策閘為準
func (s *AccessRequestService) AnnotateConnectStates(userID uint, assets []*AuthorizedAssetDTO) error {
	if len(assets) == 0 {
		return nil
	}
	now := time.Now()

	// 1. 政策解析：資產欄位直讀，無組 join。
	// 全域預設鍵整批只讀一次（語義與拆包前逐位相同，見 ResolveSegments 註解）
	assetPolicies := make([]*string, len(assets))
	for i, a := range assets {
		assetPolicies[i] = a.AccessPolicy
	}
	segments := s.accessPolicy.ResolveSegments(assetPolicies)

	// 2. 在途單集合（惰性過濾：逾期單不算申請中）
	var pendings []model.AccessRequest
	if err := s.db.Select("id", "asset_id").
		Where("requester_id = ? AND status = ? AND pending_expires_at > ?",
			userID, model.AccessRequestPending, now).
		Find(&pendings).Error; err != nil {
		return fmt.Errorf("查詢在途申請失敗: %w", err)
	}
	pendingByAsset := map[uint]uint{}
	for _, p := range pendings {
		pendingByAsset[p.AssetID] = p.ID
	}

	// 3. 時窗內 ticket 集合（每資產取最晚到期）
	var tickets []model.AssetAuthorization
	if err := s.db.Select("asset_id", "date_expired").
		Where("user_id = ? AND source = ? AND (date_start IS NULL OR date_start <= ?) AND (date_expired IS NULL OR date_expired > ?)",
			userID, model.AuthorizationSourceTicket, now, now).
		Find(&tickets).Error; err != nil {
		return fmt.Errorf("查詢臨時授權失敗: %w", err)
	}
	ticketExpiry := map[uint]*time.Time{}
	for i := range tickets {
		if tickets[i].AssetID == nil {
			continue
		}
		aid := *tickets[i].AssetID
		cur, ok := ticketExpiry[aid]
		if !ok || (tickets[i].DateExpired != nil && cur != nil && tickets[i].DateExpired.After(*cur)) {
			ticketExpiry[aid] = tickets[i].DateExpired
		}
	}

	// 4. 破窗可用性 bulk 判定：開關開啟時，
	// 非 open 段位×持時窗內常設 connect×無有效票證的資產標註可破窗——
	// 伺服端單一事實源，開關關閉＝前端零入口（藏入口語義）
	breakGlassOn := s.policies.GetBool(policy.PolicyBreakGlassEnabled)
	standing := map[uint]bool{}
	if breakGlassOn {
		nonOpen := make([]uint, 0, len(assets))
		for i, a := range assets {
			if segments[i] != model.AccessPolicyOpen {
				nonOpen = append(nonOpen, a.ID)
			}
		}
		var err error
		standing, err = s.authzRepo.StandingConnectAssetIDs(userID, nonOpen, now)
		if err != nil {
			return err
		}
	}

	for i, a := range assets {
		segment := segments[i]
		if segment == model.AccessPolicyOpen {
			// open 段位沿現狀：connect 等級才有連線入口；view-only 留空欄
			if a.Permission == model.PermissionConnect {
				a.AccessState = policy.AccessStateConnectable
			}
			continue
		}
		if exp, ok := ticketExpiry[a.ID]; ok {
			a.AccessState = policy.AccessStateConnectable
			a.TicketDateExpired = exp
			continue
		}
		// 有票證＝正常可連不需破窗；申請中（在途單不阻擋破窗）與需申請皆可破窗
		if breakGlassOn && standing[a.ID] {
			a.BreakGlassAvailable = true
		}
		if reqID, ok := pendingByAsset[a.ID]; ok {
			id := reqID
			a.AccessState = policy.AccessStatePending
			a.PendingRequestID = &id
			continue
		}
		if segment == model.AccessPolicyReason {
			a.AccessState = policy.AccessGateReasonRequired
		} else {
			a.AccessState = policy.AccessGateApprovalRequired
		}
	}
	return nil
}
