package authz

import (
	"errors"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
)

// authz 側對 policy 窄介面 `policy.ConnectSourceResolver` 的實作。
//
// 編譯期斷言方向已翻轉：authz→policy。政策閘不再持有
// `*assetAuthorizationRepository`，也不再直查 `access_requests`。
var _ policy.ConnectSourceResolver = (*AssetAuthorizationService)(nil)

// HasTicketConnect 使用者對資產在 at 時點是否具核准流臨時授權（source=ticket）的 connect。
//
// 語義與拆環前的 `repo.ResolveConnectSources(...).Ticket` 逐位相同——同一個
// repository 查詢，只取政策閘用得到的那一欄。`Standing` 不外露：政策閘不消費它，
// 讓它跨介面只會把 authz 的內部形狀複製進 policy。
func (s *AssetAuthorizationService) HasTicketConnect(userID, assetID uint, at time.Time) (bool, error) {
	sources, err := s.repo.ResolveConnectSources(userID, assetID, at)
	if err != nil {
		return false, err
	}
	return sources.Ticket, nil
}

// PendingConnectRequestID 使用者對資產的在途申請單 ID；無在途單回 (nil, nil)。
//
// 查詢逐字沿用拆環前寫在 `access_policy_service.go` 的那一句（同欄位、同條件、
// 同 First 語義）；差別只在「查無」由 `gorm.ErrRecordNotFound` 轉為 (nil, nil)，
// 呼叫端的分流結果不變——原本也是「NotFound 就留空、其餘錯誤才上拋」。
func (s *AssetAuthorizationService) PendingConnectRequestID(userID, assetID uint) (*uint, error) {
	var pending model.AccessRequest
	err := s.db.Select("id").
		Where("requester_id = ? AND asset_id = ? AND status = ?", userID, assetID, model.AccessRequestPending).
		First(&pending).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	id := pending.ID
	return &id, nil
}
