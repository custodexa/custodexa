package authz

import (
	"fmt"

	"github.com/custodexa/backend/internal/model"
)

// CountMinePending 申請人自己 pending 申請的全量件數。與 ListMine 不同，
// 不受 200 筆上限影響：儀表板的卡值與「已載入 X／共 N」都讀這個數。
func (s *AccessRequestService) CountMinePending(requesterID uint) (int64, error) {
	var n int64
	if err := s.db.Model(&model.AccessRequest{}).
		Where("requester_id = ? AND status = ?", requesterID, model.AccessRequestPending).
		Count(&n).Error; err != nil {
		return 0, fmt.Errorf("查詢我的待審申請數失敗: %w", err)
	}
	return n, nil
}
