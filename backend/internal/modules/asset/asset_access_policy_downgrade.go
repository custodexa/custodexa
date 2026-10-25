package asset

import (
	"errors"
	"fmt"
	"strconv"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
)

// 單台存取政策覆寫的降級偵測與系統告警。
//
// 有效段位的計算與分類一律來自 policy 模組（EffectiveTier／ClassifyOverrideChange），
// 本檔只負責：在更新交易內讀一次全域預設、套分類、命中降級時經交易內落地面寫入
// 一筆 access_policy_relaxed 事件。事件與覆寫值、資產變更審計同一交易，任一失敗整筆回滾。
// 新建資產（建立與匯入）沒有「變更前」，不呼叫本檔。

// ErrAccessPolicyDefaultMissing 全域預設讀取面未注入：覆寫值要變更時無法判定降級，
// 與落地面未注入同為 fail-close，整筆更新回滾，不靜默略過告警。
var ErrAccessPolicyDefaultMissing = errors.New("存取政策全域預設讀取面未注入（不得靜默略過降級判定）")

// AccessPolicyDefaultReader 讀取政策鍵現值的窄介面（*policy.SecurityPolicyService 實作）。
type AccessPolicyDefaultReader interface {
	Get(key string) string
}

// SetAccessPolicyDefaultReader 注入全域預設讀取面（main 組裝時）。
func (s *AssetService) SetAccessPolicyDefaultReader(r AccessPolicyDefaultReader) {
	s.accessDefaults = r
}

// classifyAccessPolicyUpdate 在更新交易內判定本次更新對單台覆寫的影響。
// 全域預設在此只讀一次，前後兩個有效段位都用它。請求未帶 access_policy 或覆寫值未變時
// 回傳 nil（不需要預設值，也不要求讀取面已注入）。
func (s *AssetService) classifyAccessPolicyUpdate(req *UpdateAssetRequest, before, after *model.Asset) (*policy.TierChange, error) {
	if req.AccessPolicy == nil || sameAccessPolicy(before.AccessPolicy, after.AccessPolicy) {
		return nil, nil
	}
	if s.accessDefaults == nil {
		return nil, ErrAccessPolicyDefaultMissing
	}
	def := s.accessDefaults.Get(policy.PolicyAccessPolicyDefault)
	tc := policy.ClassifyOverrideChange(before.AccessPolicy, after.AccessPolicy, def)
	return &tc, nil
}

func sameAccessPolicy(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// raiseAccessPolicyRelaxed 降級時寫入一筆 access_policy_relaxed 事件。
// 參數沿系統告警目錄登錄：relax_type（override_lowered／override_cleared）、before_level／after_level
// （有效段位前後）、asset_name。覆寫前後值留在同交易資產變更審計 diff，不進事件。
func raiseAccessPolicyRelaxed(sink port.SystemAlertSink, tx *gorm.DB, asset *model.Asset, tc *policy.TierChange,
	userID uint, username, correlationID string) error {
	if tc == nil || tc.Result != policy.TierChangeDowngraded {
		return nil
	}
	id := asset.ID
	_, err := port.RaiseInTx(sink, tx, port.SystemAlertEvent{
		Type:          port.SystemAlertAccessPolicyRelaxed,
		Actor:         port.SystemAlertActor{UserID: userID, Username: username},
		Target:        port.SystemAlertTarget{Kind: port.SystemAlertTargetAsset, ID: strconv.FormatUint(uint64(id), 10)},
		AssetID:       &id,
		CorrelationID: correlationID,
		Params: map[string]string{
			"relax_type":   tc.Cause,
			"before_level": tc.BeforeTier,
			"after_level":  tc.AfterTier,
			"asset_name":   asset.Name,
		},
	})
	if err != nil {
		return fmt.Errorf("產生存取政策放寬告警失敗: %w", err)
	}
	return nil
}
