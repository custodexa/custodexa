package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 資產寫入的範圍判定接點與掛載變更的涵蓋快照。
//
// 系統呼叫者（WithSystemCaller：無操作者主體的內部作業）不經範圍判定、不取涵蓋快照；
// 其他呼叫者缺注入即拒絕，交易回滾。判定一律在拓撲序列化鎖之後、資產列鎖與憑證列鎖之前。

// authorizeCreateScopeTx 建立的初始歸屬判定。
func (s *AssetService) authorizeCreateScopeTx(ctx context.Context, tx *gorm.DB, nodeIDs []uint) error {
	if isSystemCaller(ctx) {
		return nil
	}
	if s.writeScope == nil {
		return ErrAssetWriteScopePortMissing
	}
	return s.writeScope.AuthorizeAssetCreate(ctx, tx, nodeIDs)
}

// authorizeWriteScopeTx 對現行歸屬 current 的資產 id 執行 op 的判定。
func (s *AssetService) authorizeWriteScopeTx(ctx context.Context, tx *gorm.DB, op AssetWriteOp, id uint, current []uint) error {
	if isSystemCaller(ctx) {
		return nil
	}
	if s.writeScope == nil {
		return ErrAssetWriteScopePortMissing
	}
	return s.writeScope.AuthorizeAssetWrite(ctx, tx, op, id, current)
}

// mergeNodesScopeTx 資產 id 更新送出節點集合時的新歸屬；系統呼叫者照現行整組取代。
func (s *AssetService) mergeNodesScopeTx(ctx context.Context, tx *gorm.DB, id uint, current, requested []uint) ([]uint, error) {
	if isSystemCaller(ctx) {
		return requested, nil
	}
	if s.writeScope == nil {
		return nil, ErrAssetWriteScopePortMissing
	}
	return s.writeScope.MergeAssetNodes(ctx, tx, id, current, requested)
}

// earlyUpdateScopeCheck 交易外的提早判定：範圍外與不存在先於欄位能力與值驗證回同一個 404。
// 以交易內判定為準；這裡只讓回應順序與「資產不存在」一致。存取政策覆寫的範圍不在此判定
// （見 accessPolicyScopeBeforeValidation 與更新交易）。
func (s *AssetService) earlyUpdateScopeCheck(ctx context.Context, id uint, req *UpdateAssetRequest) error {
	if !updateNeedsScope(ctx, req) {
		return nil
	}
	current, err := assetNodeIDs(database.DB, id)
	if err != nil {
		return err
	}
	return s.authorizeWriteScopeTx(ctx, database.DB, AssetWriteUpdate, id, current)
}

// accessPolicyScopeBeforeValidation 帶存取政策覆寫的更新在值驗證失敗時，先以取拓撲序列化鎖的交易
// 判定範圍（與更新交易同一個取鎖位置與判定），範圍外與不存在同形；範圍內才由呼叫方回驗證錯誤。
// 交易不寫任何東西。
func (s *AssetService) accessPolicyScopeBeforeValidation(ctx context.Context, id uint, req *UpdateAssetRequest) error {
	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.lockTopologyTx(tx); err != nil {
			return err
		}
		_, err := s.authorizeUpdateScopeTx(ctx, tx, id, req)
		return err
	})
}

// updateNeedsScope 更新是否要套資產編輯能力的範圍：非系統呼叫者，且請求不是只含存取政策
// （只含存取政策者的單台範圍不在此判定）。新欄位一律算「其他欄位」。
func updateNeedsScope(ctx context.Context, req *UpdateAssetRequest) bool {
	if isSystemCaller(ctx) || req == nil {
		return false
	}
	return !accessPolicyOnly(req)
}

// UnmarshalJSON 照欄位標籤綁定，另記本文是否帶 access_policy 頂層鍵（值為 null 時 AccessPolicy 仍為 nil）。
// 鍵名比對不分大小寫，與 JSON 綁定及欄位閘一致。
func (r *UpdateAssetRequest) UnmarshalJSON(data []byte) error {
	type plain UpdateAssetRequest
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	*r = UpdateAssetRequest(p)
	for k := range keys {
		if strings.EqualFold(k, "access_policy") {
			r.accessPolicyKey = true
			break
		}
	}
	return nil
}

// hasAccessPolicyKey 請求帶 access_policy 鍵：有值（含清除用的空字串）或本文顯式 null。
func (r *UpdateAssetRequest) hasAccessPolicyKey() bool {
	return r != nil && (r.AccessPolicy != nil || r.accessPolicyKey)
}

// AccessPolicyOnlyUpdate 請求是否只帶存取政策鍵（含 null）；HTTP 層據此選成功回應的投影。
func AccessPolicyOnlyUpdate(req *UpdateAssetRequest) bool {
	return req != nil && accessPolicyOnly(req)
}

// accessPolicyOnly 請求只帶存取政策鍵（其他指標欄全為 nil）。空請求不算。
func accessPolicyOnly(req *UpdateAssetRequest) bool {
	if !req.hasAccessPolicyKey() {
		return false
	}
	v := reflect.ValueOf(req).Elem()
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		if name := t.Field(i).Name; name == "AccessPolicy" || name == "accessPolicyKey" {
			continue
		}
		f := v.Field(i)
		if f.Kind() != reflect.Pointer || !f.IsNil() {
			return false
		}
	}
	return true
}

// updateNeedsAccessPolicyScope 更新是否要套存取政策權限點的範圍：非系統呼叫者且本文帶 access_policy 鍵
// （含清除用的空字串與 null，與欄位閘及欄位能力同一判準），不論是否夾帶其他欄位。
func updateNeedsAccessPolicyScope(ctx context.Context, req *UpdateAssetRequest) bool {
	return !isSystemCaller(ctx) && req.hasAccessPolicyKey()
}

// disableCandidate 請求帶 active=false 即視為停用候選（交易內取鎖前不知舊值；舊值已停用時多判一次，只會更嚴）。
func disableCandidate(req *UpdateAssetRequest) bool {
	return req != nil && req.Active != nil && !*req.Active
}

// updateTakesTopologyLock 更新交易是否在第一個動作取拓撲序列化鎖。
// 帶存取政策覆寫者一律取（其範圍判定依拓撲），不以是否帶 node_ids 或改 active 為條件。
func updateTakesTopologyLock(ctx context.Context, req *UpdateAssetRequest) bool {
	return req.NodeIDs != nil || disableCandidate(req) || updateNeedsScope(ctx, req) ||
		updateNeedsAccessPolicyScope(ctx, req)
}

// authorizeUpdateScopeTx 更新交易內、資產列鎖之前的判定：停用候選套刪停規則，否則依編輯能力。
// 回傳交易內讀出的現行歸屬，供節點合併使用。
func (s *AssetService) authorizeUpdateScopeTx(ctx context.Context, tx *gorm.DB, id uint, req *UpdateAssetRequest) ([]uint, error) {
	current, err := assetNodeIDs(tx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case disableCandidate(req):
		err = s.authorizeWriteScopeTx(ctx, tx, AssetWriteDisable, id, current)
	case updateNeedsScope(ctx, req):
		err = s.authorizeWriteScopeTx(ctx, tx, AssetWriteUpdate, id, current)
	}
	if err != nil {
		return nil, err
	}
	if updateNeedsAccessPolicyScope(ctx, req) {
		if err := s.authorizeWriteScopeTx(ctx, tx, AssetWriteAccessPolicy, id, current); err != nil {
			return nil, err
		}
	}
	return current, nil
}

// accessPolicyScopeDenied 存取政策範圍不符的建立與匯入拒絕：與不持存取政策權限點者帶覆寫同一個值。
func accessPolicyScopeDenied(ctx context.Context) error {
	return capabilityDenied(ErrFieldCapabilityDenied, fieldCapabilityKeyOf(ctx, "access_policy"))
}

// accessPolicyCoversTx 每組目的節點是否至少一個在存取政策權限點的範圍內；系統呼叫者恆為真。
// 寫入範圍判定未注入時非系統呼叫者回 ErrAssetWriteScopePortMissing（不在沒有判定的情況下放行）。
func (s *AssetService) accessPolicyCoversTx(ctx context.Context, tx *gorm.DB, nodeSets [][]uint) ([]bool, error) {
	if isSystemCaller(ctx) {
		out := make([]bool, len(nodeSets))
		for i := range out {
			out[i] = true
		}
		return out, nil
	}
	if s.writeScope == nil {
		return nil, ErrAssetWriteScopePortMissing
	}
	covered, err := s.writeScope.AccessPolicyCoversNodes(ctx, tx, nodeSets)
	if err != nil {
		return nil, err
	}
	if len(covered) != len(nodeSets) {
		return nil, fmt.Errorf("存取政策範圍判定回傳筆數 %d 與請求 %d 不符", len(covered), len(nodeSets))
	}
	return covered, nil
}

// authorizeCreateAccessPolicyTx 新資產帶非空存取政策覆寫時，目的節點至少一個須在存取政策範圍內。
// 在建立交易內、初始歸屬判定之後呼叫；不符整筆拒絕。
func (s *AssetService) authorizeCreateAccessPolicyTx(ctx context.Context, tx *gorm.DB, accessPolicy *string, nodeIDs []uint) error {
	if accessPolicy == nil || *accessPolicy == "" {
		return nil
	}
	covered, err := s.accessPolicyCoversTx(ctx, tx, [][]uint{nodeIDs})
	if err != nil {
		return err
	}
	if !covered[0] {
		return accessPolicyScopeDenied(ctx)
	}
	return nil
}

// mountCoverage 掛載變更前後的涵蓋快照；skip 為真時（系統呼叫者且未注入）不取、審計列不帶該鍵。
type mountCoverage struct {
	skip   bool
	before CoverageSnapshot
}

// beginMountCoverageTx 寫掛載之前取前快照。
func (s *AssetService) beginMountCoverageTx(ctx context.Context, tx *gorm.DB, assetID uint) (*mountCoverage, error) {
	if s.coverage == nil {
		if isSystemCaller(ctx) {
			return &mountCoverage{skip: true}, nil
		}
		return nil, ErrCoverageSnapshotPortMissing
	}
	before, err := s.coverage.CoverageSnapshot(tx, []uint{assetID})
	if err != nil {
		return nil, fmt.Errorf("取得變更前涵蓋失敗: %w", err)
	}
	return &mountCoverage{before: before}, nil
}

// finishTx 寫掛載之後取後快照並產出差集；skip 時回 nil。
func (m *mountCoverage) finishTx(s *AssetService, tx *gorm.DB, assetID uint) (*TopologyCoverage, error) {
	if m == nil || m.skip {
		return nil, nil
	}
	after, err := s.coverage.CoverageSnapshot(tx, []uint{assetID})
	if err != nil {
		return nil, fmt.Errorf("取得變更後涵蓋失敗: %w", err)
	}
	cov := BuildTopologyCoverage(m.before, after)
	return &cov, nil
}

// nodeChangeDetailsJSON 掛載變更審計的 details：既有 changes 鍵不變，cov 非 nil 時附 topology_coverage。
func nodeChangeDetailsJSON(oldNodeIDs, newNodeIDs []uint, cov *TopologyCoverage, batch ...assetBatchTag) (string, error) {
	details := model.AssetChangeDetails{Changes: []model.AssetChange{
		{Field: "node_ids", Old: oldNodeIDs, New: newNodeIDs},
	}}
	applyAssetBatchTag(&details, batch)
	if cov != nil {
		raw, err := MarshalTopologyCoverage(*cov)
		if err != nil {
			return "", fmt.Errorf("涵蓋差異序列化失敗: %w", err)
		}
		details.TopologyCoverage = json.RawMessage(raw)
	}
	b, err := json.Marshal(details)
	if err != nil {
		return "", fmt.Errorf("序列化節點變更詳情失敗: %w", err)
	}
	return string(b), nil
}

// DeleteTx 單筆刪除的內層（可接收外部交易）：呼叫方已取拓撲序列化鎖，本函式不取鎖、不推進權限版本。
// 交易內做存在檢查、範圍與刪停歸屬判定，再寫既有刪除（含節點成員、授權級聯、掛載與資產列）。
// topologyChanged 為真表示刪的資產原有掛載，呼叫方應在交易最後推進權限版本（每交易至多一次）。
func (s *AssetService) DeleteTx(ctx context.Context, tx *gorm.DB, id uint) (topologyChanged bool, err error) {
	var n int64
	if err := tx.Model(&model.Asset{}).Where("id = ?", id).Count(&n).Error; err != nil {
		return false, fmt.Errorf("查詢資產失敗: %w", err)
	}
	if n == 0 {
		return false, ErrAssetNotFound
	}
	mounted, err := assetNodeIDs(tx, id)
	if err != nil {
		return false, err
	}
	if err := s.authorizeWriteScopeTx(ctx, tx, AssetWriteDelete, id, mounted); err != nil {
		return false, err
	}
	// 批次刪除在第一個寫入前已統一呼叫一次：逐台再呼叫會把前一台的撤授權記成無來源變動
	if len(mounted) > 0 && !topologyChangeBegun(ctx) {
		if err := s.beginTopologyChangeTx(tx); err != nil {
			return false, err
		}
	}
	if err := tx.Where("asset_id = ?", id).Delete(&model.AssetNode{}).Error; err != nil {
		return false, fmt.Errorf("清除節點成員失敗: %w", err)
	}
	// 授權與審核範圍隨資產失效：兩張表皆屬 authz，經 tx-taking 窄 port 交由擁有者寫入；
	// 未注入即 fail-close——靜默略過會留下幽靈授權與懸掛審核範圍
	if s.authzRevoker == nil {
		return false, fmt.Errorf("authz 級聯撤銷面未注入：資產刪除不得在不撤銷授權的情況下完成")
	}
	if _, _, err := s.authzRevoker.RevokeByAsset(tx, id); err != nil {
		return false, err
	}
	// 掛載與隨之孤兒的專用憑證：先於資產列軟刪，資產列鎖此時還鎖得到
	if err := removeAssetBindings(tx, id); err != nil {
		return false, err
	}
	if err := tx.Delete(&model.Asset{}, id).Error; err != nil {
		return false, fmt.Errorf("刪除資產失敗: %w", err)
	}
	return len(mounted) > 0, nil
}
