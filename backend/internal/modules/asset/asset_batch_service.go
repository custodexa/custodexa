package asset

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// 資產批次操作（搬移、加標籤、刪除）的共用邊界。
//
// 三動作同一流程，全在單一交易內：
//  1. 交易第一個動作取拓撲序列化鎖（早於任何資產列、憑證列鎖）；鎖後的判定一律在本交易內重解主體與拓撲。
//  2. 第一趟逐列：交易內讀現行歸屬並以單筆同一個判定入口判定。能力拒絕立即原樣回傳（整批單一 forbidden）；
//     資產種類的範圍拒絕、不存在、已刪除計入「無法操作」；刪除遇範圍外歸屬計入「受阻台數」（每台一次）；
//     其他錯誤原樣回滾。無法操作先於受阻，同一請求只回一種。
//  3. 動作專屬檢查與第二趟寫入，逐列審計與寫入同交易，任一失敗整批回滾。
//  4. 權限版本：第一個權限相關寫入之前呼叫一次 begin，所有寫入之後至多推進一次；逐列呼叫的單筆內層入口
//     在批次脈絡內不自行 begin、不自行推進。
//
// 回應錯誤由 handler 依型別寫出，本模組不解讀範圍拒絕的內容，也不建構拒絕值。

// BatchResult 批次成功的結果：Affected 實際改變的筆數，Unchanged 本來就是目標狀態的筆數。
type BatchResult struct {
	Affected  int `json:"affected"`
	Unchanged int `json:"unchanged"`
}

// BatchItemsUnavailableError 批次內有資產無法操作（範圍外、不存在、已刪除）；Count＝無法操作的筆數。
type BatchItemsUnavailableError struct {
	Count int
}

// Error 固定字串，不含識別碼。
func (e *BatchItemsUnavailableError) Error() string { return "asset: batch has unavailable items" }

// BatchOutOfScopeNodesError 批次刪除被範圍外歸屬擋下；Count＝受阻的資產台數（每台一次，不論範圍外歸屬數）。
type BatchOutOfScopeNodesError struct {
	Count int
}

// Error 固定字串，不含識別碼。
func (e *BatchOutOfScopeNodesError) Error() string {
	return "asset: batch has assets with nodes outside the caller's scope"
}

// ErrBatchEmpty 去重後沒有任何資產識別碼。
var ErrBatchEmpty = errors.New("asset: batch requires at least one asset")

// ErrBatchTagsEmpty 批次加標籤沒有任何有效標籤。
var ErrBatchTagsEmpty = errors.New("asset: batch tags require at least one tag")

// scopeDeniedTarget authz 範圍拒絕值的窄介面：本模組只讀目標種類，不 import authz。
type scopeDeniedTarget interface {
	error
	ScopeDeniedTargetKind() string
}

// scopeDeniedKindAsset 資產種類的範圍拒絕（目標種類的機器字串）。
const scopeDeniedKindAsset = "asset"

// scopeDeniedKindAssetAccount 資產帳號種類的範圍拒絕。
const scopeDeniedKindAssetAccount = "asset_account"

// assetBatchTag 批次操作逐列審計的關聯鍵；零值（ID 空）不寫。
type assetBatchTag struct {
	ID   string
	Size int
}

// applyAssetBatchTag 審計 details 補上批次鍵；batch 為空或 ID 空時不動。
func applyAssetBatchTag(d *model.AssetChangeDetails, batch []assetBatchTag) {
	if len(batch) == 0 || batch[0].ID == "" {
		return
	}
	d.BatchID, d.BatchSize = batch[0].ID, batch[0].Size
}

type topologyChangeBegunKey struct{}

// withTopologyChangeBegun 標示本交易已呼叫過 begin（批次在第一個寫入前統一呼叫）。
func withTopologyChangeBegun(ctx context.Context) context.Context {
	return context.WithValue(ctx, topologyChangeBegunKey{}, true)
}

// topologyChangeBegun 呼叫方交易是否已呼叫過 begin。
func topologyChangeBegun(ctx context.Context) bool {
	v, _ := ctx.Value(topologyChangeBegunKey{}).(bool)
	return v
}

// AssetBatchTestHooks 測試用接縫，經 WithAssetBatchTestHooksForTest 放進 ctx；正式路徑恆無。
type AssetBatchTestHooks struct {
	// BeforeTx 交易開始之前（序列化鎖之前）。
	BeforeTx func()
	// AfterLock 取得序列化鎖之後、第一趟判定之前；回錯即整批回滾。
	AfterLock func(tx *gorm.DB) error
	// BeforeItemWrite 第二趟第 index 筆（0 起）寫入之前；回錯即整批回滾。
	BeforeItemWrite func(tx *gorm.DB, index int) error
}

type assetBatchHooksKey struct{}

// WithAssetBatchTestHooksForTest 回傳帶批次測試接縫的 ctx（只供測試）。
func WithAssetBatchTestHooksForTest(ctx context.Context, h *AssetBatchTestHooks) context.Context {
	return context.WithValue(ctx, assetBatchHooksKey{}, h)
}

func assetBatchHooks(ctx context.Context) *AssetBatchTestHooks {
	h, _ := ctx.Value(assetBatchHooksKey{}).(*AssetBatchTestHooks)
	return h
}

func (h *AssetBatchTestHooks) beforeItemWrite(tx *gorm.DB, index int) error {
	if h == nil || h.BeforeItemWrite == nil {
		return nil
	}
	return h.BeforeItemWrite(tx, index)
}

// DedupeBatchIDs 去重並保留首見順序。
func DedupeBatchIDs(ids []uint) []uint {
	out := make([]uint, 0, len(ids))
	seen := make(map[uint]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// batchItem 第一趟判定通過的資產與其交易內讀出的現行歸屬。
type batchItem struct {
	id      uint
	current []uint
}

// runAssetBatchTx 三動作共用的交易邊界：structural 為真（搬移、刪除）時先取節點樹結構鎖；
// 交易第一個動作取拓撲序列化鎖，之後交給 fn。
func (s *AssetService) runAssetBatchTx(ctx context.Context, structural bool, fn func(tx *gorm.DB) error) error {
	if structural {
		treeStructMu.Lock()
		defer treeStructMu.Unlock()
	}
	hooks := assetBatchHooks(ctx)
	if hooks != nil && hooks.BeforeTx != nil {
		hooks.BeforeTx()
	}
	return database.DB.Transaction(func(tx *gorm.DB) error {
		if err := s.lockTopologyTx(tx); err != nil {
			return err
		}
		if hooks != nil && hooks.AfterLock != nil {
			if err := hooks.AfterLock(tx); err != nil {
				return err
			}
		}
		return fn(tx)
	})
}

// batchExistingIDsTx 交易內未刪除的資產識別碼集合（分段查詢，避開單一語句的參數數量上限）。
func batchExistingIDsTx(tx *gorm.DB, ids []uint) (map[uint]bool, error) {
	const chunk = 500
	out := make(map[uint]bool, len(ids))
	for start := 0; start < len(ids); start += chunk {
		end := min(start+chunk, len(ids))
		var found []uint
		if err := tx.Model(&model.Asset{}).Where("id IN ?", ids[start:end]).Pluck("id", &found).Error; err != nil {
			return nil, fmt.Errorf("查詢批次資產失敗: %w", err)
		}
		for _, id := range found {
			out[id] = true
		}
	}
	return out, nil
}

// precheckBatchTx 第一趟逐列判定（見檔頭第 2 點）。回傳通過者（保留請求順序）。
func (s *AssetService) precheckBatchTx(ctx context.Context, tx *gorm.DB, op AssetWriteOp, ids []uint) ([]batchItem, error) {
	existing, err := batchExistingIDsTx(tx, ids)
	if err != nil {
		return nil, err
	}
	items := make([]batchItem, 0, len(ids))
	unavailable, blocked := 0, 0
	for _, id := range ids {
		current, err := assetNodeIDs(tx, id)
		if err != nil {
			return nil, err
		}
		// 不存在者也判定：主體在交易內已失去能力時，第一列即回能力拒絕，不被當成無法操作
		err = s.authorizeWriteScopeTx(ctx, tx, op, id, current)
		var denied scopeDeniedTarget
		var outOfScope *AssetOutOfScopeNodesError
		switch {
		case err == nil:
			if !existing[id] {
				unavailable++
				continue
			}
			items = append(items, batchItem{id: id, current: current})
		case errors.As(err, &denied) && denied.ScopeDeniedTargetKind() == scopeDeniedKindAsset:
			unavailable++
		case errors.As(err, &outOfScope):
			if !existing[id] {
				unavailable++
				continue
			}
			blocked++
		default:
			return nil, err
		}
	}
	if unavailable > 0 {
		return nil, &BatchItemsUnavailableError{Count: unavailable}
	}
	if blocked > 0 {
		return nil, &BatchOutOfScopeNodesError{Count: blocked}
	}
	return items, nil
}

// newAssetBatchTag 每次請求一個批次識別。
func newAssetBatchTag(size int) (assetBatchTag, error) {
	id, err := newAssetCorrelationID()
	if err != nil {
		return assetBatchTag{}, err
	}
	return assetBatchTag{ID: id, Size: size}, nil
}

// BatchDelete 批次刪除：通過判定後逐台走單筆刪除的內層（清掛載、級聯撤授權與審核範圍、移除掛載與孤兒專用憑證），
// 逐台寫一列帶批次鍵的刪除審計；有掛載者被刪時權限版本推進一次。
func (s *AssetService) BatchDelete(ctx context.Context, ids []uint) (BatchResult, error) {
	ids = DedupeBatchIDs(ids)
	if len(ids) == 0 {
		return BatchResult{}, ErrBatchEmpty
	}
	tag, err := newAssetBatchTag(len(ids))
	if err != nil {
		return BatchResult{}, err
	}
	userID, username := model.UserFromContext(ctx)
	hooks := assetBatchHooks(ctx)
	var res BatchResult
	err = s.runAssetBatchTx(ctx, true, func(tx *gorm.DB) error {
		items, err := s.precheckBatchTx(ctx, tx, AssetWriteDelete, ids)
		if err != nil {
			return err
		}
		anyMounted := false
		for _, it := range items {
			if len(it.current) > 0 {
				anyMounted = true
				break
			}
		}
		innerCtx := ctx
		if anyMounted {
			if err := s.beginTopologyChangeTx(tx); err != nil {
				return err
			}
			innerCtx = withTopologyChangeBegun(ctx)
		}
		changed := false
		for i, it := range items {
			if err := hooks.beforeItemWrite(tx, i); err != nil {
				return err
			}
			var old model.Asset
			if err := tx.Where("id = ?", it.id).Limit(1).Find(&old).Error; err != nil {
				return fmt.Errorf("讀取資產失敗: %w", err)
			}
			c, err := s.DeleteTx(innerCtx, tx, it.id)
			if err != nil {
				return err
			}
			changed = changed || c
			if userID != 0 {
				// 刪除事件不帶 diff（old 與 new 同值），只帶批次鍵；資源欄位與單筆刪除相同
				if err := writeAssetChangeAudit(s.auditTx, tx, &old, &old, userID, username, model.ActionDelete, "", tag); err != nil {
					return fmt.Errorf("記錄資產刪除失敗: %w", err)
				}
			}
			res.Affected++
		}
		if changed {
			return s.advanceTopologyVersionTx(tx)
		}
		return nil
	})
	if err != nil {
		return BatchResult{}, err
	}
	return res, nil
}
