package asset

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

// 資產寫入（建立、更新、停用、刪除）的交易內範圍判定（消費者側窄介面）。
//
// asset 不 import authz：在此宣告意圖，由組裝根注入 authz 的實作。方法都在呼叫方交易內、
// 取得拓撲序列化鎖之後呼叫，不開交易、不提交；主體由呼叫方放在 ctx（本模組不讀取）。
// 判定回傳的範圍拒絕與能力拒絕是 authz 定義的值，本模組不解讀也不改寫，原樣經交易回滾交回 handler。
// 本模組只定義兩個業務規則錯誤（零歸屬、範圍外歸屬），由 authz 實作回傳、handler 寫出。

// AssetWriteOp 寫入判定的操作種類。
type AssetWriteOp string

const (
	// AssetWriteUpdate 一般更新（依資產編輯能力）。
	AssetWriteUpdate AssetWriteOp = "update"
	// AssetWriteDisable 由啟用改為停用（依資產編輯能力，另套刪停的歸屬規則）。
	AssetWriteDisable AssetWriteOp = "disable"
	// AssetWriteDelete 刪除（依資產刪除能力，另套刪停的歸屬規則）。
	AssetWriteDelete AssetWriteOp = "delete"
	// AssetWriteAccessPolicy 變更單台存取政策覆寫（依存取政策權限點，不套刪停的歸屬規則）。
	AssetWriteAccessPolicy AssetWriteOp = "access_policy"
)

// AssetWriteScopePort 資產寫入的交易內範圍判定。
type AssetWriteScopePort interface {
	// AuthorizeAssetCreate 以 nodeIDs 為初始歸屬建立資產。
	AuthorizeAssetCreate(ctx context.Context, tx *gorm.DB, nodeIDs []uint) error
	// AuthorizeAssetWrite 對現行歸屬為 current（交易內讀出）的資產 assetID 執行 op。
	AuthorizeAssetWrite(ctx context.Context, tx *gorm.DB, op AssetWriteOp, assetID uint, current []uint) error
	// MergeAssetNodes 資產 assetID 更新送出 requested 時的新歸屬（含目標判定）：只替換主體看得到且在編輯能力範圍內的既有歸屬。
	MergeAssetNodes(ctx context.Context, tx *gorm.DB, assetID uint, current, requested []uint) ([]uint, error)
	// AccessPolicyCoversNodes 新資產帶非空存取政策覆寫時，每組目的節點是否至少一個在存取政策權限點的範圍內
	// （範圍不限者恆為真；沒有生效來源者恆為假）。回傳與 nodeSets 等長。
	AccessPolicyCoversNodes(ctx context.Context, tx *gorm.DB, nodeSets [][]uint) ([]bool, error)
}

var (
	// ErrAssetWriteScopePortMissing 寫入範圍判定未注入：寧可拒絕，也不在沒有判定的情況下寫入。
	ErrAssetWriteScopePortMissing = errors.New("asset: asset write scope port not injected")
	// ErrAssetNodeRequired 主體沒有全域能力時，資產的歸屬不得為空（建立與更新）。
	ErrAssetNodeRequired = errors.New("asset: asset requires at least one node")
)

// AssetOutOfScopeNodesError 刪除或停用被範圍外歸屬擋下；Count＝該操作能力範圍外的歸屬數。
type AssetOutOfScopeNodesError struct {
	Count int
}

// Error 固定字串，不含名稱或識別碼。
func (e *AssetOutOfScopeNodesError) Error() string {
	return "asset: asset has nodes outside the caller's scope"
}

// SetAssetWriteScopePort 注入資產寫入的範圍判定（組裝時）。
func (s *AssetService) SetAssetWriteScopePort(p AssetWriteScopePort) { s.writeScope = p }

// SetCoverageSnapshotPort 注入掛載變更審計用的涵蓋快照（組裝時）。
func (s *AssetService) SetCoverageSnapshotPort(p CoverageSnapshotPort) { s.coverage = p }
