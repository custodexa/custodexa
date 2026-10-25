package asset

import (
	"context"

	"gorm.io/gorm"
)

// ChangeSecretAssetScope 某個能力對發起者的資產範圍。
//
// Limited 為假＝該能力有任一全系統來源（或超管），不收斂範圍；為真時 AssetIDs 是
// 「範圍內資產 id」的子查詢（可直接放進 IN (?)），空集合時子查詢不回任何列。
type ChangeSecretAssetScope struct {
	Limited  bool
	AssetIDs *gorm.DB
}

// ChangeSecretScopePort 批次改密在交易內需要的範圍判定（消費者側窄介面，tx-taking）。
//
// asset 不 import authz，由組裝根注入 authz 的實作。三個動作都在呼叫端交易內執行，
// 本身不開交易、不提交：
//
//   - LockTopology：取拓撲序列化鎖，必須是建立交易的第一個動作，早於任何業務列讀取。
//   - CapabilityMissing：不帶目標的能力檢核，任一有效來源（含節點範圍）即算持有；
//     回第一個缺少的能力，全部持有回空字串。只用在呼叫端其後自行以範圍收斂目標的流程。
//   - AssetScope：以發起者當下的有效指派計算該能力的資產範圍。
//   - ViewScope：讀取投影用的資產範圍。與 AssetScope 同一個三態集合，差別只在完全不持有
//     該能力的檢視者：入口權限點有全系統來源者維持全量（現行行為），否則為空。
type ChangeSecretScopePort interface {
	LockTopology(tx *gorm.DB) error
	CapabilityMissing(ctx context.Context, tx *gorm.DB, actorUserID uint, caps []string) (string, error)
	AssetScope(ctx context.Context, tx *gorm.DB, actorUserID uint, capability string) (ChangeSecretAssetScope, error)
	ViewScope(ctx context.Context, db *gorm.DB, actorUserID uint, capability string) (ChangeSecretAssetScope, error)
	// CandidateDenial 候選（候選 → 帳號 → 資產）是否在檢視者的帳號改密讀取範圍內；
	// 不在範圍內或不存在回範圍拒絕值（不透明 error，由 handler 交範圍拒絕出口），在範圍內回 nil。
	CandidateDenial(ctx context.Context, db *gorm.DB, actorUserID, candidateID uint) error
	// CredentialsVisible 憑證歸屬是否在檢視者該能力的讀取範圍內（歸屬口徑同憑證庫）。
	// 不限範圍回 (nil, true, nil)；否則回可見的憑證識別集合。
	CredentialsVisible(ctx context.Context, db *gorm.DB, actorUserID uint, capability string,
		credentialIDs []uint) (map[uint]bool, bool, error)
}

// WithScope 注入批次改密的範圍判定（組裝時）。
//
// 未注入時建立不取拓撲鎖、不收斂範圍，即全系統口徑；只經節點範圍持有能力的主體
// 會在能力判定一步被拒（不帶目標的檢核只認全系統來源），不會因缺注入而放寬。
func (s *ChangeSecretBatchService) WithScope(p ChangeSecretScopePort) *ChangeSecretBatchService {
	s.scope = p
	return s
}
