package seal

import "context"

// outcome 結果碼值域（D6.5，五類）。
// 「結果未知」不在此列——它由「有 received 無 outcome」表達，不是一個結果碼。
const (
	// OutcomeSuccess 材料驗證通過且段 2 完成。
	// 語義收窄：SHALL NOT 被解讀為「服務已發佈」——發佈另由 published 記錄。
	OutcomeSuccess = "success"
	// OutcomeMaterialFailure 材料驗證失敗（格 4）。
	OutcomeMaterialFailure = "material_failure"
	// OutcomeInitFailed 段 2 初始化失敗＝faulted（格 6）。
	OutcomeInitFailed = "init_failed"
	// OutcomeTimeout 段 2 逾時（格 7）。
	OutcomeTimeout = "timeout"
	// OutcomeAborted received 落地後的主動中止（格 4b）。
	OutcomeAborted = "aborted"
)

// rejected 合批計數的 kind 值域（D6.5 rejected 環）。
const (
	// RejectedCooldown 全域冷卻期內被拒。
	RejectedCooldown = "cooldown"
	// RejectedBackoff per-source 退避期內被拒。
	RejectedBackoff = "backoff"
	// RejectedConflict 未取得持有權被拒（進行中／待收束／已解封）。
	RejectedConflict = "conflict"
)

// Journal 是封印期留痕的注入介面（D6.5 的定長環狀 journal）。
//
// 本介面形狀為跨批次契約：實作由 internal/sealjournal 提供，本套件只依賴介面。
// 呼叫定序由狀態機保證：
//
//	取得記憶體 CAS（勝出）
//	  → WriteReceived + 同步成功
//	  → 才驗證材料
//	  → WriteOutcome 並同步
//	  → （outcome=success 且 publish CAS 成功時）WritePublished
//
// 不變式：任何被驗證的嘗試必有 durable 個別紀錄。WriteReceived 失敗
// SHALL 使狀態機回滾 CAS、拒絕該次、不進行任何驗證（格 3b）。
type Journal interface {
	// WriteReceived 寫入 PREPARE／RECEIVED 槽並確認 durable，回傳全域序號。
	// sourceDigest 為來源摘要，SHALL NOT 含請求體、KEK 材料或任何認證憑證。
	WriteReceived(ctx context.Context, gen uint64, sourceDigest string) (seq uint64, err error)

	// WriteOutcome 為同一 seq 寫入結果碼並確認 durable。
	// outcome 取值為上列 Outcome* 五者之一；同一 seq 至多一筆。
	WriteOutcome(ctx context.Context, gen uint64, seq uint64, outcome string) error

	// WritePublished 於 publish CAS 成功後寫入同世代的 published 記錄。
	// 回灌判定：有 SUCCESS(gen=N) 而無 published(gen=N) → 標「已驗證通過但未確認發佈」。
	WritePublished(ctx context.Context, gen uint64, seq uint64) error

	// RecordRejected 累計被拒嘗試（合批，不逐筆同步）。
	// kind 取值為上列 Rejected* 三者之一。
	RecordRejected(kind string)

	// Close 收束 journal 寫入器。
	Close() error
}

// validOutcomes 供狀態機自我檢查，避免寫出值域外的結果碼。
var validOutcomes = map[string]struct{}{
	OutcomeSuccess:         {},
	OutcomeMaterialFailure: {},
	OutcomeInitFailed:      {},
	OutcomeTimeout:         {},
	OutcomeAborted:         {},
}

// validRejectedKinds 供狀態機自我檢查。
var validRejectedKinds = map[string]struct{}{
	RejectedCooldown: {},
	RejectedBackoff:  {},
	RejectedConflict: {},
}
