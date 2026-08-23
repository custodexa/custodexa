// Package seal 實作 B 模式（KEK 由 UI 輸入、只存記憶體）的四態封印狀態機。
//
// 四態語義由 transitions.go 的遷移表定義，本套件逐字對應，不自行擴充語義。
//
// 核心結構：全域狀態由單一 atomic.Pointer[sealNode] 承載，所有轉態一律以
// CompareAndSwap(observed, new) 更新——observed 為呼叫方進入時所讀到的那個節點
// 指標。CAS 失敗即代表本次結果已被較新世代取代，一律丟棄。
// 本套件不得出現 `if cur.generation == mine { Store(new) }` 的兩步形式。
package seal

import (
	"time"
)

// SealState 為四態封印狀態機的態。
type SealState string

const (
	// StateSealed 未持有材料、無解封在飛。白名單外一律 503。
	StateSealed SealState = "sealed"
	// StateUnsealing 已有持有者：材料驗證與段 2 皆在其臨界區內進行。
	// 白名單外 503；解封端點回 409。
	StateUnsealing SealState = "unsealing"
	// StateUnsealed 段 2 完成且已原子發佈。
	StateUnsealed SealState = "unsealed"
	// StateSealedFaulted 材料正確但段 2 初始化失敗；可重試解封。
	StateSealedFaulted SealState = "sealed-faulted"
)

// stateBoot 為「行程尚未起始」的偽態，僅供遷移表格 1 使用，永不出現在 sealNode。
const stateBoot SealState = ""

// ServiceGraph 為段 2 建構出的完整服務圖。
//
// 本套件不解讀其內容，只要求它可被收束：逾時或初始化失敗時，舊持有者 SHALL
// 釋放已建構資源（連線池、檔案控制代碼、已建立的用戶端、背景 goroutine 與
// 排程器），並 SHALL 於 Release 內把持有的 KEK 材料歸零。
type ServiceGraph interface {
	Releaser
}

// cleanupToken 表示「有前代持有者尚未收束」。
// 取得持有權的 CAS 前置條件為 cleanup == nil（遷移表格 2），
// 於是「不放行兩份服務圖」成為 CAS 的結構性前置，而非散文承諾。
type cleanupToken struct {
	// generation 為待收束的前代世代號
	generation uint64
	// reason 為進入收束的成因機器碼（CodeInitFailed 或 CodeStage2Timeout）
	reason string
	// startedAt 為收束開始時刻，供 /seal/status 呈現等待時長
	startedAt time.Time
}

// sealNode 是全域狀態的唯一承載體。
//
// 範圍界定：入節點的一律是全域狀態。per-source（每來源）的失敗計數與退避
// SHALL NOT 入節點——它是無界的來源集合，實務上為獨立限速結構（見 limiter.go），
// 不得宣稱與本結構欄位在同一個 CAS 內更新。
type sealNode struct {
	generation    uint64        // 每次 CAS 進入 unsealing 時 +1（兩個來源態皆然）
	state         SealState     // sealed | unsealing | unsealed | sealed-faulted
	services      ServiceGraph  // 僅 unsealed 時非 nil
	sourceState   SealState     // unsealing 時記住來源態（格 3b/4/4b/5b/7 回退用）
	faultCode     string        // sealed-faulted 時的故障機器碼（逾時不得清除，格 7）
	cleanup       *cleanupToken // 非 nil＝有前代持有者待收束；取得持有權的前置為 nil
	cooldownUntil time.Time     // 全域冷卻（進入獨佔的前置，故必須在節點內）
}

// clone 產生節點淺複本，供 CAS 的 new 值構造。
// 一律以 clone 為起點修改，避免遺漏欄位而在轉態時靜默丟失冷卻或故障碼。
func (n *sealNode) clone() *sealNode {
	c := *n
	return &c
}

// Snapshot 是對外唯一的狀態讀取結果。
//
// 閘的狀態判定與 handler 的服務取用 SHALL 讀同一次指標載入結果，
// 故本套件只提供 Snapshot 這一個讀取入口；不提供會產生兩次載入的
// State()＋Services() 配對，「閘看到 unsealed、handler 拿到 nil」的撕裂窗
// 因此在 API 形狀上即不可達。
type Snapshot struct {
	Generation        uint64
	State             SealState
	Services          ServiceGraph
	SourceState       SealState
	FaultCode         string
	CleanupPending    bool
	CleanupGeneration uint64
	CleanupReason     string
	CleanupStartedAt  time.Time
	CooldownUntil     time.Time
}

func snapshotOf(n *sealNode) Snapshot {
	s := Snapshot{
		Generation:    n.generation,
		State:         n.state,
		Services:      n.services,
		SourceState:   n.sourceState,
		FaultCode:     n.faultCode,
		CooldownUntil: n.cooldownUntil,
	}
	if n.cleanup != nil {
		s.CleanupPending = true
		s.CleanupGeneration = n.cleanup.generation
		s.CleanupReason = n.cleanup.reason
		s.CleanupStartedAt = n.cleanup.startedAt
	}
	return s
}
