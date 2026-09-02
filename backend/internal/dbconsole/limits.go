package dbconsole

import "time"

// 資源上限的**單一定義點**。
//
// 每一項都是「合法帳號在單一實例上能耗掉多少」的答案：多會話、寬欄、巨量節點、
// 慢速消費者各自都能耗盡記憶體或連線，而它們單獨看起來都像正常使用。
//
// **全部是常數、本版不提供設定面**：每加一個政策鍵或環境變數鍵都要動設定範本與
// 其守衛、或動政策頁；在還沒有人反映上限不合實務之前，那是替想像中的需求先付代價。
// 值由 limits_test.go 逐項釘住——上限被悄悄調寬時要有東西會紅。
const (
	// MaxConcurrentSessionsPerUser 每人同時進行的主控台會話數。
	// 4 的來由是實務形態：同一個人對三種靶機各開一場，再多一場備用
	MaxConcurrentSessionsPerUser = 4
	// MaxConcurrentSessionsGlobal 全域同時進行的主控台會話數。
	// **計數口徑是運行時的連線註冊表，不是 sessions 表的 active 列**：
	// 崩潰後等待收斂的孤兒列不在註冊表內，故不佔名額——
	// 否則使用者會被自己的殘留會話擋在門外，而他沒有任何辦法自救
	MaxConcurrentSessionsGlobal = 64

	// MaxStatementBytes 單次送出的語句文字上限（256 KiB）。
	// 在訊息層即拒絕，不產生審計列——那不是一個執行單位，是一個畸形請求
	MaxStatementBytes = 256 * 1024
	// MaxRowsPerUnit 單一執行單位回傳的資料列上限（跨結果集合計）。
	// **是回傳上限不是查詢上限**：目標端仍會算完整個結果，我們只是不搬回來
	MaxRowsPerUnit = 1000
	// MaxBytesPerSubmission 單次送出序列化後的位元組上限（8 MiB，跨單位合計）。
	// MSSQL 的多批次共用這個額度
	MaxBytesPerSubmission = 8 * 1024 * 1024
	// MaxCellBytes 單一欄位原始值的上限（64 KiB）。逾限截斷該欄並標記，
	// 使一個 BLOB 欄不能單獨把整場會話的記憶體吃掉
	MaxCellBytes = 64 * 1024
	// MaxTreeNodesPerLevel 目錄樹每一層的節點上限
	MaxTreeNodesPerLevel = 2000

	// StatementTimeout 單一執行單位的逾時。逾時＝ctx 取消，
	// 其後的狀態取決於目標端有沒有確認取消（確認＝timeout，未確認＝effect_unknown）
	StatementTimeout = 60 * time.Second
	// ConnectTimeout 建立目標連線的逾時（含握手）
	ConnectTimeout = 15 * time.Second
	// ProbeTimeout 逐單位的狀態探詢（當前庫＋交易態）逾時。
	// 探詢失敗不使單位失敗——它是脈絡不是結果，取不到就記 unknown
	ProbeTimeout = 5 * time.Second

	// pgCancelRequestDelay PostgreSQL 帶外取消請求的送出延遲。
	// 取 0＝立刻送：本路徑的取消一律來自使用者的明示動作或語句逾時，
	// 兩者都沒有「等一下說不定自己結束了」的餘地
	pgCancelRequestDelay = 0
	// pgCancelDeadlineDelay 取消請求送出後，對連線設下的保命期限。
	// 目標端對取消請求毫無反應時，它讓讀取不會無限期地掛著；
	// 值與 ProbeTimeout 同級——超過這個時間還沒回應，連線的健康度已無從主張
	pgCancelDeadlineDelay = 5 * time.Second

	// WriteDeadline 對客戶端的單則訊息寫入期限。
	// 觀察者路徑的先例是 5 秒；主控台是主路徑（結果送不出去等於功能失效），放寬一倍
	WriteDeadline = 10 * time.Second
	// OutboundQueueDepth 伺服端外送佇列深度。滿即關閉連線，
	// 不無界緩衝——無界緩衝把一個慢客戶端變成整個行程的記憶體風險
	OutboundQueueDepth = 16
)

// CellTruncationMarker 單欄截斷後附加的標記格式（`…[truncated N bytes]`）。
// 標記本身進值裡，使畫面與 CSV 都看得到截斷發生過——
// 只靠列層旗標的話，使用者分不出是哪一欄被砍了
const CellTruncationMarker = "…[truncated %d bytes]"
