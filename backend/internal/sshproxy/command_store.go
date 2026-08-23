package sshproxy

import (
	"github.com/custodexa/backend/internal/modules/audit"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

const (
	// commandQueueSize 異步入庫佇列容量：滿載時丟棄而非阻塞，
	// 會話可用性優先於審計完整性
	commandQueueSize = 256
	// commandWriteBatchSize 批次寫入大小：湊批減少 DB round-trip
	commandWriteBatchSize = 32
)

// CommandStore 指令異步入庫：佇列 → 批次寫 session_commands → 告警比對。
// 佇列/湊批/drain 機制與 guacd 路徑的 CommandRecorder 一致（該版隨 SSH
// 退出 guacd 一併移除），輸入源改為虛擬螢幕重組後的指令字串。
type CommandStore struct {
	sessionID uint
	userID    uint
	assetID   *uint
	seq       int

	// K8s 當次 pod/container（k8s-exec）：冗餘入每條指令，免 JOIN 跨會話搜尋
	k8sPod       string
	k8sContainer string

	// protocol 會話協議：告警比對依此分流 shell/SQL 規則（避免跨協議誤報）
	protocol string

	db        *gorm.DB
	ch        chan model.SessionCommand
	done      chan struct{}
	dropped   atomic.Uint64
	closeOnce sync.Once

	// alerts 降級告警的落地面：與阻斷路徑同一個 AlertSink，
	// 故入庫、通知、syslog 離機轉發三件事一併接上。
	// nil 時 gatewayapi.RecordAlert 回 ErrAlertSinkMissing 並留 log，不靜默 no-op。
	alerts gatewayapi.AlertSink
	// span 連續降級輪次的聚合狀態，只由 writeLoop 讀寫（見 command_degrade_alert.go）
	span degradeSpan
}

// NewCommandStore 建立入庫器並啟動寫入 goroutine
func NewCommandStore(db *gorm.DB, sessionID, userID uint, assetID *uint, protocol string) *CommandStore {
	s := &CommandStore{
		sessionID: sessionID,
		userID:    userID,
		assetID:   assetID,
		protocol:  protocol,
		db:        db,
		ch:        make(chan model.SessionCommand, commandQueueSize),
		done:      make(chan struct{}),
	}
	go s.writeLoop()
	return s
}

// SetAlertSink 掛上降級告警的落地面。
//
// **與 onCommand／SetRecordSink 同型的後設注入**：既有呼叫端與測試以
// `NewCommandStore(db, …)` 建構，改建構簽名會把一個純新增的能力變成一次全域改寫。
// 未掛上時降級告警發不出去且每次都留下 log（ErrAlertSinkMissing），不靜默消失。
func (s *CommandStore) SetAlertSink(sink gatewayapi.AlertSink) {
	s.alerts = sink
}

// SetK8s 設定當次 K8s pod/container（k8s-exec：冗餘入每條指令）
func (s *CommandStore) SetK8s(pod, container string) {
	s.k8sPod = pod
	s.k8sContainer = container
}

// Enqueue 非阻塞入隊一條已重組的指令；佇列滿時丟棄並計數
func (s *CommandStore) Enqueue(command string, executedAt time.Time) {
	s.enqueue(command, false, "", executedAt)
}

// EnqueueDegraded 入隊一筆降級紀錄：該輪存在，但指令文字無法可信重組。
//
// **共用 s.seq++**：seq 是會話內的執行順序，兩個讀取面都靠它排序
// （session_command_service.go 的 `Order("seq ASC")`、SessionDetail.vue 的時間軸）。
// 另立計數器會讓降級紀錄與指令列的先後關係消失，而「第 N 輪無法還原」
// 這個事實的價值有一半在於它落在哪兩條指令之間。
//
// **command 恆為空**：呼叫端傳不進文字，且 baseline 的
// `CHECK (NOT degraded OR command = '')` 在 DB 層再擋一次。
func (s *CommandStore) EnqueueDegraded(reason string, executedAt time.Time) {
	s.enqueue("", true, reason, executedAt)
}

// Record CommandParser 的 CommandRecordFunc 落地入口：
// degraded 決定走降級（無文字）或限定（有文字但可信度受限）路徑。
func (s *CommandStore) Record(command string, degraded bool, reason string, executedAt time.Time) {
	if degraded {
		s.EnqueueDegraded(reason, executedAt)
		return
	}
	s.enqueue(command, false, reason, executedAt)
}

// enqueue 非阻塞入隊；佇列滿時丟棄並計數。
//
// **s.seq++ 刻意在 select 之前**：丟棄因此留下一個 seq 斷號，
// 而斷號本身即證據——稽核看到 1,2,4 就知道第 3 筆存在過且沒進來，
// 遠好過一段看起來完整無缺的 1,2,3。
func (s *CommandStore) enqueue(command string, degraded bool, reason string, executedAt time.Time) {
	s.seq++
	cmd := model.SessionCommand{
		SessionID:     s.sessionID,
		UserID:        s.userID,
		AssetID:       s.assetID,
		Command:       command,
		Seq:           s.seq,
		ExecutedAt:    executedAt,
		Degraded:      degraded,
		DegradeReason: reason,
		K8sPod:        s.k8sPod,
		K8sContainer:  s.k8sContainer,
	}

	select {
	case s.ch <- cmd:
	default:
		n := s.dropped.Add(1)
		if n == 1 || n%100 == 0 {
			log.Printf("[SSHProxy] 指令佇列已滿，丟棄記錄 (SessionID=%d, 累計丟棄=%d)", s.sessionID, n)
		}
	}
}

// writeLoop 單一寫入 goroutine：湊批寫入，flush 成功後過告警比對
func (s *CommandStore) writeLoop() {
	defer close(s.done)

	batch := make([]model.SessionCommand, 0, commandWriteBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.db.CreateInBatches(batch, commandWriteBatchSize).Error; err != nil {
			// 寫入失敗僅記 log：審計盡力而為，不重試避免堆積
			log.Printf("[SSHProxy] 指令批次入庫失敗 (SessionID=%d, count=%d): %v", s.sessionID, len(batch), err)
		} else {
			if matcher := audit.GetAlertMatcher(); matcher != nil {
				// 告警比對掛載點（command-alerts）：flush 成功後逐條比對，
				// MatchAndStore 內部錯誤僅 log，不反向影響入庫
				matcher.MatchAndStore(batch, s.protocol)
			}
			// 降級告警的專用發射器：同樣在**入庫成功之後**，
			// 且刻意在規則比對之後——規則路徑的行為一個字都不變。
			// **不走規則表**：規則可被 CRUD 停用，等於交出一鍵靜默規格要求的安全訊號的開關。
			s.observeDegraded(batch)
		}
		batch = batch[:0]
	}

	for cmd := range s.ch {
		batch = append(batch, cmd)
	collect:
		for len(batch) < commandWriteBatchSize {
			select {
			case next, ok := <-s.ch:
				if !ok {
					break collect
				}
				batch = append(batch, next)
			default:
				break collect
			}
		}
		flush()
	}
	flush()
}

// Close 關閉入庫器並等待殘餘批次寫完（drain）。
// 必須在 bridge 結束後（sinks 不再被呼叫）才能呼叫。
//
// **降級告警的 drain 點即此**：會話在降級中結束時，最後一批降級列
// 由 writeLoop 收尾的那次 flush 寫入並觀測，其 span 告警在本函式回傳前發出。
// 「會話在全螢幕狀態下直接斷線」正是最需要留痕的形態，不能等到下一批才發。
func (s *CommandStore) Close() {
	s.closeOnce.Do(func() {
		close(s.ch)
		<-s.done
		if n := s.dropped.Load(); n > 0 {
			log.Printf("[SSHProxy] 會話 %d 因佇列滿載共丟棄 %d 筆指令記錄", s.sessionID, n)
		}
	})
}

// auditTap 將 CommandParser 掛上 bridge 旁路的執行緒安全包裝。
// bridge 的輸入（pumpInput goroutine）與輸出（讀取 goroutine）來自
// 不同 goroutine，而 CommandParser 非併發安全，以單一鎖序列化。
type auditTap struct {
	mu     sync.Mutex
	parser *CommandParser
}

func newAuditTap(parser *CommandParser) *auditTap {
	return &auditTap{parser: parser}
}

func (t *auditTap) WriteInput(p []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.parser.WriteInput(p)
}

func (t *auditTap) WriteOutput(p []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.parser.WriteOutput(p)
}

func (t *auditTap) Resize(cols, rows int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.parser.Resize(cols, rows)
}

// Flush 會話結束時結算 pending 指令
func (t *auditTap) Flush() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.parser.Flush()
}
