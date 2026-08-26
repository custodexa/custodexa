package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
)

// AuditLogEntry 審計日誌條目（從 middleware 傳入）
type AuditLogEntry struct {
	UserID     uint
	Username   string
	Action     model.AuditAction
	Resource   model.AuditResource
	ResourceID *uint
	// AssetID 資產主體鍵：作用於資產的動作**必須**填，
	// 工作台的資產樞紐只認本欄。非資產類動作留 nil
	AssetID     *uint
	Status      model.AuditStatus
	Method      string
	Path        string
	ClientIP    string
	StatusCode  int
	Duration    time.Duration
	RequestBody string // JSON 格式，已脫敏
	ErrorMsg    string
	RequestID   string
	Details     string // 變更/操作詳情（JSON），對應 model.AuditLog.Details
}

// AuditLogFilter 審計日誌查詢過濾器
type AuditLogFilter struct {
	UserID *uint
	// AssetID 資產維度（auditor-workbench 補入 audit_logs.asset_id 後才成立）：
	// 只認本欄，不以 (resource, resource_id) 冒充——後者會把改密計畫／授權列的
	// id 當成資產 id，把別的實體的事件掛到這台資產上
	AssetID   *uint
	Action    *model.AuditAction
	Resource  *model.AuditResource
	Status    *model.AuditStatus
	ClientIP  *string
	StartTime *time.Time
	EndTime   *time.Time
	Page      int
	PageSize  int
	// SortBy 排序欄位，取值限 auditSortableColumns，默認 "created_at"；
	// SortOrder 限 "asc"／"desc"，默認 "desc"。兩者由 List 收斂（值進 ORDER BY 原始子句）
	SortBy    string
	SortOrder string
}

// AuditLogListResult 審計日誌列表結果
type AuditLogListResult struct {
	Data  []*model.AuditLog `json:"data"`
	Total int64             `json:"total"`
	Page  int               `json:"page"`
	Size  int               `json:"page_size"`
}

// AuditLogService 審計日誌服務
type AuditLogService struct {
	cfg         *config.FeatureFlags
	logChan     chan *model.AuditLog
	workerCount int
	batchSize   int
	flushTicker *time.Ticker
	stopChan    chan struct{}
	wg          sync.WaitGroup
	fallbackDir string

	// dropObserver 佇列滿載致本筆未能直接入庫時的觀測掛勾。
	//
	// **以函式注入而非直接呼叫指標包**：本模組不因監控需求而新增依賴，
	// 語義（降級寫檔 vs 直接丟棄）的字串映射留在組裝根。
	//
	// 參數 fellBackToFile 為真表示已降級寫檔（資料仍可事後回收），
	// 為假表示**直接丟棄**（資料永久遺失）——兩者的營運意義不同，
	// 合併計數會使「到底有沒有掉資料」答不出來。
	dropObserverMu sync.RWMutex
	dropObserver   func(fellBackToFile bool)
}

// SetDropObserver 注入佇列滿載時的觀測掛勾。未注入時不影響任何行為。
func (s *AuditLogService) SetDropObserver(f func(fellBackToFile bool)) {
	s.dropObserverMu.Lock()
	defer s.dropObserverMu.Unlock()
	s.dropObserver = f
}

// notifyDrop 通知觀測掛勾。best-effort：觀測失敗不得影響審計路徑本身。
func (s *AuditLogService) notifyDrop(fellBackToFile bool) {
	s.dropObserverMu.RLock()
	f := s.dropObserver
	s.dropObserverMu.RUnlock()
	if f != nil {
		f(fellBackToFile)
	}
}

// QueueDepth 回傳非同步寫入佇列的目前深度（供指標曝光）。
//
// 同步模式下恆為 0——該模式不使用 channel，深度沒有意義。
func (s *AuditLogService) QueueDepth() int { return len(s.logChan) }

// resolveFallbackDir 決定審計降級 fallback 檔案的落地目錄。
// AUDIT_LOG_PATH 設定時採用該持久化路徑（compose/生產下對應掛載卷或 DATA_PATH bind mount），
// 未設時退回內建相對路徑保獨立二進位相容。
// 見 deployment-configuration 與 audit-failure-alerting spec（Req 10 降級模式審計持久化）。
func resolveFallbackDir() string {
	if p := os.Getenv("AUDIT_LOG_PATH"); p != "" {
		return p
	}
	return filepath.Join("logs", "audit_fallback")
}

// NewAuditLogService 創建審計日誌服務
func NewAuditLogService(cfg *config.FeatureFlags) *AuditLogService {
	service := &AuditLogService{
		cfg:         cfg,
		logChan:     make(chan *model.AuditLog, 1000), // Buffered channel，容量 1000
		workerCount: 3,                                // Worker 數量
		batchSize:   10,                               // 批次寫入大小（降低以便測試）
		flushTicker: time.NewTicker(2 * time.Second),  // 2 秒自動 flush（加快測試）
		stopChan:    make(chan struct{}),
		fallbackDir: resolveFallbackDir(),
	}

	// 確保 fallback 目錄存在
	if cfg.AuditFallbackToFile {
		if err := os.MkdirAll(service.fallbackDir, 0755); err != nil {
			log.Printf("警告: 創建 audit fallback 目錄失敗: %v", err)
		}
	}

	// 啟動 worker pool（僅在啟用異步模式時）
	if cfg.AsyncAuditEnabled {
		for i := 0; i < service.workerCount; i++ {
			service.wg.Add(1)
			go service.worker(i)
		}
		log.Printf("審計日誌異步寫入已啟動（%d workers, batch size %d）", service.workerCount, service.batchSize)
	}

	return service
}

// Log 記錄審計日誌（異步，不阻塞）
func (s *AuditLogService) Log(entry *AuditLogEntry) {
	s.logAt(entry, time.Time{})
}

// logAt 是 Log 的實作本體，多收一個「事件時刻」。
//
// **抽出的唯一理由是 AsyncSink.Submit**：gatewayapi.AuditEvent 帶
// OccurredAt 欄，而 Log 的簽名表達不了它。若讓 Submit 直接呼叫 Log，
// 非零的 OccurredAt 會被靜默丟棄——事件時刻被替換成入列時刻，是無聲的失真。
// occurredAt 為零值時行為與收口前逐字相同（time.Now()）。
func (s *AuditLogService) logAt(entry *AuditLogEntry, occurredAt time.Time) {
	if !s.cfg.AuditLogEnabled {
		return
	}
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}

	auditLog := &model.AuditLog{
		CreatedAt:   occurredAt,
		UserID:      entry.UserID,
		Username:    entry.Username,
		Action:      entry.Action,
		Resource:    entry.Resource,
		ResourceID:  entry.ResourceID,
		AssetID:     entry.AssetID,
		Status:      entry.Status,
		Method:      entry.Method,
		Path:        entry.Path,
		ClientIP:    entry.ClientIP,
		StatusCode:  entry.StatusCode,
		Duration:    int(entry.Duration.Milliseconds()),
		RequestBody: entry.RequestBody,
		ErrorMsg:    entry.ErrorMsg,
		RequestID:   entry.RequestID,
		Details:     entry.Details,
	}

	if s.cfg.AsyncAuditEnabled {
		// 異步寫入
		select {
		case s.logChan <- auditLog:
			// 成功加入 channel
			log.Printf("[Audit] 日誌已加入隊列：%s %s %s (Path: %s)",
				auditLog.Username, auditLog.Action, auditLog.Resource, auditLog.Path)
		default:
			// Channel 滿載：僅在啟用檔案降級時寫檔（與 DB 寫失敗分支一致，尊重開關——
			// 關閉時 fallback 目錄本就未建，硬寫必失敗），否則丟棄本筆並告警資料遺失
			//
			// 兩個分支皆通知觀測掛勾：此路徑不記
			// audit_failure_events（該條文的涵蓋範圍明文限定為「fallback 檔案觸發時」
			// 的寫庫失敗），原先唯一的痕跡是下面這行 log——不可查詢、不可告警、
			// 容器重啟即失。指標使「審計曾經掉過資料」成為可查證的持久事實
			if s.cfg.AuditFallbackToFile {
				log.Printf("警告: 審計日誌 channel 滿載，降級至檔案備份")
				s.writeToFile(auditLog)
				s.notifyDrop(true)
			} else {
				log.Printf("警告: 審計日誌 channel 滿載且檔案降級已關閉，本筆日誌丟棄")
				s.notifyDrop(false)
			}
		}
	} else {
		// 同步寫入（阻塞）
		if err := s.writeToDatabase([]*model.AuditLog{auditLog}); err != nil {
			log.Printf("錯誤: 審計日誌寫入失敗: %v", err)
			if s.cfg.AuditFallbackToFile {
				s.writeToFile(auditLog)
			}
		}
	}
}

// worker 處理 channel 中的日誌（批次寫入）
func (s *AuditLogService) worker(id int) {
	defer s.wg.Done()

	batch := make([]*model.AuditLog, 0, s.batchSize)
	flushBatch := func() {
		batch = s.flushBatch(id, batch)
	}

	for {
		select {
		case auditLog := <-s.logChan:
			log.Printf("[Audit] Worker %d 接收日誌：%s %s", id, auditLog.Username, auditLog.Path)
			batch = append(batch, auditLog)
			if len(batch) >= s.batchSize {
				flushBatch()
			}

		case <-s.flushTicker.C:
			// 定時 flush（避免小流量時日誌積壓）
			flushBatch()

		case <-s.stopChan:
			// 優雅關閉：flush 剩餘日誌
			log.Printf("Worker %d: 收到關閉信號，flush 剩餘日誌...", id)
			flushBatch()
			return
		}
	}
}

// flushBatch 寫出一批審計列，回傳清空後的 slice（供 worker 續用同一段底層陣列）。
//
// **抽成方法而非留在 worker 的閉包裡**：批次失敗的隔離語義是安全契約
//（見下方），必須能被測試直接驅動；留在閉包內只能靠啟動 worker、塞 channel、
// 等 ticker 這條間接路徑去逼近，而那種測試對時序敏感、驗不準確切筆數。
func (s *AuditLogService) flushBatch(id int, batch []*model.AuditLog) []*model.AuditLog {
	if len(batch) == 0 {
		return batch
	}

	dropped := batch
	err := s.writeToDatabase(batch)
	if err == nil {
		dropped = nil
	} else {
		// 失敗隔離。
		//
		// 批次是**單一 INSERT 語句**（`CreateInBatches` 在筆數不超過批量時走
		// 一次語句，超過時整組包在交易裡），故任一列違反欄位約束就是整批回滾——
		// 一列壞列可以把同批其他**合法**審計列一起沖掉。實測 9 發 401 中夾
		// 1 發超長路徑 → 入庫 3/9。這條路徑**零憑證即可觸發**，
		// 於是「夾帶一發畸形請求把同批的真實攻擊記錄一併抹掉」成為可行的
		// 清除證據手段。
		//
		// 逐列重試把損害限縮在真正違規的那幾列。重試不會產生重複列：失敗的
		// 批次是原子的，一列都沒進去。
		//
		// 只在**失敗路徑**上多花這幾次往返；正常路徑逐字不變。DB 整體不可用時
		// 全部重試都會失敗，成本上界為 batchSize 次快速失敗的往返。
		dropped = s.retryRowsIndividually(batch)
		log.Printf("Worker %d: 批次寫入失敗（%d 條），逐列隔離後 %d 條入庫、%d 條仍失敗；錯誤: %v",
			id, len(batch), len(batch)-len(dropped), len(dropped), err)
	}

	if len(dropped) > 0 {
		// 失效偵測：每批失敗直接上報，
		// 進行中節流由 AuditFailureService 的 in-memory 狀態機承擔——
		// worker 側自帶 CAS 旗標會與服務端轉換交錯出懸掛事件
		if failure := GetAuditFailure(); failure != nil {
			// 原因碼須反映開關真實行為，避免關閉時誤示「已降級至檔案」而遮蔽資料遺失
			causeCode := model.CauseAuditWriteFallbackFile
			params := map[string]string{model.CauseParamDetail: err.Error()}
			if !s.cfg.AuditFallbackToFile {
				causeCode = model.CauseAuditWriteBatchDropped
				// 計數取**實際未入庫**的列數而非整批筆數：隔離之後兩者不再相等，
				// 報整批筆數會把已入庫的列謊報為遺失
				params["dropped"] = strconv.Itoa(len(dropped))
			}
			failure.Report(model.MechanismAuditWrite, causeCode, params)
		}
		// 降級至檔案（僅在啟用時；與 channel 滿載/同步 DB 失敗分支一致）
		if s.cfg.AuditFallbackToFile {
			for _, l := range dropped {
				s.writeToFile(l)
			}
		}
	} else {
		log.Printf("Worker %d: 批次寫入完成（%d 條）", id, len(batch))
		// 恢復偵測：每批成功直接呼叫，非失效中為廉價 no-op
		if failure := GetAuditFailure(); failure != nil {
			failure.Resolve(model.MechanismAuditWrite)
		}
	}

	return batch[:0] // 清空 batch
}

// retryRowsIndividually 批次失敗後逐列重試，回傳仍然寫不進去的列。
//
// 回傳的是**指標本身**而非索引：呼叫端要拿它們走降級與遺失計數，
// 兩者都需要列的內容
func (s *AuditLogService) retryRowsIndividually(logs []*model.AuditLog) []*model.AuditLog {
	var failed []*model.AuditLog
	for _, l := range logs {
		if err := s.writeToDatabase([]*model.AuditLog{l}); err != nil {
			log.Printf("錯誤: 審計列逐列重試仍失敗（%s %s，status=%d）: %v",
				l.Method, l.Path, l.StatusCode, err)
			failed = append(failed, l)
		}
	}
	return failed
}

// writeToDatabase 批次寫入資料庫
func (s *AuditLogService) writeToDatabase(logs []*model.AuditLog) error {
	if len(logs) == 0 {
		return nil
	}

	// 完整性 HMAC（10.3.4）與 syslog tee（10.3.3）掛在 model 的
	// BeforeCreate/AfterCreate 註冊 hook（main 注入）——audit_logs 有
	// middleware 批次以外的直寫路徑（asset GORM hook、file_tap、k8s cp），
	// 集中在 model 層才能覆蓋全部（此處顯式蓋章會漏掉其他路徑）

	// 使用 CreateInBatches 批次插入（每次最多 100 條）
	if err := database.DB.CreateInBatches(logs, 100).Error; err != nil {
		return fmt.Errorf("批次寫入審計日誌失敗: %w", err)
	}

	return nil
}

// writeToFile 降級至檔案備份
func (s *AuditLogService) writeToFile(auditLog *model.AuditLog) {
	// 按日期分檔
	filename := fmt.Sprintf("audit_%s.log", time.Now().Format("2006-01-02"))
	filepath := filepath.Join(s.fallbackDir, filename)

	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("錯誤: 打開 fallback 檔案失敗: %v", err)
		return
	}
	defer file.Close()

	// 序列化為 JSON
	data, err := json.Marshal(auditLog)
	if err != nil {
		log.Printf("錯誤: 序列化審計日誌失敗: %v", err)
		return
	}

	// 寫入檔案（每行一條 JSON）
	if _, err := file.Write(append(data, '\n')); err != nil {
		log.Printf("錯誤: 寫入 fallback 檔案失敗: %v", err)
	}
}

// 審計日誌列表的排序預設值。SortBy／SortOrder 收斂失敗時一律退回這組。
const (
	defaultAuditSortBy    = "created_at"
	defaultAuditSortOrder = "desc"
)

// auditSortableColumns 允許排序的欄位白名單。**鍵＝合法輸入，值＝實際拼進
// ORDER BY 的欄名**，兩者恆等（key == value，由守衛測試釘住）；鍵與值都是
// audit_logs 的**實際 DB 欄位名**（非 JSON 欄位名，例如 Duration 的 json tag 是
// duration_ms 而欄位是 duration）。
//
// **為何必須是白名單而非過濾字元**：SortBy 來自 query 參數，最終以 fmt.Sprintf
// 拼進 ORDER BY 子句，而 GORM 的 string 型 `.Order()` 是逐字寫入、不參數化——
// 任何未收斂的值都是注入點，已認證的稽核檢視者即可用布林盲注逐字外洩任意表。
// 黑名單／跳脫字元擋不住這個位置（識別字位置無法參數化），只有列舉可以。
//
// **為何是 map[string]string 而非 map[string]struct{}**：命中時回傳**值**，
// 使流向 sink 的字串其資料流源頭是本檔的字面量而非請求參數，靜態分析
// （CodeQL 的 taint 追蹤）得以自行驗證 sink 不可達，不必依賴人記得這裡有
// 白名單約定。membership 檢查本身不在其 barrier 模型內，回傳輸入變數時
// taint 會穿過驗證流到 `.Order()`。
//
// 擴充時必須確認新增的名字是 model.AuditLog 的真實欄位；不存在的欄位會讓整個
// 查詢失敗，而不是靜默退回預設（守衛測試 TestAuditSortableColumnsAreRealColumns 會擋）。
var auditSortableColumns = map[string]string{
	"created_at":  "created_at",
	"id":          "id",
	"action":      "action",
	"resource":    "resource",
	"status":      "status",
	"user_id":     "user_id",
	"username":    "username",
	"client_ip":   "client_ip",
	"status_code": "status_code",
	"duration":    "duration",
}

// normalizeAuditSortBy 把排序欄位收斂進白名單，其餘（含空字串與注入載荷）退回預設。
//
// **回傳 map 的值而非輸入參數**：兩者恆等（key == value），故行為零差異，
// 但回傳值的來源是本檔字面量，資料流上與請求參數無關（見 auditSortableColumns）。
//
// **靜默退回而非回錯**：排序是次要語義，為它讓整筆稽核查詢失敗代價不對稱；
// 且回錯等於給探測者回饋，讓他能逐欄位試出哪些名字存在。
func normalizeAuditSortBy(sortBy string) string {
	if column, ok := auditSortableColumns[sortBy]; ok {
		return column
	}
	return defaultAuditSortBy
}

// normalizeAuditSortOrder 只接受 asc／desc（不分大小寫，正規化為小寫），其餘退回預設。
//
// 各 case 回傳字面量而非 `strings.ToLower` 的結果：同理於 normalizeAuditSortBy，
// 讓回傳值的資料流源頭是本檔字面量（值與行為不變——比對已是小寫化後的精確相等）。
func normalizeAuditSortOrder(sortOrder string) string {
	switch strings.ToLower(sortOrder) {
	case "asc":
		return "asc"
	case "desc":
		return "desc"
	default:
		return defaultAuditSortOrder
	}
}

// List 查詢審計日誌列表（支援過濾、分頁、排序）
func (s *AuditLogService) List(filter *AuditLogFilter) (*AuditLogListResult, error) {
	// 設定默認值
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 || filter.PageSize > 100 {
		filter.PageSize = 20
	}
	// 排序參數收斂必須在此處（而非 handler）：AuditExportService 也經本方法查詢，
	// 收在唯一的 choke point 才不會漏掉任何呼叫端
	filter.SortBy = normalizeAuditSortBy(filter.SortBy)
	filter.SortOrder = normalizeAuditSortOrder(filter.SortOrder)

	// 構建查詢
	query := database.DB.Model(&model.AuditLog{})

	// 應用過濾條件
	if filter.UserID != nil {
		query = query.Where("user_id = ?", *filter.UserID)
	}
	if filter.AssetID != nil {
		query = query.Where("asset_id = ?", *filter.AssetID)
	}
	if filter.Action != nil {
		query = query.Where("action = ?", *filter.Action)
	}
	if filter.Resource != nil {
		query = query.Where("resource = ?", *filter.Resource)
	}
	if filter.Status != nil {
		query = query.Where("status = ?", *filter.Status)
	}
	if filter.ClientIP != nil {
		query = query.Where("client_ip = ?", *filter.ClientIP)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
	}

	// 計算總數
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("查詢審計日誌總數失敗: %w", err)
	}

	// 應用分頁和排序
	offset := (filter.Page - 1) * filter.PageSize
	orderClause := fmt.Sprintf("%s %s", filter.SortBy, filter.SortOrder)

	var logs []*model.AuditLog
	if err := query.Order(orderClause).Offset(offset).Limit(filter.PageSize).Find(&logs).Error; err != nil {
		return nil, fmt.Errorf("查詢審計日誌失敗: %w", err)
	}

	return &AuditLogListResult{
		Data:  logs,
		Total: total,
		Page:  filter.Page,
		Size:  filter.PageSize,
	}, nil
}

// Get 獲取單條審計日誌
func (s *AuditLogService) Get(id uint) (*model.AuditLog, error) {
	var auditLog model.AuditLog
	if err := database.DB.First(&auditLog, id).Error; err != nil {
		return nil, fmt.Errorf("查詢審計日誌失敗: %w", err)
	}
	return &auditLog, nil
}

// GetByResourceID 查詢特定資源的審計歷史
func (s *AuditLogService) GetByResourceID(resource model.AuditResource, resourceID uint) ([]*model.AuditLog, error) {
	var logs []*model.AuditLog
	if err := database.DB.Where("resource = ? AND resource_id = ?", resource, resourceID).
		Order("created_at DESC").
		Find(&logs).Error; err != nil {
		return nil, fmt.Errorf("查詢資源審計歷史失敗: %w", err)
	}
	return logs, nil
}

// Shutdown 優雅關閉（flush 剩餘日誌）
func (s *AuditLogService) Shutdown(ctx context.Context) error {
	if !s.cfg.AsyncAuditEnabled {
		return nil
	}

	log.Println("審計日誌服務正在關閉，flush 剩餘日誌...")

	// 停止 ticker
	s.flushTicker.Stop()

	// 發送關閉信號給所有 workers
	close(s.stopChan)

	// 等待所有 workers 完成（帶超時）
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("審計日誌服務已優雅關閉")
		return nil
	case <-ctx.Done():
		log.Println("警告: 審計日誌服務關閉超時")
		return ctx.Err()
	}
}

// safeAuditFieldSet 請求本文的**放行**清單（default-deny：清單外一律遮罩）。
//
// 清單由兩個**角色**組成，union 即放行集合：`safeAuditIdentityFields`（動的是誰／
// 哪一個）與 `safeAuditSubstanceFields`（動成什麼）。角色不是註解而是結構——
// 新增放行鍵時沒有「不選角色」這個選項，故 `internal/guards/auditmask` 的
// G2b（只剩識別欄位可見＝實質內容全被遮）永遠拿得到完整輸入，不靠任何人填表。
//
// **刻意是函式而非包級 var**：這份清單是不可變字面量，沒有初始化順序語義，
// 做成包級全域只會讓它被 lifecycle manifest 當成有時序風險的狀態登記一次
// （徒增噪音）。每次呼叫重建一張 map 的成本與收斂前逐字相同——收斂前它本來
// 就建在 MaskSensitiveFields 函式體內。
//
// # 登記判準（三條同時成立才登記）
//
//  1. **非機密**：值不是憑證、金鑰材料、權杖、密碼，也不是可被貼進機密的自由文字
//     欄（`note`／`reason`／`content`／`description` 一律不登記——長度無上限的
//     自由文字是機密外洩的通道，而 audit_logs 受檢查點鏈保護，寫進去刪不掉）。
//     **判準吃的是鍵名的全域語義**：遮罩只看 map 的鍵，不知道請求打的是哪個端點，
//     故同名鍵在任一端點上可能是憑證，就一律不登記（`url` 即因此不登記，見下）。
//  2. **課責必要**：少了它，這一列就答不出「動了誰／動了什麼／變成什麼」。
//     純粹的顯示偏好、逾時秒數、旗標噪音不因「反正不機密」而登記。
//  3. **純量或識別字列表**：遮罩只走一層 map，登記鍵的值會**整包**原樣入庫。
//     巢狀物件／自由形狀的 map 不得登記（`policies` 即因此不登記，見下方例外說明）。
//
// # 為什麼維持 default-deny
//
// 反過來（default-allow ＋ 黑名單）會讓日後新增的欄位在無人察覺下進入審計記錄，
// 一次疏忽就是機密永久封存在不可篡改的紀錄裡。本清單的維護成本由
// `internal/guards/auditmask` 的機械守衛承擔——清單裡出現沒有任何請求綁定的
// 死鍵、或有端點的審計本文只剩識別欄位可見，測試即紅。
//
// # 已知不登記的課責空白（由他體系承擔或由判準排除）
//
//   - `policies`（PUT /security-policies）：巢狀 map，違反判準 3。該端點在
//     handler 內逐鍵寫 old→new 的專屬審計列（PCI 10.2.2），課責不靠 request_body。
//   - `url`（PUT /ldap-directory 與 notification-channels）：**違反判準 1 的全域
//     語義條款**。LDAP 的 `ldaps://host:636` 不是憑證，但同一個鍵名在通知通道上
//     承載 webhook 位址，而 Slack／Teams／釘釘形態的 webhook URL 本身就是持有型
//     權杖。遮罩分不出這兩個端點，只能取嚴的一側。LDAP 的認證來源變更改由
//     `base_dn`／`user_filter`／`skip_tls_verify`／`enabled` 課責，伺服器位址的
//     可見性須待端點感知遮罩（列入 backlog）。
//   - `tls_ca`／`db_ca_cert`／`k8s_ca_cert`／`rdp_verify_cert`／`risk_keys`／
//     `key_strategy`／`secret_type`／`password_length` 等：鍵名命中 auditmask G3
//     的機密語義片段（cert／key／secret／password）。**不為個案開名稱例外**——
//     G3 的過度攔截是刻意的安全側，代價由對應端點的其他實質欄位吸收。
func safeAuditFieldSet() map[string]bool {
	set := safeAuditIdentityFields()
	for k := range safeAuditSubstanceFields() {
		set[k] = true
	}
	return set
}

// safeAuditIdentityFields 識別角色：這一列動的是**誰／哪一個**。
//
// 這些欄位單獨存在時只回答得出「動到了哪個物件」，回答不出「動成什麼」。
// 先前的缺陷正是整批端點只剩這一類欄位可見（`{"name":"prod-idp"}` 之於
// 「issuer 被指到攻擊者端點」與「單純改名」完全同形），故守衛把它們與實質
// 欄位分開計數。
func safeAuditIdentityFields() map[string]bool {
	return map[string]bool{
		// ── 目標識別：這一列動的是哪一台／哪一個人 ──────────────────────
		"name":     true,
		"host":     true,
		"port":     true,
		"protocol": true,
		"username": true,
		"email":    true,
		// full_name/local_display_name 非機密，不應被脫敏成 ***MASKED***
		//（user 更新審計需能看到 full_name 實值）
		"full_name":          true,
		"local_display_name": true,
		"asset_id":           true,
		// account_id 為資產帳號 FK（非憑證本體），與 asset_id 同類：連線 token
		// 簽發審計要看得出「這次連線選了哪個帳號」，脫掉即失去帳號維度的可稽核性
		"account_id": true,
		"parent_id":  true, // 資產群組搬遷的目的地（群組結構牽動授權繼承範圍）

		// ── 身分綁定：綁到哪個 IdP 的哪個 subject ──────────────────────
		// subject 是 IdP 簽發的識別字而非持有型憑證，知道它不能拿來登入
		"provider_id": true,
		"subject":     true,

		// ── 授權關係的主體與客體 ───────────────────────────────────────
		// 少了主體／客體 id 就不知道授給了誰、授的是哪台
		"user_id":         true,
		"user_group_id":   true,
		"asset_group_id":  true,
		"user_ids":        true,
		"user_group_ids":  true,
		"asset_ids":       true,
		"asset_group_ids": true,

		// ── 核准路由設定：誰有權核准誰的什麼 ───────────────────────────
		"approver_id":       true,
		"approver_group_id": true,
		"subject_user_id":   true,
		"subject_group_id":  true,

		// ── 金鑰營運 ───────────────────────────────────────────────────
		// purpose 是輪替目標的用途枚舉（非金鑰材料本身）
		"purpose": true,
	}
}

// safeAuditSubstanceFields 實質角色：這一列把它動成**什麼**。
//
// 判準與識別角色的分界線是一句話：**少了它，兩次語義完全不同的變更會寫出無法
// 區分的審計列**。一類是提權（roles／active），另一類是「安全開關」——
// 關掉審計外送、關掉偵測規則、降級傳輸安全、把 IdP issuer 指到攻擊者端點，
// 這些在只剩 `name` 可見的審計列上與改個顯示名稱完全同形。
//
// 三條登記判準（見 safeAuditFieldSet）對本組一體適用，未通過者不因「它是實質
// 欄位」而破例：`url`（判準 1 的全域語義條款）與命中 G3 機密片段的鍵一律不在此。
func safeAuditSubstanceFields() map[string]bool {
	return map[string]bool{
		// ── 提權與帳號狀態：變更**後**的值 ─────────────────────────────
		// 這一組是稽核涵蓋補洞的缺口本體。舊清單有 `role`（單數）
		// 卻沒有任何請求綁定它，真正上線的鍵是 `roles`（PUT /users/:id/roles 與
		// POST /users 皆是），於是「誰把誰升成什麼角色」全庫無處可查。
		// 角色名稱、啟停旗標、豁免旗標都不是機密——它們正是課責的內容本身。
		"roles":  true, // 升權後的角色集合
		"active": true, // 帳號（與資產）停用／啟用的方向
		"exempt": true, // 閒置停用豁免的授予／撤銷方向（PCI 8.2.6 例外文件化）

		// ── 授權的權限級別與帳號範圍 ───────────────────────────────────
		// 少了 permission 就不知道授的是 view 還是 connect。accounts 是資產帳號的
		// **使用者名稱**列表（與 username 同性質，非憑證），它決定被授權者能用
		// root 還是一般帳號
		"permission": true,
		"accounts":   true,

		// ── 臨時授權的時窗與審核結論 ───────────────────────────────────
		// 「核准了多久」與「結論是什麼」是臨時提權唯一的量化課責維度
		"duration_minutes": true,
		"date_start":       true,
		"disposition":      true,

		// ── 安全機制的總開關 ────────────────
		// `enabled` 一鍵橫跨 OIDC provider、LDAP 目錄、syslog 外送、告警規則、
		// 通知通道、改密計畫：每一個的 false 都是「關掉一道安全機制」，而它今天
		// 與改名寫出同一列。全部是布林，不可能承載機密材料
		"enabled": true,

		// ── 身分提供者（OIDC）的信任錨與准入 ───────────────────────────
		// issuer 是**信任的根**：指到攻擊者控制的端點即等於接管全站登入，而該次
		// 變更今天與改名不可區分（頭號缺口）。admission_* 決定「誰准進來」，
		// scopes 決定據以判定的宣告來源，force_shared 是共用身分域的收緊／放寬意圖。
		// client_id 依 OAuth 規格為公開識別字（client_secret 仍遮）
		"issuer":          true,
		"client_id":       true,
		"scopes":          true,
		"admission_mode":  true,
		"admission_rules": true,
		"force_shared":    true,

		// ── 目錄服務（LDAP）的傳輸安全與認證範圍 ───────────────────────
		// skip_tls_verify=true 是明確的傳輸降級；base_dn／user_filter 決定「哪些
		// 目錄項可以登入」，放寬 filter 等同開門。三者皆為純量字串／布林。
		//（伺服器位址 `url` 因判準 1 的全域語義條款不登記，見 safeAuditFieldSet）
		"skip_tls_verify": true,
		"base_dn":         true,
		"user_filter":     true,

		// ── 風險確認聲明 ───────────────────────────────────────────────
		// 走 http 明文 webhook、跳過 TLS 驗證等降級動作要求操作者顯式聲明；
		// 「誰在什麼時候簽了這個風險」本身就是課責內容
		"risk_acknowledged": true,

		// ── 命令偵測規則 ───────────────────────────────────────────────
		// pattern 改成永不匹配、action 由 block 降為 alert、severity 降級、
		// protocols 縮到不涵蓋目標協議——四種都是「關掉偵測」的變體。
		// pattern 是機器解讀的正規式而非自由文字說明欄，與 name 同級的可控性
		"pattern":   true,
		"action":    true,
		"severity":  true,
		"protocols": true,

		// ── 資產帳號的特權標記與認證類型 ───────────────────────────────
		// privileged 是「這是特權帳號」的標記本身（覆核與報表據以分類）；
		// auth_method 是認證類型枚舉（憑證本體 password／private_key 仍遮）
		"privileged":  true,
		"auth_method": true,

		// ── 通知通道類型 ───────────────────────────────────────────────
		// 與 enabled 併用回答「告警還送不送得出去、送去哪一類管道」
		//（webhook 位址 `url` 不登記，理由同 LDAP）
		"type": true,

		// ── 改密計畫的排程 ─────────────────────────────────────────────
		// 停掉輪替不必改 enabled——把 cron 改成永不觸發即可，兩者同屬「關掉輪替」
		"cron": true,

		// ── 資產側的傳輸安全與存取策略 ─────────────────────────────────
		// 與 LDAP 的 skip_tls_verify 同型：k8s_insecure_skip_tls／db_tls_mode／
		// rdp_security 決定連線是否驗證對端與加密強度；access_policy 是資產層級的
		// 存取策略枚舉；sftp_enabled 決定該資產是否開啟檔案傳輸通道
		//（`rdp_verify_cert` 同型但鍵名命中 G3 的 cert 片段，不為個案開例外）
		"k8s_insecure_skip_tls": true,
		"db_tls_mode":           true,
		"rdp_security":          true,
		"access_policy":         true,
		"sftp_enabled":          true,

		// ── 帳號的允許來源網段 ─────────────────────────────────────────
		// 清單本身就是一道存取控制：清空＝任何位址都進得來，換一組＝把原本的人
		// 關在門外。少了它，「把來源限制關掉」與「改個顯示名稱」在 request_body
		// 面寫出同一列（更新端點另有欄位級 diff 走 audit_details，但那條路徑只在
		// 更新端點上有，且守衛看的是本文）。值為 CIDR 字串列表——非機密、非自由
		// 文字、單層列表，三條登記判準皆過。
		//
		// **連帶效果（刻意接受）**：遮罩以鍵名為單位、分不出端點，故判定端點
		// POST /users/source-policy/check 的**草稿**清單也隨之可見。該草稿是管理者
		// 自己輸入的網段字面，不是機密；記下它的代價可接受，換到的是所有真正的
		// 清單變更都答得出「變成什麼」
		"allowed_cidrs": true,
	}
}

// SafeAuditFieldNames 放行清單的鍵（無序副本）。
//
// 存在的唯一理由是讓 `internal/guards/auditmask` 的守衛能把清單與**實際的請求
// 綁定欄位**對照——死鍵（清單裡有、沒有任何 DTO 綁定）正是這類缺陷的指紋。
// 回傳副本，呼叫端改不動清單本體。
func SafeAuditFieldNames() []string {
	set := safeAuditFieldSet()
	names := make([]string, 0, len(set))
	for k := range set {
		names = append(names, k)
	}
	return names
}

// SafeAuditSubstanceFieldNames 放行清單中**實質角色**的鍵（無序副本）。
//
// 存在的唯一理由是讓 `internal/guards/auditmask` 的 G2b 能判定「這個端點的審計列
// 只剩識別欄位可見」——G2 只在頂層鍵**全部**落在清單外才報，於是一個
// `name` 就能讓「issuer 被改到攻擊者端點」永遠不被報。回傳副本，呼叫端改不動本體。
func SafeAuditSubstanceFieldNames() []string {
	set := safeAuditSubstanceFields()
	names := make([]string, 0, len(set))
	for k := range set {
		names = append(names, k)
	}
	return names
}

// SafeAuditIdentityFieldNames 放行清單中**識別角色**的鍵（無序副本）。
//
// 供守衛驗證兩個角色互斥（同一個鍵不得兼具兩角色，否則 G2b 的判定失去意義）。
func SafeAuditIdentityFieldNames() []string {
	set := safeAuditIdentityFields()
	names := make([]string, 0, len(set))
	for k := range set {
		names = append(names, k)
	}
	return names
}

// MaskSensitiveFields 脫敏敏感欄位（白名單機制，見 safeAuditFieldSet 的登記判準）
func MaskSensitiveFields(data map[string]interface{}) map[string]interface{} {
	safe := safeAuditFieldSet()
	masked := make(map[string]interface{})
	for key, value := range data {
		if safe[key] {
			masked[key] = value
		} else {
			// 脫敏處理
			masked[key] = "***MASKED***"
		}
	}

	return masked
}
