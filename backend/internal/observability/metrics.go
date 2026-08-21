// Package observability 提供營運指標的 Prometheus 曝光（observability-lite）。
//
// **本包不 import 任何業務模組**：所有資料源以函式型別注入（`SetXxxSource`），
// 故 asset／session／audit 等模組不因指標需求而被本包耦合，也不會產生循環。
// 反向亦然——業務模組只呼叫本包的計數方法（`ObserveXxx`），不知道 Prometheus 存在。
package observability

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// SealStateSource 回傳目前的封印態與可能態的全集。
//
// **回傳全集而非只回目前態**：封印狀態以 Prometheus 的 enum 慣例曝光
// （`custodexa_seal_state{state="…"}`，當前態 1、其餘 0），採集端才能對
// 「處於某態」直接寫 PromQL，不必知道本系統有哪些態、也不必處理缺值。
// 全集由 `seal` 套件提供而非在此抄寫——抄本在對方新增態時不會有任何訊號。
type SealStateSource func() (current string, all []string)

// Metrics 持有本行程的營運指標與其專屬 registry。
//
// **不使用 prometheus 預設全域 registry**：全域 registry 是跨測試共用的可變狀態，
// 一個測試註冊的序列會殘留給下一個測試，使斷言結果取決於執行順序。自建 registry
// 讓每個測試能建構獨立實例。
//
// **註冊分兩階段**（design D4）：建構時只註冊封印期即成立的指標（封印狀態＋行程
// 執行期）；段 2 服務就緒後才註冊其餘。未註冊的指標在曝光內容中**缺席而非為 0**
// ——0 值會讓採集端把「服務不存在」讀成「服務正常且計數為零」，而缺值在 PromQL
// 中可由 `absent()` 明確偵測。
//
// HTTP 指標歸在段 2：段 1 的 engine 註冊了全部業務路由（只是掛佔位 handler），
// 故封印期的請求仍能解析出路由模板；此時曝光 HTTP 指標等於在未解封狀態下洩漏
// 端點清單，正是本 change 要消滅的形態。
type Metrics struct {
	registry *prometheus.Registry

	// 段 2 註冊的旗標，保證重複解封（B 模式）不重複註冊
	stage2Once sync.Once

	// --- 會話與連線 ---
	activeSessions *prometheus.GaugeVec

	// --- 錄影儲存 ---
	recordingStorageBytes prometheus.Gauge

	// --- 告警 ---
	commandAlertsPending *prometheus.GaugeVec

	// --- 審計 ---
	auditDropped *prometheus.CounterVec

	// --- HTTP ---
	httpRequests *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec

	// --- 注入的資料源 ---
	mu               sync.RWMutex
	sealStateSource  SealStateSource
	connectionSource func() float64
	auditQueueSource func() float64
}

// New 建立指標集合並註冊封印期即成立的部分。
func New() *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),

		activeSessions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "custodexa_active_sessions",
			Help: "目前活躍的會話數，依協議分。",
		}, []string{"protocol"}),

		recordingStorageBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "custodexa_recording_storage_bytes",
			Help: "錄影檔案佔用的儲存位元組數。",
		}),

		// **未審閱數而非累計產生數**：PCI 10.4.1 要求的是告警被審閱，
		// 堆積未審才是實質風險訊號；累計數在行程重啟後歸零，而未審閱的告警仍在，
		// 前者答不出「現在有沒有人沒在看」。
		commandAlertsPending: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "custodexa_command_alerts_pending",
			Help: "尚未審閱處置的指令告警數，依嚴重度分。",
		}, []string{"severity"}),

		// reason 區分「已降級寫檔」與「直接丟棄」：前者資料仍在檔案內可事後回收，
		// 後者是永久遺失。合併計數會使「到底有沒有掉資料」答不出來，
		// 而那正是本指標存在的唯一理由
		auditDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "custodexa_audit_dropped_total",
			Help: "審計佇列滿載時未能直接入庫的審計列數，依處置方式分。",
		}, []string{"reason"}),

		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "custodexa_http_requests_total",
			Help: "累計的 HTTP 請求數。",
		}, []string{"method", "path", "status"}),

		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "custodexa_http_request_duration_seconds",
			Help:    "HTTP 請求處理耗時分佈。",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "path"}),
	}

	// 行程執行期指標：封印期即成立（不依賴任何段 2 服務）
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// 封印狀態：採集當下現讀，避免狀態機與指標之間出現需要同步的第二份真相
	m.registry.MustRegister(&sealStateCollector{m: m})

	return m
}

// sealStateCollector 以 enum 慣例曝光封印狀態。
//
// 自訂 collector 而非 GaugeVec：GaugeVec 需要有人在轉態時寫入，那就多出一份
// 需要與狀態機同步的真相，而漏寫的症狀是指標永遠停在舊態——監控看起來正常，
// 實際上在說謊。現讀則不可能不同步。
type sealStateCollector struct{ m *Metrics }

var sealStateDesc = prometheus.NewDesc(
	"custodexa_seal_state",
	"封印狀態；目前所處的態為 1，其餘為 0。",
	[]string{"state"}, nil,
)

func (c *sealStateCollector) Describe(ch chan<- *prometheus.Desc) { ch <- sealStateDesc }

func (c *sealStateCollector) Collect(ch chan<- prometheus.Metric) {
	c.m.mu.RLock()
	src := c.m.sealStateSource
	c.m.mu.RUnlock()
	if src == nil {
		// 來源未注入即不曝光任何序列。**不可改為輸出一個猜測值**：
		// 監控據此判斷要不要派人去解封，猜錯的代價是實際封印中卻無人知曉
		return
	}

	current, all := src()
	for _, state := range all {
		value := 0.0
		if state == current {
			value = 1
		}
		ch <- prometheus.MustNewConstMetric(sealStateDesc, prometheus.GaugeValue, value, state)
	}
}

// Registry 回傳曝光用的 registry。
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// SetSealStateSource 注入封印狀態的現讀函式。
func (m *Metrics) SetSealStateSource(f SealStateSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sealStateSource = f
}

// SetConnectionSource 注入活躍連線數的現讀函式（行程內註冊表，取值成本為 O(1)，
// 故現讀而非背景刷新）。
func (m *Metrics) SetConnectionSource(f func() float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectionSource = f
}

// SetAuditQueueSource 注入審計佇列深度的現讀函式（`len(chan)`，同樣 O(1)）。
func (m *Metrics) SetAuditQueueSource(f func() float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditQueueSource = f
}

// RegisterStage2 註冊段 2 服務就緒後才成立的指標。
//
// 冪等：B 模式下每次解封都會走到這裡，重複註冊會使 `MustRegister` panic。
func (m *Metrics) RegisterStage2() {
	m.stage2Once.Do(func() {
		m.registry.MustRegister(
			m.activeSessions,
			m.recordingStorageBytes,
			m.commandAlertsPending,
			m.auditDropped,
			m.httpRequests,
			m.httpDuration,
		)

		m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "custodexa_active_connections",
			Help: "目前活躍的連線數（本行程內註冊表）。",
		}, func() float64 {
			m.mu.RLock()
			src := m.connectionSource
			m.mu.RUnlock()
			if src == nil {
				return 0
			}
			return src()
		}))

		m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "custodexa_audit_queue_depth",
			Help: "審計非同步寫入佇列的目前深度。",
		}, func() float64 {
			m.mu.RLock()
			src := m.auditQueueSource
			m.mu.RUnlock()
			if src == nil {
				return 0
			}
			return src()
		}))
	})
}

// --- 業務模組呼叫的觀測方法（不需知道 Prometheus 存在） ---

// 審計列未能直接入庫時的處置方式。
const (
	AuditDropReasonFallbackFile = "fallback_file" // 降級寫檔，資料仍可事後回收
	AuditDropReasonDiscarded    = "discarded"     // 直接丟棄，資料永久遺失
)

// ObserveAuditDropped 記錄一筆未能直接入庫的審計列。
//
// **這是本指標盤中價值最高的一個**：`discarded` 路徑原先唯一的痕跡是行程日誌
// （不可查詢、不可告警、容器重啟即失），而它代表的是審計資料的永久遺失。
func (m *Metrics) ObserveAuditDropped(reason string) {
	m.auditDropped.WithLabelValues(reason).Inc()
}

// SetActiveSessions 由背景刷新任務寫入（DB 查詢，成本不對稱故不現讀）。
func (m *Metrics) SetActiveSessions(byProtocol map[string]float64) {
	m.activeSessions.Reset()
	for protocol, n := range byProtocol {
		m.activeSessions.WithLabelValues(protocol).Set(n)
	}
}

// SetRecordingStorage 由背景刷新任務寫入（檔案系統遍歷，成本不對稱故不現讀）。
func (m *Metrics) SetRecordingStorage(usedBytes float64) {
	m.recordingStorageBytes.Set(usedBytes)
}

// SetPendingAlerts 由背景刷新任務寫入（DB 聚合查詢，成本不對稱故不現讀）。
//
// `Reset` 使已歸零的嚴重度序列消失，而非停在最後一個非零值——後者會讓
// 「已全部審閱完畢」看起來像「還有一批沒處理」。
func (m *Metrics) SetPendingAlerts(bySeverity map[string]float64) {
	m.commandAlertsPending.Reset()
	for severity, n := range bySeverity {
		m.commandAlertsPending.WithLabelValues(severity).Set(n)
	}
}
