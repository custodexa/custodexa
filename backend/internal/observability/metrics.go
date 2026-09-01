// Package observability 提供營運指標的 Prometheus 曝光。
//
// **本包不 import 任何業務模組**：所有資料源以函式型別注入（`SetXxxSource`），
// 故 asset／session／audit 等模組不因指標需求而被本包耦合，也不會產生循環。
// 反向亦然——業務模組只呼叫本包的計數方法（`ObserveXxx`），不知道 Prometheus 存在。
package observability

import (
	"sync"
	"time"

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

// InstanceGuardStatus 單實例守衛指標的現讀資料。
//
// State 為守衛狀態字串（held／overridden／lost／stopping／released），空字串＝守衛
// 尚未建立（段 1 取鎖前）。四條序列由 collector 自本結構推導，不需狀態機另行寫入。
type InstanceGuardStatus struct {
	State     string
	LostTotal uint64
	Peers     int
}

// InstanceGuardSource 回傳守衛的現況；由組裝根注入（database 包的快照經 adapter 轉換）。
type InstanceGuardSource func() InstanceGuardStatus

// Metrics 持有本行程的營運指標與其專屬 registry。
//
// **不使用 prometheus 預設全域 registry**：全域 registry 是跨測試共用的可變狀態，
// 一個測試註冊的序列會殘留給下一個測試，使斷言結果取決於執行順序。自建 registry
// 讓每個測試能建構獨立實例。
//
// **註冊分兩階段**：建構時只註冊封印期即成立的指標（封印狀態＋行程
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

	// --- 離機儲存（註冊分兩面，見 RegisterOffsiteInventory） ---
	//
	// **兩面分開註冊**：停用態（有歷史世代、零現行世代）下 worker 不存在，
	// 上傳車道的序列若還在，採集端看到的是「待上傳恆為 0、最後成功時刻永遠停在
	// 某個過去」——那與「一切正常且無事可做」在 PromQL 上無從分辨。存量與失敗面
	// 則必須照常曝光：停用不代表既有物件不見了，取回仍在服務（停用態表）。
	offsitePending           *prometheus.GaugeVec
	offsiteUploading         *prometheus.GaugeVec
	offsiteOldestPendingAge  *prometheus.GaugeVec
	offsiteLastSuccess       prometheus.Gauge
	offsiteUploads           *prometheus.CounterVec
	offsiteUploadedBytes     *prometheus.CounterVec
	offsiteLeaseExpired      *prometheus.CounterVec
	offsiteFailed            *prometheus.GaugeVec
	offsiteIntegrityMismatch *prometheus.GaugeVec
	offsiteForeign           *prometheus.GaugeVec
	offsiteGenerations       prometheus.Gauge
	offsiteSpoolBytes        prometheus.Gauge
	offsiteCredentialState   *prometheus.GaugeVec

	offsiteInventoryOnce  sync.Once
	offsiteUploadLaneOnce sync.Once

	// --- 注入的資料源 ---
	mu                  sync.RWMutex
	sealStateSource     SealStateSource
	instanceGuardSource InstanceGuardSource
	connectionSource    func() float64
	auditQueueSource    func() float64
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

		// --- 離機儲存：上傳車道 ---
		offsitePending: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "custodexa_offsite_pending",
			Help: "等待離機上傳的物件數，依種類與車道分。",
		}, []string{"kind", "origin"}),
		offsiteUploading: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "custodexa_offsite_uploading",
			Help: "持有租約、上傳進行中的物件數，依種類分。",
		}, []string{"kind"}),
		// **回填積壓的年齡而非件數**：純「最新優先」下回填件可能長期停在本機唯一
		// 副本，而件數在穩定積壓時是平的——只有年齡會漲
		offsiteOldestPendingAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "custodexa_offsite_oldest_pending_age_seconds",
			Help: "最老一件待上傳物件的等待秒數，依車道分；該車道無待上傳件時序列缺席。",
		}, []string{"origin"}),
		offsiteLastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "custodexa_offsite_last_success_timestamp_seconds",
			Help: "最近一次離機上傳成功的 Unix 時刻。",
		}),
		// 每一次上傳**嘗試**的結果各計一次：同一件重試 N 次即計 N 次 failed。
		// 若只計終態失敗，反覆重試但尚未到上限的積壓在此完全看不見
		offsiteUploads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "custodexa_offsite_uploads_total",
			Help: "離機上傳嘗試的累計次數，依種類與結果分。",
		}, []string{"kind", "result"}),
		offsiteUploadedBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "custodexa_offsite_uploaded_bytes_total",
			Help: "離機上傳成功的累計位元組數，依種類分。",
		}, []string{"kind"}),
		// 租約回收＝卡死訊號（行程被砍、deadline 被繞過）；它比「上傳失敗」更早
		// 需要人看，故獨立成序列而不是併進 uploads_total 的 result
		offsiteLeaseExpired: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "custodexa_offsite_lease_expired_total",
			Help: "離機上傳租約到期被回收的累計次數，依種類分。",
		}, []string{"kind"}),

		// --- 離機儲存：存量與失敗面（停用態照常曝光） ---
		offsiteFailed: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "custodexa_offsite_failed",
			Help: "離機上傳已達重試上限的物件數，依種類分。",
		}, []string{"kind"}),
		offsiteIntegrityMismatch: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "custodexa_offsite_integrity_mismatch",
			Help: "取回時內容與紀錄不符而遭拒付的物件數，依種類分。",
		}, []string{"kind"}),
		offsiteForeign: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "custodexa_offsite_foreign",
			Help: "屬於已退役儲存設定世代的物件數，依種類分。",
		}, []string{"kind"}),
		offsiteGenerations: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "custodexa_offsite_generations",
			Help: "離機儲存設定世代的總列數（含已退役者）。",
		}),
		offsiteSpoolBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "custodexa_offsite_spool_bytes",
			Help: "取回暫存區佔用的位元組數。",
		}),
		// **enum 慣例（當前態 1、其餘 0）而非單一數值**，沿 custodexa_seal_state：
		// 採集端可直接對「處於 failed」寫 PromQL，不必知道本系統有哪些態。
		//
		// **為何要有這一條**（指標清單原未列，接線時補上）：
		// 紅線是「禁止把金鑰事故併吞成未設定」。少了它，「憑證解密失敗」
		// 在指標面與「一切正常」只差在上傳失敗數會漲——而上傳失敗數在網路抖動時
		// 也會漲，兩者無從分辨；金鑰事故需要的是立刻有人去看，不是等重試上限。
		offsiteCredentialState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "custodexa_offsite_credential_state",
			Help: "離機儲存憑證的三態；目前所處的態為 1，其餘為 0。",
		}, []string{"state"}),
	}

	// 行程執行期指標：封印期即成立（不依賴任何段 2 服務）
	m.registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	// 封印狀態：採集當下現讀，避免狀態機與指標之間出現需要同步的第二份真相
	m.registry.MustRegister(&sealStateCollector{m: m})

	// 單實例守衛：同樣段 1 註冊、採集當下現讀——守衛自段 1 起存在，封印期就該可採集
	m.registry.MustRegister(newInstanceGuardCollector(m))

	return m
}

// instanceGuardCollector 曝光單實例守衛的四條序列。
//
// 自訂 collector 而非 Gauge：理由同 sealStateCollector——狀態轉移時漏寫的症狀是
// 指標永遠停在舊態，而「守衛失守但指標仍說持有」正是監控最不能說的謊。
// 資料源未注入時四條序列**缺席而非為 0**：0 會讓採集端把「守衛不存在」讀成「未持鎖」
// 而誤報，缺值可由 absent() 明確偵測。
// Desc 放在 collector 內而非包級：避免為四個純描述子在生命週期 manifest 各登記一列。
type instanceGuardCollector struct {
	m          *Metrics
	held       *prometheus.Desc
	lostTotal  *prometheus.Desc
	overridden *prometheus.Desc
	peers      *prometheus.Desc
}

func newInstanceGuardCollector(m *Metrics) *instanceGuardCollector {
	return &instanceGuardCollector{
		m: m,
		held: prometheus.NewDesc("custodexa_instance_guard_held",
			"單實例鎖是否由本實例持有；1 持有、0 未持有。", nil, nil),
		lostTotal: prometheus.NewDesc("custodexa_instance_guard_lost_total",
			"偵測到失鎖的累計次數。", nil, nil),
		overridden: prometheus.NewDesc("custodexa_instance_guard_overridden",
			"本實例是否以 INSTANCE_GUARD_ACK 啟動且尚未取得鎖；1 是、0 否。", nil, nil),
		peers: prometheus.NewDesc("custodexa_instance_guard_peers",
			"偵測到的其他守衛版實例連線數（同一資料庫、同 application_name）。", nil, nil),
	}
}

func (c *instanceGuardCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.held
	ch <- c.lostTotal
	ch <- c.overridden
	ch <- c.peers
}

func (c *instanceGuardCollector) Collect(ch chan<- prometheus.Metric) {
	c.m.mu.RLock()
	src := c.m.instanceGuardSource
	c.m.mu.RUnlock()
	if src == nil {
		return
	}
	st := src()
	held, overridden := 0.0, 0.0
	switch st.State {
	case "held":
		held = 1
	case "overridden":
		overridden = 1
	}
	ch <- prometheus.MustNewConstMetric(c.held, prometheus.GaugeValue, held)
	ch <- prometheus.MustNewConstMetric(c.lostTotal, prometheus.CounterValue, float64(st.LostTotal))
	ch <- prometheus.MustNewConstMetric(c.overridden, prometheus.GaugeValue, overridden)
	ch <- prometheus.MustNewConstMetric(c.peers, prometheus.GaugeValue, float64(st.Peers))
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

// SetInstanceGuardSource 注入單實例守衛狀態的現讀函式（段 1 組裝根，取鎖後即注入）。
func (m *Metrics) SetInstanceGuardSource(f InstanceGuardSource) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.instanceGuardSource = f
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

// --- 離機儲存（停用態表） ---

// OffsiteKindOrigin 「種類×車道」的標籤鍵（快照的 map 鍵，避免字串拼接）。
type OffsiteKindOrigin struct {
	Kind   string
	Origin string
}

// OffsiteQueueSnapshot 一次背景刷新讀到的離機帳冊切面。
//
// **純資料、不含業務型別**：本包不 import 任何業務模組（見套件註解），
// 帳冊的 `StateCount` 由組裝根轉成本結構後交進來。
//
// **缺席與 0 是兩件事**：map 內沒有的鍵不會被寫成 0——`Reset` 之後只寫有值的鍵，
// 故「該車道目前沒有待上傳件」在採集端是序列消失而非值為 0。
type OffsiteQueueSnapshot struct {
	// Pending 待上傳件數（種類×車道）
	Pending map[OffsiteKindOrigin]float64
	// Uploading 持有租約、上傳中的件數（依種類）
	Uploading map[string]float64
	// Failed 已達重試上限的件數（依種類）
	Failed map[string]float64
	// IntegrityMismatch 取回驗證不符的件數（依種類）
	IntegrityMismatch map[string]float64
	// Foreign 屬已退役世代的件數（依種類）
	Foreign map[string]float64
	// OldestPendingAgeSeconds 各車道最老待上傳件的年齡；無待上傳件的車道**不出現**
	OldestPendingAgeSeconds map[string]float64
	// Generations 設定世代總列數（含已退役者）
	Generations float64
	// SpoolBytes 取回暫存佔用
	SpoolBytes float64
	// CredentialState 憑證三態之一（unconfigured／ok／failed）；空字串＝視為 unconfigured
	CredentialState string
}

// OffsiteCredentialStates 憑證三態的全集（enum 曝光需要全集才能讓採集端不必處理缺值）。
//
// **在此抄一份而非 import offsite**：本包不 import 業務模組（見套件註解）。
// 兩處值不一致的風險由組裝根的接線測試承擔。
var OffsiteCredentialStates = []string{"unconfigured", "ok", "failed"}

// RegisterOffsiteInventory 註冊存量與失敗面的離機序列。
//
// **停用態（有歷史世代、零現行世代）也註冊**：停用不代表既有物件消失，
// 失敗清單與取回仍在服務；把這一面一起藏起來，管理員在停用後就看不見
// 「還有 12 件從未上傳成功」這種事實（停用態表）。
//
// 設定表零列（從未設定）時**兩面都不呼叫**，全部離機序列缺席。
func (m *Metrics) RegisterOffsiteInventory() {
	m.offsiteInventoryOnce.Do(func() {
		m.registry.MustRegister(
			m.offsiteFailed,
			m.offsiteIntegrityMismatch,
			m.offsiteForeign,
			m.offsiteGenerations,
			m.offsiteSpoolBytes,
			m.offsiteCredentialState,
		)
	})
}

// RegisterOffsiteUploadLane 註冊上傳車道的離機序列（**僅在有現行世代時**）。
//
// 停用態下 worker 不存在，這些序列若還在，採集端讀到的是「待上傳恆為 0、
// 最後成功時刻永遠停在某個過去」——與「一切正常且無事可做」無從分辨，
// 而 `absent()` 能明確表達前者。
func (m *Metrics) RegisterOffsiteUploadLane() {
	m.offsiteUploadLaneOnce.Do(func() {
		m.registry.MustRegister(
			m.offsitePending,
			m.offsiteUploading,
			m.offsiteOldestPendingAge,
			m.offsiteLastSuccess,
			m.offsiteUploads,
			m.offsiteUploadedBytes,
			m.offsiteLeaseExpired,
		)
	})
}

// SetOffsiteQueue 由背景刷新任務寫入（單表 GROUP BY ＋暫存目錄統計，成本不對稱）。
//
// 未註冊的 collector 被寫入是無害的——曝光與否由註冊決定，故本方法在三種狀態
// 下都可以照常呼叫，不必在呼叫端再判一次啟用。
func (m *Metrics) SetOffsiteQueue(s OffsiteQueueSnapshot) {
	setGaugeVec2(m.offsitePending, s.Pending)
	setGaugeVec1(m.offsiteUploading, s.Uploading)
	setGaugeVec1(m.offsiteFailed, s.Failed)
	setGaugeVec1(m.offsiteIntegrityMismatch, s.IntegrityMismatch)
	setGaugeVec1(m.offsiteForeign, s.Foreign)
	setGaugeVec1(m.offsiteOldestPendingAge, s.OldestPendingAgeSeconds)
	m.offsiteGenerations.Set(s.Generations)
	m.offsiteSpoolBytes.Set(s.SpoolBytes)

	current := s.CredentialState
	if current == "" {
		current = OffsiteCredentialStates[0]
	}
	for _, state := range OffsiteCredentialStates {
		value := 0.0
		if state == current {
			value = 1
		}
		m.offsiteCredentialState.WithLabelValues(state).Set(value)
	}
}

// setGaugeVec1／setGaugeVec2 `Reset` 後只寫有值的鍵：已歸零的標籤組因此**消失**
// 而非停在最後一個非零值（後者會讓「已全部處理完畢」看起來像「還有一批沒動」）。
func setGaugeVec1(v *prometheus.GaugeVec, values map[string]float64) {
	v.Reset()
	for label, n := range values {
		v.WithLabelValues(label).Set(n)
	}
}

func setGaugeVec2(v *prometheus.GaugeVec, values map[OffsiteKindOrigin]float64) {
	v.Reset()
	for k, n := range values {
		v.WithLabelValues(k.Kind, k.Origin).Set(n)
	}
}

// 離機上傳嘗試的結果標籤。
const (
	OffsiteUploadResultUploaded = "uploaded"
	OffsiteUploadResultFailed   = "failed"
)

// ObserveOffsiteUpload 記錄一次上傳嘗試的結果（worker 直寫）。
// 成功時 bytes 為送出的位元組數；失敗時忽略。
func (m *Metrics) ObserveOffsiteUpload(kind, result string, bytes int64) {
	m.offsiteUploads.WithLabelValues(kind, result).Inc()
	if result == OffsiteUploadResultUploaded && bytes > 0 {
		m.offsiteUploadedBytes.WithLabelValues(kind).Add(float64(bytes))
	}
}

// ObserveOffsiteLeaseExpired 記錄一次租約回收（worker 直寫）。
func (m *Metrics) ObserveOffsiteLeaseExpired(kind string) {
	m.offsiteLeaseExpired.WithLabelValues(kind).Inc()
}

// SetOffsiteLastSuccess 記錄最近一次上傳成功的時刻（worker 直寫）。
func (m *Metrics) SetOffsiteLastSuccess(ts time.Time) {
	m.offsiteLastSuccess.Set(float64(ts.Unix()))
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
