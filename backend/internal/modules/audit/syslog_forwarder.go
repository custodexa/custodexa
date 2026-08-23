package audit

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// syslog forwarder 參數（PCI 10.3.3）
const (
	// syslogFacility RFC5424 facility 13 = log audit
	syslogFacility = 13
	// syslogSeverityInfo / Warning：audit 事件用 info、告警用 warning
	syslogSeverityInfo    = 6
	syslogSeverityWarning = 4

	syslogAppName = branding.Slug

	// syslogBufferSize 有界緩衝：目的地斷線期間的暫存量，滿即丟最新並計數
	syslogBufferSize = 4096
	// syslogWriteTimeout 單筆寫入逾時（tunnel write deadline 教訓：無 deadline 的
	// 阻塞寫會卡死整條 loop）
	syslogWriteTimeout = 5 * time.Second
	// syslogReconnectMax 重連退避上限
	syslogReconnectMax = 30 * time.Second
	syslogDialTimeout  = 5 * time.Second
)

// syslogEvent 一筆待轉發事件
type syslogEvent struct {
	severity int
	msgID    string
	payload  []byte
}

// failureReporter 失效上報 hook（audit-failure-alerting 於任務 6 接上；nil 安全）。
// mechanism 見 model.MechanismSyslogForward；causeCode 見 model.Cause*
// （cause 走機器碼，散文與 err 原文放
// params[model.CauseParamDetail]）；recovered=true 表示機制恢復（碼與參數為空）
type failureReporter func(mechanism, causeCode string, params map[string]string, recovered bool)

// SyslogForwarder RFC5424 syslog 離機轉發器。
// 設計要點：DB 寫入成功後 tee 入有界 channel，斷線指數退避重連、
// 緩衝滿丟棄並誠實計數——任何轉發故障都不得阻塞審計主鏈
type SyslogForwarder struct {
	db *gorm.DB

	mu      sync.RWMutex
	setting model.SyslogSetting
	loaded  bool

	ch      chan syslogEvent
	dropped atomic.Uint64
	// settingGen 設定世代：Reload 遞增，run loop 比對後棄舊連線重撥——
	// 否則設定變更後事件仍寫向舊目的地（UDP 舊連線 write 永遠「成功」，
	// 新目的地/協議靜默不生效，live 驗證實踩）
	settingGen atomic.Uint64
	// failing 進行中失效狀態（觸發/恢復各上報一次）
	failing   atomic.Bool
	onFailure failureReporter

	hostname string
	stopCh   chan struct{}
	doneCh   chan struct{}
	started  bool
}

// 套件級單例（沿 AlertNotifier 慣例）：tee 點在 audit worker 與 alert matcher
// 的寫入路徑深處，getter 取用、main 啟動時注入；未初始化（單測）回 nil
var (
	syslogForwarderMu       sync.RWMutex
	syslogForwarderInstance *SyslogForwarder
)

// InitSyslogForwarder 建立並註冊單例；main 啟動時呼叫一次
func InitSyslogForwarder(db *gorm.DB) *SyslogForwarder {
	f := NewSyslogForwarder(db)
	syslogForwarderMu.Lock()
	syslogForwarderInstance = f
	syslogForwarderMu.Unlock()
	return f
}

// GetSyslogForwarder 取得單例；未初始化回 nil，呼叫端需 nil 檢查
func GetSyslogForwarder() *SyslogForwarder {
	syslogForwarderMu.RLock()
	defer syslogForwarderMu.RUnlock()
	return syslogForwarderInstance
}

// NewSyslogForwarder 建立轉發器（尚未啟動；Start 前 Enqueue 為 no-op）
func NewSyslogForwarder(db *gorm.DB) *SyslogForwarder {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "-"
	}
	return &SyslogForwarder{
		db:       db,
		ch:       make(chan syslogEvent, syslogBufferSize),
		hostname: hostname,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// SetFailureReporter 設定失效上報 hook（audit-failure-alerting）
func (f *SyslogForwarder) SetFailureReporter(r failureReporter) {
	f.onFailure = r
}

// Start 載入設定並啟動送信 loop
func (f *SyslogForwarder) Start() {
	f.Reload()
	f.started = true
	go f.run()
	log.Printf("[Syslog] 轉發器已啟動（enabled=%v）", f.Enabled())
}

// Stop 停止送信 loop
func (f *SyslogForwarder) Stop() {
	if !f.started {
		return
	}
	close(f.stopCh)
	<-f.doneCh
}

// Reload 重讀 DB 設定（設定 API 更新後呼叫）；無列 = 停用
func (f *SyslogForwarder) Reload() {
	var s model.SyslogSetting
	err := f.db.First(&s, 1).Error
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case err == nil:
		f.setting = s
	case errors.Is(err, gorm.ErrRecordNotFound):
		f.setting = model.SyslogSetting{}
	default:
		// DB 讀取失敗：保留上次設定（fail-safe，不因 DB 抖動關掉轉發）
		log.Printf("[Syslog] 讀取設定失敗，沿用現值: %v", err)
		return
	}
	f.loaded = true
	f.settingGen.Add(1) // 通知 run loop 棄舊連線重撥
}

// Enabled 轉發是否啟用
func (f *SyslogForwarder) Enabled() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.setting.Enabled && f.setting.Host != ""
}

// Dropped 累計丟棄筆數（狀態 API 曝露；只增不歸零）
func (f *SyslogForwarder) Dropped() uint64 {
	return f.dropped.Load()
}

// EnqueueAuditLog audit_logs 寫 DB 成功後 tee（audit_log_service worker 呼叫）
func (f *SyslogForwarder) EnqueueAuditLog(l *model.AuditLog) {
	if !f.Enabled() {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"id": l.ID, "created_at": l.CreatedAt.Format(time.RFC3339),
		"username": l.Username, "user_id": l.UserID,
		"action": l.Action, "resource": l.Resource, "resource_id": l.ResourceID,
		"status": l.Status, "client_ip": l.ClientIP,
		"method": l.Method, "path": l.Path, "error_msg": l.ErrorMsg,
	})
	if err != nil {
		return
	}
	f.enqueue(syslogEvent{severity: syslogSeverityInfo, msgID: "audit", payload: payload})
}

// EnqueueAlert command_alerts 寫 DB 成功後 tee（alert_matcher 呼叫）
func (f *SyslogForwarder) EnqueueAlert(a *model.CommandAlert) {
	if !f.Enabled() {
		return
	}
	payload, err := json.Marshal(map[string]any{
		"id": a.ID, "triggered_at": a.TriggeredAt.Format(time.RFC3339),
		"user_id": a.UserID, "session_id": a.SessionID, "asset_id": a.AssetID,
		"rule_name": a.RuleName, "severity": a.Severity, "command": a.Command,
		// kind／reason_code：離機收集端
		// 只讀 rule_name 會把降級類的機器碼當成規則名。這兩欄是穩定的機器鍵，
		// 比翻譯過的散文更適合 SIEM 側的規則撰寫
		"kind": a.Kind, "reason_code": a.ReasonCode,
	})
	if err != nil {
		return
	}
	f.enqueue(syslogEvent{severity: syslogSeverityWarning, msgID: "alert", payload: payload})
}

// EnqueueCheckpoint 檢查點錨定事件：封章成功並落庫後送出。
//
// 與前兩個 Enqueue 的兩點差異（刻意）：
//   - **回傳是否入列成功**：檢查點需把結果落回 `anchor_status`，
//     「丟了」在此是要記錄的永久事實，不是只進計數器的雜訊。
//   - payload 只含聚合結果與簽章，**不含任何審計列內容欄位**——
//     錨定要的是「這段序列的指紋」，把日誌明細再外送一份是無謂的外洩面。
//
// msgID 用獨立值 `checkpoint`，使收集端能與一般審計事件區分並長期留存。
func (f *SyslogForwarder) EnqueueCheckpoint(cp *model.AuditCheckpoint) bool {
	if !f.Enabled() {
		return false
	}
	payload, err := json.Marshal(map[string]any{
		"seq": cp.Seq, "id_from": cp.IDFrom, "id_to": cp.IDTo,
		"row_count": cp.RowCount, "agg_hash": cp.AggHash, "agg_scheme": cp.AggScheme,
		"signature": cp.Signature, "signing_key_version": cp.SigningKeyVersion,
		"sealed_at": cp.SealedAt.Format(time.RFC3339),
	})
	if err != nil {
		return false
	}
	return f.enqueue(syslogEvent{severity: syslogSeverityInfo, msgID: "checkpoint", payload: payload})
}

// enqueue 入緩衝；滿即丟並計數（不阻塞呼叫端＝審計主鏈）。回傳是否入列成功。
// 失效上報移至 run loop 的計數差偵測——producer 側上報會與 run loop 的
// 恢復上報跨 goroutine 交錯，且 producer 路徑必須零阻塞
func (f *SyslogForwarder) enqueue(e syslogEvent) bool {
	select {
	case f.ch <- e:
		return true
	default:
		f.dropped.Add(1)
		return false
	}
}

// run 送信 loop：取事件 → 確保連線 → 寫出；失敗退避重連（事件留在手上重試一次，
// 再失敗即丟棄計數，不無限重試單筆）。
// 失效/恢復上報集中於此單一 goroutine：溢出經 dropped 計數差偵測；
// 恢復以「寫出成功且計數穩定」為準——原寫法恢復掛在重撥成功，
// 緩衝溢出（連線健在、永不重撥）的失效事件永無人回填
func (f *SyslogForwarder) run() {
	defer close(f.doneCh)
	var conn net.Conn
	var connGen uint64
	var reportedDrops uint64
	backoff := time.Second
	closeConn := func() {
		if conn != nil {
			conn.Close()
			conn = nil
		}
	}
	defer closeConn()

	for {
		select {
		case <-f.stopCh:
			return
		case e := <-f.ch:
			// 設定變更（Reload）後棄舊連線：舊 UDP conn write 永遠「成功」，
			// 不重撥則新目的地/協議靜默不生效
			if gen := f.settingGen.Load(); gen != connGen {
				closeConn()
				connGen = gen
			}
			// 溢出偵測（計數差）：無論失效中與否都推進 reportedDrops，
			// 否則斷線期間的丟棄會永久卡住恢復判定
			if d := f.dropped.Load(); d > reportedDrops {
				reportedDrops = d
				f.reportFailure(model.CauseSyslogBufferOverflow,
					map[string]string{"dropped": strconv.FormatUint(d, 10)})
			}
			setting := f.snapshot()
			if !setting.Enabled || setting.Host == "" {
				continue // 停用期間清空殘留事件
			}
			sent := false
			for attempt := 0; attempt < 2 && !sent; attempt++ {
				if conn == nil {
					c, err := f.dial(setting)
					if err != nil {
						f.reportFailure(model.CauseSyslogConnectFailed,
							map[string]string{model.CauseParamDetail: err.Error()})
						// 退避等待（可被 stop 中斷）
						select {
						case <-f.stopCh:
							return
						case <-time.After(backoff):
						}
						if backoff *= 2; backoff > syslogReconnectMax {
							backoff = syslogReconnectMax
						}
						continue
					}
					conn = c
					backoff = time.Second
				}
				if err := f.write(conn, e, setting); err != nil {
					closeConn()
					continue
				}
				sent = true
			}
			if !sent {
				f.dropped.Add(1)
			} else if f.dropped.Load() == reportedDrops {
				// 寫出成功且期間無新丟棄＝機制恢復（溢出/斷線同一判準；
				// 溢出持續時計數仍在增長，恢復判定被自然壓住）
				f.reportRecovered()
			}
		}
	}
}

// dial 依傳入設定建立連線（run loop 傳 snapshot、SendTest 傳待測表單值——
// 不讀共享狀態，測試按鈕才不會暫停真轉發）
func (f *SyslogForwarder) dial(s model.SyslogSetting) (net.Conn, error) {
	addr := net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port))
	switch s.Protocol {
	case model.SyslogProtocolUDP, "":
		return net.DialTimeout("udp", addr, syslogDialTimeout)
	case model.SyslogProtocolTCP:
		return net.DialTimeout("tcp", addr, syslogDialTimeout)
	case model.SyslogProtocolTCPTLS:
		cfg := &tls.Config{ServerName: s.Host}
		if s.TLSCA != "" {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM([]byte(s.TLSCA)) {
				return nil, errors.New("TLS CA 解析失敗（非有效 PEM）")
			}
			cfg.RootCAs = pool
		}
		dialer := &net.Dialer{Timeout: syslogDialTimeout}
		return tls.DialWithDialer(dialer, "tcp", addr, cfg)
	default:
		return nil, fmt.Errorf("未知協議 %q", s.Protocol)
	}
}

// write 寫出單筆（UDP 單 datagram；TCP/TLS 用 RFC6587 octet-counting framing）。
// 協議取自傳入設定，與 dial 同一份——避免寫出中途讀到變更後的共享值
func (f *SyslogForwarder) write(conn net.Conn, e syslogEvent, s model.SyslogSetting) error {
	msg := f.format(e, time.Now())
	if s.Protocol == model.SyslogProtocolTCP || s.Protocol == model.SyslogProtocolTCPTLS {
		msg = fmt.Sprintf("%d %s", len(msg), msg)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(syslogWriteTimeout)); err != nil {
		return err
	}
	_, err := conn.Write([]byte(msg))
	return err
}

// format RFC5424：<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
func (f *SyslogForwarder) format(e syslogEvent, ts time.Time) string {
	pri := syslogFacility*8 + e.severity
	return fmt.Sprintf("<%d>1 %s %s %s - %s - %s",
		pri, ts.Format(time.RFC3339), f.hostname, syslogAppName, e.msgID, e.payload)
}

// SendTest 同步發送一筆測試訊息（設定 UI 測試按鈕；不經緩衝，直連直寫，
// 回傳具體失敗原因）。傳入待測設定而非讀 DB——測試未儲存的表單值。
// 不觸碰共享 setting（原暫換寫法使測試期間真轉發被靜默
// 暫停且丟棄不計數）
func (f *SyslogForwarder) SendTest(s model.SyslogSetting) error {
	if s.Host == "" {
		return errors.New("目的地 host 未設定")
	}
	conn, err := f.dial(s)
	if err != nil {
		return fmt.Errorf("連線失敗: %w", err)
	}
	defer conn.Close()
	// message 為機器識別字：收端是機器（syslog server），非使用者
	// 可見文案，英文常數即可，不需 i18n 碼化
	payload, _ := json.Marshal(map[string]any{
		"message": branding.Slug + " syslog test", "sent_at": time.Now().Format(time.RFC3339),
	})
	if err := f.write(conn, syslogEvent{severity: syslogSeverityInfo, msgID: "test", payload: payload}, s); err != nil {
		return fmt.Errorf("寫入失敗: %w", err)
	}
	return nil
}

func (f *SyslogForwarder) snapshot() model.SyslogSetting {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.setting
}

// reportFailure 失效上報（節流：進行中不重複）
func (f *SyslogForwarder) reportFailure(causeCode string, params map[string]string) {
	if f.failing.CompareAndSwap(false, true) && f.onFailure != nil {
		f.onFailure(model.MechanismSyslogForward, causeCode, params, false)
	}
}

// reportRecovered 恢復上報
func (f *SyslogForwarder) reportRecovered() {
	if f.failing.CompareAndSwap(true, false) && f.onFailure != nil {
		f.onFailure(model.MechanismSyslogForward, "", nil, true)
	}
}
