package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupSyslogDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := db.AutoMigrate(&model.SyslogSetting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// TestSyslogFormat RFC5424 結構與 PRI（facility 13 * 8 + severity）
func TestSyslogFormat(t *testing.T) {
	f := NewSyslogForwarder(setupSyslogDB(t))
	f.hostname = "bastion"
	ts := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	got := f.format(syslogEvent{severity: syslogSeverityInfo, msgID: "audit", payload: []byte(`{"a":1}`)}, ts)
	want := `<110>1 2026-07-13T10:00:00Z bastion custodexa - audit - {"a":1}`
	if got != want {
		t.Errorf("format = %q, want %q", got, want)
	}
	got = f.format(syslogEvent{severity: syslogSeverityWarning, msgID: "alert", payload: []byte(`{}`)}, ts)
	if !strings.HasPrefix(got, "<108>1 ") {
		t.Errorf("alert PRI 應為 108（13*8+4）, got %q", got)
	}
}

// TestSyslogTCPForwarding 端到端：TCP octet-counting framing＋audit JSON 含 10.2.2 六要素
func TestSyslogTCPForwarding(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	received := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		for {
			// RFC6587 octet-counting：LEN SP MSG
			lenStr, err := r.ReadString(' ')
			if err != nil {
				return
			}
			var n int
			fmt.Sscanf(strings.TrimSpace(lenStr), "%d", &n)
			buf := make([]byte, n)
			if _, err := readFull(r, buf); err != nil {
				return
			}
			received <- string(buf)
		}
	}()

	db := setupSyslogDB(t)
	port := ln.Addr().(*net.TCPAddr).Port
	db.Create(&model.SyslogSetting{ID: 1, Enabled: true, Host: "127.0.0.1", Port: port, Protocol: model.SyslogProtocolTCP})

	f := NewSyslogForwarder(db)
	f.Start()
	t.Cleanup(f.Stop)

	f.EnqueueAuditLog(&model.AuditLog{
		ID: 7, CreatedAt: time.Now(), Username: "admin", UserID: 1,
		Action: model.ActionUpdate, Resource: model.ResourceAsset, Status: model.StatusSuccess,
		ClientIP: "10.0.0.9", Method: "PUT", Path: "/api/v1/assets/7",
	})

	select {
	case msg := <-received:
		if !strings.Contains(msg, "custodexa - audit - ") {
			t.Errorf("訊息缺 RFC5424 頭: %q", msg)
		}
		jsonPart := msg[strings.Index(msg, "{"):]
		var payload map[string]any
		if err := json.Unmarshal([]byte(jsonPart), &payload); err != nil {
			t.Fatalf("JSON 解析失敗: %v (%q)", err, jsonPart)
		}
		// PCI 10.2.2 六要素：使用者/事件類型/時間/成敗/來源/受影響資源
		for _, key := range []string{"username", "action", "created_at", "status", "client_ip", "resource"} {
			if _, ok := payload[key]; !ok {
				t.Errorf("payload 缺 10.2.2 要素 %s: %v", key, payload)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("3s 內未收到轉發訊息")
	}
}

// TestSyslogOverflowNonBlocking 緩衝溢出：producer 側只計數丟棄、零上報
// （對抗驗證修正：producer 側上報與 run loop 恢復跨 goroutine 交錯，
// 且上報含 DB/通知 IO，違反審計主鏈零阻塞——偵測移 run loop 計數差）
func TestSyslogOverflowNonBlocking(t *testing.T) {
	db := setupSyslogDB(t)
	db.Create(&model.SyslogSetting{ID: 1, Enabled: true, Host: "127.0.0.1", Port: 1, Protocol: model.SyslogProtocolTCP})

	f := NewSyslogForwarder(db)
	f.Reload()
	f.ch = make(chan syslogEvent, 2) // 縮小緩衝便於塞爆；不啟動 run loop＝無消費者
	var failures int
	f.SetFailureReporter(func(mechanism, causeCode string, params map[string]string, recovered bool) {
		if mechanism == model.MechanismSyslogForward && !recovered {
			failures++
		}
	})

	for i := 0; i < 5; i++ {
		f.EnqueueAuditLog(&model.AuditLog{ID: uint(i + 1), CreatedAt: time.Now(), Username: "u"})
	}
	if got := f.Dropped(); got != 3 {
		t.Errorf("dropped = %d, want 3（緩衝 2、進 5）", got)
	}
	if failures != 0 {
		t.Errorf("producer 側不應直接上報（偵測在 run loop）, got %d", failures)
	}
}

// TestSyslogOverflowReportAndRecover run loop 計數差偵測溢出失效＋
// 寫出成功且計數穩定即恢復（對抗驗證回歸：原恢復只掛重撥成功，
// 溢出時連線健在永不重撥，失效事件永無人回填）
func TestSyslogOverflowReportAndRecover(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn // 收下連線即可，單筆訊息塞得進 kernel buffer
		}
	}()

	db := setupSyslogDB(t)
	port := ln.Addr().(*net.TCPAddr).Port
	db.Create(&model.SyslogSetting{ID: 1, Enabled: true, Host: "127.0.0.1", Port: port, Protocol: model.SyslogProtocolTCP})

	f := NewSyslogForwarder(db)
	reports := make(chan bool, 4) // recovered 旗標序列
	var firstCause string
	f.SetFailureReporter(func(mechanism, causeCode string, params map[string]string, recovered bool) {
		if !recovered && firstCause == "" {
			firstCause = causeCode
		}
		reports <- recovered
	})
	f.Start()
	t.Cleanup(f.Stop)

	// 模擬 producer 溢出（計數已增），run loop 於下一筆事件偵測到計數差
	f.dropped.Add(3)
	f.EnqueueAuditLog(&model.AuditLog{ID: 1, CreatedAt: time.Now(), Username: "u"})

	select {
	case recovered := <-reports:
		if recovered {
			t.Fatal("首個上報應為溢出失效而非恢復")
		}
		// M5：cause 走機器碼，不再是散文
		if firstCause != model.CauseSyslogBufferOverflow {
			t.Fatalf("溢出上報的 cause code = %q, want %q",
				firstCause, model.CauseSyslogBufferOverflow)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("3s 內未收到溢出失效上報")
	}
	select {
	case recovered := <-reports:
		if !recovered {
			t.Fatal("寫出成功且計數穩定後應上報恢復")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("3s 內未收到恢復上報")
	}
}

// TestSyslogDisabledNoop 停用時 Enqueue 為 no-op
func TestSyslogDisabledNoop(t *testing.T) {
	f := NewSyslogForwarder(setupSyslogDB(t))
	f.Reload() // 無設定列 = 停用
	f.EnqueueAuditLog(&model.AuditLog{ID: 1, CreatedAt: time.Now()})
	if len(f.ch) != 0 || f.Dropped() != 0 {
		t.Errorf("停用時不應入隊或計數（ch=%d dropped=%d）", len(f.ch), f.Dropped())
	}
}

// TestSyslogSendTest 測試訊息：可達目的地成功、不可達回具體原因
func TestSyslogSendTest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	f := NewSyslogForwarder(setupSyslogDB(t))
	port := ln.Addr().(*net.TCPAddr).Port
	if err := f.SendTest(model.SyslogSetting{Host: "127.0.0.1", Port: port, Protocol: model.SyslogProtocolTCP}); err != nil {
		t.Errorf("SendTest 應成功: %v", err)
	}
	if err := f.SendTest(model.SyslogSetting{Host: "127.0.0.1", Port: 1, Protocol: model.SyslogProtocolTCP}); err == nil || !strings.Contains(err.Error(), "連線失敗") {
		t.Errorf("對死埠應回連線失敗, got %v", err)
	}
	if err := f.SendTest(model.SyslogSetting{}); err == nil {
		t.Error("空 host 應回錯誤")
	}
}

// TestSyslogReloadSwitchesDestination Reload 後棄舊連線重撥（live 實踩回歸）：
// 設定變更前建立的連線不得繼續使用，事件須送達新目的地
func TestSyslogReloadSwitchesDestination(t *testing.T) {
	newSink := func() (net.Listener, chan string) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		received := make(chan string, 8)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					r := bufio.NewReader(c)
					for {
						lenStr, err := r.ReadString(' ')
						if err != nil {
							return
						}
						var n int
						fmt.Sscanf(strings.TrimSpace(lenStr), "%d", &n)
						buf := make([]byte, n)
						if _, err := readFull(r, buf); err != nil {
							return
						}
						received <- string(buf)
					}
				}(conn)
			}
		}()
		return ln, received
	}
	lnA, recvA := newSink()
	defer lnA.Close()
	lnB, recvB := newSink()
	defer lnB.Close()

	db := setupSyslogDB(t)
	portA := lnA.Addr().(*net.TCPAddr).Port
	db.Create(&model.SyslogSetting{ID: 1, Enabled: true, Host: "127.0.0.1", Port: portA, Protocol: model.SyslogProtocolTCP})

	f := NewSyslogForwarder(db)
	f.Start()
	t.Cleanup(f.Stop)

	f.EnqueueAuditLog(&model.AuditLog{ID: 1, CreatedAt: time.Now(), Username: "first"})
	select {
	case <-recvA:
	case <-time.After(3 * time.Second):
		t.Fatal("A 未收到第一筆（前置失敗）")
	}

	// 切換目的地到 B 並 Reload
	portB := lnB.Addr().(*net.TCPAddr).Port
	db.Save(&model.SyslogSetting{ID: 1, Enabled: true, Host: "127.0.0.1", Port: portB, Protocol: model.SyslogProtocolTCP})
	f.Reload()

	f.EnqueueAuditLog(&model.AuditLog{ID: 2, CreatedAt: time.Now(), Username: "second"})
	select {
	case msg := <-recvB:
		if !strings.Contains(msg, "second") {
			t.Errorf("B 收到的訊息不對: %q", msg)
		}
	case msg := <-recvA:
		t.Fatalf("Reload 後事件仍送舊目的地 A: %q", msg)
	case <-time.After(3 * time.Second):
		t.Fatal("Reload 後 3s 內 B 未收到事件")
	}
}

// readFull io.ReadFull 的簡版（避免多引一個 import 別名衝突）
func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
