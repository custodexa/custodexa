package sshproxy

import (
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/proxy"
)

// 正式接線：經 Handler.runTerminal（會話建立後的轉發入口）建出的橋接，
// 對資料庫命令列協議必須掛上改連目標守衛。其他測試以 newBridge 加手動 attach 組裝，
// 刪掉 runTerminal 內的接線也不會轉紅；本測試走真正的入口，補上這個缺口。
func TestRunTerminalAttachesReconnectGuard(t *testing.T) {
	cases := []struct {
		protocol string
		line     string
		benign   string
	}{
		{"redis", "connect 203.0.113.5 6379\r", "INFO clients\r"},
		{"mysql", "\\r db 203.0.113.5\r", "SELECT 1;\r"},
		{"mssql", ":connect 203.0.113.5\r", "SELECT 1;\r"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.protocol, func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
			if err != nil {
				t.Fatalf("open db: %v", err)
			}
			sqlDB, _ := db.DB()
			sqlDB.SetMaxOpenConns(1)
			if err := db.AutoMigrate(&model.User{}); err != nil {
				t.Fatalf("migrate: %v", err)
			}
			if err := db.Create(&model.User{ID: 1, Username: "wiring-user", Active: true}).Error; err != nil {
				t.Fatalf("seed user: %v", err)
			}
			oldDB := database.DB
			database.DB = db
			t.Cleanup(func() { database.DB = oldDB })

			cli := newFakeCLI(nil)
			h := &Handler{
				AuthService:   &identity.AuthService{},
				AlertSink:     &reconnectAlertSink{},
				TimeoutPolicy: func() (time.Duration, time.Duration) { return 0, 0 },
			}
			est := &EstablishedTerminal{
				conn:  cli,
				grant: proxy.ConnectGrant{UserID: 1, AssetID: 2},
				asset: &model.Asset{Protocol: model.ProtocolType(c.protocol)},
				cols:  80, rows: 24,
			}
			server, client := NewInProcessTransportPair()
			done := make(chan struct{})
			go func() { h.runTerminal(est, server); close(done) }()
			t.Cleanup(func() {
				client.Close()
				cli.Close()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
				}
			})

			send := func(s string) {
				raw, err := EncodeMessage(MsgData, s)
				if err != nil {
					t.Fatalf("encode: %v", err)
				}
				if err := client.WriteMessage(1, raw); err != nil {
					t.Fatalf("send: %v", err)
				}
			}
			executed := func(want string) bool {
				for _, l := range cli.executedLines() {
					if strings.HasSuffix(l, want) {
						return true
					}
				}
				return false
			}

			send(c.line)
			// 對照：一般輸入經同一條橋接照常轉送，證明橋接確實在跑、且先前那行已被處理
			send(c.benign)
			want := strings.TrimRight(c.benign, "\r")
			rcWaitFor(t, "一般輸入被轉送", func() bool { return executed(want) })

			for _, l := range cli.executedLines() {
				if strings.Contains(strings.ToLower(l), "connect") || strings.Contains(l, `\r`) {
					t.Fatalf("改連行進入子程序：%q", l)
				}
			}
		})
	}
}
