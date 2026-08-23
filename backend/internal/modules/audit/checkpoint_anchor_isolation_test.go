package audit

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 故障注入 C：錨定失敗的隔離（audit-checkpoint-chain）。
//
// 與 5.4（`TestCheckpointAnchorFailureDoesNotBlockSealing`，只測「緩衝滿」）
// 的差別有兩點：本組**逐種故障記錄注入器觸發次數**，並額外覆蓋「收集器
// 不可達」——那是實務上最常見的形態（收集端停機、防火牆改規則），且它
// 與緩衝滿的路徑不同：入列成功、送達失敗，`anchor_status` 會是 `enqueued`
// 而離機證據其實不存在（誠實邊界 R4 的實證）。
//
// **注入器觸發計數是本組的核心斷言**：本專案吃過「前置條件早退導致注入器
// 零觸發、測試永遠通過」的虧，沒有計數就無從分辨「故障下仍正常」與
// 「故障根本沒發生」。

// countingAnchor 可注入故障的錨定 sink，並記錄每種路徑的觸發次數
type countingAnchor struct {
	mu sync.Mutex
	// mode: "ok"／"full"（入列被拒）／"disabled"（轉發未啟用）
	mode string
	// calls Enqueue 被呼叫次數；drops 回傳 false 的次數
	calls, drops, enabledCalls int
}

func (a *countingAnchor) Enabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabledCalls++
	return a.mode != "disabled"
}

func (a *countingAnchor) EnqueueCheckpoint(cp *model.AuditCheckpoint) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if a.mode == "full" {
		a.drops++
		return false
	}
	return true
}

func (a *countingAnchor) stats() (calls, drops, enabled int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls, a.drops, a.enabledCalls
}

// TestAnchorFailureIsolation 錨定故障不影響封章與審計寫入。
func TestAnchorFailureIsolation(t *testing.T) {
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name       string
		mode       string
		wantStatus string
		wantDrops  int
	}{
		{"緩衝滿：入列被拒", "full", model.AnchorStatusDropped, 3},
		{"轉發未啟用：無收集器", "disabled", model.AnchorStatusDisabled, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := setupCheckpointDB(t)
			anchor := &countingAnchor{mode: tc.mode}
			var failures []recordedFailure
			svc, signer := newCheckpointService(t, db, anchor, &failures)
			if err := svc.EnsureGenesis(); err != nil {
				t.Fatalf("EnsureGenesis: %v", err)
			}

			// 封章三輪，每輪之間照常寫審計列（審計寫入必須全程可用）
			for i := 0; i < 3; i++ {
				seedAuditRows(t, db, 2, base.Add(time.Duration(i)*time.Hour))
				if _, err := svc.SealNow(); err != nil {
					t.Fatalf("第 %d 輪封章因錨定故障而中止: %v", i, err)
				}
			}
			// 錨定故障期間寫入的審計列一筆不少
			var rows int64
			db.Model(&model.AuditLog{}).Count(&rows)
			if rows != 6 {
				t.Errorf("審計列數 = %d, want 6（錨定故障不得影響審計寫入）", rows)
			}

			// 注入器自證：故障路徑真的被走到
			calls, drops, enabledCalls := anchor.stats()
			if enabledCalls == 0 {
				t.Fatal("Enabled() 從未被呼叫：錨定路徑根本沒執行，本測是零觸發的假綠")
			}
			switch tc.mode {
			case "full":
				if calls < 3 {
					t.Fatalf("EnqueueCheckpoint 只被呼叫 %d 次（genesis＋三輪應 >= 3）："+
						"注入器沒被觸發，通過與否無意義", calls)
				}
				if drops < tc.wantDrops {
					t.Fatalf("注入器丟棄計數 = %d, want >= %d：故障未實際發生", drops, tc.wantDrops)
				}
			case "disabled":
				if calls != 0 {
					t.Errorf("轉發未啟用時仍呼叫 EnqueueCheckpoint %d 次", calls)
				}
			}
			t.Logf("[%s] 注入器：Enabled 呼叫 %d 次、Enqueue %d 次、丟棄 %d 次",
				tc.name, enabledCalls, calls, drops)

			// 鏈完好：genesis＋三輪＝4 點，逐點簽章有效、狀態符合預期
			var chain []model.AuditCheckpoint
			if err := db.Order("seq").Find(&chain).Error; err != nil {
				t.Fatalf("讀鏈: %v", err)
			}
			if len(chain) != 4 {
				t.Fatalf("鏈長 = %d, want 4（封章不得被錨定阻擋）", len(chain))
			}
			for i := range chain {
				assertSignatureValid(t, signer, &chain[i])
				if chain[i].AnchorStatus != tc.wantStatus {
					t.Errorf("seq=%d anchor_status = %q, want %q",
						chain[i].Seq, chain[i].AnchorStatus, tc.wantStatus)
				}
			}
			// 未啟用不算失效（沒有收集器不是故障，是部署選擇；降級以橫幅呈現）
			if tc.mode == "disabled" && len(failures) != 0 {
				t.Errorf("轉發未啟用不應上報失效事件: %+v", failures)
			}
			if tc.mode == "full" && len(failures) == 0 {
				t.Error("錨定丟棄未上報失效：靜默的證據缺口是本機制最不能接受的形態")
			}
		})
	}
}

// TestAnchorUnreachableCollectorDoesNotBlockSealing 收集器不可達（真 forwarder）。
//
// 用真的 `SyslogForwarder` 指向一個**已關閉的埠**：入列成功、送達必然失敗。
// 這條路徑用 fake 測不出來——fake 的 Enqueue 回 true 就結束了，而真實形態是
// 「入列成功、run loop 連不上、`anchor_status` 停在 enqueued」。
// 本測因此同時是誠實邊界 R4 的實證：**enqueued 不等於送達**。
func TestAnchorUnreachableCollectorDoesNotBlockSealing(t *testing.T) {
	// 取一個確定沒人聽的埠：先 listen 拿到埠號，立刻關掉
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if c, derr := net.DialTimeout("tcp", ln.Addr().String(), 300*time.Millisecond); derr == nil {
		c.Close()
		t.Fatalf("前提破了：埠 %d 仍可連線，「收集器不可達」的注入沒有生效", port)
	}

	db := setupCheckpointDB(t)
	if err := db.AutoMigrate(&model.SyslogSetting{}); err != nil {
		t.Fatalf("migrate syslog setting: %v", err)
	}
	db.Create(&model.SyslogSetting{ID: 1, Enabled: true, Host: "127.0.0.1",
		Port: port, Protocol: model.SyslogProtocolTCP})

	fwd := NewSyslogForwarder(db)
	// 注入器觸發計數：連線失敗每次都經 onFailure 上報，比等 Dropped 的
	// 退避（1s＋2s）快得多，且直接證明「撥號真的失敗過」
	var mu sync.Mutex
	connectFailures := 0
	fwd.onFailure = func(mechanism, cause string, params map[string]string, recovered bool) {
		mu.Lock()
		defer mu.Unlock()
		if !recovered && cause == model.CauseSyslogConnectFailed {
			connectFailures++
		}
	}
	fwd.Start()
	t.Cleanup(fwd.Stop)
	if !fwd.Enabled() {
		t.Fatal("前提破了：forwarder 未啟用，本測不會走到錨定路徑")
	}

	svc, signer := newCheckpointService(t, db, fwd, nil)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}

	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	start := time.Now()
	for i := 0; i < 3; i++ {
		seedAuditRows(t, db, 2, base.Add(time.Duration(i)*time.Hour))
		if _, err := svc.SealNow(); err != nil {
			t.Fatalf("第 %d 輪封章因收集器不可達而中止: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	// 封章不得等待網路：連不上的收集器若進了封章的同步路徑，這裡會是秒級
	if elapsed > 3*time.Second {
		t.Errorf("三輪封章耗時 %v：錨定疑似進入封章同步路徑（外部依賴成為單點）", elapsed)
	}

	var chain []model.AuditCheckpoint
	if err := db.Order("seq").Find(&chain).Error; err != nil {
		t.Fatalf("讀鏈: %v", err)
	}
	if len(chain) != 4 {
		t.Fatalf("鏈長 = %d, want 4", len(chain))
	}
	for i := range chain {
		assertSignatureValid(t, signer, &chain[i])
	}
	// R4 實證：入列成功即記 enqueued，但收集端根本收不到
	if chain[len(chain)-1].AnchorStatus != model.AnchorStatusEnqueued {
		t.Errorf("anchor_status = %q, want enqueued（入列成功；送達與否本地不可知）",
			chain[len(chain)-1].AnchorStatus)
	}
	// 注入自證：轉發器確實嘗試過送達並失敗
	deadline := time.Now().Add(10 * time.Second)
	got := 0
	for time.Now().Before(deadline) {
		mu.Lock()
		got = connectFailures
		mu.Unlock()
		if got > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got == 0 {
		t.Fatal("轉發器從未記錄連線失敗：注入的「收集器不可達」沒有被走到，" +
			"本測退化為零觸發的假綠")
	}
	t.Logf("收集器不可達：三輪封章 %v 完成、鏈長 %d、連線失敗上報 %d 次、丟棄 %d 筆",
		elapsed, len(chain), got, fwd.Dropped())
}
