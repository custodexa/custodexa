package main

import (
	"context"
	"fmt"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/crypto"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func backgroundWorkers() map[string]int {
	raw := make([]byte, 2<<20)
	n := runtime.Stack(raw, true)
	counts := map[string]int{}
	for _, stack := range strings.Split(string(raw[:n]), "\n\n") {
		lines := strings.Split(stack, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "created by github.com/custodexa/backend/") || strings.HasPrefix(line, "created by github.com/robfig/cron/") {
				key := strings.Split(line, " in goroutine ")[0]
				counts[key]++
				break
			}
		}
	}
	return counts
}
func TestRepeatedSealRestoreHTTP(t *testing.T) {
	for _, mode := range []string{"ui", "env", "delegated"} {
		t.Run(mode, func(t *testing.T) {
			e, token, reads := modeFixture(t, mode)
			server := httptest.NewServer(e.swap)
			defer server.Close()
			client := &http.Client{Timeout: 10 * time.Second}
			payload := initPayload(testInitialKEK)
			if mode != "ui" {
				payload = "{}"
			}
			initial, err := restoreHTTP(client, server.URL+"/api/v1/seal/unseal", "POST", payload, token)
			if err != nil || initial.status != 200 {
				t.Fatalf("startup HTTP=%d", initial.status)
			}
			baseline := backgroundWorkers()
			if len(baseline) == 0 {
				t.Fatal("no worker observation")
			}
			for round := 1; round <= 2; round++ {
				old := e.machine.Snapshot()
				g := old.Services.(*appGraph)
				r, err := restoreHTTP(client, server.URL+"/api/v1/seal/seal", "POST", "{}", token)
				if err != nil || r.status != 200 {
					t.Fatalf("seal HTTP=%d", r.status)
				}
				if !g.bag.Released() || g.MaterialGate().InFlight() != 0 {
					t.Fatal("old graph not drained")
				}
				before := *reads
				// **授權面自本版起換人承擔**：解封不再看 Bearer，改看解封授權脈絡
				// （`Authorization: SealGrant <grant>`）。原案守的是「未授權的還原
				// 在碰到部署來源之前就被擋下」——那條性質不變，只是「未授權」的
				// 形態自「過期的 Bearer」變成「不成立的脈絡」。
				// 三種形態各驗一次：完全不帶、帶過期的 Bearer、帶假脈絡。
				for _, auth := range []string{"", "Bearer " + expiredBearer(t, e), "SealGrant not-a-real-grant"} {
					denied, err := restoreHTTPAuth(client, server.URL+"/api/v1/seal/unseal", "POST", "{}", auth)
					if err != nil || denied.status != 401 || *reads != before {
						t.Fatalf("未授權的還原未在碰到部署來源之前被擋下（auth=%q status=%d reads=%d→%d）",
							auth, denied.status, before, *reads)
					}
				}
				status, err := restoreHTTP(client, server.URL+"/api/v1/seal/status", "GET", "", "")
				if err != nil || status.state != "sealed" || *reads != before {
					t.Fatal("status caused restore")
				}
				if mode != "ui" && !strings.Contains(status.guidance, "restart the backend") {
					t.Fatal("missing restart guidance")
				}
				payload = fmt.Sprintf(`{"kek":%q}`, testInitialKEK)
				if mode != "ui" {
					payload = "{}"
				}
				results := make(chan int, 2)
				var wg sync.WaitGroup
				for i := 0; i < 2; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						r, err := restoreHTTP(client, server.URL+"/api/v1/seal/unseal", "POST", payload, token)
						if err != nil {
							results <- 0
						} else {
							results <- r.status
						}
					}()
				}
				wg.Wait()
				close(results)
				success, conflict := 0, 0
				for status := range results {
					switch status {
					case 200:
						success++
					case 409:
						conflict++
					default:
						t.Fatalf("concurrent restore HTTP=%d", status)
					}
				}
				if success != 1 || conflict != 1 {
					t.Fatalf("success=%d conflict=%d", success, conflict)
				}
				next := e.machine.Snapshot()
				if next.State != seal.StateUnsealed || next.Generation <= old.Generation || next.Services == g {
					t.Fatal("graph or generation reused")
				}
				if e.machine.CompleteCleanup(old.Generation) {
					t.Fatal("old cleanup callback accepted")
				}
				if e.machine.Snapshot() != next {
					t.Fatal("old cleanup changed new graph")
				}
				if err = g.Release(context.Background()); err != nil {
					t.Fatal(err)
				}
				after := backgroundWorkers()
				for name, count := range after {
					if count > baseline[name] {
						t.Fatalf("worker count increased for %s: before=%d after=%d", name, baseline[name], count)
					}
				}
				t.Logf("EVIDENCE repeated-seal-restore mode=%s round=%d generation=%d,%d concurrent=200,409 old_graph=released stale_callback=rejected status_source_reads=unchanged worker_families=%d growth=0 expired_admin=%s", mode, round, old.Generation, next.Generation, len(after), map[bool]string{true: "not_required_for_ui_restore", false: "401_restart_guidance"}[mode == "ui"])
			}
		})
	}
}

// expiredBearer 產一個已過期的業務權杖。
//
// 留著它是為了守一件事：**過期的業務權杖也不得成為解封憑據**——兩套授權自本版起
// 不互相代償，而「Bearer 恰好還有效就放行」正是那條代償最可能出現的形態。
func expiredBearer(t *testing.T, e *sealIntegrationEnv) string {
	t.Helper()
	token, err := crypto.NewJWTManager(e.s1.cfg.Security.JWTSecret, time.Hour).
		GenerateScopedToken(1, testAdminUser, "", "admin", "", -time.Hour, crypto.AuthContext{})
	if err != nil {
		t.Fatal("expired fixture failed")
	}
	return token
}
