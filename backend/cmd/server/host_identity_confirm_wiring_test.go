package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
)

// TestHostIdentityConfirmWiring 人工承接服務的正式組裝：缺依賴時段 2 在任何排程啟動之前回錯、
// 路由不掛載；依賴齊全時兩條 retry handler 都持有可用的承接服務。
func TestHostIdentityConfirmWiring(t *testing.T) {
	newFull := func() *asset.HostIdentityTakeoverService {
		retry := asset.NewChangeSecretRetryRunner(nil, nil, nil, nil, nil)
		rotations := asset.NewCredentialRotationService(nil, nil, nil, nil, nil, audit.NewTxSink(), stubAuthorizer{})
		svc := asset.NewHostIdentityTakeoverService(nil, stubAuthorizer{})
		svc.SetAuditTxSink(audit.NewTxSink())
		return svc.WithCandidateRunner(retry).WithMemberRunner(rotations)
	}

	t.Run("缺口清單逐項指名且錯誤非空", func(t *testing.T) {
		// db 為 nil 是本案刻意的底：下面逐項補齊後，唯一剩下的缺口只有 db
		full := newFull()
		if gaps := full.WiringGaps(); len(gaps) != 1 || gaps[0] != "db" {
			t.Fatalf("除 db 外皆已注入，缺口應只有 db，實得 %v", gaps)
		}
		bare := asset.NewHostIdentityTakeoverService(nil, nil)
		gaps := bare.WiringGaps()
		want := []string{"db", "authorizer", "auditSink", "candidateRunner", "memberRunner"}
		if strings.Join(gaps, ",") != strings.Join(want, ",") {
			t.Fatalf("全缺時缺口應為 %v，實得 %v", want, gaps)
		}
		if hostIdentityTakeoverWiringError(gaps) == nil {
			t.Fatal("有缺口卻回 nil 啟動錯誤")
		}
		if hostIdentityTakeoverWiringError(nil) != nil {
			t.Fatal("無缺口卻回啟動錯誤")
		}
		var nilSvc *asset.HostIdentityTakeoverService
		if len(nilSvc.WiringGaps()) == 0 {
			t.Fatal("nil 服務必須回報缺口，不可 panic 也不可視為就緒")
		}
	})

	t.Run("未注入時段2在排程前回錯且無排程啟動且路由不掛載", func(t *testing.T) {
		env := newSealIntegrationEnv(t)
		var started []string
		prevGate := stage2BackgroundGate
		stage2BackgroundGate = func(name string) bool { started = append(started, name); return false }
		prevOverride := stage2HostIdentityTakeoverOverride
		// 換入一個沒有任何依賴的承接服務，模擬組裝漏接
		stage2HostIdentityTakeoverOverride = func(*asset.HostIdentityTakeoverService) *asset.HostIdentityTakeoverService {
			return asset.NewHostIdentityTakeoverService(database.DB, nil)
		}
		t.Cleanup(func() { stage2BackgroundGate = prevGate; stage2HostIdentityTakeoverOverride = prevOverride })

		kek, err := buildUIKEKProvider([]byte(testInitialKEK))
		if err != nil {
			t.Fatalf("建構 KEK provider 失敗: %v", err)
		}
		g, err := runStage2(context.Background(), env.s1, kek, nil, nil)
		if g != nil {
			t.Cleanup(func() {
				rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = g.Release(rctx)
			})
		}
		if err == nil {
			t.Fatal("承接服務缺依賴，段 2 竟成功")
		}
		if !strings.Contains(err.Error(), "hostIdentityTakeoverWiring") || !strings.Contains(err.Error(), "candidateRunner") {
			t.Fatalf("錯誤應指名步驟與缺口，實得: %v", err)
		}
		// syslogForwarder 在人工承接服務之前就已啟動（與本檢查無關）；其餘排程一個都不得啟動
		for _, n := range started {
			if n != "syslogForwarder" {
				t.Fatalf("缺依賴時不得有排程在檢查之後啟動，實際啟動: %v", started)
			}
		}
		built := g.ServiceNames()
		if len(built) == 0 || built[len(built)-1] != "credentialRotationInterruptedRecovery" {
			t.Fatalf("失敗應停在啟動收束之後、改密排程之前，已建構尾端: %v", built)
		}
		for _, n := range built {
			if n == "changeSecretScheduler" || n == "changeSecretRetryScheduler" || n == "apiHandlers" {
				t.Fatalf("缺依賴時 %s 竟已建構", n)
			}
		}
		// 路由依賴由 apiHandlers 一步建構；沒走到就沒有任何 handler 可掛載
		if g.deps.changeSecret != nil || g.deps.credential != nil {
			t.Fatal("缺依賴時路由依賴竟已建構：路由會在沒有承接服務下掛載")
		}
	})

	t.Run("注入時兩條retry handler的依賴非nil", func(t *testing.T) {
		env := newSealIntegrationEnv(t)
		prevGate := stage2BackgroundGate
		stage2BackgroundGate = func(string) bool { return false }
		t.Cleanup(func() { stage2BackgroundGate = prevGate })
		kek, err := buildUIKEKProvider([]byte(testInitialKEK))
		if err != nil {
			t.Fatalf("建構 KEK provider 失敗: %v", err)
		}
		g, err := runStage2(context.Background(), env.s1, kek, nil, nil)
		if err != nil {
			t.Fatalf("依賴齊全時段 2 應成功: %v", err)
		}
		t.Cleanup(func() {
			rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = g.Release(rctx)
		})
		if g.deps.changeSecret == nil || !g.deps.changeSecret.HostIdentityTakeoverWired() {
			t.Fatal("候選 retry handler 未持有完整的承接服務")
		}
		if g.deps.credential == nil || !g.deps.credential.HostIdentityTakeoverWired() {
			t.Fatal("成員補跑 handler 未持有完整的承接服務")
		}
	})

	t.Run("缺依賴檢查字面早於改密排程與路由建構", func(t *testing.T) {
		body, err := os.ReadFile(filepath.Join(lifecycleModuleRoot(t), "cmd", "server", "stage2.go"))
		if err != nil {
			t.Fatalf("讀取 stage2.go 失敗: %v", err)
		}
		src := string(body)
		at := func(needle string) int {
			t.Helper()
			if strings.Count(src, needle) != 1 {
				t.Fatalf("stage2.go 內 %q 應恰出現一次，實際 %d 次", needle, strings.Count(src, needle))
			}
			return strings.Index(src, needle)
		}
		check := at(`fail("hostIdentityTakeoverWiring"`)
		for _, later := range []string{
			"changeSecretScheduler.Start()",
			"changeSecretRetryScheduler.Start()",
			`mark("apiHandlers")`,
		} {
			if check >= at(later) {
				t.Errorf("承接服務缺依賴檢查必須早於 %s", later)
			}
		}
	})
}
