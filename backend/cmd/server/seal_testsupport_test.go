package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/internal/sealjournal"
)

// newStageOneTestEngine 以 **production 的段 1 engine 建構路徑**建 router。
//
// 不用 gin.New()：段 1 專屬的設定（關閉尾斜線／路徑修正的自動 redirect、
// 可信代理套用）全掛在 newEngine 上，測試自建 engine 等於驗一個不存在於
// production 的 router——而 M2 的路由存在性 oracle 正是只在那些設定缺席時出現。
// 日誌導向 io.Discard：逐路由掃描會產生上百行 gin 日誌，淹掉真正的失敗訊息。
func newStageOneTestEngine(t *testing.T, s1 *stage1) *gin.Engine {
	t.Helper()
	if s1 == nil {
		s1 = &stage1{cfg: &config.Config{}}
	}
	prev := gin.DefaultWriter
	gin.DefaultWriter = io.Discard
	defer func() { gin.DefaultWriter = prev }()
	r, err := newEngine(s1, true)
	if err != nil {
		t.Fatalf("建立段 1 測試 router 失敗: %v", err)
	}
	return r
}

// 封印相關測試的共用夾具。
//
// **一律用真的 journal**（開在 t.TempDir 的定長檔）而非假物件：本批要驗的多數
// 性質——admission 間隔、received 落地與否、回灌——都落在 journal 的真實行為上，
// 用假物件驗這些等於驗自己寫的假物件。

// testJournal 開一個測試專用的定長 journal。
func testJournal(t *testing.T) *sealjournal.Journal {
	t.Helper()
	j, err := sealjournal.Open(t.TempDir(),
		sealjournal.WithCapacity(64, 64),
		// 測試不驗速率上界，故把 admission 間隔壓到 0：留著只會讓每個
		// 案例平白等一段固定時間，且該間隔已由 sealjournal 自身的測試涵蓋。
		sealjournal.WithMinAdmissionInterval(0))
	if err != nil {
		t.Fatalf("開啟測試 journal 失敗: %v", err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}

// testMachineOption 調整測試狀態機的建構參數。
type testMachineOption func(*seal.Config)

// withVerify 覆寫材料驗證。
func withVerify(fn seal.VerifyFunc) testMachineOption {
	return func(c *seal.Config) { c.Verify = fn }
}

// withStage2 覆寫段 2。
func withStage2(fn seal.Stage2Func) testMachineOption {
	return func(c *seal.Config) { c.Stage2 = fn }
}

// withLimiter 覆寫限速結構。
func withLimiter(l *seal.Limiter) testMachineOption {
	return func(c *seal.Config) { c.Limiter = l }
}

// withStage2Timeout 覆寫段 2 逾時。
func withStage2Timeout(d time.Duration) testMachineOption {
	return func(c *seal.Config) { c.Stage2Timeout = d }
}

// withNow 注入可控時鐘。退避與冷卻的驗收都是時間性質，真等下去會讓測試
// 既慢又不穩；注入時鐘使「冷卻期滿自動恢復」成為可確定觀察的事實。
func withNow(fn func() time.Time) testMachineOption {
	return func(c *seal.Config) { c.Now = fn }
}

// fakeClock 是測試用的可推進時鐘。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// errTestMaterial 測試用的材料驗證失敗成因。
var errTestMaterial = errors.New("測試：材料驗證失敗")

// fakeGraph 是最小的 seal.ServiceGraph 實作。
type fakeGraph struct{ released bool }

func (g *fakeGraph) Release(context.Context) error { g.released = true; return nil }

// newTestSealSetup 建立「真 journal ＋ 可注入 verify／stage2」的狀態機與 handler。
func newTestSealSetup(t *testing.T, opts ...testMachineOption) (*seal.Machine, *api.SealHandler) {
	t.Helper()
	j := testJournal(t)
	cfg := seal.Config{
		Journal: j,
		Verify: func(context.Context, []byte) (seal.VerifiedMaterial, error) {
			return seal.VerifiedMaterial{}, errTestMaterial
		},
		Stage2: func(context.Context, seal.VerifiedMaterial) (seal.ServiceGraph, error) {
			return &fakeGraph{}, nil
		},
	}
	for _, o := range opts {
		o(&cfg)
	}
	m, err := seal.New(cfg)
	if err != nil {
		t.Fatalf("建立測試狀態機失敗: %v", err)
	}
	h := api.NewSealHandler(m, j)
	h.SetAdmitter(func(ctx context.Context) (func(bool), error) {
		ticket, err := j.Admit(ctx)
		if err != nil {
			return nil, err
		}
		return ticket.Release, nil
	})
	return m, h
}
