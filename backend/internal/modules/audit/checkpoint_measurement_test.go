package audit

import (
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/testgate"
	"gorm.io/gorm"
)

// audit-checkpoint-chain 第 4 組的 postgres 實測腳本（tasks 4.7 O2／4.8）。
//
// **為何非測不可**：D3 的 grace 預設 30 秒是**估計值**——「自增 id 的取號順序
// 不等於 commit 順序」是事實，但「在途窗口有多長」從來沒被量過。太短會讓遲到
// 列變成已封區間的多出列（誤報），太長則拖慢每次封章。tasks 4.7 明文要求實測
// 後定案，本檔即該量測的單一落點。
//
// 與第 1 組基準同樣走 TEST_PG_DSN gating 與獨立 schema，不觸碰 dev 現況資料。
// 跑法：
//
//	docker compose exec -T backend sh -c 'TEST_PG_DSN="host=postgres user=postgres \
//	  password=postgres dbname=custodexa port=5432 sslmode=disable" \
//	  go test ./internal/modules/audit -run "TestCheckpointGraceMeasurementPostgres|TestCheckpointSealDoesNotSlowWritesPostgres" -v -count=1 -timeout 20m'

// checkpointSchemaDB 於獨立 schema 建立封章量測所需的最小 schema。
func checkpointSchemaDB(t *testing.T, schema string) *gorm.DB {
	t.Helper()
	db := baselineSchemaDB(t, schema)
	if err := db.AutoMigrate(&model.AuditCheckpoint{}, &model.IntegrityBaseline{}); err != nil {
		t.Fatalf("AutoMigrate 檢查點表: %v", err)
	}
	if err := db.Create(&model.IntegrityBaseline{
		ID: 1, BaselineAt: time.Now().UTC(), MaxLogID: 0,
	}).Error; err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	return db
}

// TestCheckpointGraceMeasurementPostgres tasks 4.7（O2）：在途上界與封章掃描耗時。
//
// 量測方法（三輪）：
//  1. 起 N 條並發寫入者持續灌 audit_logs；
//  2. 於負載中途以獨立查詢取 `idHi = MAX(id)`（＝觸發瞬間的上界觀測）；
//  3. **立刻**數 `id <= idHi` 的列數（＝grace=0 時會封進去的列數）；
//  4. 於數個延遲點重複計數，最後停下負載並靜置，取最終值；
//  5. `最終值 − 立刻值` ＝ 觸發瞬間的**在途列數**；各延遲點的落地率即 grace 曲線。
func TestCheckpointGraceMeasurementPostgres(t *testing.T) {
	testgate.Value(t, testgate.EnvPGDSN) // 未設即 skip
	db := checkpointSchemaDB(t, "cpchain_grace_measure")

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(40)

	countUpTo := func(idHi uint) int64 {
		var n int64
		if err := db.Raw("SELECT count(*) FROM audit_logs WHERE id <= ?", idHi).Scan(&n).Error; err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}
	maxID := func() uint {
		var v uint
		if err := db.Raw("SELECT COALESCE(MAX(id),0) FROM audit_logs").Scan(&v).Error; err != nil {
			t.Fatalf("max id: %v", err)
		}
		return v
	}

	// 取樣點：涵蓋「毫秒級」到「遠低於預設 30 秒」的區間
	samples := []time.Duration{0, 50 * time.Millisecond, 200 * time.Millisecond,
		time.Second, 3 * time.Second}

	for round := 1; round <= 3; round++ {
		var stop atomic.Bool
		var wg sync.WaitGroup
		const writers = 24
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; !stop.Load(); i++ {
					row := &model.AuditLog{
						Action: model.ActionRead, Resource: model.ResourceAuditLog,
						Status: model.StatusSuccess, UserID: 1, Username: "grace",
						Method: "GET", Path: fmt.Sprintf("/r%d/w%d/%d", round, w, i),
						IntegrityHMAC: "x", KeyVersion: 1,
					}
					if err := db.Create(row).Error; err != nil {
						return
					}
				}
			}(w)
		}
		// 讓負載先跑起來再觀測（避免量到暖機期）
		time.Sleep(1500 * time.Millisecond)

		idHi := maxID()
		counts := make([]int64, len(samples))
		t0 := time.Now()
		for i, d := range samples {
			if wait := d - time.Since(t0); wait > 0 {
				time.Sleep(wait)
			}
			counts[i] = countUpTo(idHi)
		}
		stop.Store(true)
		wg.Wait()
		time.Sleep(2 * time.Second) // 靜置：確保全部在途交易皆已落地或回滾
		final := countUpTo(idHi)

		inFlight := final - counts[0]
		t.Logf("[4.7] 第 %d 輪：idHi=%d、觸發瞬間已 commit %d 列、最終 %d 列 ⇒ **在途 %d 列**",
			round, idHi, counts[0], final, inFlight)
		for i, d := range samples {
			landed := counts[i] - counts[0]
			pct := 100.0
			if inFlight > 0 {
				pct = float64(landed) / float64(inFlight) * 100
			}
			t.Logf("[4.7]   grace=%-6v → 已落地 %d/%d（%.1f%%）", d, landed, inFlight, pct)
		}
		if final < counts[0] {
			t.Errorf("最終列數少於觸發瞬間列數：id 區間非 append-closed，D1 的前提不成立")
		}
	}

	// ── 量測器的偵測力自證（否則「在途 0 列」是零觸發的假綠）──────────────
	//
	// 上面三輪都量到 0，必須先證明本量測器**有能力**量到非 0，否則
	// 「grace 0 秒就夠」的結論是儀器壞掉而非事實。
	// 注入一筆**刻意長交易**：它先取得 id（INSERT）但延遲 commit，
	// 期間其他寫入者繼續推進 MAX(id)——這正是 D3 描述的形態。
	{
		var held sync.WaitGroup
		release := make(chan struct{})
		committed := make(chan struct{})
		held.Add(1)
		go func() {
			defer held.Done()
			err := db.Transaction(func(tx *gorm.DB) error {
				row := &model.AuditLog{
					Action: model.ActionRead, Resource: model.ResourceAuditLog,
					Status: model.StatusSuccess, Username: "long-tx",
					IntegrityHMAC: "x", KeyVersion: 1,
				}
				if err := tx.Create(row).Error; err != nil {
					return err
				}
				<-release // 已取號、尚未 commit
				return nil
			})
			if err != nil {
				t.Errorf("長交易失敗: %v", err)
			}
			close(committed)
		}()
		time.Sleep(300 * time.Millisecond) // 確保長交易已取號

		// 其他寫入者推進 MAX(id) 越過長交易那一列
		for i := 0; i < 20; i++ {
			row := &model.AuditLog{
				Action: model.ActionRead, Resource: model.ResourceAuditLog,
				Status: model.StatusSuccess, Username: "after-long",
				Method: "GET", Path: fmt.Sprintf("/after/%d", i),
				IntegrityHMAC: "x", KeyVersion: 1,
			}
			if err := db.Create(row).Error; err != nil {
				t.Fatalf("後續寫入: %v", err)
			}
		}
		idHi := maxID()
		before := countUpTo(idHi)
		close(release)
		<-committed
		time.Sleep(200 * time.Millisecond)
		after := countUpTo(idHi)

		t.Logf("[4.7] **偵測力自證**（注入長交易）：idHi=%d、封章瞬間 %d 列、長交易 commit 後 %d 列 "+
			"⇒ 在途 %d 列", idHi, before, after, after-before)
		if after-before != 1 {
			t.Fatalf("量測器未偵測到刻意注入的在途列（差 %d，want 1）："+
				"前述三輪的「在途 0 列」因此不可採信——是儀器沒有偵測力，不是現象不存在",
				after-before)
		}
	}

	// 封章掃描耗時（10 萬列級）
	if err := db.Exec("TRUNCATE audit_logs RESTART IDENTITY").Error; err != nil {
		t.Fatalf("truncate: %v", err)
	}
	seedExpiredAuditLogs(t, db, 100000, time.Hour)
	svc := NewCheckpointService(db, newTestSigner(t), nil, nil)
	for _, n := range []uint{10000, 100000} {
		start := time.Now()
		hash, rows, _, _, err := svc.Aggregate(1, n)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("Aggregate: %v", err)
		}
		t.Logf("[4.7] 封章掃描 [1,%d]：%d 列、耗時 %v、agg=%s…",
			n, rows, elapsed.Round(time.Millisecond), hash[:16])
	}
}

// TestCheckpointSealDoesNotSlowWritesPostgres tasks 4.8：封章密集觸發下的寫入吞吐。
//
// 判準（tasks 4.8 原文）：吞吐與 p95 相對第 1 組基準劣化 >10% 即未通過。
// 本測在同一 schema 內先跑一次**無封章**的對照組，再跑一次**封章密集觸發**組，
// 兩組同機同時段比對——直接拿 design 附錄的絕對數字比對會混入機器負載差異。
func TestCheckpointSealDoesNotSlowWritesPostgres(t *testing.T) {
	testgate.Value(t, testgate.EnvPGDSN)
	db := checkpointSchemaDB(t, "cpchain_hotpath_measure")

	svc := &AuditIntegrityService{
		activeFn: func() (int, []byte) { return 1, []byte("baseline-stamp-key-32-bytes-long") },
		keyFn:    func(int) []byte { return []byte("baseline-stamp-key-32-bytes-long") },
	}
	model.SetAuditCreateHooks(svc.StampOne, nil)
	t.Cleanup(func() { model.SetAuditCreateHooks(nil, nil) })

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取 sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(40)

	type result struct {
		throughput float64
		p50, p95   time.Duration
	}
	runLoad := func(concurrency, perWorker int) result {
		var mu sync.Mutex
		lat := make([]time.Duration, 0, concurrency*perWorker)
		var wg sync.WaitGroup
		start := time.Now()
		for w := 0; w < concurrency; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				local := make([]time.Duration, 0, perWorker)
				for i := 0; i < perWorker; i++ {
					row := &model.AuditLog{
						Action: model.ActionRead, Resource: model.ResourceAuditLog,
						Status: model.StatusSuccess, UserID: 1, Username: "hotpath",
						Method: "GET", Path: fmt.Sprintf("/w%d/%d", w, i),
						ClientIP: "127.0.0.1", StatusCode: 200, Duration: 3,
					}
					t0 := time.Now()
					if err := db.Create(row).Error; err != nil {
						t.Errorf("寫入失敗: %v", err)
						return
					}
					local = append(local, time.Since(t0))
				}
				mu.Lock()
				lat = append(lat, local...)
				mu.Unlock()
			}(w)
		}
		wg.Wait()
		elapsed := time.Since(start)
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		return result{
			throughput: float64(concurrency*perWorker) / elapsed.Seconds(),
			p50:        lat[len(lat)/2],
			p95:        lat[int(float64(len(lat))*0.95)],
		}
	}

	const concurrency, perWorker = 8, 1000

	cpSvc := NewCheckpointService(db, newTestSigner(t), nil, nil)
	if err := cpSvc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	// withSealing 在指定間隔持續封章的情況下跑同一份負載；interval<=0 為忙迴圈
	withSealing := func(interval time.Duration) (result, int64) {
		var stop atomic.Bool
		var seals atomic.Int64
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if _, err := cpSvc.SealNow(); err != nil {
					t.Errorf("封章失敗: %v", err)
					return
				}
				seals.Add(1)
				if interval > 0 {
					time.Sleep(interval)
				}
			}
		}()
		r := runLoad(concurrency, perWorker)
		stop.Store(true)
		wg.Wait()
		return r, seals.Load()
	}

	// **量測設計：暖機丟棄 ＋ 三對交錯 ＋ 取中位數**。
	//
	// 單次 A／B 對照在本環境不可用：實測同一份「零封章」負載連跑四輪，
	// 吞吐落在 3740–4339 列/秒（±16%），首輪最慢（冷啟）。以「第一輪當對照組、
	// 第二輪當實驗組」的樸素設計，量到的是執行序位而非封章成本——初版即因此
	// 誤報 24% 劣化。交錯配對使序位效應對兩組等量作用，中位數再壓掉單輪抖動。
	runLoad(concurrency, perWorker) // 暖機，丟棄

	// 判準組的封章率：排程器每分鐘才檢查一次觸發條件，故生產環境最快就是
	// 每分鐘一次封章；本組取每秒一次＝生產上限的約 60 倍
	const pairs = 3
	var baseTP, denseTP []float64
	var baseP95, denseP95 []time.Duration
	var totalSeals int64
	for i := 0; i < pairs; i++ {
		b := runLoad(concurrency, perWorker)
		baseTP = append(baseTP, b.throughput)
		baseP95 = append(baseP95, b.p95)
		d, seals := withSealing(time.Second)
		denseTP = append(denseTP, d.throughput)
		denseP95 = append(denseP95, d.p95)
		totalSeals += seals
		t.Logf("[4.8] 第 %d 對：對照 %.0f 列/秒 p95 %v ／ 每秒封章（%d 次）%.0f 列/秒 p95 %v",
			i+1, b.throughput, b.p95.Round(time.Microsecond), seals,
			d.throughput, d.p95.Round(time.Microsecond))
	}
	if totalSeals < int64(pairs) {
		t.Fatalf("三對只封了 %d 次：封章未實際發生，本測退化為空跑（假綠）", totalSeals)
	}

	medF := func(v []float64) float64 {
		c := append([]float64(nil), v...)
		sort.Float64s(c)
		return c[len(c)/2]
	}
	medD := func(v []time.Duration) time.Duration {
		c := append([]time.Duration(nil), v...)
		sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
		return c[len(c)/2]
	}
	// 雜訊底：對照組自身的極差。判準若小於它，這個判準就不可分辨
	noise := (medF(baseTP) - minF(baseTP)) / medF(baseTP) * 100
	bTP, dTP := medF(baseTP), medF(denseTP)
	bP95, dP95 := medD(baseP95), medD(denseP95)
	tpDrop := (bTP - dTP) / bTP * 100
	p95Drop := (float64(dP95) - float64(bP95)) / float64(bP95) * 100
	t.Logf("[4.8] 中位數：對照 %.0f 列/秒 p95 %v ／ 封章 %.0f 列/秒 p95 %v",
		bTP, bP95.Round(time.Microsecond), dTP, dP95.Round(time.Microsecond))
	t.Logf("[4.8] 劣化：吞吐 %.1f%%、p95 %.1f%%（判準 >10%%；對照組自身雜訊底 %.1f%%）",
		tpDrop, p95Drop, noise)
	if tpDrop > 10 {
		t.Errorf("封章使寫入吞吐劣化 %.1f%%（>10%%）：封章已進入熱路徑", tpDrop)
	}
	if p95Drop > 10 {
		t.Errorf("封章使寫入 p95 劣化 %.1f%%（>10%%）：封章已進入熱路徑", p95Drop)
	}

	// ── 觀測組：忙迴圈封章（**不作為判準**）─────────────────────────────
	//
	// 排程器在結構上到不了這個速率（每分鐘一次檢查、單飛旗標），故它量的不是
	// 「封章是否進熱路徑」，而是「若有人把封章接進迴圈會付出多少」。
	// 不拿它當判準，但也不隱藏——它是未來任何「提高封章頻率」提案的成本上界。
	busy, busySeals := withSealing(0)
	t.Logf("[4.8] 觀測組（忙迴圈封章，期間封 %d 次；**非判準**）："+
		"吞吐 %.0f 列/秒（相對對照中位數 %+.1f%%）、p95 %v（相對 %+.1f%%）",
		busySeals, busy.throughput, (busy.throughput-bTP)/bTP*100,
		busy.p95.Round(time.Microsecond), (float64(busy.p95)-float64(bP95))/float64(bP95)*100)
}

func minF(v []float64) float64 {
	m := v[0]
	for _, x := range v {
		if x < m {
			m = x
		}
	}
	return m
}
