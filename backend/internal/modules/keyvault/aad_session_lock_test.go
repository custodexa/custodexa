package keyvault

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

// session 級 advisory lock 的三組必測（鎖分級）：
// 洩漏（panic 後仍可取得）／取消後可重取／session↔xact 互斥。
//
// 前兩組在 sqlite 分流亦有意義（kekProcessMu 的 defer 解鎖語義相同）；
// 第三組**必須**兩條不同的 postgres session 才驗得出——同一 session 對自有
// advisory lock 可重入，單 session 恆綠＝假綠。故沿 TEST_PG_DSN gating 前例。

// TestKeyOpSessionLockReleasedOnPanic 取鎖 → panic → 後續仍可取得。
// 一次 panic 就永久鎖死是 session 級鎖最典型的災難形態。
func TestKeyOpSessionLockReleasedOnPanic(t *testing.T) {
	db := newAADTestDB(t)

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("測試前提不成立：fn 應 panic")
			}
		}()
		_ = withKeyOpSessionLock(context.Background(), db, func() error {
			panic("boom")
		})
	}()

	ran := false
	if err := withKeyOpSessionLock(context.Background(), db, func() error { ran = true; return nil }); err != nil {
		t.Fatalf("panic 後 MUST 仍可取得 session 鎖，實得 %v", err)
	}
	if !ran {
		t.Fatal("後續取鎖未進入臨界區")
	}
}

// TestKeyOpSessionLockReleasedOnCancel fn 因 context 取消而中止時，鎖仍須釋放
// （解鎖走獨立的 bounded cleanup context，不繼承已取消的請求 context）。
func TestKeyOpSessionLockReleasedOnCancel(t *testing.T) {
	db := newAADTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := withKeyOpSessionLock(context.Background(), db, func() error { return ctx.Err() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("應原樣回傳 fn 的錯誤，實得 %v", err)
	}
	if err := withKeyOpSessionLock(context.Background(), db, func() error { return nil }); err != nil {
		t.Fatalf("取消後 MUST 可重取，實得 %v", err)
	}
}

// TestKeyOpSessionLockIsTryNotBlocking try 語義：持鎖期間他者立即 busy，不阻塞。
func TestKeyOpSessionLockIsTryNotBlocking(t *testing.T) {
	db := newAADTestDB(t)
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- withKeyOpSessionLock(context.Background(), db, func() error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held
	start := time.Now()
	if err := withKeyOpSessionLock(context.Background(), db, func() error { return nil }); !errors.Is(err, ErrKeyOpBusy) {
		close(release)
		t.Fatalf("持鎖期間應立即回 ErrKeyOpBusy，實得 %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		close(release)
		t.Fatalf("try 語義應立即返回，實耗 %v", elapsed)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("持鎖方應正常結束: %v", err)
	}
}

// TestKeyOpSessionLockUnknownDialectFailsClose 未知 dialect 一律拒絕：
// 靜默退化為行程內鎖會讓多實例部署失去跨實例互斥而無人察覺。
func TestKeyOpSessionLockUnknownDialectFailsClose(t *testing.T) {
	db := newAADTestDB(t)
	orig := db.Config.Dialector
	db.Config.Dialector = fakeDialector{Dialector: orig, name: "mysql"}
	defer func() { db.Config.Dialector = orig }()
	ran := false
	err := withKeyOpSessionLock(context.Background(), db, func() error { ran = true; return nil })
	if err == nil {
		t.Fatal("未知 dialect MUST fail-close")
	}
	if ran {
		t.Fatal("fail-close 時不得執行臨界區")
	}
	if !strings.Contains(err.Error(), "dialect") {
		t.Fatalf("錯誤訊息應指明 dialect 白名單拒絕: %v", err)
	}
}

// TestPGSessionLockVsXactLockMutex postgres 真路徑：session 級鎖與交易級鎖
// **同一把 key**，必須互斥。以兩條不同 session（兩個連線池）驗——
// 同一 session 對自有 advisory lock 可重入，單 session 測不出互斥。
func TestPGSessionLockVsXactLockMutex(t *testing.T) {
	dsn := setupPGLockSchema(t, pgLockTestDSN(t))
	dbA := openPGLockDB(t, dsn)
	dbB := openPGLockDB(t, dsn)
	if name := dbA.Dialector.Name(); name != "postgres" {
		t.Fatalf("本測試必須跑在 postgres 分流，實得 %q", name)
	}
	kmB := newTestKeyManager(t, dbB, 1)

	t.Run("session 鎖持有時 xact 鎖 busy", func(t *testing.T) {
		held := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- withKeyOpSessionLock(context.Background(), dbA, func() error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held
		err := kmB.withDataKeysLock(func(*gorm.DB) error { return nil })
		close(release)
		if !errors.Is(err, ErrKeyOpBusy) {
			t.Fatalf("session 鎖持有時，另一 session 的 xact 鎖 MUST busy，實得 %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("持鎖方應正常結束: %v", err)
		}
	})

	t.Run("xact 鎖持有時 session 鎖 busy", func(t *testing.T) {
		held := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- kmB.withDataKeysLock(func(*gorm.DB) error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held
		err := withKeyOpSessionLock(context.Background(), dbA, func() error { return nil })
		close(release)
		if !errors.Is(err, ErrKeyOpBusy) {
			t.Fatalf("xact 鎖持有時 session 鎖 MUST busy，實得 %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("持鎖方應正常結束: %v", err)
		}
	})

	t.Run("釋放後可重取且無殘留 advisory lock", func(t *testing.T) {
		if err := withKeyOpSessionLock(context.Background(), dbA, func() error { return nil }); err != nil {
			t.Fatalf("釋放後應可重取: %v", err)
		}
		if n := grantedDataKeysAdvisoryLocks(t, dbB); n != 0 {
			t.Fatalf("session 鎖結束後 pg_locks 不得殘留，實得 %d 筆", n)
		}
	})
}

// waitAdvisoryLocksDrained 等 pg_locks 上的目標 advisory lock 歸零。
//
// 為何要等：丟棄實體連線是 database/sql 在 Close 時做的事，postgres 端的 backend
// 終止與鎖釋放隨其後——直接斷言會偶發假紅。上限內未歸零才是真的洩漏。
func waitAdvisoryLocksDrained(t *testing.T, probe *gorm.DB, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := grantedDataKeysAdvisoryLocks(t, probe)
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s：pg_locks 仍殘留 %d 筆 advisory lock（永久鎖洩漏）", what, n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestPGSessionLockReleasedOnPanic postgres 真路徑：臨界區 panic 後
// **DB 端**不得殘留 advisory lock。
//
// sqlite 分流的同名測試只證明 kekProcessMu 的 defer 有效；session 級鎖的災難
// 形態在 postgres——鎖由一條釘選連線持有，一次 panic 若沒解鎖就是永久鎖死，
// 而那只有查 pg_locks 才看得見。
func TestPGSessionLockReleasedOnPanic(t *testing.T) {
	dsn := setupPGLockSchema(t, pgLockTestDSN(t))
	db := openPGLockDB(t, dsn)
	probe := openPGLockDB(t, dsn)

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("測試前提不成立：fn 應 panic")
			}
		}()
		_ = withKeyOpSessionLock(context.Background(), db, func() error {
			panic("boom")
		})
	}()

	waitAdvisoryLocksDrained(t, probe, "panic 後")
	if err := withKeyOpSessionLock(context.Background(), db, func() error { return nil }); err != nil {
		t.Fatalf("panic 後 MUST 仍可取得 session 鎖，實得 %v", err)
	}
	waitAdvisoryLocksDrained(t, probe, "重取並釋放後")
}

// TestPGSessionLockReleasedOnCancel postgres 真路徑：操作 context 取消後
// 鎖不得殘留、且可重取。兩個子案分別覆蓋「取鎖前就取消」與「臨界區內取消」。
func TestPGSessionLockReleasedOnCancel(t *testing.T) {
	dsn := setupPGLockSchema(t, pgLockTestDSN(t))
	db := openPGLockDB(t, dsn)
	probe := openPGLockDB(t, dsn)

	t.Run("取鎖前即取消：不得取得鎖", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ran := false
		err := withKeyOpSessionLock(ctx, db, func() error { ran = true; return nil })
		if err == nil {
			t.Fatal("已取消的操作 context MUST 使取鎖失敗（否則 ctx 根本沒被傳進去）")
		}
		if ran {
			t.Fatal("取鎖失敗時不得進入臨界區")
		}
		waitAdvisoryLocksDrained(t, probe, "取鎖前取消後")
	})

	t.Run("臨界區內取消：鎖仍釋放且可重取", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := withKeyOpSessionLock(context.Background(), db, func() error { return ctx.Err() })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("應原樣回傳 fn 的錯誤，實得 %v", err)
		}
		waitAdvisoryLocksDrained(t, probe, "臨界區取消後")
		if err := withKeyOpSessionLock(context.Background(), db, func() error { return nil }); err != nil {
			t.Fatalf("取消後 MUST 可重取，實得 %v", err)
		}
		waitAdvisoryLocksDrained(t, probe, "重取並釋放後")
	})
}

// TestPGSessionLockAcquireResponseFailureLeavesNoLock 本檔最危險的分支：
// **鎖已在 DB 端授予、取鎖回應卻在客戶端失敗**。
//
// 此時把連線歸池＝一條持鎖的連線回到池中＝永久鎖洩漏（且下一個借到它的人會
// 「莫名其妙地」持有鎖）。真 postgres 上無法用一般手段觸發，故以
// pgSessionLockAcquireSQL 覆寫出「多回一欄使 Scan 失敗」的變體——
// `pg_try_advisory_lock` 已在伺服端執行完畢、鎖確實被授予，錯誤純發生在回應解析。
func TestPGSessionLockAcquireResponseFailureLeavesNoLock(t *testing.T) {
	dsn := setupPGLockSchema(t, pgLockTestDSN(t))
	db := openPGLockDB(t, dsn)
	probe := openPGLockDB(t, dsn)

	orig := pgSessionLockAcquireSQL
	pgSessionLockAcquireSQL = "SELECT pg_try_advisory_lock($1), 1"
	defer func() { pgSessionLockAcquireSQL = orig }()

	ran := false
	err := withKeyOpSessionLock(context.Background(), db, func() error { ran = true; return nil })
	if err == nil {
		t.Fatal("測試前提不成立：取鎖回應應失敗")
	}
	if errors.Is(err, ErrKeyOpBusy) {
		t.Fatalf("回應失敗 SHALL NOT 折疊為 busy（兩者處置不同）: %v", err)
	}
	if ran {
		t.Fatal("取鎖失敗時不得進入臨界區")
	}

	// 核心斷言：鎖已被 DB 端授予，但持鎖連線被丟棄而非歸池，故鎖隨連線結束釋放
	waitAdvisoryLocksDrained(t, probe, "取鎖回應失敗後")

	// 且該連線確實沒回到池裡帶著鎖——還原 SQL 後可正常取得鎖
	pgSessionLockAcquireSQL = orig
	if err := withKeyOpSessionLock(context.Background(), db, func() error { return nil }); err != nil {
		t.Fatalf("回應失敗後 MUST 仍可正常取鎖，實得 %v", err)
	}
	waitAdvisoryLocksDrained(t, probe, "還原後取鎖並釋放")
}

// TestPGSessionLockNoLeakUnderConcurrency postgres：多輪併發取鎖後不得有連線
// 持著未釋放的 advisory lock（釘選連線＋同連線解鎖的直接證據）。
func TestPGSessionLockNoLeakUnderConcurrency(t *testing.T) {
	dsn := setupPGLockSchema(t, pgLockTestDSN(t))
	db := openPGLockDB(t, dsn)
	probe := openPGLockDB(t, dsn)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = withKeyOpSessionLock(context.Background(), db, func() error { return nil })
		}()
	}
	wg.Wait()
	if n := grantedDataKeysAdvisoryLocks(t, probe); n != 0 {
		t.Fatalf("併發取鎖後 pg_locks 殘留 %d 筆 advisory lock（疑似解鎖落在別條連線）", n)
	}
}

// TestKeyOpLockBusyBidirectional 兩級鎖共用同一把 key，故**雙向必測**：
// 只測單向會漏掉「session 鎖用了另一把 key」這種一測就綠、上線才發現的失真。
//
// 註：原以 enable／migrate 兩個 AAD 操作為載體，該兩操作已隨過渡機制拆除；
// 此處直接以兩支鎖原語為載體，
// 被驗證的互斥性質不變。
func TestKeyOpLockBusyBidirectional(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)

	t.Run("session 鎖持有時 xact 鎖 busy", func(t *testing.T) {
		held := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- withKeyOpSessionLock(context.Background(), db, func() error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held
		err := km.withDataKeysLock(func(*gorm.DB) error { return nil })
		close(release)
		if !errors.Is(err, ErrKeyOpBusy) {
			t.Fatalf("session 鎖持有時 xact 鎖 MUST 回 ErrKeyOpBusy，實得 %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("持鎖方應正常結束: %v", err)
		}
	})

	t.Run("xact 鎖持有時 session 鎖 busy", func(t *testing.T) {
		held := make(chan struct{})
		release := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- km.withDataKeysLock(func(*gorm.DB) error {
				close(held)
				<-release
				return nil
			})
		}()
		<-held
		err := withKeyOpSessionLock(context.Background(), db, func() error { return nil })
		close(release)
		if !errors.Is(err, ErrKeyOpBusy) {
			t.Fatalf("xact 鎖持有時 session 鎖 MUST 回 ErrKeyOpBusy，實得 %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("持鎖方應正常結束: %v", err)
		}
	})
}
