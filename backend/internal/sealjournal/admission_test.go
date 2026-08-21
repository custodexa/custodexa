package sealjournal

import (
	"context"
	"testing"
	"time"
)

// TestAdmissionBaselineOnlyUpdatesAfterReceivedLanded 驗收：
// 基準僅於「CAS 勝出且 received 落地」後更新；未落地者不推遲下一次。
func TestAdmissionBaselineOnlyUpdatesAfterReceivedLanded(t *testing.T) {
	dir := t.TempDir()
	j := openTestJournal(t, dir, WithMinAdmissionInterval(200*time.Millisecond))
	ctx := context.Background()

	// 取得資格但 received 未落地（例如寫入失敗或請求取消）。
	tk, err := j.Admit(ctx)
	if err != nil {
		t.Fatalf("Admit 失敗: %v", err)
	}
	tk.Release(false)

	start := time.Now()
	tk2, err := j.Admit(ctx)
	if err != nil {
		t.Fatalf("Admit 失敗: %v", err)
	}
	tk2.Release(false)
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Fatalf("received 未落地不得推遲下一次受理，卻等了 %v", elapsed)
	}
}

// TestAdmissionBaselineNotDeferredByRejectedAttempts 驗收：
// 間隔基準不因被拒嘗試而後移——正當管理員於原間隔屆滿即可受理。
// 這是「間隔不是可耗盡配額」的唯一可測形式。
func TestAdmissionBaselineNotDeferredByRejectedAttempts(t *testing.T) {
	const interval = 150 * time.Millisecond
	dir := t.TempDir()
	j := openTestJournal(t, dir, WithMinAdmissionInterval(interval))
	ctx := context.Background()

	tk, err := j.Admit(ctx)
	if err != nil {
		t.Fatalf("Admit 失敗: %v", err)
	}
	if _, err := j.WriteReceived(ctx, 1, testDigest); err != nil {
		t.Fatalf("WriteReceived 失敗: %v", err)
	}
	tk.Release(true)
	baseline := time.Now()

	// 洪水期：持續有被拒嘗試（cooldown／backoff／conflict）。
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				j.RecordRejected(RejectedCooldown)
				j.RecordRejected(RejectedConflict)
				time.Sleep(time.Millisecond)
			}
		}
	}()
	defer close(stop)

	tk2, err := j.Admit(ctx)
	if err != nil {
		t.Fatalf("Admit 失敗: %v", err)
	}
	tk2.Release(false)
	elapsed := time.Since(baseline)

	if elapsed < interval-20*time.Millisecond {
		t.Fatalf("最小間隔未生效：只等了 %v（間隔 %v）", elapsed, interval)
	}
	if elapsed > interval+80*time.Millisecond {
		t.Fatalf("被拒嘗試把基準往後推了：等了 %v（間隔 %v）＝配額語義回流", elapsed, interval)
	}

	st := mustStatus(t, j)
	if st.RejectedObservedTotal == 0 {
		t.Fatal("測試前提：期間應確實有被拒嘗試")
	}
}

// TestAdmissionBoundForEligibleWaiter 驗收：
// 已具受理資格且僅等待當前 received 寫入完成的請求，
// 其阻塞 ≤（最小間隔 ＋ received 寫入逾時）。
// 此上界僅適用於該限縮範圍，不得表述為「任何正當請求的最壞阻塞」。
func TestAdmissionBoundForEligibleWaiter(t *testing.T) {
	const (
		interval     = 100 * time.Millisecond
		writeTimeout = 1500 * time.Millisecond
	)
	dir := t.TempDir()
	j, probe := openProbedJournal(t, dir,
		WithMinAdmissionInterval(interval),
		WithWriteTimeout(writeTimeout))
	ctx := context.Background()

	// 先落地一次，建立基準。
	tk, err := j.Admit(ctx)
	if err != nil {
		t.Fatalf("Admit 失敗: %v", err)
	}
	if _, err := j.WriteReceived(ctx, 1, testDigest); err != nil {
		t.Fatalf("WriteReceived 失敗: %v", err)
	}
	tk.Release(true)

	// 等到間隔屆滿：此後的請求「已具受理資格」。
	time.Sleep(interval + 20*time.Millisecond)

	// 另一個請求佔住當前 received 寫入（人為放慢每次 fdatasync）。
	probe.setSyncDelay(70 * time.Millisecond)
	holderDone := make(chan struct{})
	go func() {
		defer close(holderDone)
		ht, err := j.Admit(ctx)
		if err != nil {
			return
		}
		_, err = j.WriteReceived(ctx, 2, testDigest)
		ht.Release(err == nil)
	}()
	time.Sleep(20 * time.Millisecond) // 確保 holder 已持有在途寫入

	waiterStart := time.Now()
	wt, err := j.Admit(ctx)
	blocked := time.Since(waiterStart)
	if err != nil {
		t.Fatalf("Admit 失敗: %v", err)
	}
	wt.Release(false)
	<-holderDone
	probe.setSyncDelay(0)

	if upper := interval + writeTimeout; blocked > upper {
		t.Fatalf("阻塞 %v 超過上界（間隔 %v ＋ 寫入逾時 %v = %v）", blocked, interval, writeTimeout, upper)
	}
	if blocked < interval {
		t.Fatalf("holder 落地後基準應重新起算，阻塞 %v 短於間隔 %v", blocked, interval)
	}
}

// TestAdmissionIsGlobalAndProcessWide 驗收：單一全域間隔（非 per-source），
// 行程內全執行緒共享。
func TestAdmissionIsGlobalAndProcessWide(t *testing.T) {
	const interval = 120 * time.Millisecond
	dir := t.TempDir()
	j := openTestJournal(t, dir, WithMinAdmissionInterval(interval))
	ctx := context.Background()

	tk, err := j.Admit(ctx)
	if err != nil {
		t.Fatalf("Admit 失敗: %v", err)
	}
	if _, err := j.WriteReceived(ctx, 1, testDigest); err != nil {
		t.Fatalf("WriteReceived 失敗: %v", err)
	}
	tk.Release(true)
	baseline := time.Now()

	// 另一個 goroutine（模擬另一個來源）不得享有獨立額度。
	done := make(chan time.Duration, 1)
	go func() {
		t2, err := j.Admit(ctx)
		if err != nil {
			done <- 0
			return
		}
		t2.Release(false)
		done <- time.Since(baseline)
	}()
	elapsed := <-done
	if elapsed < interval-20*time.Millisecond {
		t.Fatalf("其他來源亦須受同一全域間隔約束，卻只等了 %v", elapsed)
	}
}

// TestAdmissionRejectsWhenClosed 驗收：關閉後不再受理。
func TestAdmissionRejectsWhenClosed(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir, testOptions()...)
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("Close 失敗: %v", err)
	}
	if _, err := j.Admit(context.Background()); err == nil {
		t.Fatal("關閉後 Admit 應回錯")
	}
}
