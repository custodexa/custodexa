package database

import (
	"context"
	"log"
	"time"
)

// watchdog 狀態機。
//
//	held ──驗證「未持有」或「未知」──▶ lost ──每週期重取，取得即──▶ held
//	overridden ──每週期重取，取得即──▶ held
//
// 紀律：DB 查詢在互斥鎖**外**跑，返回後重新檢查狀態——已是 stopping／released 則本輪
// 結果丟棄（不計失鎖、不重取、不發事件）。失鎖後**不改任何服務行為**：不進柵欄、
// 不關通道、不退出；告知面＝日誌、事件、指標、橫幅。
// panic 由 recover 兜底：只記 log、不改狀態、下一輪照跑（goroutine panic 會殺行程，
// 旁路功能不該有這個權力）。

const (
	instanceGuardPeerLogInterval      = 10 * time.Minute
	instanceGuardRetryableLogInterval = time.Minute
)

// startWatchdog 啟動背景驗證（sqlite 分支不啟動；重複呼叫為 no-op）。
func (g *InstanceGuard) startWatchdog() {
	g.mu.Lock()
	backend := g.backend
	if backend == nil || !backend.runsWatchdog() || g.wdCancel != nil {
		g.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	g.wdCancel = cancel
	g.mu.Unlock()

	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		ticker := time.NewTicker(g.opts.WatchPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.runCycle(ctx)
			}
		}
	}()
}

// CheckNow 同步跑完整一輪 watchdog（測試用；生產不呼叫）。
func (g *InstanceGuard) CheckNow(ctx context.Context) GuardState {
	if ctx == nil {
		ctx = context.Background()
	}
	g.runCycle(ctx)
	return g.State()
}

// runCycle 一輪：依狀態驗證或重取，並順帶對等計數。
func (g *InstanceGuard) runCycle(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[InstanceGuard] watchdog panic 已攔截（守衛狀態不變，下一輪照跑）: %v", r)
		}
	}()
	g.mu.Lock()
	state := g.state
	backend := g.backend
	g.mu.Unlock()
	if backend == nil {
		return
	}
	switch state {
	case GuardStateHeld:
		g.verifyHeld(ctx, backend)
	case GuardStateLost, GuardStateOverridden:
		g.retake(ctx, backend, state)
	default:
		return
	}
	g.countPeers(ctx, backend)
}

// stoppingOrReleased 關閉序已開始（此後任何 watchdog 結果一律丟棄）。
func (g *InstanceGuard) stoppingOrReleased() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.state == GuardStateStopping || g.state == GuardStateReleased
}

// verifyHeld held 態：查 pg_locks 三分——持有／未持有／未知；後兩者轉 lost。
func (g *InstanceGuard) verifyHeld(ctx context.Context, backend lockBackend) {
	qctx, cancel := g.queryCtx(ctx)
	held, err := backend.isHeld(qctx)
	cancel()
	if g.stoppingOrReleased() {
		return
	}
	if err == nil && held {
		return
	}

	reason := GuardReasonUnknown
	if err != nil {
		reason = classifyGuardError(err).reason()
	}
	// 丟棄舊連線、重釘一條；重釘成功時查持鎖者以判定是否為競爭
	rctx, rcancel := g.queryCtx(ctx)
	rerr := backend.reconnect(rctx)
	rcancel()
	if g.stoppingOrReleased() {
		return
	}
	var holder *HolderFingerprint
	if rerr == nil {
		fctx, fcancel := g.queryCtx(ctx)
		fp, found := backend.holderFingerprint(fctx)
		fcancel()
		if found {
			reason = GuardReasonContention
			holder = &fp
		}
	} else if err == nil {
		reason = classifyGuardError(rerr).reason()
	}

	now := time.Now().UTC()
	g.mu.Lock()
	if g.state != GuardStateHeld {
		g.mu.Unlock()
		return
	}
	g.state = GuardStateLost
	g.since = now
	g.unheldSince = now
	g.reason = reason
	g.holder = holder
	g.lostTotal++
	total := g.lostTotal
	ev := g.eventLocked(GuardEventLost, reason, now)
	g.mu.Unlock()

	detail := ""
	if err != nil {
		detail = " err=" + err.Error()
	}
	if rerr != nil {
		detail += " reconnect_err=" + rerr.Error()
	}
	if holder != nil {
		detail += " holder=[" + holder.readable() + "]"
	}
	log.Printf("[InstanceGuard] CRITICAL：單實例鎖已失守（reason=%s lost_total=%d）；本實例繼續服務、每週期重取，不阻擋任何操作%s",
		reason, total, detail)
	g.emit(ev)
}

// retake lost／overridden 態：每週期 pg_try_advisory_lock 重取，無上限、不退出。
func (g *InstanceGuard) retake(ctx context.Context, backend lockBackend, state GuardState) {
	if !backend.connected() {
		rctx, rcancel := g.queryCtx(ctx)
		err := backend.reconnect(rctx)
		rcancel()
		if g.stoppingOrReleased() {
			return
		}
		if err != nil {
			g.noteRetakeError(err, state)
			return
		}
	}
	qctx, cancel := g.queryCtx(ctx)
	got, err := backend.tryLock(qctx)
	cancel()
	if g.stoppingOrReleased() {
		return
	}
	if err != nil {
		g.noteRetakeError(err, state)
		return
	}
	if got {
		g.enterHeldAfterRetake(state)
		return
	}

	// 競爭：他人持鎖，刷新持鎖者指紋供橫幅與事件使用
	fctx, fcancel := g.queryCtx(ctx)
	fp, found := backend.holderFingerprint(fctx)
	fcancel()
	if g.stoppingOrReleased() {
		return
	}
	g.mu.Lock()
	if g.state != state {
		g.mu.Unlock()
		return
	}
	if found {
		h := fp
		g.holder = &h
	}
	if state == GuardStateLost {
		g.reason = GuardReasonContention
	}
	logNow := state == GuardStateLost || g.lastOverriddenLog.IsZero() ||
		time.Since(g.lastOverriddenLog) >= instanceGuardPeerLogInterval
	if logNow {
		g.lastOverriddenLog = time.Now()
	}
	g.mu.Unlock()
	if !logNow {
		return
	}
	if state == GuardStateLost {
		log.Printf("[InstanceGuard] CRITICAL：重取單實例鎖失敗（reason=contention）：鎖由另一個工作階段持有 [%s]；本實例繼續服務、下一週期再試", fp.readable())
		return
	}
	log.Printf("[InstanceGuard] 以 INSTANCE_GUARD_ACK 啟動的實例仍未取得單實例鎖：鎖由 [%s] 持有；每週期重取中", fp.readable())
}

// noteRetakeError 重取錯誤的告知：可重試類節流；永久／未知類每週期 CRITICAL。
func (g *InstanceGuard) noteRetakeError(err error, state GuardState) {
	class := classifyGuardError(err)
	reason := class.reason()
	g.mu.Lock()
	if g.state != state {
		g.mu.Unlock()
		return
	}
	if state == GuardStateLost {
		g.reason = reason
	}
	throttled := false
	if class == guardErrRetryable {
		if !g.lastRetryableLog.IsZero() && time.Since(g.lastRetryableLog) < instanceGuardRetryableLogInterval {
			throttled = true
		} else {
			g.lastRetryableLog = time.Now()
		}
	}
	g.mu.Unlock()
	if throttled {
		return
	}
	if class == guardErrRetryable {
		log.Printf("[InstanceGuard] 重取單實例鎖失敗（reason=%s，可重試；本行每分鐘至多一次）: %v", reason, err)
		return
	}
	log.Printf("[InstanceGuard] CRITICAL：守衛無法驗證或重取單實例鎖（reason=%s）；本實例繼續服務、下一週期再試: %v", reason, err)
}

// enterHeldAfterRetake 重取成功：回到 held、發 regained（含未持鎖時長與先前的 reason）。
func (g *InstanceGuard) enterHeldAfterRetake(prev GuardState) {
	now := time.Now().UTC()
	g.mu.Lock()
	if g.state != prev {
		g.mu.Unlock()
		return
	}
	prevReason := g.reason
	g.state = GuardStateHeld
	g.since = now
	g.reason = GuardReasonNone
	g.holder = nil
	g.lastRetryableLog = time.Time{}
	g.lastOverriddenLog = time.Time{}
	ev := g.eventLocked(GuardEventRegained, prevReason, now)
	g.unheldSince = time.Time{}
	g.mu.Unlock()
	log.Printf("[InstanceGuard] 已重新取得單實例鎖（自 %s 起未持鎖 %d ms，reason=%s）；告知解除", prev, ev.UnheldForMS, prevReason)
	g.emit(ev)
}

// countPeers 對等偵測：同庫其他守衛版實例的連線數；不寫事件、不改狀態。
func (g *InstanceGuard) countPeers(ctx context.Context, backend lockBackend) {
	if !backend.connected() {
		return
	}
	qctx, cancel := g.queryCtx(ctx)
	n, err := backend.countPeers(qctx)
	cancel()
	if g.stoppingOrReleased() || err != nil {
		// 查詢失敗時維持上一次的值：不以 0 假稱「無對等」
		return
	}
	g.mu.Lock()
	g.peers = n
	logNow := false
	if n > 0 {
		if !g.peerLogged || time.Since(g.lastPeerLog) >= instanceGuardPeerLogInterval {
			g.peerLogged = true
			g.lastPeerLog = time.Now()
			logNow = true
		}
	} else {
		g.peerLogged = false
	}
	g.mu.Unlock()
	if logNow {
		log.Printf("[InstanceGuard] 偵測到 %d 個其他守衛版實例連線至同一資料庫（application_name=%s；本行每 10 分鐘至多一次）", n, g.opts.ApplicationName)
	}
}
