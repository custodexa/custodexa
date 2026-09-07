package database

import (
	"context"
	"errors"
	"log"
	"time"

	"gorm.io/gorm"
)

// 攔下模式（halted）。
//
// 取鎖失敗且無相符確認時，本實例**不退出行程**：保留釘選連線、狀態轉 halted、
// 依 watchdog 週期重取，並由組裝根開放守衛攔下頁所需的最小監聽。
// 離開 halted 的兩條路徑：
//
//	(a) watchdog 取得鎖 → held，繼續啟動，**不寫 overridden 事件**；
//	(b) 攔下頁送出的確認與**當下**持鎖者的碼相符 → overridden，繼續啟動並留痕。
//
// 攔下模式下 SHALL NOT 執行 migration、SHALL NOT 產生任何資料庫寫入；
// 頁面確認所需的唯一資料庫存取是持鎖者指紋查詢與管理員憑證讀取（皆唯讀）。

// HaltConfirmOutcome 是攔下頁確認送出的判定結果。
//
// 具名列舉而非 error 值：呼叫端（api 層 handler）要據此決定 HTTP 狀態與機器碼，
// 以錯誤字串分類會把對外契約綁在訊息文字上。
type HaltConfirmOutcome string

const (
	// HaltConfirmAccepted 三要件相符：已轉 overridden（或直接取得鎖），可繼續啟動。
	HaltConfirmAccepted HaltConfirmOutcome = "accepted"
	// HaltConfirmHolderChanged 重打的碼不等於當下持鎖者的碼（含持鎖者已變更）。
	HaltConfirmHolderChanged HaltConfirmOutcome = "holder_changed"
	// HaltConfirmNotHalted 本實例已不在攔下模式（鎖已取得或行程正在收束）。
	HaltConfirmNotHalted HaltConfirmOutcome = "not_halted"
	// HaltConfirmUnavailable 仍在攔下模式，但釘選連線建不起來，這一刻判定不了。
	//
	// **與 not_halted 嚴格區分**：後者是「不必再確認了」，前者是「現在還不知道」。
	// 兩者合併會讓資料庫暫時不可達被讀成「已經啟動了」，操作者於是不再重試——
	// 而那正是先前把連線重建失敗當成永久拒絕的形態。
	HaltConfirmUnavailable HaltConfirmOutcome = "unavailable"
)

// HaltConfirmResult 確認送出的結果；Holder 恆為**送出當下重查**的持鎖者指紋。
type HaltConfirmResult struct {
	Outcome HaltConfirmOutcome
	Holder  *HolderFingerprint
}

// AcquireOrHalt 取鎖，取不到且無相符確認時進入攔下模式（而非回攔下錯誤）。
//
// 回傳 (halted=false, nil) 代表可以直接繼續啟動（held 或 overridden）；
// 回傳 (halted=true, blockedErr) 代表已停在攔下模式：**釘選連線與 watchdog 皆保留**，
// blockedErr 為既有的攔下訊息（單一事實源在 blockedMessage，此處不加工），
// 呼叫端應印出它並開放攔下頁，然後在 Resume() 上等待。
func (g *InstanceGuard) AcquireOrHalt(ctx context.Context) (bool, error) {
	err := g.Acquire(ctx)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, ErrInstanceGuardBlocked) {
		// 取鎖回應失敗／dialect 不支援／啟動被取消：這些不是「有人持鎖」，
		// 攔下頁對它們無能為力（頁面能做的只有「確認另一實例已停」），故維持既有 fail-close。
		return false, err
	}
	g.enterHalted(ctx)
	return true, err
}

// enterHalted 攔下模式的進入點：重建釘選連線（Acquire 的攔下分支已關閉它）、
// 狀態轉 halted、啟動 watchdog 每週期重取。
//
// **重建連線是必要的**：Acquire 在判定攔下時已 close 釘選連線（該路徑原本要退出行程），
// 而攔下模式需要它來重取鎖與重查持鎖者。重建失敗**不是終局**：仍進攔下、仍啟動
// watchdog，由它每週期重試重建（ensureBackend），否則資料庫恢復後行程會永遠卡在
// 攔下模式——那與「攔下模式不需要重啟」這個賣點直接相反。
func (g *InstanceGuard) enterHalted(ctx context.Context) {
	now := time.Now().UTC()

	backend, err := g.newBackend(ctx)
	if err != nil {
		log.Printf("[InstanceGuard] 攔下模式無法重建釘選連線（攔下頁的持鎖者資訊暫時不可得，仍不退出行程；"+
			"watchdog 會每週期重試重建，資料庫恢復後不需重啟）: %v", err)
	}

	g.mu.Lock()
	if backend != nil {
		g.backend = backend
	}
	g.state = GuardStateHalted
	g.since = now
	g.unheldSince = now
	g.reason = GuardReasonContention
	g.mu.Unlock()

	if backend != nil {
		fctx, fcancel := g.queryCtx(ctx)
		fp, found := backend.holderFingerprint(fctx)
		fcancel()
		if found {
			h := fp
			g.mu.Lock()
			g.holder = &h
			g.mu.Unlock()
		}
	}
	g.startWatchdog()
}

// instanceGuardMaxRebuildSkips 釘選連線重建的退避上限（單位＝watchdog 週期）。
//
// 有界：退避只用來壓住「資料庫還沒回來」時的重建噪音，不是放棄。上限取 6 個週期
// 後即維持每 6 週期一試——**退避不得無限增長**，否則長時間離線之後的恢復會被
// 一個誰也沒在看的指數退避拖住，那與永久攔下的差別只剩「理論上會好」。
const instanceGuardMaxRebuildSkips = 6

// ensureBackend 取得可用的鎖後端；backend 為 nil 時嘗試重建。
//
// **它補的是一個永久攔下的缺陷**：enterHalted 的重建失敗只印一行日誌就把 backend
// 留成 nil，而 watchdog 見 nil 即整輪返回、ConfirmHalt 見 nil 即直接拒絕——資料庫
// 恢復之後沒有任何路徑會再試一次，行程就此卡死在攔下模式，只能靠外部重啟。
// 攔下模式存在的理由本來就是「不要求重啟」，那個缺陷等於把它的價值抵銷掉。
//
// respectBackoff 為真（watchdog 週期）時遵守有界退避；為假（頁面確認送出）時
// 立即試一次——操作者按下按鈕的那一刻不該因為背景退避還沒到期而被拒絕。
// 重建失敗回 nil，由呼叫端決定告知形式。
func (g *InstanceGuard) ensureBackend(ctx context.Context, respectBackoff bool) lockBackend {
	if ctx == nil {
		ctx = context.Background()
	}
	g.mu.Lock()
	if g.backend != nil {
		b := g.backend
		g.mu.Unlock()
		return b
	}
	if g.state == GuardStateStopping || g.state == GuardStateReleased {
		g.mu.Unlock()
		return nil
	}
	if respectBackoff && g.rebuildSkips > 0 {
		g.rebuildSkips--
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()

	backend, err := g.newBackend(ctx)
	if err != nil || backend == nil {
		g.mu.Lock()
		g.rebuildFails++
		skips := g.rebuildFails
		if skips > instanceGuardMaxRebuildSkips {
			skips = instanceGuardMaxRebuildSkips
		}
		g.rebuildSkips = skips
		fails := g.rebuildFails
		g.mu.Unlock()
		log.Printf("[InstanceGuard] 攔下模式：釘選連線重建失敗（連續第 %d 次，下次於 %d 個週期後再試；仍不退出行程）: %v",
			fails, skips, err)
		return nil
	}

	g.mu.Lock()
	if g.state == GuardStateStopping || g.state == GuardStateReleased {
		g.mu.Unlock()
		backend.close(context.Background(), false)
		return nil
	}
	if g.backend != nil {
		// 另一條路徑（頁面確認與 watchdog 可能同時發生）已經重建好了：
		// 用既有的那條，把自己這條關掉，不讓兩條釘選連線同時存在。
		existing := g.backend
		g.mu.Unlock()
		backend.close(context.Background(), false)
		return existing
	}
	g.backend = backend
	g.rebuildFails = 0
	g.rebuildSkips = 0
	g.mu.Unlock()
	log.Println("[InstanceGuard] 攔下模式：釘選連線已重建，恢復每週期重取單實例鎖")
	return backend
}

// Resume 於本實例離開攔下模式時關閉。
//
// 組裝根在開放攔下頁之後阻塞於此；關閉即代表「可以繼續段 1 其餘步驟與段 2」。
// 兩條路徑（watchdog 取得鎖、頁面確認相符）共用同一個訊號，呼叫端不必分辨是哪一條。
func (g *InstanceGuard) Resume() <-chan struct{} { return g.resume }

// signalResume 關閉 resume（冪等）。
func (g *InstanceGuard) signalResume() { g.resumeOnce.Do(func() { close(g.resume) }) }

// Halted 是否停在攔下模式。
func (g *InstanceGuard) Halted() bool { return g.State() == GuardStateHalted }

// RetryInterval watchdog 的重取週期（攔下頁用於告知「多久自動重試一次」）。
func (g *InstanceGuard) RetryInterval() time.Duration { return g.opts.WatchPeriod }

// NoteHaltCredentialFailure 記一次攔下頁的憑證失敗。
//
// 攔下模式寫不了審計列（段 2 未起）且不得產生任何資料庫寫入，故失敗只累計於記憶體，
// 並於成功後隨 overridden 事件的 details 出門（PageFailedAttempts）。
func (g *InstanceGuard) NoteHaltCredentialFailure() {
	g.mu.Lock()
	g.pageFailed++
	n := g.pageFailed
	g.mu.Unlock()
	log.Printf("[InstanceGuard] 攔下頁確認：管理員憑證驗證失敗（本攔下期累計 %d 次；未寫入任何資料列）", n)
}

// ConfirmHalt 處理攔下頁送出的確認碼。
//
// 語義刻意與環境變數路徑相同：**與送出當下重查的持鎖者比對**，不與頁面先前顯示的
// 指紋比對——持鎖者在操作者填表期間換人時，舊碼必須失效（Terraform force-unlock 形態）。
//
// actor 為已通過驗證的管理員帳號；呼叫端 SHALL 於憑證驗證通過後才呼叫本方法。
// 本方法不做憑證驗證——那是 identity 的語義，且 database 不得反向依賴 identity。
func (g *InstanceGuard) ConfirmHalt(ctx context.Context, code, actor string) HaltConfirmResult {
	if ctx == nil {
		ctx = context.Background()
	}
	g.mu.Lock()
	if g.state != GuardStateHalted {
		g.mu.Unlock()
		return HaltConfirmResult{Outcome: HaltConfirmNotHalted}
	}
	backend := g.backend
	g.mu.Unlock()
	if backend == nil {
		// 釘選連線在進入攔下時建不起來（或事後掉了）：先當場重試一次再判定，
		// 不遵守背景退避——操作者按下按鈕的那一刻本身就是重試的理由。
		if backend = g.ensureBackend(ctx, false); backend == nil {
			log.Println("[InstanceGuard] 攔下頁確認：釘選連線仍建不起來，本次判定不了（請稍後重試或改用環境變數路徑）")
			return HaltConfirmResult{Outcome: HaltConfirmUnavailable}
		}
	}

	// 先試取鎖：確認期間鎖可能已被釋放。取得即照 (a) 路徑繼續，不寫 overridden。
	lctx, lcancel := g.queryCtx(ctx)
	got, err := backend.tryLock(lctx)
	lcancel()
	if err == nil && got {
		g.enterHeldFromHalted()
		return HaltConfirmResult{Outcome: HaltConfirmAccepted}
	}

	fctx, fcancel := g.queryCtx(ctx)
	fp, _ := backend.holderFingerprint(fctx)
	fcancel()

	if evaluateAck(code, fp.Code, true) != ackMatch {
		holder := fp
		return HaltConfirmResult{Outcome: HaltConfirmHolderChanged, Holder: &holder}
	}

	now := time.Now().UTC()
	holder := fp
	g.mu.Lock()
	if g.state != GuardStateHalted {
		g.mu.Unlock()
		return HaltConfirmResult{Outcome: HaltConfirmNotHalted}
	}
	g.state = GuardStateOverridden
	g.since = now
	g.unheldSince = now
	g.reason = GuardReasonAckPage
	g.holder = &holder
	g.actor = actor
	g.actorSource = GuardActorSourcePage
	ev := g.eventLocked(GuardEventOverridden, GuardReasonAckPage, now)
	g.mu.Unlock()

	log.Printf("[InstanceGuard] CRITICAL：以守衛攔下頁的確認啟動：單實例鎖仍由 %s 持有；"+
		"本實例將照常執行 migration 與服務；此確認已記錄（actor=%s actor_source=%s）",
		fp.readable(), actor, GuardActorSourcePage)
	g.emit(ev)
	g.signalResume()
	return HaltConfirmResult{Outcome: HaltConfirmAccepted, Holder: &holder}
}

// enterHeldFromHalted 攔下期間取得鎖：轉 held、放行啟動、**不寫任何事件**
// （本實例從未持鎖，regained 在此無意義；overridden 未發生）。
func (g *InstanceGuard) enterHeldFromHalted() {
	now := time.Now().UTC()
	g.mu.Lock()
	if g.state != GuardStateHalted {
		g.mu.Unlock()
		return
	}
	g.state = GuardStateHeld
	g.since = now
	g.reason = GuardReasonNone
	g.holder = nil
	g.unheldSince = time.Time{}
	g.mu.Unlock()
	log.Println("[InstanceGuard] 攔下期間已取得單實例鎖：不需重啟，繼續啟動（未寫入 overridden 事件）")
	g.signalResume()
}

// ── 包級單例包裝 ──────────────────────────────────────────────────────────

// AcquireInstanceLockOrHalt 段 1 的生產入口（攔下模式版）。
//
// 與 AcquireInstanceLock 的差別只在攔下時不放棄：守衛**無論攔下與否都登記為包級單例**
// ——攔下頁的狀態查詢與確認送出都經包級單例讀取，不登記就沒有頁面可用。
//
// 收 InstanceGuardOptions 而非只收 ack：組裝根填 Ack 即得生產預設，
// 組裝根的測試另填重試參數（該型別的既有定調就是「只有測試與組裝根會填」）。
func AcquireInstanceLockOrHalt(ctx context.Context, db *gorm.DB, opts InstanceGuardOptions) (bool, error) {
	g := NewInstanceGuard(db, opts)
	halted, err := g.AcquireOrHalt(ctx)
	if err != nil && !halted {
		return false, err
	}
	instanceGuard.Store(g)
	return halted, err
}

// InstanceGuardResume 包級單例的攔下解除訊號；守衛未建立時回一個永不關閉的 channel。
func InstanceGuardResume() <-chan struct{} {
	if g := instanceGuard.Load(); g != nil {
		return g.Resume()
	}
	return make(chan struct{})
}

// InstanceGuardHalted 包級單例是否停在攔下模式。
func InstanceGuardHalted() bool {
	g := instanceGuard.Load()
	return g != nil && g.Halted()
}

// InstanceGuardRetryInterval 包級單例的重取週期；未建立時回生產預設。
func InstanceGuardRetryInterval() time.Duration {
	if g := instanceGuard.Load(); g != nil {
		return g.RetryInterval()
	}
	return instanceGuardDefaultWatchPeriod
}

// ConfirmInstanceGuardHalt 包級單例的攔下確認入口。
func ConfirmInstanceGuardHalt(ctx context.Context, code, actor string) HaltConfirmResult {
	g := instanceGuard.Load()
	if g == nil {
		return HaltConfirmResult{Outcome: HaltConfirmNotHalted}
	}
	return g.ConfirmHalt(ctx, code, actor)
}

// NoteInstanceGuardHaltCredentialFailure 包級單例的憑證失敗計數入口。
func NoteInstanceGuardHaltCredentialFailure() {
	if g := instanceGuard.Load(); g != nil {
		g.NoteHaltCredentialFailure()
	}
}
