package sealjournal

import (
	"context"
	"sync"
	"time"
)

// Ticket 為一次 admission 資格。取得後呼叫端才可寫 received 並驗證材料。
// 用畢 SHALL 呼叫 Release；Release 為冪等。
type Ticket struct {
	j    *Journal
	once sync.Once
}

// Admit 取得 admission 資格。
//
// 正面契約（D6.5 誠實邊界 1）：
//   - 範圍＝單一全域最小間隔，不做 per-source（保護的是全域 fsync 與材料驗證成本）。
//   - 時鐘＝單調時鐘（time.Since），SHALL NOT 使用牆鐘，否則校時可繞過或無限延長。
//   - 基準僅於「CAS 勝出且 received 成功落地」之後更新（見 Release），
//     SHALL NOT 於請求抵達時更新——否則被拒請求也會推遲下一次，
//     可耗盡配額的語義即被偷渡回來。
//   - 範圍＝行程內全執行緒共享，不跨實例；不持久化，重啟即重置。
//
// 可測上界：對「已具受理資格且僅等待當前 received 寫入完成」的請求，
// 阻塞 ≤（最小間隔 ＋ received 寫入逾時）。
// 此上界 SHALL NOT 被表述為「任何正當請求的最壞阻塞」。
//
// 間隔不是可耗盡的配額：無扣減、無重置、無視窗語義。
func (j *Journal) Admit(ctx context.Context) (*Ticket, error) {
	// 序列化：同一時刻至多一個 received 寫入在途，故等待時間由寫入逾時界定。
	select {
	case j.admitToken <- struct{}{}:
	case <-j.closedCh:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// 已關閉時 token 仍可取得（緩衝通道），故取得後必須再判一次，
	// 否則 select 的隨機選擇會讓關閉後的請求偶爾被受理。
	select {
	case <-j.closedCh:
		<-j.admitToken
		return nil, ErrClosed
	default:
	}
	// 運行期 I/O 故障 → 拒收新嘗試（fail-close）；修復後自動恢復。
	if j.Faulted() {
		<-j.admitToken
		return nil, ErrIOFaulted
	}
	for {
		wait := j.remainingInterval()
		if wait <= 0 {
			return &Ticket{j: j}, nil
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			<-j.admitToken
			return nil, ctx.Err()
		case <-j.closedCh:
			timer.Stop()
			<-j.admitToken
			return nil, ErrClosed
		}
	}
}

// remainingInterval 以單調時鐘計算距下次可受理還剩多久。
func (j *Journal) remainingInterval() time.Duration {
	j.admitMu.Lock()
	defer j.admitMu.Unlock()
	if !j.hasBase || j.opt.MinAdmissionInterval <= 0 {
		return 0
	}
	// time.Since 使用單調時鐘讀數，不受牆鐘校時影響。
	elapsed := time.Since(j.baseline)
	if elapsed >= j.opt.MinAdmissionInterval {
		return 0
	}
	return j.opt.MinAdmissionInterval - elapsed
}

// Release 釋放資格。receivedLanded 為真（且僅在此時）才推進間隔基準——
// 對應「該次資源實際被消耗的那一刻」。
// 被拒的嘗試不經此路徑，故基準不會因被拒嘗試而後移。
func (t *Ticket) Release(receivedLanded bool) {
	if t == nil {
		return
	}
	t.once.Do(func() {
		if receivedLanded {
			t.j.admitMu.Lock()
			// time.Now() 的回傳值帶單調時鐘讀數，供 time.Since 使用。
			t.j.baseline = time.Now()
			t.j.hasBase = true
			t.j.admitMu.Unlock()
		}
		<-t.j.admitToken
	})
}
