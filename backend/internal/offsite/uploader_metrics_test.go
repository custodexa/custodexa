package offsite

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// 上傳 worker 直寫指標（「worker 直寫」那一組）的行為層驗收。
//
// # 為什麼要在 worker 這一層驗，而不是只驗 observability
//
// `internal/observability` 那一組測試證明的是「序列註冊了就曝光、沒註冊就缺席」；
// 它證不出「上傳成功的那一刻真的有人去記一筆」。兩者之間正是最容易斷掉的一節——
// 掛勾寫在錯的分支（例如寫在 `MarkUploaded` 之前）會讓累計數大於帳冊裡的
// uploaded 列數，而那種偏差沒有任何測試看得見。

// recordingUploadMetrics 記錄 worker 交出來的每一筆觀測。
type recordingUploadMetrics struct {
	mu       sync.Mutex
	uploads  []string // "kind/result"
	bytes    map[string]int64
	leases   []string
	lastSucc time.Time
}

func newRecordingUploadMetrics() *recordingUploadMetrics {
	return &recordingUploadMetrics{bytes: map[string]int64{}}
}

func (r *recordingUploadMetrics) ObserveOffsiteUpload(kind, result string, n int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.uploads = append(r.uploads, kind+"/"+result)
	if result == UploadResultUploaded {
		r.bytes[kind] += n
	}
}

func (r *recordingUploadMetrics) ObserveOffsiteLeaseExpired(kind string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.leases = append(r.leases, kind)
}

func (r *recordingUploadMetrics) SetOffsiteLastSuccess(ts time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastSucc = ts
}

func (r *recordingUploadMetrics) snapshot() ([]string, map[string]int64, []string, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	up := append([]string{}, r.uploads...)
	by := map[string]int64{}
	for k, v := range r.bytes {
		by[k] = v
	}
	return up, by, append([]string{}, r.leases...), r.lastSucc
}

// TestUploaderRecordsSuccessMetricsAfterLedgerWriteBack 成功路徑：計數與位元組數落在帳冊寫回之後。
//
// **順序是斷言的一部分**：Put 成功但帳冊寫回失敗時，下一輪會重領並重傳同 key，
// 那一輪才是真正落定的一次。提早計數會讓 uploads_total 大於帳冊裡的 uploaded 列數，
// 而採集端無從察覺這個偏差——它看到的只是一個比實際多的數字。
func TestUploaderRecordsSuccessMetricsAfterLedgerWriteBack(t *testing.T) {
	rig := newUploaderRig(t)
	mx := newRecordingUploadMetrics()
	rig.uploader.SetMetrics(mx)

	content := []byte("cast-content")
	rig.adapter.put(1, &fakeFile{content: content, mtime: rig.clk.Now()})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)

	rig.uploader.RunCycle(context.Background())

	got, _ := rig.ledger.Get(row.ID)
	if got.State != StateUploaded {
		t.Fatalf("前置條件不成立：state = %q（本測試要驗的成功路徑沒走到）", got.State)
	}
	uploads, bytesByKind, leases, last := mx.snapshot()
	if len(uploads) != 1 || uploads[0] != KindRecording+"/"+UploadResultUploaded {
		t.Fatalf("上傳結果計數 = %v, want 一筆 recording/uploaded", uploads)
	}
	if bytesByKind[KindRecording] != int64(len(content)) {
		t.Fatalf("累計位元組 = %d, want %d（與帳冊 size 同源）",
			bytesByKind[KindRecording], len(content))
	}
	if last.IsZero() {
		t.Fatal("最後成功時刻未寫：採集端無從得知上傳是否還在動")
	}
	if len(leases) != 0 {
		t.Fatalf("成功路徑不該有租約回收，實得 %v", leases)
	}
}

// TestUploaderCountsEveryFailedAttemptNotOnlyTerminal 失敗路徑：每一次嘗試都計數。
//
// 只計終態失敗會讓「一直在重試但還沒到上限」在採集端完全看不見——
// 而那正是積壓形成的階段，也是還來得及處理的階段。
func TestUploaderCountsEveryFailedAttemptNotOnlyTerminal(t *testing.T) {
	rig := newUploaderRig(t)
	mx := newRecordingUploadMetrics()
	rig.uploader.SetMetrics(mx)

	rig.adapter.put(1, &fakeFile{content: []byte("x"), mtime: rig.clk.Now()})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)
	slot := rig.client.Inject(&FaultSlot{Op: "put", Err: errors.New("注入：遠端寫入失敗")})

	// 兩輪失敗，兩輪都在重試上限之內（退避時間以測試時鐘推進）
	for i := 0; i < 2; i++ {
		rig.uploader.RunCycle(context.Background())
		rig.clk.Advance(24 * time.Hour)
	}

	if slot.Fired() < 2 {
		t.Fatalf("注入格只命中 %d 次：失敗路徑沒有走到兩次，下面的計數斷言將驗到別的東西",
			slot.Fired())
	}
	got, _ := rig.ledger.Get(row.ID)
	if got.Attempts < 2 {
		t.Fatalf("前置條件不成立：attempts = %d，兩輪失敗沒有都走到", got.Attempts)
	}
	if got.State == StateFailed {
		t.Fatalf("前置條件不成立：已進終態，本測試要驗的是「終態之前也要計數」")
	}
	uploads, bytesByKind, _, last := mx.snapshot()
	if len(uploads) != 2 {
		t.Fatalf("失敗計數 = %v, want 兩筆（每次嘗試各一）", uploads)
	}
	for _, u := range uploads {
		if u != KindRecording+"/"+UploadResultFailed {
			t.Fatalf("失敗計數含非預期項 %q", u)
		}
	}
	if bytesByKind[KindRecording] != 0 {
		t.Fatalf("失敗竟累計了位元組 %d：那會讓「已離機的量」虛報",
			bytesByKind[KindRecording])
	}
	if !last.IsZero() {
		t.Fatal("從未成功卻寫了最後成功時刻——採集端會據此認為上傳正常")
	}
}

// TestUploaderCountsEveryLeaseReclaimNotOnlyStalled 租約回收：每一次都計數。
//
// 卡死的判準是「同一件回收 ≥2 次」，但採集端要看的是「這一小時內有沒有回收發生」
// （部署文件建議的規則即 `lease_expired_total` 一小時內增量 >0）。
// 只計卡死者會讓第一次回收——真正的早期訊號——完全不出現。
func TestUploaderCountsEveryLeaseReclaimNotOnlyStalled(t *testing.T) {
	rig := newUploaderRig(t)
	mx := newRecordingUploadMetrics()
	rig.uploader.SetMetrics(mx)

	rig.adapter.put(1, &fakeFile{content: []byte("x"), mtime: rig.clk.Now()})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)

	// 一次領件、一次逾期回收（尚未達卡死判準）
	if ok, _ := rig.ledger.Claim(row.ID, rig.clk.Now().Add(time.Minute)); !ok {
		t.Fatal("預置領件失敗")
	}
	rig.clk.Advance(2 * time.Minute)
	rig.uploader.reapLeases()

	got, _ := rig.ledger.Get(row.ID)
	if got.LeaseExpiries != 1 {
		t.Fatalf("前置條件不成立：lease_expiries = %d, want 1（尚未達卡死判準）", got.LeaseExpiries)
	}
	_, _, leases, _ := mx.snapshot()
	if len(leases) != 1 || leases[0] != KindRecording {
		t.Fatalf("租約回收計數 = %v, want 一筆 recording——第一次回收是最早的卡死訊號", leases)
	}
}

// TestUploaderWithoutMetricsStillWorks 未注入指標面時 worker 照常運作。
//
// 指標是旁路：`NewUploader` 之後若沒人呼叫 `SetMetrics`（單元測試建構路徑、
// 或組裝順序改動），worker 不得因此 panic——那等於讓一個旁路功能有能力
// 殺掉正在保全證據的上傳迴圈。
func TestUploaderWithoutMetricsStillWorks(t *testing.T) {
	rig := newUploaderRig(t)
	rig.adapter.put(1, &fakeFile{content: []byte("cast-content"), mtime: rig.clk.Now()})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)

	rig.uploader.RunCycle(context.Background())

	got, _ := rig.ledger.Get(row.ID)
	if got.State != StateUploaded {
		t.Fatalf("未注入指標面時上傳竟未成功：state = %q", got.State)
	}
}
