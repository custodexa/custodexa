package offsite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 上傳 worker 的行為層驗收。

// ── 測試替身 ────────────────────────────────────────────────────────────

// seekableCloser 以 bytes.Reader 實作 io.ReadSeekCloser。
type seekableCloser struct{ *bytes.Reader }

func (seekableCloser) Close() error { return nil }

// fakeFile adapter 手上的一份本機檔。
type fakeFile struct {
	content []byte
	mtime   time.Time
	// notReady true＝Open 回 ErrNotReadyYet（圖形寬限期未到／擁有者仍在進行中）
	notReady bool
	// openPanics true＝Open 直接 panic（證明兩層 recover 都走到）
	openPanics bool
	// tailAppend 非 nil＝**上傳完成後**才追加的位元組（畫格中途收線的長尾）
	tailAppend []byte
}

// fakeAdapter 模組側適配的測試替身。
type fakeAdapter struct {
	mu    sync.Mutex
	kind  string
	files map[uint]*fakeFile
	// statuses 擁有表快取的寫回紀錄
	statuses map[uint]string
	// unenqueued／classes 回填掃描面
	unenqueued []uint
	classes    map[uint]BackfillClass
	// openCalls 逐 owner 的 Open 次數（注入格「證明走到」用）
	openCalls map[uint]int
	// statAfterUpload true＝Stat 回傳含 tailAppend 的長度（模擬上傳後才變動）
	uploaded map[uint]bool
}

func newFakeAdapter(kind string) *fakeAdapter {
	return &fakeAdapter{
		kind: kind, files: map[uint]*fakeFile{}, statuses: map[uint]string{},
		classes: map[uint]BackfillClass{}, openCalls: map[uint]int{}, uploaded: map[uint]bool{},
	}
}

func (a *fakeAdapter) put(ownerID uint, f *fakeFile) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.files[ownerID] = f
}

func (a *fakeAdapter) Kind() string { return a.kind }

func (a *fakeAdapter) Open(ownerID uint) (io.ReadSeekCloser, int64, time.Time, error) {
	a.mu.Lock()
	f := a.files[ownerID]
	a.openCalls[ownerID]++
	a.mu.Unlock()
	if f == nil {
		return nil, 0, time.Time{}, errors.New("本機檔不存在")
	}
	if f.openPanics {
		panic("注入的 adapter panic（本機檔開啟路徑）")
	}
	if f.notReady {
		return nil, 0, time.Time{}, ErrNotReadyYet
	}
	return seekableCloser{bytes.NewReader(f.content)}, int64(len(f.content)), f.mtime, nil
}

func (a *fakeAdapter) Stat(ownerID uint) (int64, time.Time, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.files[ownerID]
	if f == nil {
		return 0, time.Time{}, errors.New("本機檔不存在")
	}
	// 上傳完成後才追加的長尾：複驗這一步才看得到
	if a.uploaded[ownerID] && len(f.tailAppend) > 0 {
		return int64(len(f.content) + len(f.tailAppend)), f.mtime.Add(time.Second), nil
	}
	return int64(len(f.content)), f.mtime, nil
}

func (a *fakeAdapter) SetStatus(ownerID, _ uint, status string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.statuses[ownerID] = status
	return nil
}

func (a *fakeAdapter) Describe(ownerID uint) (OwnerDescription, error) {
	return OwnerDescription{
		Label:   fmt.Sprintf("owner-%d", ownerID),
		EndedAt: time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC),
	}, nil
}

func (a *fakeAdapter) ListUnenqueued(limit int) ([]uint, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.unenqueued) > limit {
		return append([]uint{}, a.unenqueued[:limit]...), nil
	}
	return append([]uint{}, a.unenqueued...), nil
}

func (a *fakeAdapter) Classify(ownerID uint) (BackfillClass, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.classes[ownerID]; ok {
		return c, nil
	}
	return BackfillUploadable, nil
}

func (a *fakeAdapter) Extension(uint) (string, error) { return "cast", nil }

func (a *fakeAdapter) MarkForeignBatch(_ *gorm.DB, _ uint) error { return nil }

func (a *fakeAdapter) status(ownerID uint) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.statuses[ownerID]
}

func (a *fakeAdapter) markUploaded(ownerID uint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.uploaded[ownerID] = true
}

// fakeReporter 記錄機制級失效事件的上報與解除。
type fakeReporter struct {
	mu       sync.Mutex
	reports  []string
	resolves []string
}

func (r *fakeReporter) Report(mechanism, cause string, _ map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, mechanism+"/"+cause)
}

func (r *fakeReporter) Resolve(mechanism string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolves = append(r.resolves, mechanism)
}

func (r *fakeReporter) snapshot() ([]string, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.reports...), append([]string{}, r.resolves...)
}

// uploaderRig 一組接好線的 worker。
type uploaderRig struct {
	*offsiteTestRig
	clk      *fixedClock
	adapter  *fakeAdapter
	reporter *fakeReporter
	uploader *Uploader
	client   *FakeClient
	genID    uint
}

func newUploaderRig(t *testing.T) *uploaderRig {
	t.Helper()
	rig, clk := newClockedRig(t)
	gen := mustSave(t, rig, s3Settings("evidence")).View
	client := NewFakeClient("evidence")
	rig.factory.client = client

	adapter := newFakeAdapter(KindRecording)
	reporter := &fakeReporter{}
	up := NewUploader(rig.ledger, rig.svc, reporter, adapter)
	up.SetClockForTest(clk.Now)
	return &uploaderRig{offsiteTestRig: rig, clk: clk, adapter: adapter,
		reporter: reporter, uploader: up, client: client, genID: gen.GenerationID}
}

// ── 測試 ────────────────────────────────────────────────────────────────

// TestUploaderUploadsAndRecordsCustody 主路徑：上傳、記帳、保管鏈事件、快取寫回。
func TestUploaderUploadsAndRecordsCustody(t *testing.T) {
	rig := newUploaderRig(t)
	rig.adapter.put(1, &fakeFile{content: []byte("cast-content"), mtime: rig.clk.Now()})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)

	rig.uploader.RunCycle(context.Background())

	got, _ := rig.ledger.Get(row.ID)
	if got.State != StateUploaded {
		t.Fatalf("state = %q, want uploaded（error_code=%q）", got.State, got.ErrorCode)
	}
	// key 由系統組出（不接受使用者輸入），含年月分桶
	if got.ObjectKey != "custodexa/recordings/2026/08/session-1.cast" {
		t.Fatalf("object_key = %q", got.ObjectKey)
	}
	if len(got.SHA256) != 64 || got.Size != int64(len("cast-content")) {
		t.Fatalf("完整性欄不正確: sha=%q size=%d", got.SHA256, got.Size)
	}
	if got.UploadedAt == nil {
		t.Fatal("缺 uploaded_at")
	}
	// 遠端確實有這個物件，且 metadata 帶了 sha256
	data, meta, ok := rig.client.ObjectData(ObjectRef{Bucket: "evidence", Key: got.ObjectKey})
	if !ok || string(data) != "cast-content" {
		t.Fatalf("遠端物件不正確: ok=%v data=%q", ok, data)
	}
	if meta["sha256"] != got.SHA256 {
		t.Fatalf("metadata sha256 = %q, 帳冊 = %q（兩者必須是同一串位元組的雜湊）",
			meta["sha256"], got.SHA256)
	}
	if rig.adapter.status(1) != StateUploaded {
		t.Fatalf("擁有表快取 = %q, want uploaded", rig.adapter.status(1))
	}
	// 保管鏈事件（Details 欄位齊、無端點無憑證）
	var upload *CustodyEvent
	for _, ev := range rig.journal.all() {
		if ev.Action == CustodyActionUpload {
			c := ev
			upload = &c
		}
	}
	if upload == nil {
		t.Fatalf("缺上傳保管鏈事件（實得 %v）", rig.journal.actions())
	}
	for _, key := range []string{"object_id", "kind", "origin", "bucket",
		"storage_generation_id", "key", "sha256", "size", "attempts", "result"} {
		if _, ok := upload.Details[key]; !ok {
			t.Errorf("上傳事件缺欄位 %q", key)
		}
	}
	if dump := formatDetails(upload.Details); strings.Contains(dump, "minio.example.internal") ||
		strings.Contains(dump, "s3cr3t") {
		t.Fatalf("上傳事件夾帶端點或憑證: %s", dump)
	}
	// 全部成功→機制事件解除
	_, resolves := rig.reporter.snapshot()
	if len(resolves) != 1 || resolves[0] != model.MechanismOffsiteUpload {
		t.Fatalf("failed 歸零時應 Resolve，實得 %v", resolves)
	}
}

// TestUploaderGraceDeferralDoesNotCountAttempts 寬限期未到＝延後，**不計 attempts**。
func TestUploaderGraceDeferralDoesNotCountAttempts(t *testing.T) {
	rig := newUploaderRig(t)
	rig.adapter.put(1, &fakeFile{content: []byte("x"), mtime: rig.clk.Now(), notReady: true})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)

	rig.uploader.RunCycle(context.Background())
	got, _ := rig.ledger.Get(row.ID)
	if got.State != StatePending {
		t.Fatalf("寬限期未到應維持 pending，實得 %q", got.State)
	}
	if got.Attempts != 0 {
		t.Fatalf("寬限期不是失敗，attempts 不得遞增，實得 %d", got.Attempts)
	}
	if got.NextAttemptAt != nil {
		t.Fatal("寬限期延後不得寫退避（那會讓它被推遲一整輪退避）")
	}

	// 寬限期過了就取得到
	rig.adapter.put(1, &fakeFile{content: []byte("x"), mtime: rig.clk.Now()})
	rig.uploader.RunCycle(context.Background())
	if got, _ = rig.ledger.Get(row.ID); got.State != StateUploaded {
		t.Fatalf("寬限期到期後應上傳，實得 %q", got.State)
	}
	if GraphicsUploadGraceSeconds != 60 {
		t.Fatalf("GraphicsUploadGraceSeconds = %d，調小即降低保護（單一定義點）",
			GraphicsUploadGraceSeconds)
	}
}

// TestUploaderPanicDoesNotKillProcessAndHitsRetryCap
// panic 不殺行程（兩層 recover），且該件仍會走到重試上限。
//
// **注入證明走到**：斷言 adapter.Open 真的被呼叫了 MaxUploadAttempts 次
// ——沒有這個計數，「行程沒死」與「根本沒跑到注入點」無法區分。
func TestUploaderPanicDoesNotKillProcessAndHitsRetryCap(t *testing.T) {
	rig := newUploaderRig(t)
	rig.adapter.put(1, &fakeFile{openPanics: true})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)

	for i := 0; i < MaxUploadAttempts; i++ {
		rig.uploader.RunCycle(context.Background())
		rig.clk.Advance(7 * time.Hour) // 跨過最長的退避段
	}

	rig.adapter.mu.Lock()
	calls := rig.adapter.openCalls[1]
	rig.adapter.mu.Unlock()
	if calls != MaxUploadAttempts {
		t.Fatalf("注入點被呼叫 %d 次, want %d（注入點沒走到的話，"+
			"「行程沒死」不構成證據）", calls, MaxUploadAttempts)
	}
	got, _ := rig.ledger.Get(row.ID)
	if got.State != StateFailed {
		t.Fatalf("state = %q, want failed（attempts=%d）", got.State, got.Attempts)
	}
	reports, _ := rig.reporter.snapshot()
	if len(reports) != 1 || reports[0] != model.MechanismOffsiteUpload+"/"+model.CauseOffsiteUploadFailed {
		t.Fatalf("達上限應恰發一次機制事件，實得 %v", reports)
	}
}

// TestUploaderRevalidatesFileAfterUpload 上傳後複驗：本機檔變動→重試（重傳同 key）。
func TestUploaderRevalidatesFileAfterUpload(t *testing.T) {
	rig := newUploaderRig(t)
	rig.adapter.put(1, &fakeFile{
		content: []byte("frame-1"), mtime: rig.clk.Now(),
		tailAppend: []byte("frame-2"), // 上傳完成後才追加
	})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)
	rig.adapter.markUploaded(1) // 讓 Stat 在複驗時看到長尾

	rig.uploader.RunCycle(context.Background())

	got, _ := rig.ledger.Get(row.ID)
	if got.ErrorCode != ErrCodeFileChangedDuringUpload {
		t.Fatalf("error_code = %q, want %q", got.ErrorCode, ErrCodeFileChangedDuringUpload)
	}
	if got.State != StatePending {
		t.Fatalf("複驗不符應走重試（退避），實得 %q", got.State)
	}
	// **重試＝重傳同 key**：遠端物件數不因重試而增加
	if n := rig.client.ObjectCount(); n != 1 {
		t.Fatalf("遠端物件數 = %d, want 1（重傳同 key，內容相同故覆寫無害）", n)
	}
}

// TestUploaderResumesAfterWriteBackFailure Put 成功但 DB 寫回失敗的收斂。
//
// 以「重啟時的殘留形狀」直接重現：帳冊停在 uploading、租約已過期、遠端已有物件。
// 租約回收後重領 → **重傳同 key** → 帳冊收斂 uploaded，且遠端物件數不增加。
func TestUploaderResumesAfterWriteBackFailure(t *testing.T) {
	rig := newUploaderRig(t)
	content := []byte("cast-content")
	rig.adapter.put(1, &fakeFile{content: content, mtime: rig.clk.Now()})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)

	// 造出「Put 已成功、DB 寫回未完成」的殘留狀態
	key := RecordingObjectKey("custodexa", 1, time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC), "cast")
	if _, err := rig.client.Put(context.Background(), key, bytes.NewReader(content),
		PutOpts{ContentLength: int64(len(content))}); err != nil {
		t.Fatalf("預置遠端物件失敗: %v", err)
	}
	if ok, _ := rig.ledger.Claim(row.ID, rig.clk.Now().Add(time.Minute)); !ok {
		t.Fatal("預置領件失敗")
	}
	if n := rig.client.ObjectCount(); n != 1 {
		t.Fatalf("預置後遠端物件數 = %d", n)
	}

	// 租約到期 → 下一輪回收並重傳
	rig.clk.Advance(2 * time.Minute)
	rig.uploader.RunCycle(context.Background())

	got, _ := rig.ledger.Get(row.ID)
	if got.State != StateUploaded {
		t.Fatalf("state = %q, want uploaded（租約回收後應重傳同 key 並收斂）", got.State)
	}
	if got.ObjectKey != key {
		t.Fatalf("object_key = %q, want %q（重傳必須是同一個 key）", got.ObjectKey, key)
	}
	if n := rig.client.ObjectCount(); n != 1 {
		t.Fatalf("遠端物件數 = %d, want 1（同 key 覆寫，不得產生第二個物件）", n)
	}
	if got.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2（回收不歸零）", got.Attempts)
	}
}

// TestUploaderMechanismEventResolvesOnlyWhenFailedCountIsZero
// 機制級事件的解除判準：**兩件 failed 一件成功仍不解除，歸零才解除**。
//
// 「任一成功即解除」會把其他仍 failed 的證據在通知面誤報為恢復。
func TestUploaderMechanismEventResolvesOnlyWhenFailedCountIsZero(t *testing.T) {
	rig := newUploaderRig(t)
	// 兩件已在 failed
	seedObject(t, rig.db, rig.genID, 90, StateFailed)
	seedObject(t, rig.db, rig.genID, 91, StateFailed)
	// 一件會成功
	rig.adapter.put(1, &fakeFile{content: []byte("ok"), mtime: rig.clk.Now()})
	enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)

	rig.uploader.RunCycle(context.Background())
	if _, resolves := rig.reporter.snapshot(); len(resolves) != 0 {
		t.Fatalf("仍有 %d 件 failed 時不得 Resolve，實得 %v", 2, resolves)
	}

	// 清掉 failed 後再成功一件 → 解除
	if _, err := rig.ledger.RetryFailed(0); err != nil {
		t.Fatalf("RetryFailed: %v", err)
	}
	if err := rig.db.Exec("DELETE FROM offsite_objects WHERE owner_id IN (90, 91)").Error; err != nil {
		t.Fatalf("清理失敗: %v", err)
	}
	rig.adapter.put(2, &fakeFile{content: []byte("ok2"), mtime: rig.clk.Now()})
	enqueue(t, rig.offsiteTestRig, KindRecording, 2, OriginLive)
	rig.uploader.RunCycle(context.Background())
	if _, resolves := rig.reporter.snapshot(); len(resolves) == 0 {
		t.Fatal("failed 歸零後應 Resolve")
	}
}

// TestUploaderStalledLeaseRaisesEvent 租約回收 ≥2 次＝卡死，發保管鏈事件＋機制事件。
func TestUploaderStalledLeaseRaisesEvent(t *testing.T) {
	rig := newUploaderRig(t)
	rig.adapter.put(1, &fakeFile{content: []byte("x"), mtime: rig.clk.Now()})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)

	for i := 0; i < StalledLeaseExpiries; i++ {
		if ok, _ := rig.ledger.Claim(row.ID, rig.clk.Now().Add(time.Minute)); !ok {
			t.Fatalf("第 %d 次預置領件失敗", i+1)
		}
		rig.clk.Advance(2 * time.Minute)
		rig.uploader.reapLeases()
	}

	reports, _ := rig.reporter.snapshot()
	want := model.MechanismOffsiteUpload + "/" + model.CauseOffsiteUploadStalled
	found := false
	for _, r := range reports {
		if r == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("卡死應發 %s，實得 %v", want, reports)
	}
	var stalled *CustodyEvent
	for _, ev := range rig.journal.all() {
		if ev.Action == CustodyActionUpload && ev.Details["result"] == "stalled" {
			c := ev
			stalled = &c
		}
	}
	if stalled == nil {
		t.Fatalf("缺卡死的保管鏈事件（實得 %v）", rig.journal.actions())
	}
	if stalled.Status != string(model.StatusFailure) {
		t.Errorf("卡死事件 status = %q, want failure", stalled.Status)
	}
}

// TestUploaderLaneQuota 雙車道配額（純函式逐格）。
func TestUploaderLaneQuota(t *testing.T) {
	mk := func(n int, origin string) []model.OffsiteObject {
		out := make([]model.OffsiteObject, n)
		for i := range out {
			out[i] = model.OffsiteObject{ID: uint(i + 1), Origin: origin}
		}
		return out
	}
	count := func(rows []model.OffsiteObject, origin string) int {
		n := 0
		for _, r := range rows {
			if r.Origin == origin {
				n++
			}
		}
		return n
	}

	// 兩條車道都塞滿：16 live + 4 backfill（**backfill 仍得 4**）
	got := planLanes(mk(30, OriginLive), mk(30, OriginBackfill))
	if len(got) != LaneQuotaTotal ||
		count(got, OriginLive) != LaneQuotaLive || count(got, OriginBackfill) != LaneQuotaBackfill {
		t.Fatalf("滿載配額 = live %d／backfill %d／總 %d, want %d／%d／%d",
			count(got, OriginLive), count(got, OriginBackfill), len(got),
			LaneQuotaLive, LaneQuotaBackfill, LaneQuotaTotal)
	}
	// live 空：backfill 補滿到總量
	got = planLanes(nil, mk(30, OriginBackfill))
	if len(got) != LaneQuotaTotal || count(got, OriginBackfill) != LaneQuotaTotal {
		t.Fatalf("live 空時 backfill 應補滿，實得 %d 件", len(got))
	}
	// backfill 空：live 補滿到總量
	got = planLanes(mk(30, OriginLive), nil)
	if len(got) != LaneQuotaTotal || count(got, OriginLive) != LaneQuotaTotal {
		t.Fatalf("backfill 空時 live 應補滿，實得 %d 件", len(got))
	}
	// 兩邊都不足：全取
	got = planLanes(mk(3, OriginLive), mk(2, OriginBackfill))
	if len(got) != 5 {
		t.Fatalf("不足時應全取，實得 %d 件", len(got))
	}
}

// TestUploaderBackfillScanClassifies 回填三分類＋與清理不重複建列。
func TestUploaderBackfillScanClassifies(t *testing.T) {
	rig := newUploaderRig(t)
	rig.adapter.unenqueued = []uint{10, 11, 12}
	rig.adapter.classes[10] = BackfillUploadable
	rig.adapter.classes[11] = BackfillMissing
	rig.adapter.classes[12] = BackfillExpired
	rig.adapter.put(10, &fakeFile{content: []byte("y"), mtime: rig.clk.Now()})

	rig.uploader.RunBackfillScan(context.Background())

	if n, _ := rig.ledger.TotalObjects(); n != 1 {
		t.Fatalf("只有可上傳者建列，帳冊列數 = %d, want 1", n)
	}
	if rig.adapter.status(11) != CacheSkippedMissing {
		t.Fatalf("缺檔者的快取 = %q, want %q", rig.adapter.status(11), CacheSkippedMissing)
	}
	if rig.adapter.status(12) != CacheSkippedExpired {
		t.Fatalf("已逾保留者的快取 = %q, want %q", rig.adapter.status(12), CacheSkippedExpired)
	}
	if rig.adapter.status(10) != StatePending {
		t.Fatalf("可上傳者的快取 = %q, want pending", rig.adapter.status(10))
	}

	// 再掃一輪：冪等，不重複建列
	rig.uploader.RunBackfillScan(context.Background())
	if n, _ := rig.ledger.TotalObjects(); n != 1 {
		t.Fatalf("重複掃描不得重複建列，帳冊列數 = %d", n)
	}
}

// TestUploaderBackfillScanSkipsWhenDisabled 停用態（零現行世代）下回填不建列。
func TestUploaderBackfillScanSkipsWhenDisabled(t *testing.T) {
	rig := newUploaderRig(t)
	if err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	rig.adapter.unenqueued = []uint{10}
	rig.adapter.put(10, &fakeFile{content: []byte("y"), mtime: rig.clk.Now()})

	rig.uploader.RunBackfillScan(context.Background())
	if n, _ := rig.ledger.TotalObjects(); n != 0 {
		t.Fatalf("停用態下不得建列，帳冊列數 = %d", n)
	}
}

// TestUploaderNeverCallsRemoteDelete **正式路徑零遠端刪除**的行為層承擔。
//
// 靜態守衛（internal/guards/offsitedelete）擋的是「非測試碼呼叫 Delete」；
// 本格擋的是「經由某條間接路徑真的刪到了」——兩者形態不同，缺一都留缺口。
func TestUploaderNeverCallsRemoteDelete(t *testing.T) {
	rig := newUploaderRig(t)
	rig.adapter.put(1, &fakeFile{content: []byte("a"), mtime: rig.clk.Now()})
	row, _ := enqueue(t, rig.offsiteTestRig, KindRecording, 1, OriginLive)
	rig.uploader.RunCycle(context.Background())

	// 到期清理
	if _, err := rig.ledger.MarkLocalPurged(row.ID); err != nil {
		t.Fatalf("MarkLocalPurged: %v", err)
	}
	// 世代切換與停止離機
	if err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1}); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if n := rig.client.DeleteCalls(); n != 0 {
		t.Fatalf("遠端 Delete 被呼叫 %d 次：產品對遠端物件不發 DeleteObject，"+
			"到期清理歸部署方的 bucket lifecycle", n)
	}
}

// TestUploaderSkipsUnknownKind 無對應 adapter 的 kind 不會讓整輪掛掉。
func TestUploaderSkipsUnknownKind(t *testing.T) {
	rig := newUploaderRig(t)
	row, _ := enqueue(t, rig.offsiteTestRig, KindExport, 5, OriginLive)
	rig.uploader.RunCycle(context.Background())
	got, _ := rig.ledger.Get(row.ID)
	if got.State != StatePending {
		t.Fatalf("無 adapter 時應維持 pending（不誤判為失敗），實得 %q", got.State)
	}
	if got.Attempts != 0 {
		t.Fatalf("無 adapter 不是該件的錯，attempts 不得遞增，實得 %d", got.Attempts)
	}
}
