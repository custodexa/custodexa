package offsite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 取回：先驗後送、跨世代憑證匹配、
// 停用態仍可取回、暫存的命中與回收。

// reportingFailure 記錄機制級告警（Report／Resolve）。
type reportingFailure struct {
	mu        sync.Mutex
	reports   []string
	resolved  []string
	lastParam map[string]string
}

func (r *reportingFailure) Report(mechanism, cause string, params map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, mechanism+"/"+cause)
	r.lastParam = params
}

func (r *reportingFailure) Resolve(mechanism string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolved = append(r.resolved, mechanism)
}

func (r *reportingFailure) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reports)
}

// cacheAdapter 只記錄 SetStatus 的最小 Adapter（取回路徑只用得到它）。
type cacheAdapter struct {
	kind     string
	mu       sync.Mutex
	statuses map[uint]string
}

func newCacheAdapter(kind string) *cacheAdapter {
	return &cacheAdapter{kind: kind, statuses: map[uint]string{}}
}

func (a *cacheAdapter) Kind() string { return a.kind }
func (a *cacheAdapter) Open(uint) (io.ReadSeekCloser, int64, time.Time, error) {
	return nil, 0, time.Time{}, ErrNotReadyYet
}
func (a *cacheAdapter) Stat(uint) (int64, time.Time, error) { return 0, time.Time{}, nil }
func (a *cacheAdapter) SetStatus(ownerID, _ uint, status string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.statuses[ownerID] = status
	return nil
}
func (a *cacheAdapter) Describe(uint) (OwnerDescription, error) { return OwnerDescription{}, nil }
func (a *cacheAdapter) ListUnenqueued(int) ([]uint, error)      { return nil, nil }
func (a *cacheAdapter) Classify(uint) (BackfillClass, error)    { return BackfillUploadable, nil }
func (a *cacheAdapter) Extension(uint) (string, error)          { return "cast", nil }
func (a *cacheAdapter) MarkForeignBatch(*gorm.DB, uint) error   { return nil }

func (a *cacheAdapter) status(ownerID uint) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.statuses[ownerID]
}

// fetchRig 取回測試裝配。
type fetchRig struct {
	*offsiteTestRig
	fetcher *Fetcher
	failure *reportingFailure
	adapter *cacheAdapter
	root    string
}

func newFetchRig(t *testing.T) *fetchRig {
	t.Helper()
	rig := newOffsiteRig(t)
	failure := &reportingFailure{}
	adapter := newCacheAdapter(KindRecording)
	root := filepath.Join(t.TempDir(), "spool")
	f := NewFetcher(root, rig.ledger, rig.svc, rig.journal, failure, adapter)
	return &fetchRig{offsiteTestRig: rig, fetcher: f, failure: failure, adapter: adapter, root: root}
}

// putObject 在某世代的 fake client 上放一份內容，並在帳冊建對應的 uploaded 列。
func (r *fetchRig) putObject(t *testing.T, client *FakeClient, generationID, ownerID uint,
	bucket, key string, body []byte) model.OffsiteObject {
	t.Helper()
	if _, err := client.Put(context.Background(), key, strings.NewReader(string(body)),
		PutOpts{ContentLength: int64(len(body))}); err != nil {
		t.Fatalf("fake put: %v", err)
	}
	sum := sha256.Sum256(body)
	now := time.Now()
	row := model.OffsiteObject{
		Kind: KindRecording, OwnerID: ownerID, Origin: OriginLive, Provider: ProviderS3,
		StorageGenerationID: generationID, Bucket: bucket, ObjectKey: key,
		SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)),
		State: StateUploaded, UploadedAt: &now,
	}
	if err := r.db.Create(&row).Error; err != nil {
		t.Fatalf("建立帳冊列失敗: %v", err)
	}
	return row
}

// ── 主線 ──────────────────────────────────────────────────────────────────

// TestFetcherVerifiesBeforeServing 取回成功：暫存檔內容與帳冊逐位元組相同，
// 且第二次呼叫命中暫存（零次 Fetch）。
func TestFetcherVerifiesBeforeServing(t *testing.T) {
	rig := newFetchRig(t)
	client := NewFakeClient("evidence")
	rig.factory.client = client
	mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))

	body := []byte("asciicast-body-0123456789")
	row := rig.putObject(t, client, 1, 42, "evidence", "custodexa/recordings/2026/03/42.cast", body)

	got, err := rig.fetcher.Fetch(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	data, err := os.ReadFile(got.Path)
	if err != nil {
		t.Fatalf("讀暫存檔: %v", err)
	}
	if string(data) != string(body) {
		t.Fatalf("暫存內容不符：%q", data)
	}
	if filepath.Ext(got.Path) != ".cast" {
		t.Errorf("暫存檔應保留副檔名（供 handler 依副檔名分流），實得 %s", got.Path)
	}
	if n := client.FetchCalls(); n != 1 {
		t.Fatalf("首次取回應打一次遠端，實得 %d", n)
	}
	if _, err := rig.fetcher.Fetch(context.Background(), row.ID); err != nil {
		t.Fatalf("二次 Fetch: %v", err)
	}
	if n := client.FetchCalls(); n != 1 {
		t.Errorf("已驗證的暫存檔必須直接服務，實得 %d 次遠端取回", n)
	}
}

// TestFetcherRejectsTamperedContent 遠端內容被竄改：**零位元組交付**，
// 且四件事都發生（帳冊態、擁有表快取、保管鏈事件、機制級告警）。
func TestFetcherRejectsTamperedContent(t *testing.T) {
	rig := newFetchRig(t)
	client := NewFakeClient("evidence")
	rig.factory.client = client
	mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))

	body := []byte("original-evidence-body")
	key := "custodexa/recordings/2026/03/7.cast"
	row := rig.putObject(t, client, 1, 7, "evidence", key, body)

	slot := client.Inject(&FaultSlot{Op: "fetch", Key: key, Content: []byte("TAMPERED")})
	t.Cleanup(func() {
		if slot.Fired() == 0 {
			t.Error("竄改注入格從未被命中：本測試沒有驗到任何東西")
		}
	})

	got, err := rig.fetcher.Fetch(context.Background(), row.ID)
	if err == nil {
		t.Fatal("竄改內容必須被拒絕交付")
	}
	if got != nil {
		t.Fatalf("拒絕交付時不得回傳任何可讀路徑：%+v", got)
	}
	if MachineCodeOf(err) != ErrCodeIntegrityMismatch {
		t.Errorf("機器碼應為 %s，實得 %v", ErrCodeIntegrityMismatch, err)
	}

	// 零位元組交付：暫存目錄不得留下任何可服務的檔案
	entries, _ := os.ReadDir(rig.root)
	for _, e := range entries {
		t.Errorf("不符時暫存目錄不得留檔，實見 %s", e.Name())
	}

	var after model.OffsiteObject
	if err := rig.db.First(&after, row.ID).Error; err != nil {
		t.Fatalf("重讀帳冊: %v", err)
	}
	if after.State != StateIntegrityMismatch {
		t.Errorf("帳冊態應為 %s，實得 %s", StateIntegrityMismatch, after.State)
	}
	if s := rig.adapter.status(7); s != StateIntegrityMismatch {
		t.Errorf("擁有表快取應同步為 %s，實得 %q", StateIntegrityMismatch, s)
	}
	if rig.failure.count() != 1 {
		t.Errorf("應發一次機制級告警，實得 %d", rig.failure.count())
	}
	var integrityEvents int
	for _, ev := range rig.journal.all() {
		if ev.Action != CustodyActionIntegrity {
			continue
		}
		integrityEvents++
		if ev.Status != string(model.StatusFailure) {
			t.Errorf("完整性事件應為失敗列，實得 %s", ev.Status)
		}
		for k, v := range ev.Details {
			if s, ok := v.(string); ok && strings.Contains(s, "minio.example.internal") {
				t.Errorf("保管鏈 Details 不得含端點（%s=%v）", k, v)
			}
		}
	}
	if integrityEvents != 1 {
		t.Errorf("應寫一筆 offsite_integrity 事件，實得 %d", integrityEvents)
	}

	// 已判不可信者不再重取（重取只會再驗一次同樣的內容）
	before := client.FetchCalls()
	if _, err := rig.fetcher.Fetch(context.Background(), row.ID); err == nil {
		t.Error("已判 integrity_mismatch 的物件不得再交付")
	}
	if client.FetchCalls() != before {
		t.Error("已判不可信的物件不應再打遠端")
	}
}

// TestFetcherSingleflightCollapsesConcurrentFetches 並發兩次取回只打一次遠端。
func TestFetcherSingleflightCollapsesConcurrentFetches(t *testing.T) {
	rig := newFetchRig(t)
	client := NewFakeClient("evidence")
	rig.factory.client = client
	mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))

	body := []byte(strings.Repeat("x", 4096))
	row := rig.putObject(t, client, 1, 9, "evidence", "custodexa/recordings/2026/03/9.cast", body)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	paths := make([]string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, err := rig.fetcher.Fetch(context.Background(), row.ID)
			errs[i] = err
			if got != nil {
				paths[i] = got.Path
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("並發取回 %d 失敗: %v", i, err)
		}
	}
	if paths[0] != paths[1] {
		t.Errorf("並發取回應得到同一份暫存檔：%s vs %s", paths[0], paths[1])
	}
	if n := client.FetchCalls(); n != 1 {
		t.Errorf("並發取回應合併為一次遠端呼叫，實得 %d", n)
	}
}

// TestFetcherNoOffsiteCopy 從未上傳成功的列：不打遠端、回「沒有離機副本」。
func TestFetcherNoOffsiteCopy(t *testing.T) {
	rig := newFetchRig(t)
	client := NewFakeClient("evidence")
	rig.factory.client = client
	mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))

	row := seedObject(t, rig.db, 1, 5, StatePending)
	_, err := rig.fetcher.Fetch(context.Background(), row.ID)
	if err == nil || !strings.Contains(err.Error(), "沒有可取回") {
		t.Fatalf("應回「沒有可取回的離機副本」，實得 %v", err)
	}
	if client.FetchCalls() != 0 {
		t.Error("尚未上傳成功的列不得打遠端")
	}
}

// ── 跨世代取回 ────────────────────────────────────────

// TestFetcherCrossGenerationUsesLedgerGeneration 四格：
// (1) 切 provider 後舊世代物件仍取得回，且用的是**該世代**的憑證；
// (2) 該世代憑證撤銷後回 foreign_credentials_missing 且零 driver 建構；
// (3) 世代查無回 profile_missing 且零位元組交付；
// (4) 停用態（零現行世代）下歷史物件仍取得回。
func TestFetcherCrossGenerationUsesLedgerGeneration(t *testing.T) {
	rig := newFetchRig(t)
	oldClient := NewFakeClient("old-bucket")
	rig.factory.client = oldClient

	// 世代 1（s3）
	first := s3Settings("old-bucket")
	mustSave(t, rig.offsiteTestRig, first)
	body := []byte("generation-one-evidence")
	row := rig.putObject(t, rig.factory.client.(*FakeClient), 1, 11, "old-bucket",
		"custodexa/recordings/2026/03/11.cast", body)

	// 切到世代 2（gcs，另一組憑證與 bucket）
	second := SettingsInput{
		Provider: ProviderGCS, Bucket: "new-bucket", Prefix: "custodexa",
		ServiceAccountJSON: `{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com","private_key":"k"}`,
	}
	res, err := rig.svc.Save(context.Background(), second, OffsiteActor{ID: 1, Name: "admin"})
	if err != nil {
		t.Fatalf("Save（切世代）: %v", err)
	}
	if !res.NeedsConfirmation {
		t.Fatalf("有存量物件時切世代必須先要求確認")
	}
	if _, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
		Settings: second, ExpectedCurrentGenerationID: res.ExpectedCurrentGenerationID,
		SettingsDigest: res.SettingsDigest,
	}, OffsiteActor{ID: 1, Name: "admin"}); err != nil {
		t.Fatalf("ConfirmGenerationSwitch: %v", err)
	}

	t.Run("舊世代物件以該世代的憑證取回", func(t *testing.T) {
		got, err := rig.fetcher.Fetch(context.Background(), row.ID)
		if err != nil {
			t.Fatalf("跨世代取回失敗: %v", err)
		}
		data, _ := os.ReadFile(got.Path)
		if string(data) != string(body) {
			t.Fatalf("內容不符: %q", data)
		}
		spec := rig.factory.lastSpec(t)
		if spec.Bucket != "old-bucket" || spec.Provider != ProviderS3 {
			t.Errorf("必須用帳冊列的世代建 client，實得 provider=%s bucket=%s",
				spec.Provider, spec.Bucket)
		}
		if spec.AccessKeyID != first.AccessKeyID {
			t.Errorf("必須用該世代自己的憑證，而非現行世代的")
		}
	})

	t.Run("撤銷該世代憑證後零 driver 建構", func(t *testing.T) {
		os.RemoveAll(rig.root) // 清暫存，否則會命中已驗證的副本
		if err := rig.svc.RevokeCredentials(context.Background(), 1,
			OffsiteActor{ID: 1, Name: "admin"}); err != nil {
			t.Fatalf("RevokeCredentials: %v", err)
		}
		before := rig.factory.count()
		got, err := rig.fetcher.Fetch(context.Background(), row.ID)
		if err == nil {
			t.Fatal("憑證已撤銷的世代不得取回")
		}
		if got != nil {
			t.Fatal("拒絕時不得回傳可讀路徑")
		}
		if MachineCodeOf(err) != ErrCodeForeignCredentialsMissing {
			t.Errorf("應回 %s，實得 %v", ErrCodeForeignCredentialsMissing, err)
		}
		if !strings.Contains(err.Error(), "世代 1") || !strings.Contains(err.Error(), ProviderS3) {
			t.Errorf("訊息須指名世代與 provider，實得 %v", err)
		}
		if rig.factory.count() != before {
			t.Errorf("撤銷世代必須零 driver 建構（即使環境有可用的預設鏈），實增 %d",
				rig.factory.count()-before)
		}
	})

	t.Run("世代查無回 profile_missing", func(t *testing.T) {
		orphan := seedObject(t, rig.db, 999, 33, StateUploaded)
		if err := rig.db.Model(&model.OffsiteObject{}).Where("id = ?", orphan.ID).
			Updates(map[string]any{"sha256": strings.Repeat("a", 64), "size": 3}).Error; err != nil {
			t.Fatalf("補齊孤兒列: %v", err)
		}
		got, err := rig.fetcher.Fetch(context.Background(), orphan.ID)
		if err == nil || got != nil {
			t.Fatal("世代查無時必須 fail-close 且零位元組交付")
		}
		if MachineCodeOf(err) != ErrCodeProfileMissing {
			t.Errorf("應回 %s，實得 %v", ErrCodeProfileMissing, err)
		}
	})

	t.Run("停用態下歷史物件仍取得回", func(t *testing.T) {
		os.RemoveAll(rig.root)
		// 世代 2 的物件（現行世代），先造一份
		newClient := NewFakeClient("new-bucket")
		rig.factory.client = newClient
		body2 := []byte("generation-two-evidence")
		row2 := rig.putObject(t, newClient, 2, 21, "new-bucket",
			"custodexa/recordings/2026/03/21.cast", body2)

		if err := rig.svc.Disable(context.Background(), OffsiteActor{ID: 1, Name: "admin"}); err != nil {
			t.Fatalf("Disable: %v", err)
		}
		if n := currentCount(t, rig.db); n != 0 {
			t.Fatalf("停止離機後現行世代應為零列，實得 %d", n)
		}
		got, err := rig.fetcher.Fetch(context.Background(), row2.ID)
		if err != nil {
			t.Fatalf("停用態下歷史物件仍必須取得回，實得 %v", err)
		}
		data, _ := os.ReadFile(got.Path)
		if string(data) != string(body2) {
			t.Fatalf("內容不符: %q", data)
		}
	})
}

// ── 暫存回收 ──────────────────────────────────────────────────────────────

// TestFetcherReclaimsIdleSpool 閒置逾 30 分鐘的暫存副本被回收；
// 未逾時者保留。
func TestFetcherReclaimsIdleSpool(t *testing.T) {
	rig := newFetchRig(t)
	client := NewFakeClient("evidence")
	rig.factory.client = client
	mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))

	body := []byte("spool-body")
	row := rig.putObject(t, client, 1, 3, "evidence", "custodexa/recordings/2026/03/3.cast", body)
	got, err := rig.fetcher.Fetch(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if n := rig.fetcher.SpoolBytes(); n != int64(len(body)) {
		t.Errorf("暫存佔用應為 %d，實得 %d", len(body), n)
	}

	// 尚未逾時：保留
	rig.fetcher.SetClockForTest(func() time.Time { return time.Now().Add(29 * time.Minute) })
	rig.fetcher.Reclaim()
	if _, err := os.Stat(got.Path); err != nil {
		t.Fatalf("未逾閒置門檻不得回收: %v", err)
	}

	// 逾時：回收資料檔與標記檔
	rig.fetcher.SetClockForTest(func() time.Time { return time.Now().Add(31 * time.Minute) })
	rig.fetcher.Reclaim()
	if _, err := os.Stat(got.Path); !os.IsNotExist(err) {
		t.Errorf("閒置逾 30 分鐘的暫存副本應被回收，實得 %v", err)
	}
	if n := rig.fetcher.SpoolBytes(); n != 0 {
		t.Errorf("回收後暫存佔用應歸零，實得 %d", n)
	}
}

// TestFetcherIgnoresUnverifiedSpoolFile 沒有 .ok 標記的殘檔不得被當成已驗證內容。
//
// 中斷、行程被砍或人為放檔都可能在暫存目錄留下同名檔案；只看資料檔存在就服務，
// 等於把一份沒驗過的位元組交出去。
func TestFetcherIgnoresUnverifiedSpoolFile(t *testing.T) {
	rig := newFetchRig(t)
	client := NewFakeClient("evidence")
	rig.factory.client = client
	mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))

	body := []byte("real-body")
	row := rig.putObject(t, client, 1, 4, "evidence", "custodexa/recordings/2026/03/4.cast", body)

	if err := os.MkdirAll(rig.root, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	planted := filepath.Join(rig.root, strconv.FormatUint(uint64(row.ID), 10)+".cast")
	if err := os.WriteFile(planted, []byte("planted!!"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := rig.fetcher.Fetch(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	data, _ := os.ReadFile(got.Path)
	if string(data) != string(body) {
		t.Fatalf("無標記檔的殘檔必須被重新取回覆寫，實得 %q", data)
	}
	if client.FetchCalls() != 1 {
		t.Errorf("應實際取回一次，實得 %d", client.FetchCalls())
	}
}

// TestRetentionPathNeverDeletesRemoteObject 保留清理路徑對遠端**零 Delete 呼叫**
// （產品不代刪，遠端到期清理歸部署方的 bucket lifecycle）。
//
// **啟用與未啟用都驗**：防誤接雙層之一是行為層——靜態守衛
// （`internal/guards/offsitedelete`）擋的是「有沒有寫下這行呼叫」，本格擋的是
// 「執行到底有沒有發出去」。兩者失敗方向不同，缺一不可。
func TestRetentionPathNeverDeletesRemoteObject(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
	}{{"已設定離機", true}, {"未設定離機", false}} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newFetchRig(t)
			client := NewFakeClient("evidence")
			rig.factory.client = client
			if tc.enabled {
				mustSave(t, rig.offsiteTestRig, s3Settings("evidence"))
			}

			// 逐一走過到期轉移表的每一種前態
			for i, state := range []string{
				StateUploaded, StatePending, StateFailed,
				StateIntegrityMismatch, StateForeign, StateLocalPurged,
			} {
				row := seedObject(t, rig.db, 1, uint(100+i), state)
				if _, err := rig.ledger.MarkLocalPurged(row.ID); err != nil {
					t.Fatalf("到期處置（前態 %s）失敗: %v", state, err)
				}
			}
			if n := client.DeleteCalls(); n != 0 {
				t.Fatalf("保留清理對遠端發出了 %d 次 Delete——產品不代刪遠端證據", n)
			}
			if n := client.FetchCalls(); n != 0 {
				t.Errorf("保留清理不應觸發任何遠端讀取，實得 %d 次", n)
			}
		})
	}
}
