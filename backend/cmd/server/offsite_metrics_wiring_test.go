package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/observability"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/gin-gonic/gin"
)

// 離機儲存三態的組裝面驗收（停用態表）。
//
// # 為什麼要在組裝根這一層再驗一次
//
// `internal/observability` 那一組證明「註冊了就曝光」，但**誰在什麼條件下呼叫註冊**
// 是組裝根的事。三個狀態的判準各不相同（世代總列數 vs 現行世代），寫反了不會有
// 編譯錯誤，而症狀是監控在說謊——停用之後採集端仍讀到「待上傳 0、一切正常」。
//
// 同一組也釘住 worker 的 goroutine：以真實堆疊掃描而非日誌字串，
// 日誌可以被改寫，正在跑的 goroutine 不會。

// offsiteUploaderGoroutineSymbol 上傳迴圈在堆疊上的符號。
//
// **以堆疊為判準而非日誌**：「未啟用時不建 goroutine」是行為，不是一行訊息；
// 有人把 `return nil` 改成照樣 `go Run(...)` 而日誌照印，字串判準會全綠。
const offsiteUploaderGoroutineSymbol = "offsite.(*Uploader).Run"

// offsiteUploaderRunning 掃全行程堆疊，判斷上傳迴圈是否在跑。
func offsiteUploaderRunning() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Contains(string(buf[:n]), offsiteUploaderGoroutineSymbol)
}

// scrapeStage2Metrics 走完整曝光路徑取 /metrics 內容。
func scrapeStage2Metrics(t *testing.T, m *observability.Metrics) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET(observability.MetricsPath, m.Handler(""))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, observability.MetricsPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/metrics 回 %d", w.Code)
	}
	return w.Body.String()
}

// waitForMetric 等背景刷新把某條序列寫出來，回傳當下的曝光內容。
//
// **不是 sleep 固定秒數**：首刷跑在自己的 goroutine 內，固定等待要嘛太短（偶發紅）
// 要嘛太長（每次都付）。等不到即 Fatal 並指名——那代表刷新源沒接上，
// 而那正是本組測試要抓的裝配缺陷之一。
func waitForMetric(t *testing.T, m *observability.Metrics, series string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		body = scrapeStage2Metrics(t, m)
		if strings.Contains(body, series) {
			return body
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等不到序列 %s：背景刷新源可能未接上（OffsiteQueue 為 nil 或整項被跳過）", series)
	return body
}

// runStage2ForOffsite 以整合環境跑一次段 2，回傳環境與圖（呼叫端負責 Release）。
func runStage2ForOffsite(t *testing.T, seedProfiles func(t *testing.T)) (*sealIntegrationEnv, *appGraph) {
	t.Helper()
	env := newSealIntegrationEnv(t)
	if seedProfiles != nil {
		seedProfiles(t)
	}
	kek, err := buildUIKEKProvider([]byte(testInitialKEK))
	if err != nil {
		t.Fatalf("建構 KEK provider 失敗: %v", err)
	}
	g, err := runStage2(context.Background(), env.s1, kek)
	if err != nil {
		t.Fatalf("段 2 建構失敗: %v", err)
	}
	t.Cleanup(func() {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = g.Release(rctx)
	})
	return env, g
}

// TestOffsiteNeverConfiguredHasNoSeriesAndNoWorker 設定表零列：零序列、零 goroutine。
//
// 「未設定＝行為完全不變」的組裝面機械保證。
func TestOffsiteNeverConfiguredHasNoSeriesAndNoWorker(t *testing.T) {
	env, _ := runStage2ForOffsite(t, nil)

	var n int64
	if err := database.DB.Model(&model.OffsiteProfile{}).Count(&n).Error; err != nil {
		t.Fatalf("計數設定世代: %v", err)
	}
	if n != 0 {
		t.Fatalf("前置條件不成立：設定表有 %d 列（本格要驗的是零列態）", n)
	}

	body := scrapeStage2Metrics(t, env.s1.metrics)
	if strings.Contains(body, "custodexa_offsite_") {
		t.Fatal("設定表零列時 /metrics 竟含 custodexa_offsite_ 序列：" +
			"一個從未啟用的功能會被採集端讀成「已啟用且一切為零」")
	}
	if offsiteUploaderRunning() {
		t.Fatal("設定表零列時竟啟動了上傳 worker goroutine")
	}
}

// TestOffsiteDisabledStateKeepsRetrievalAndInventory 停用態：零 worker、存量面仍在、取回子系統仍組裝。
//
// 停用態表的第二欄逐格對照。與零列態**分立**——合併之後
// 「停用時整組消失」與「停用時只少了車道」會用同一個斷言通過。
func TestOffsiteDisabledStateKeepsRetrievalAndInventory(t *testing.T) {
	now := time.Now()
	env, g := runStage2ForOffsite(t, func(t *testing.T) {
		retired := now.Add(-time.Hour)
		row := model.OffsiteProfile{
			ProfileFingerprint: "abcdef0123456789",
			Singleton:          1,
			Provider:           "s3",
			Endpoint:           "https://minio.example.internal:9000",
			Bucket:             "evidence",
			Region:             "us-east-1",
			CredentialMode:     model.OffsiteCredentialDefaultChain,
			CreatedAt:          retired,
			ActivatedAt:        retired,
			RetiredAt:          &retired, // 停用態＝有歷史世代、零現行世代
		}
		if err := database.DB.Create(&row).Error; err != nil {
			t.Fatalf("預置已退役世代失敗: %v", err)
		}
		// **帳冊必須有列，存量面的斷言才有內容**：空的 GaugeVec 在 Prometheus
		// 文字格式下本來就不輸出任何一行（那是正確語義——沒有失敗件就沒有序列），
		// 拿空帳冊去斷言「序列存在」等於驗一個永遠不成立的命題
		for i, state := range []string{"foreign", "failed", "integrity_mismatch"} {
			obj := model.OffsiteObject{
				// owner_id 各異：唯一鍵是 (kind, owner_id, storage_generation_id)
				Kind: "recording", OwnerID: uint(i + 1), Origin: "live", Provider: "s3",
				StorageGenerationID: row.GenerationID,
				Bucket:              "evidence", ObjectKey: "k-" + state, State: state,
			}
			if err := database.DB.Create(&obj).Error; err != nil {
				t.Fatalf("預置帳冊列（%s）失敗: %v", state, err)
			}
		}
	})

	// 背景刷新的首刷在自己的 goroutine 內，等它把快照寫進去（上限 3 秒）
	body := waitForMetric(t, env.s1.metrics, "custodexa_offsite_foreign")
	for _, name := range []string{
		"custodexa_offsite_failed",
		"custodexa_offsite_integrity_mismatch",
		"custodexa_offsite_foreign",
		"custodexa_offsite_generations",
		"custodexa_offsite_spool_bytes",
		"custodexa_offsite_credential_state",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("停用態下 %s 缺席：停用不代表既有物件消失，"+
				"管理員仍需看得見「還有幾件從未上傳成功」", name)
		}
	}
	for _, name := range []string{
		"custodexa_offsite_pending",
		"custodexa_offsite_uploading",
		"custodexa_offsite_oldest_pending_age_seconds",
		"custodexa_offsite_last_success_timestamp_seconds",
		"custodexa_offsite_uploads_total",
		"custodexa_offsite_uploaded_bytes_total",
		"custodexa_offsite_lease_expired_total",
	} {
		if strings.Contains(body, name) {
			t.Errorf("停用態下 %s 竟存在：worker 不在跑而序列還在，"+
				"採集端讀到的「待上傳為 0」與「一切正常且無事可做」無從分辨", name)
		}
	}
	if offsiteUploaderRunning() {
		t.Error("停用態竟啟動了上傳 worker goroutine")
	}

	// 取回子系統**照常組裝**（停用態表第二列）：停用之後歷史物件仍須取得回
	built := strings.Join(g.ServiceNames(), ",")
	for _, name := range []string{"offsiteProfiles", "offsiteLedger"} {
		if !strings.Contains(built, name) {
			t.Errorf("停用態下 %s 未組裝：歷史世代的取回將無從進行", name)
		}
	}
}

// TestOffsiteLedgerContinuityFailureRollsBackStage2 健檢失敗＝段 2 建構失敗且整筆回滾。
//
// 帳冊列指向一個不存在的設定世代＝資料損壞（部分還原、DB 手術）。此時繼續啟動，
// 取回只能「拿現行設定去猜」——猜錯的形態是拿另一個 bucket 的憑證去要一份證據，
// 而失敗訊息會指向網路或權限，沒有人會想到是世代對不上。
//
// 本格同時補上驗收條款裡的「`Stage2InjectedFailureRollsBack` 對
// 健檢失敗情境」——既有那一支注入的是取消，注入點在 offsiteLedger 之後。
func TestOffsiteLedgerContinuityFailureRollsBackStage2(t *testing.T) {
	env := newSealIntegrationEnv(t)

	orphan := model.OffsiteObject{
		Kind: "recording", OwnerID: 1, Origin: "live", Provider: "s3",
		StorageGenerationID: 999, // 世代表裡沒有這一列
		Bucket:              "evidence", ObjectKey: "k", State: "uploaded",
	}
	if err := database.DB.Create(&orphan).Error; err != nil {
		t.Fatalf("預置孤兒帳冊列失敗: %v", err)
	}

	kek, err := buildUIKEKProvider([]byte(testInitialKEK))
	if err != nil {
		t.Fatalf("建構 KEK provider 失敗: %v", err)
	}
	g, err := runStage2(context.Background(), env.s1, kek)
	if err == nil {
		t.Fatal("帳冊指向不存在的世代時段 2 竟成功：取回將以「用現行設定猜」收場")
	}
	if !strings.Contains(err.Error(), "offsiteLedger") {
		t.Fatalf("失敗未落在 offsiteLedger 步驟：%v", err)
	}
	// 訊息須指名對不上的世代與物件數，且**不含端點**
	if !strings.Contains(err.Error(), "999") {
		t.Errorf("失敗訊息未指名對不上的世代，管理員無從著手：%v", err)
	}
	if strings.Contains(err.Error(), "minio.example.internal") ||
		strings.Contains(err.Error(), "://") {
		t.Errorf("失敗訊息夾帶端點：%v", err)
	}
	if g == nil {
		t.Fatal("段 2 失敗回傳 nil 圖：已取得的資源將無人收束")
	}
	rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := g.Release(rctx); err != nil {
		t.Fatalf("半建構圖收束失敗: %v", err)
	}
	if offsiteUploaderRunning() {
		t.Error("健檢失敗後竟仍有上傳 worker goroutine")
	}
}

// TestOffsiteUploadResultConstantsMatchMetricsLabels 兩包各自定義的結果標籤必須同值。
//
// `internal/offsite` 刻意不 import observability（模組邊界），代價是同一組字串
// 在兩處各有一份。值一旦漂移，worker 寫進去的是一個沒有人在查的標籤，
// 而 `/metrics` 上那條序列會永遠停在 0——兩邊都不會有任何東西轉紅。
func TestOffsiteUploadResultConstantsMatchMetricsLabels(t *testing.T) {
	if got, want := offsite.UploadResultUploaded, observability.OffsiteUploadResultUploaded; got != want {
		t.Errorf("uploaded 標籤不一致：offsite=%q observability=%q", got, want)
	}
	if got, want := offsite.UploadResultFailed, observability.OffsiteUploadResultFailed; got != want {
		t.Errorf("failed 標籤不一致：offsite=%q observability=%q", got, want)
	}
	// 憑證三態的全集同樣是兩份（observability 抄了一份）
	want := []string{"unconfigured", "ok", "failed"}
	if len(observability.OffsiteCredentialStates) != len(want) {
		t.Fatalf("憑證三態全集長度 = %d, want %d", len(observability.OffsiteCredentialStates), len(want))
	}
	for i, s := range want {
		if observability.OffsiteCredentialStates[i] != s {
			t.Errorf("憑證態第 %d 項 = %q, want %q", i, observability.OffsiteCredentialStates[i], s)
		}
	}
}
