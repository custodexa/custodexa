package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
)

// 上傳 worker 熱啟動的組裝面驗收。
//
// 包內測試證明「設定服務在寫入後呼叫了啟動回呼」，但**誰把回呼接上去**是組裝根
// 的事：漏接一行不會有編譯錯誤，症狀是零列啟動的部署在管理員完成設定之後
// 帳冊照排、無人領件，一路積到下次重啟。
//
// 判準一律是**真實堆疊上的 goroutine**（沿本包既有的判準）：日誌可以被改寫，
// 正在跑的迴圈不會。

// offsiteUploaderGoroutines 全行程堆疊上的上傳迴圈條數。
//
// **回條數而非布林**：接線寫成「每次儲存都 go Run(...)」時 worker 確實在跑，
// 布林判準全綠，而兩條迴圈會各自領同一批件。
func offsiteUploaderGoroutines() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), offsiteUploaderGoroutineSymbol)
}

// waitForUploaderGoroutines 等堆疊上的迴圈條數達到期望值（起 goroutine 非同步）。
func waitForUploaderGoroutines(t *testing.T, want int, why string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if offsiteUploaderGoroutines() == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s：上傳迴圈條數 = %d, want %d", why, offsiteUploaderGoroutines(), want)
}

// offsiteAdminRouter 以段 2 的服務圖建一個可直接打的 router 與 admin bearer。
//
// **走真的路由與真的 handler**：本組要驗的是「管理員在管理介面按下儲存」這條路
// 的終點有沒有把 worker 拉起來，而 handler 與設定服務之間也是接線
// （handler 拿到的若不是組裝根接過回呼的那個實例，症狀與完全沒接線相同）。
// 封印閘在此放行——本測試直呼段 2 的建構函式，狀態機並未真的解封過。
func offsiteAdminRouter(t *testing.T, env *sealIntegrationEnv, g *appGraph) (*gin.Engine, string) {
	t.Helper()
	deps := g.deps
	deps.sealGate = func(c *gin.Context) { c.Next() }
	deps.seal = env.handler
	r := gin.New()
	registerRoutes(r, deps)

	var admin model.User
	if err := database.DB.Where("username = ?", testAdminUser).First(&admin).Error; err != nil {
		t.Fatalf("讀取初始管理員失敗: %v", err)
	}
	email := ""
	if admin.Email != nil {
		email = *admin.Email
	}
	token, err := crypto.NewJWTManager(env.s1.cfg.Security.JWTSecret, time.Hour).
		GenerateToken(admin.ID, admin.Username, email, "admin", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("簽發管理員 token 失敗: %v", err)
	}
	return r, token
}

// putOffsiteSettings 以管理員身分打設定端點。
func putOffsiteSettings(t *testing.T, r *gin.Engine, token, bucket string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"provider": "s3", "endpoint": "https://minio.example.internal:9000",
		"bucket": bucket, "prefix": "custodexa", "region": "us-east-1", "path_style": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/offsite-storage/settings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("儲存離機設定回 %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"needs_confirmation":true`) {
		t.Fatalf("非預期的「需確認」回應（本格應直接寫入）: %s", w.Body.String())
	}
}

// TestOffsiteUploaderStartsOnFirstSaveWithoutRestart 零列啟動 → 管理介面完成設定 → worker 就位。
//
// 這是「設定改由管理介面進行」的前提：完成設定之後不需要重啟服務。
// 缺這條接線時，其後結束的每一場會話都會排入帳冊而沒有任何人領件。
func TestOffsiteUploaderStartsOnFirstSaveWithoutRestart(t *testing.T) {
	env, g := runStage2ForOffsite(t, nil)

	if offsiteUploaderRunning() {
		t.Fatal("前置條件不成立：設定表零列時就有上傳 worker 在跑")
	}
	r, token := offsiteAdminRouter(t, env, g)

	putOffsiteSettings(t, r, token, "evidence")
	waitForUploaderGoroutines(t, 1,
		"零列啟動的服務於管理介面完成首次設定後，上傳 worker 未被拉起（排入的證據將停在待上傳直到重啟）")

	// 第二次儲存（指紋相同＝就地更新）不得再放出一條迴圈
	putOffsiteSettings(t, r, token, "evidence")
	time.Sleep(100 * time.Millisecond)
	if got := offsiteUploaderGoroutines(); got != 1 {
		t.Fatalf("重複儲存後上傳迴圈 = %d, want 1：啟動回呼必須冪等", got)
	}
}

// TestOffsiteUploaderRunsWhenGenerationExistsAtStartup 啟動時已有現行世代 → worker 就位。
//
// 停用態表的第三欄（既有兩支各自釘住「零列」與「停用」都不起 worker，
// 「有現行世代就要起」反而沒有任何一支在盯——那一半才是功能本身）。
func TestOffsiteUploaderRunsWhenGenerationExistsAtStartup(t *testing.T) {
	runStage2ForOffsite(t, func(t *testing.T) {
		now := time.Now()
		row := model.OffsiteProfile{
			ProfileFingerprint: "abcdef0123456789",
			Singleton:          1,
			Provider:           "s3",
			Endpoint:           "https://minio.example.internal:9000",
			Bucket:             "evidence",
			Region:             "us-east-1",
			CredentialMode:     model.OffsiteCredentialDefaultChain,
			CreatedAt:          now,
			ActivatedAt:        now,
		}
		if err := database.DB.Create(&row).Error; err != nil {
			t.Fatalf("預置現行世代失敗: %v", err)
		}
	})
	waitForUploaderGoroutines(t, 1, "啟動時已有現行世代，上傳 worker 卻沒有在跑")
}

// TestOffsiteEnvSeedLeavesUploaderRunning env→DB 的初次 seed 之後 worker 直接就位。
//
// seed 跑在解封後遷移佇列，而該佇列在啟動步序上**早於**上傳 worker 的建立，
// 故 seed 建出的世代在啟動當下就讀得到，不需要另一條熱啟動路徑。
// 這一支盯的正是那個先後：把 seed 挪到 worker 之後，`.env` 首啟即用的部署
// 會安靜地少一輪上傳，而編譯與其餘測試全綠。
func TestOffsiteEnvSeedLeavesUploaderRunning(t *testing.T) {
	t.Setenv("OFFSITE_PROVIDER", "s3")
	t.Setenv("OFFSITE_S3_BUCKET", "evidence-seeded")
	t.Setenv("OFFSITE_S3_ENDPOINT", "https://minio.example.internal:9000")
	t.Setenv("OFFSITE_S3_REGION", "us-east-1")

	if i, j := indexOfRelease(stage2ServiceInventory, "postUnsealMigrations"),
		indexOfRelease(stage2ServiceInventory, "offsiteUploader"); i < 0 || j < 0 || i > j {
		t.Fatalf("啟動步序已變動（postUnsealMigrations=%d、offsiteUploader=%d）："+
			"env seed 不再早於上傳 worker 的建立，seed 出來的世代將等到下次重啟才被看見", i, j)
	}

	runStage2ForOffsite(t, func(t *testing.T) {
		// seed 的執行標記寫在 schema_migrations；整合環境以 model 清單建表，
		// 該表不在清單內（它屬 migration 機制本身），故此處補上
		if err := database.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
			version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)`).Error; err != nil {
			t.Fatalf("建立 schema_migrations 失敗: %v", err)
		}
	})

	var n int64
	if err := database.DB.Model(&model.OffsiteProfile{}).
		Where("retired_at IS NULL").Count(&n).Error; err != nil {
		t.Fatalf("計數現行世代失敗: %v", err)
	}
	if n != 1 {
		t.Fatalf("env seed 未建出現行世代（實得 %d 列）：本格的前提不成立", n)
	}
	waitForUploaderGoroutines(t, 1, "env seed 建出世代之後上傳 worker 沒有在跑")
}
