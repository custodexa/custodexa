package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 候選憑證零外洩的**行為式**守衛。
//
// 為何不用結構式（檢查 struct tag）：那只擋得住「直接序列化 model」這一種寫法，
// handler 自己拼一個 gin.H 把欄位塞進去照樣洩漏。本測試種入已知明文，
// 逐一打過全部改密相關端點，對回應體做字串比對——任何形態的洩漏都會被抓到。

const (
	leakProbePassword   = "PROBE-cand-password-8Xq2"
	leakProbePrivateKey = "PROBE-cand-privatekey-7Zt9"
	// leakProbeAssetPassword 由**真的跑 runner** 的資產所持有的舊憑證。
	// 只種候選列證明不了 runner 的寫入端安全——runner 會把憑證與遠端訊息
	// 寫進 record.error／candidate.last_error，那是兩條獨立的反射通道
	leakProbeAssetPassword = "PROBE-asset-oldpw-5Kd3"
)

func setupCandidateLeakEnv(t *testing.T) (*ChangeSecretHandler, *gorm.DB, *model.ChangeSecretCandidate) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.AuditLog{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetHostKey{},
		&model.ChangeSecretPlan{}, &model.ChangeSecretRecord{}, &model.ChangeSecretCandidate{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	if err := db.Create(&model.Asset{Name: "a1", Protocol: "ssh", Host: "127.0.0.1", Port: 1,
		CreatedBy: 1, Active: true}).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := db.Create(&model.AssetAccount{AssetID: 1, Username: "root", IsDefault: true}).Error; err != nil {
		t.Fatalf("seed account: %v", err)
	}

	codec := aesColumnCodec(t, make([]byte, 32))
	assetSvc, err := asset.NewAssetService(codec, "localhost", 4822, audit.NewTxSink())
	if err != nil {
		t.Fatalf("asset service: %v", err)
	}
	candidates, err := asset.NewChangeSecretCandidateService(db, codec, assetSvc, audit.NewTxSink())
	if err != nil {
		t.Fatalf("candidate service: %v", err)
	}
	hostKeys := asset.NewHostKeyService(db)
	runner := asset.NewChangeSecretRunner(db, assetSvc, candidates, hostKeys, nil)
	retry := asset.NewChangeSecretRetryRunner(db, candidates, assetSvc, hostKeys, nil)
	planSvc := asset.NewChangeSecretPlanService(db)

	cand, err := candidates.Create(context.Background(), asset.CandidateInput{
		AssetID: 1, AccountID: 1, AccountUsername: "root",
		SecretType: model.ChangeSecretTypeSSHKey,
		Password:   leakProbePassword, PrivateKey: leakProbePrivateKey,
		PublicKey: "ssh-ed25519 AAAApub probe",
	})
	if err != nil {
		t.Fatalf("seed candidate: %v", err)
	}
	// 前置條件：密文確實落庫（否則本測試會在空資料下假綠）
	var stored model.ChangeSecretCandidate
	if err := db.First(&stored, cand.ID).Error; err != nil {
		t.Fatalf("read back candidate: %v", err)
	}
	if stored.PasswordEnc == "" || stored.PrivateKeyEnc == "" {
		t.Fatal("候選密文未落庫：零外洩斷言將由空值假綠")
	}
	if strings.Contains(stored.PasswordEnc, leakProbePassword) {
		t.Fatal("候選密碼以明文落庫：加密未生效")
	}

	// 第二台資產走**真的 runner**：帳號憑證經 asset service 加密落庫，
	// 主機指向保證連不上的位址，runner 因而產生自己的新秘密、建候選、
	// 失敗後寫 record.error。這條路徑才驗得到「runner 產生的秘密不外洩」
	target, err := assetSvc.Create(&asset.CreateAssetRequest{
		Name: "runner-target", Protocol: model.ProtocolSSH,
		Host: "127.0.0.1", Port: 1, Username: "root",
		Password: leakProbeAssetPassword, CreatedBy: 1,
	})
	if err != nil {
		t.Fatalf("seed runner target: %v", err)
	}
	ids, _ := json.Marshal([]uint{target.ID})
	scope, _ := json.Marshal([]string{model.AccountScopeAll})
	plan := &model.ChangeSecretPlan{
		Name: "leak-probe-plan", AssetIDs: string(ids), Accounts: string(scope),
		Enabled: true, SecretType: model.ChangeSecretTypePassword,
		KeyStrategy: model.KeyStrategyAppendReplace, PasswordLength: 16,
		PasswordIncludeSymbol: true, PasswordExcludeAmbiguous: true,
	}
	if err := db.Create(plan).Error; err != nil {
		t.Fatalf("seed plan: %v", err)
	}
	recs := runner.RunPlan(plan)
	if len(recs) == 0 {
		t.Fatal("runner 未產生任何記錄：反射面斷言將由空資料假綠")
	}

	handler := NewChangeSecretHandler(planSvc, runner, candidates, retry, nil)
	return handler, db, &stored
}

// candidateRouter 掛上改密的全部端點（計劃側 6 支＋候選側 3 支），
// 與 RegisterRoutes 的清單逐支對齊——漏掛任何一支即等於該端點未被守衛
func candidateRouter(h *ChangeSecretHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "admin")
		c.Set("role", "admin")
	})
	r.GET("/change-secret-candidates", h.ListCandidates)
	r.POST("/change-secret-candidates/:id/retry", h.RetryCandidate)
	r.DELETE("/change-secret-candidates/:id", h.DiscardCandidate)
	r.GET("/change-secret-plans", h.List)
	r.GET("/change-secret-plans/:id/records", h.Records)
	return r
}

// reasonValues 取出回應 data 陣列中每個項目的 error／last_error 值。
// 這兩欄是 runner 唯一能把字串送到 API 的通道，故守衛須逐值檢查其形狀
func reasonValues(t *testing.T, body, field string) []string {
	t.Helper()
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("回應非預期 JSON 形狀（%s）: %v", field, err)
	}
	var out []string
	for _, item := range payload.Data {
		if v, ok := item[field].(string); ok {
			out = append(out, v)
		}
	}
	return out
}

func TestChangeSecretCandidateSecretsNeverLeakThroughAPI(t *testing.T) {
	h, _, stored := setupCandidateLeakEnv(t)
	r := candidateRouter(h)

	// DELETE 排在最後：它會刪掉候選列，先跑會讓其後端點的比對面變空
	type call struct{ method, path string }
	calls := []call{
		{"GET", "/change-secret-candidates"},
		{"POST", "/change-secret-candidates/1/retry"},
		{"GET", "/change-secret-plans"},
		{"GET", "/change-secret-plans/1/records"},
		{"GET", "/change-secret-plans/2/records"},
		{"DELETE", "/change-secret-candidates/1"},
	}
	forbidden := []struct{ name, value string }{
		{"候選密碼明文", leakProbePassword},
		{"候選私鑰明文", leakProbePrivateKey},
		{"候選密碼密文", stored.PasswordEnc},
		{"候選私鑰密文", stored.PrivateKeyEnc},
		{"加密欄位名 password_enc", "password_enc"},
		{"加密欄位名 private_key_enc", "private_key_enc"},
		{"runner 目標資產的舊憑證明文", leakProbeAssetPassword},
	}

	hitBodies := 0
	seenReasons := 0
	for _, c := range calls {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(c.method, c.path, nil))
		if w.Code >= http.StatusInternalServerError {
			t.Fatalf("%s %s 回 %d：端點未被真正執行，洩漏斷言將由錯誤回應假綠（body=%s）",
				c.method, c.path, w.Code, w.Body.String())
		}
		body := w.Body.String()
		if body != "" {
			hitBodies++
		}
		for _, f := range forbidden {
			if strings.Contains(body, f.value) {
				t.Fatalf("%s %s 的回應含%s：候選憑證 SHALL NOT 出現於任何 API 回應",
					c.method, c.path, f.name)
			}
		}
		// 反射欄位的形狀：error／last_error 只能是封閉集合內的原因碼。
		// 任何遠端原文或庫錯誤字串被拼進來，都會落在集合外——這是「訊息含秘密」
		// 這類洩漏的通用攔截（遮蔽式比對只擋得住已知的那一個秘密）
		if w.Code < http.StatusBadRequest {
			for _, field := range []string{"error", "last_error"} {
				for _, v := range reasonValues(t, body, field) {
					if !model.IsChangeSecretReason(v) {
						t.Fatalf("%s %s 回應的 %s=%q 不是原因碼：有動態字串被拼入反射欄位",
							c.method, c.path, field, v)
					}
					if v != "" {
						seenReasons++
					}
				}
			}
		}
	}
	if seenReasons == 0 {
		t.Fatal("回應中沒有任何非空的 error／last_error：形狀斷言由空值假綠")
	}
	if hitBodies < len(calls) {
		t.Fatalf("只有 %d/%d 個端點回了非空 body：比對面不完整", hitBodies, len(calls))
	}

	// 反向自證：同一組比對規則對「真的含秘密的字串」必須命中，
	// 否則上面的全綠只證明比對邏輯壞掉
	sentinel := `{"password_enc":"` + stored.PasswordEnc + `"}`
	matched := 0
	for _, f := range forbidden {
		if strings.Contains(sentinel, f.value) {
			matched++
		}
	}
	if matched < 2 {
		t.Fatalf("比對規則對哨兵字串只命中 %d 項：本守衛的比對面失效", matched)
	}
}

// TestChangeSecretCandidateModelIsNotSerializedDirectly 型別層的第二道：
// 即使有人把 model 直接 JSON 化，兩個密文欄位也不得出現。
func TestChangeSecretCandidateModelIsNotSerializedDirectly(t *testing.T) {
	_, _, stored := setupCandidateLeakEnv(t)
	w := httptest.NewRecorder()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/raw", func(c *gin.Context) { c.JSON(http.StatusOK, stored) })
	r.ServeHTTP(w, httptest.NewRequest("GET", "/raw", nil))

	body := w.Body.String()
	if strings.Contains(body, stored.PasswordEnc) || strings.Contains(body, stored.PrivateKeyEnc) {
		t.Fatal("model 直接序列化仍帶出密文：兩個加密欄位 SHALL 標 json:\"-\"")
	}
	if !strings.Contains(body, "account_username") {
		t.Fatal("序列化結果不含預期欄位：本斷言由空回應假綠")
	}
}
