package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
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

// allowAllAssetPermissions 資產權限判定的全放行樁。
//
// 本檔驗的是回應體的洩漏面，不是授權面：判定器是輪替引擎的建構期必填相依，
// 此處只需要它有值。授權面的行為鎖定在憑證服務與輪替引擎自己的測試裡
type allowAllAssetPermissions struct{}

func (allowAllAssetPermissions) CheckPermission(context.Context, uint, uint,
	model.PermissionType) (bool, error) {
	return true, nil
}

func setupCandidateLeakEnv(t *testing.T) (*ChangeSecretHandler, *CredentialHandler, *gorm.DB, *model.ChangeSecretCandidate) {
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
	if err := db.AutoMigrate(&model.Asset{}, &model.AssetAccount{}, &model.Credential{}, &model.CredentialSecretVersion{}, &model.AuditLog{},
		&model.AssetGroup{}, &model.AssetNode{}, &model.AssetHostKey{},
		&model.ChangeSecretPlan{}, &model.ChangeSecretRecord{}, &model.ChangeSecretCandidate{},
		&model.ChangeSecretBatch{},
		&model.CredentialRotation{}, &model.CredentialRotationMember{}); err != nil {
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

	// 批次側同樣走真的 runner：整批同一組模式對同一台連不上的目標跑一次，
	// 產生批次列與批次記錄——批次端點的反射面才有東西可比
	reports := asset.NewRotationReportBuilder(db, planSvc, func() int { return 0 })
	batches := asset.NewChangeSecretBatchService(db, reports)
	batch, assetIDs, err := batches.Create(&asset.ChangeSecretBatchRequest{
		Username: "root", All: true, PasswordMode: model.BatchPasswordShared,
		CredentialName: "洩漏面探針批次",
	}, 1, "admin")
	if err != nil {
		t.Fatalf("seed batch: %v", err)
	}
	if len(runner.RunBatch(batch, assetIDs)) == 0 {
		t.Fatal("批次未產生任何記錄：批次端點的反射面斷言將由空資料假綠")
	}

	// 憑證庫端點同樣是候選與憑證密文的反射面：憑證詳情帶掛載清單與版本序號，
	// 改密進度帶逐成員的失敗原因——兩者都是「把字串送到 API」的通道
	creds := asset.NewCredentialService(assetSvc, codec, audit.NewTxSink())
	rotations := asset.NewCredentialRotationService(db, assetSvc, candidates, hostKeys,
		codec, audit.NewTxSink(), allowAllAssetPermissions{})

	handler := NewChangeSecretHandler(planSvc, runner, candidates, retry, batches, nil)
	return handler, NewCredentialHandler(creds, rotations, reports), db, &stored
}

// candidateRouter 掛上改密的全部讀取與反射端點（計劃側、候選側、批次側），
// 與 RegisterRoutes 的清單逐支對齊——漏掛任何一支即等於該端點未被守衛
func candidateRouter(h *ChangeSecretHandler, c *CredentialHandler) *gin.Engine {
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
	r.GET("/change-secret-batches/usernames", h.BatchUsernames)
	r.GET("/change-secret-batches/targets", h.BatchTargets)
	r.GET("/change-secret-batches", h.ListBatches)
	r.POST("/change-secret-batches", h.CreateBatch)
	r.GET("/change-secret-batches/:id", h.GetBatch)
	// 憑證庫：**全部**端點（讀取面逐支、寫入面取會回投影的那幾支）。
	// 與 CredentialHandler.RegisterRoutes 的清單逐支對齊——漏掛任何一支
	// 即等於該端點未被本守衛涵蓋
	r.GET("/credentials", c.List)
	r.POST("/credentials", c.Create)
	r.GET("/credentials/:id", c.Get)
	r.PUT("/credentials/:id", c.Update)
	r.DELETE("/credentials/:id", c.Delete)
	r.POST("/credentials/:id/bindings", c.Bind)
	r.DELETE("/credentials/:id/bindings/:accountId", c.Unbind)
	r.POST("/credentials/:id/bindings/:accountId/detach", c.Detach)
	r.POST("/credentials/:id/scope", c.ConvertScope)
	r.POST("/credentials/:id/secret", c.SetSecret)
	r.POST("/credentials/:id/rotations", c.StartRotation)
	r.GET("/credentials/:id/rotations/:rid", c.GetRotation)
	r.POST("/credentials/:id/rotations/:rid/members/:mid/retry", c.RetryMember)
	r.POST("/credentials/:id/rotations/:rid/abandon", c.AbandonRotation)
	r.PUT("/assets/:id/accounts/:accountId/credential", c.RebindAccount)
	return r
}

// credentialRoutesFromRegistrar 由 CredentialHandler.RegisterRoutes 推導出的憑證端點集合。
//
// **不手抄**：手抄的清單與真實註冊之間會靜默分岔，而分岔的失敗方向是低報——
// 漏抄一支的症狀是那支端點的回應從未被掃過，而本守衛照樣全綠。
// 探針引擎只用來讀路由表，不服務任何請求，故認證服務傳 nil 無妨。
func credentialRoutesFromRegistrar() map[string]bool {
	gin.SetMode(gin.TestMode)
	probe := gin.New()
	(&CredentialHandler{}).RegisterRoutes(probe.Group(""), nil)
	out := map[string]bool{}
	for _, route := range probe.Routes() {
		out[route.Method+" "+route.Path] = true
	}
	return out
}

// assertCredentialRoutesFullyMounted 守衛掛入的憑證端點與註冊器逐支相等。
func assertCredentialRoutesFullyMounted(t *testing.T, r *gin.Engine) {
	t.Helper()
	want := credentialRoutesFromRegistrar()
	got := map[string]bool{}
	for _, route := range r.Routes() {
		if strings.Contains(route.Path, "credential") {
			got[route.Method+" "+route.Path] = true
		}
	}
	if len(want) == 0 {
		t.Fatal("註冊器推導出零支憑證端點：本比對將在空集合上假綠")
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("憑證端點 %s 未掛入本守衛：該端點的回應從未被掃過", k)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("守衛掛入 %d 支憑證端點、註冊器有 %d 支：兩份清單已分岔", len(got), len(want))
	}
}

// reasonValues 取出回應 data 中每個項目的 error／last_error 值。
// 這兩欄是 runner 唯一能把字串送到 API 的通道，故守衛須逐值檢查其形狀。
// data 可能是陣列（清單端點）或物件（單一批次：{batch, records}），
// 後者的記錄陣列同樣要檢查
func reasonValues(t *testing.T, body, field string) []string {
	t.Helper()
	var payload struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("回應非預期 JSON 形狀（%s）: %v", field, err)
	}
	var items []map[string]any
	if len(payload.Data) > 0 && payload.Data[0] == '{' {
		var obj struct {
			Records []map[string]any `json:"records"`
		}
		if err := json.Unmarshal(payload.Data, &obj); err != nil {
			t.Fatalf("回應 data 物件非預期形狀（%s）: %v", field, err)
		}
		items = obj.Records
	} else if len(payload.Data) > 0 {
		if err := json.Unmarshal(payload.Data, &items); err != nil {
			t.Fatalf("回應 data 陣列非預期形狀（%s）: %v", field, err)
		}
	}
	var out []string
	for _, item := range items {
		if v, ok := item[field].(string); ok {
			out = append(out, v)
		}
	}
	return out
}

func TestChangeSecretCandidateSecretsNeverLeakThroughAPI(t *testing.T) {
	h, credHandler, db, stored := setupCandidateLeakEnv(t)
	r := candidateRouter(h, credHandler)
	assertCredentialRoutesFullyMounted(t, r)

	// 憑證密文版本的密文本體：憑證庫端點的比對面（候選密文之外的第二組秘密落點）
	var versions []model.CredentialSecretVersion
	if err := db.Find(&versions).Error; err != nil {
		t.Fatalf("read credential versions: %v", err)
	}
	if len(versions) == 0 {
		t.Fatal("零筆密文版本：憑證庫端點的洩漏斷言將由空資料假綠")
	}

	// DELETE 排在最後：它會刪掉候選列，先跑會讓其後端點的比對面變空。
	// 批次的 POST 不在清單內：它非同步啟動 runner，回應體與單一批次端點的 batch
	// 投影是同一個 DTO，而測試結束後仍在跑的 runner 會撞上已還原的全域 DB
	type call struct{ method, path, body string }
	calls := []call{
		{"GET", "/change-secret-candidates", ""},
		{"POST", "/change-secret-candidates/1/retry", ""},
		{"GET", "/change-secret-plans", ""},
		{"GET", "/change-secret-plans/1/records", ""},
		{"GET", "/change-secret-plans/2/records", ""},
		{"GET", "/change-secret-batches/usernames", ""},
		{"GET", "/change-secret-batches/targets?username=root", ""},
		{"GET", "/change-secret-batches", ""},
		{"GET", "/change-secret-batches/1", ""},
		{"GET", "/credentials", ""},
		{"GET", "/credentials?scope=shared", ""},
		{"GET", "/credentials/1", ""},
		{"GET", "/credentials/2", ""},
		{"GET", "/credentials/1/rotations/1", ""},
		{"POST", "/credentials", `{"name":"洩漏面探針憑證","username":"probe","protocol_family":"ssh","password":"` + leakProbeAssetPassword + `"}`},
		{"PUT", "/credentials/1", `{"note":"probe"}`},
		{"POST", "/credentials/1/scope", `{"scope":"shared","name":"探針轉共用"}`},
		{"POST", "/credentials/1/secret", `{"password":"` + leakProbeAssetPassword + `"}`},
		{"POST", "/credentials/1/bindings", `{"asset_id":1}`},
		{"POST", "/credentials/1/rotations", `{"mode":"nope"}`},
		{"POST", "/credentials/1/rotations/1/members/1/retry", ""},
		{"POST", "/credentials/1/rotations/1/abandon", ""},
		{"POST", "/credentials/1/bindings/1/detach", `{"source":"bogus"}`},
		{"PUT", "/assets/1/accounts/1/credential", `{"credential_id":1}`},
		{"DELETE", "/credentials/1/bindings/1", ""},
		{"DELETE", "/credentials/1", ""},
		{"DELETE", "/change-secret-candidates/1", ""},
	}
	forbidden := []struct{ name, value string }{
		{"候選密碼明文", leakProbePassword},
		{"候選私鑰明文", leakProbePrivateKey},
		{"候選密碼密文", stored.PasswordEnc},
		{"候選私鑰密文", stored.PrivateKeyEnc},
		{"加密欄位名 password_enc", "password_enc"},
		{"加密欄位名 private_key_enc", "private_key_enc"},
		{"runner 目標資產的舊憑證明文", leakProbeAssetPassword},
		{"憑證群組識別欄位名 shared_group", "shared_group"},
		{"憑證群組識別欄位名 credential_group", "credential_group"},
	}
	for i := range versions {
		if versions[i].PasswordEnc != "" {
			forbidden = append(forbidden, struct{ name, value string }{
				"憑證密文版本的密碼密文", versions[i].PasswordEnc})
		}
		if versions[i].PrivateKeyEnc != "" {
			forbidden = append(forbidden, struct{ name, value string }{
				"憑證密文版本的私鑰密文", versions[i].PrivateKeyEnc})
		}
	}
	hitBodies := 0
	seenReasons := 0
	for _, c := range calls {
		w := httptest.NewRecorder()
		var reqBody io.Reader
		if c.body != "" {
			reqBody = strings.NewReader(c.body)
		}
		req := httptest.NewRequest(c.method, c.path, reqBody)
		if c.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		r.ServeHTTP(w, req)
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
	_, _, _, stored := setupCandidateLeakEnv(t)
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
