package offsite

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
)

// GCS 憑證內容與端點的出站邊界測試。
//
// 判準只有一條：受管憑證與平台自身的雲端身分只會被用在設定所指的目標上。
// 因此每一格都用「收件端有沒有收到請求」當觀測點，而不是只看回傳的錯誤——
// 錯誤可能來自前置失敗（缺 ADC、TLS 驗證失敗），不代表沒有送出。

const (
	reasonGCSCredentialInvalid       = "offsite.gcs_credential_invalid"
	reasonGCSEndpointNeedsCredential = "offsite.gcs_endpoint_needs_credential"
	officialTokenURI                 = "https://oauth2.googleapis.com/token"

	// minimalServiceAccountJSON 只過內容檢查、不會被 SDK 實際載入的服務帳號 JSON
	// （供使用假 driver 的測試；私鑰欄是占位字串）。
	minimalServiceAccountJSON = `{"type":"service_account","client_email":"sa@example.iam","private_key":"k","token_uri":"https://oauth2.googleapis.com/token"}`
)

// egressRecorder 記錄收到的每一筆請求；/token 與 /sts 兩個路徑回合法的權杖回應。
type egressRecorder struct {
	mu   sync.Mutex
	reqs []egressReq
}

type egressReq struct {
	Path string
	Auth string
	Body string
}

func (r *egressRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<16))
	r.mu.Lock()
	r.reqs = append(r.reqs, egressReq{Path: req.URL.Path, Auth: req.Header.Get("Authorization"), Body: string(body)})
	r.mu.Unlock()
	if strings.HasPrefix(req.URL.Path, "/token") || strings.HasPrefix(req.URL.Path, "/sts") {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-access","token_type":"Bearer","expires_in":3600}`))
		return
	}
	http.NotFound(w, req)
}

// total 所有請求數。
func (r *egressRecorder) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reqs)
}

// tokenCount 權杖端點收到的請求數。
func (r *egressRecorder) tokenCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, q := range r.reqs {
		if strings.HasPrefix(q.Path, "/token") || strings.HasPrefix(q.Path, "/sts") {
			n++
		}
	}
	return n
}

// bearerCount 非權杖路徑上帶 Authorization 標頭的請求數。
func (r *egressRecorder) bearerCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, q := range r.reqs {
		if strings.HasPrefix(q.Path, "/token") || strings.HasPrefix(q.Path, "/sts") {
			continue
		}
		if q.Auth != "" {
			n++
		}
	}
	return n
}

func newEgressServer(t *testing.T) (*httptest.Server, *egressRecorder) {
	t.Helper()
	rec := &egressRecorder{}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	return srv, rec
}

func newEgressTLSServer(t *testing.T) (*httptest.Server, *egressRecorder) {
	t.Helper()
	rec := &egressRecorder{}
	srv := httptest.NewTLSServer(rec)
	t.Cleanup(srv.Close)
	return srv, rec
}

var (
	testKeyOnce sync.Once
	testKeyPEM  string
)

// testPrivateKeyPEM 測試專用的一次性 RSA 私鑰（只用來讓 JWT 簽章可進行）。
func testPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	testKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("產生測試金鑰失敗: %v", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatalf("編碼測試金鑰失敗: %v", err)
		}
		testKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})
	return testKeyPEM
}

// serviceAccountJSON 組一份服務帳號金鑰 JSON；tokenURI 空則用官方值。
func serviceAccountJSON(t *testing.T, tokenURI string) string {
	t.Helper()
	if tokenURI == "" {
		tokenURI = officialTokenURI
	}
	b, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "test-project",
		"private_key_id": "key-1",
		"private_key":    testPrivateKeyPEM(t),
		"client_email":   "sa@test-project.iam.gserviceaccount.com",
		"client_id":      "1",
		"token_uri":      tokenURI,
	})
	if err != nil {
		t.Fatalf("序列化測試憑證失敗: %v", err)
	}
	return string(b)
}

// externalAccountJSON 組一份外部帳號型別的憑證 JSON（讀本機檔、向 tokenURL 換權杖）。
func externalAccountJSON(t *testing.T, subjectFile, tokenURL string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type":               "external_account",
		"audience":           "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/x",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"token_url":          tokenURL,
		"credential_source":  map[string]string{"file": subjectFile},
	})
	if err != nil {
		t.Fatalf("序列化測試憑證失敗: %v", err)
	}
	return string(b)
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("寫暫存檔失敗: %v", err)
	}
	return p
}

// gcsInput 一組 gcs 設定輸入。
func gcsInput(bucket, endpoint, credJSON string) SettingsInput {
	return SettingsInput{Provider: ProviderGCS, Bucket: bucket, Prefix: "custodexa",
		Endpoint: endpoint, ServiceAccountJSON: credJSON}
}

// insertGeneration 直接寫入一個世代列（模擬升級前就存在的資料狀態）。
func insertGeneration(t *testing.T, rig *offsiteTestRig, provider, mode, endpoint, bucket, plainCred string, retired bool) model.OffsiteProfile {
	t.Helper()
	enc := ""
	if plainCred != "" {
		var err error
		enc, err = rig.codec.EncryptFor(context.Background(), keyvault.RefOffsiteCredentials, plainCred)
		if err != nil {
			t.Fatalf("加密測試憑證失敗: %v", err)
		}
	}
	now := time.Now()
	row := model.OffsiteProfile{
		ProfileFingerprint: "0123456789abcdef", Singleton: 1,
		Provider: provider, Endpoint: endpoint, Bucket: bucket, Prefix: "custodexa",
		CredentialMode: mode, CredentialsEnc: enc, CredentialRevision: 1,
		CreatedAt: now, ActivatedAt: now,
	}
	if mode == model.OffsiteCredentialRevoked {
		row.CredentialsClearedAt = &now
	}
	if retired {
		row.RetiredAt = &now
	}
	if err := rig.db.Create(&row).Error; err != nil {
		t.Fatalf("寫入世代列失敗: %v", err)
	}
	return row
}

// digestOf 世代切換確認的摘要（不經驗證核心，只由正規化後的欄位算出）。
func digestOf(in SettingsInput, intent string) string {
	n := normalizedSettings{Provider: in.Provider, Bucket: in.Bucket, Prefix: in.Prefix, credentialIntent: intent}
	if in.Endpoint != "" {
		n.EndpointFull, _ = NormalizeEndpointFull(in.Endpoint)
	}
	return n.settingsDigest()
}

func generationCount(t *testing.T, rig *offsiteTestRig) int64 {
	t.Helper()
	var n int64
	if err := rig.db.Model(&model.OffsiteProfile{}).Count(&n).Error; err != nil {
		t.Fatalf("計數世代失敗: %v", err)
	}
	return n
}

// ── 憑證型別：外送面 ──────────────────────────────────────────────────

// TestGCSCredentialTypeEgress 測試連線收到非服務帳號型別的憑證時，
// 不得讀本機檔案、也不得對憑證內指定的位址發出任何請求。
func TestGCSCredentialTypeEgress(t *testing.T) {
	srv, rec := newEgressServer(t)
	subject := writeTempFile(t, "subject.txt", "subject-file-marker")
	rig := newOffsiteRig(t)
	rig.svc.SetClientFactoryForTest(DefaultClientFactory)

	in := gcsInput("bucket-x", srv.URL, externalAccountJSON(t, subject, srv.URL+"/sts"))
	_, err := rig.svc.TestSettings(context.Background(), in, OffsiteActor{ID: 1, Name: "admin"})

	if n := rec.tokenCount(); n != 0 {
		t.Fatalf("憑證內指定的權杖位址收到 %d 筆請求（本格要求零外送）；TestSettings err=%v", n, err)
	}
	if got := ReasonOf(err); got != reasonGCSCredentialInvalid {
		t.Fatalf("拒因 = %q, want %q（err=%v）", got, reasonGCSCredentialInvalid, err)
	}
	if err != nil && strings.Contains(err.Error(), "subject-file-marker") {
		t.Fatal("錯誤訊息不得回顯憑證內容")
	}
}

// TestGCSCredentialTypeReject 寫入入口（儲存、世代切換確認、seed）收到非服務帳號型別
// 的憑證時以靜態拒因拒絕，且世代、憑證版號與 seed 標記都不變。
func TestGCSCredentialTypeReject(t *testing.T) {
	subject := writeTempFile(t, "subject.txt", "subject-file-marker")
	bad := externalAccountJSON(t, subject, "http://127.0.0.1:1/sts")

	t.Run("Save", func(t *testing.T) {
		rig := newOffsiteRig(t)
		_, err := rig.svc.Save(context.Background(), gcsInput("bucket-x", "", bad), OffsiteActor{ID: 1})
		if got := ReasonOf(err); got != reasonGCSCredentialInvalid {
			t.Fatalf("拒因 = %q, want %q（err=%v）；世代數=%d", got, reasonGCSCredentialInvalid, err, generationCount(t, rig))
		}
		if n := generationCount(t, rig); n != 0 {
			t.Fatalf("被拒的儲存不得產生世代，實得 %d", n)
		}
	})

	t.Run("Save 不改現行世代的憑證版號", func(t *testing.T) {
		rig := newOffsiteRig(t)
		first := mustSave(t, rig, gcsInput("bucket-x", "", serviceAccountJSON(t, "")))
		before := profileRow(t, rig.db, first.View.GenerationID).CredentialRevision
		_, err := rig.svc.Save(context.Background(), gcsInput("bucket-x", "", bad), OffsiteActor{ID: 1})
		if got := ReasonOf(err); got != reasonGCSCredentialInvalid {
			t.Fatalf("拒因 = %q, want %q（err=%v）", got, reasonGCSCredentialInvalid, err)
		}
		if after := profileRow(t, rig.db, first.View.GenerationID).CredentialRevision; after != before {
			t.Fatalf("credential_revision %d → %d，被拒的儲存不得改動", before, after)
		}
		if n := generationCount(t, rig); n != 1 {
			t.Fatalf("世代數 = %d, want 1", n)
		}
	})

	t.Run("Confirm", func(t *testing.T) {
		rig := newOffsiteRig(t)
		first := mustSave(t, rig, s3Settings("evidence"))
		seedObject(t, rig.db, first.View.GenerationID, 1, StateUploaded)
		in := gcsInput("bucket-x", "", bad)
		_, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
			Settings:                    in,
			ExpectedCurrentGenerationID: first.View.GenerationID,
			SettingsDigest:              digestOf(in, credIntentNew),
		}, OffsiteActor{ID: 1})
		if got := ReasonOf(err); got != reasonGCSCredentialInvalid {
			t.Fatalf("拒因 = %q, want %q（err=%v）；世代數=%d", got, reasonGCSCredentialInvalid, err, generationCount(t, rig))
		}
		if n := generationCount(t, rig); n != 1 {
			t.Fatalf("被拒的確認不得產生新世代，世代數 = %d", n)
		}
		if row := profileRow(t, rig.db, first.View.GenerationID); row.RetiredAt != nil {
			t.Fatal("被拒的確認不得退役現行世代")
		}
	})

	t.Run("Seed", func(t *testing.T) {
		clearSeedEnv(t)
		t.Setenv("OFFSITE_PROVIDER", ProviderGCS)
		t.Setenv("OFFSITE_GCS_BUCKET", "bucket-x")
		t.Setenv("OFFSITE_GCS_CREDENTIALS_FILE", writeTempFile(t, "cred.json", bad))
		db := newOffsiteDB(t)
		err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{})
		if got := ReasonOf(err); got != reasonGCSCredentialInvalid {
			t.Fatalf("拒因 = %q, want %q（err=%v）；世代數=%d", got, reasonGCSCredentialInvalid, err, profileCount(t, db))
		}
		if n := profileCount(t, db); n != 0 {
			t.Fatalf("seed 被拒時不得寫入世代，實得 %d", n)
		}
		if markerWritten(t, db) {
			t.Fatal("seed 被拒時不得寫標記（修正設定後下次啟動重試）")
		}
	})
}

// TestGCSClientRejectsNonServiceAccountStored 客戶端建構是縱深：即使資料庫裡已有
// 非服務帳號型別的憑證，建構也失敗、且不發出任何請求。
func TestGCSClientRejectsNonServiceAccountStored(t *testing.T) {
	srv, rec := newEgressServer(t)
	subject := writeTempFile(t, "subject.txt", "subject-file-marker")
	c, err := NewGCSClient(context.Background(), GCSParams{
		Bucket: "bucket-x", Endpoint: srv.URL,
		CredentialsJSON: externalAccountJSON(t, subject, srv.URL+"/sts"),
	})
	if err == nil {
		_, _ = c.ProbeBucket(context.Background())
	}
	if n := rec.total(); n != 0 {
		t.Fatalf("收件端收到 %d 筆請求（本格要求零外送）；建構 err=%v", n, err)
	}
	if err == nil {
		t.Fatal("非服務帳號型別的憑證建構應失敗")
	}
}

// TestGCSStoredTokenURINonOfficial 型別合法、權杖端點不是官方值的既存世代，
// 沿用測試、現行世代建構與歷史世代取回三條路徑都不得向該位址發出請求。
func TestGCSStoredTokenURINonOfficial(t *testing.T) {
	srv, rec := newEgressServer(t)
	cred := serviceAccountJSON(t, srv.URL+"/token")

	t.Run("測試連線沿用", func(t *testing.T) {
		rig := newOffsiteRig(t)
		rig.svc.SetClientFactoryForTest(DefaultClientFactory)
		before := rec.total()
		insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialStored, "", "bucket-x", cred, false)
		_, err := rig.svc.TestSettings(context.Background(), gcsInput("bucket-x", "", ""), OffsiteActor{ID: 1})
		if n := rec.tokenCount() - before; n != 0 {
			t.Fatalf("權杖位址收到 %d 筆請求；err=%v", n, err)
		}
		if err == nil {
			t.Fatal("沿用不合規憑證的測試連線應失敗")
		}
	})

	t.Run("現行世代建構", func(t *testing.T) {
		rig := newOffsiteRig(t)
		rig.svc.SetClientFactoryForTest(DefaultClientFactory)
		before := rec.total()
		row := insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialStored, "", "bucket-x", cred, false)
		c, err := rig.svc.ClientFor(context.Background(), row.GenerationID)
		if err == nil {
			_, _ = c.ProbeBucket(context.Background())
		}
		if n := rec.tokenCount() - before; n != 0 {
			t.Fatalf("權杖位址收到 %d 筆請求；err=%v", n, err)
		}
		if err == nil {
			t.Fatal("不合規憑證的現行世代建構應失敗")
		}
	})

	t.Run("歷史世代取回", func(t *testing.T) {
		rig := newOffsiteRig(t)
		rig.svc.SetClientFactoryForTest(DefaultClientFactory)
		before := rec.total()
		row := insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialStored, "", "bucket-x", cred, true)
		c, err := rig.svc.ClientForRetrieval(context.Background(), row.GenerationID)
		if err == nil {
			_, _ = c.ProbeBucket(context.Background())
		}
		if n := rec.tokenCount() - before; n != 0 {
			t.Fatalf("權杖位址收到 %d 筆請求；err=%v", n, err)
		}
		if err == nil {
			t.Fatal("不合規憑證的歷史世代建構應失敗")
		}
	})
}

// ── 端點限制：設定面 ──────────────────────────────────────────────────

// TestGCSEndpointNeedsCredential 本次結果不帶顯式服務帳號憑證時，端點只能為空或
// Google 官方網域；儲存、確認、測試連線與 seed 一致受檢，且被拒時狀態不變。
func TestGCSEndpointNeedsCredential(t *testing.T) {
	const external = "https://storage.example.net"
	actor := OffsiteActor{ID: 1, Name: "admin"}

	t.Run("測試連線_清除旗標", func(t *testing.T) {
		rig := newOffsiteRig(t)
		in := gcsInput("bucket-x", external, "")
		in.ClearCredentials = true
		_, err := rig.svc.TestSettings(context.Background(), in, actor)
		assertEndpointRejected(t, err, rig)
	})
	t.Run("測試連線_既存預設憑證鏈世代沿用", func(t *testing.T) {
		rig := newOffsiteRig(t)
		insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialDefaultChain, "", "bucket-x", "", false)
		_, err := rig.svc.TestSettings(context.Background(), gcsInput("bucket-x", external, ""), actor)
		assertEndpointRejected(t, err, rig)
	})
	t.Run("測試連線_無世代未填", func(t *testing.T) {
		rig := newOffsiteRig(t)
		_, err := rig.svc.TestSettings(context.Background(), gcsInput("bucket-x", external, ""), actor)
		assertEndpointRejected(t, err, rig)
	})

	t.Run("儲存_清除旗標", func(t *testing.T) {
		rig := newOffsiteRig(t)
		in := gcsInput("bucket-x", external, "")
		in.ClearCredentials = true
		_, err := rig.svc.Save(context.Background(), in, actor)
		assertEndpointRejected(t, err, rig)
		assertNoGeneration(t, rig)
	})
	t.Run("儲存_既存預設憑證鏈世代沿用", func(t *testing.T) {
		rig := newOffsiteRig(t)
		row := insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialDefaultChain, "", "bucket-x", "", false)
		_, err := rig.svc.Save(context.Background(), gcsInput("bucket-x", external, ""), actor)
		assertEndpointRejected(t, err, rig)
		if got := profileRow(t, rig.db, row.GenerationID); got.Endpoint != "" || got.RetiredAt != nil {
			t.Fatalf("被拒的儲存不得改動現行世代：%+v", got)
		}
		if n := generationCount(t, rig); n != 1 {
			t.Fatalf("世代數 = %d, want 1", n)
		}
	})
	t.Run("儲存_無世代未填", func(t *testing.T) {
		rig := newOffsiteRig(t)
		_, err := rig.svc.Save(context.Background(), gcsInput("bucket-x", external, ""), actor)
		assertEndpointRejected(t, err, rig)
		assertNoGeneration(t, rig)
	})

	t.Run("確認_既存預設憑證鏈世代沿用", func(t *testing.T) {
		rig := newOffsiteRig(t)
		row := insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialDefaultChain, "", "bucket-old", "", false)
		seedObject(t, rig.db, row.GenerationID, 1, StateUploaded)
		in := gcsInput("bucket-new", external, "")
		_, err := rig.svc.ConfirmGenerationSwitch(context.Background(), ConfirmRequest{
			Settings:                    in,
			ExpectedCurrentGenerationID: row.GenerationID,
			SettingsDigest:              digestOf(in, credIntentReuse),
		}, actor)
		assertEndpointRejected(t, err, rig)
		if n := generationCount(t, rig); n != 1 {
			t.Fatalf("被拒的確認不得產生新世代，世代數 = %d", n)
		}
		if got := profileRow(t, rig.db, row.GenerationID); got.RetiredAt != nil {
			t.Fatal("被拒的確認不得退役現行世代")
		}
	})

	t.Run("Seed_未填憑證檔", func(t *testing.T) {
		clearSeedEnv(t)
		t.Setenv("OFFSITE_PROVIDER", ProviderGCS)
		t.Setenv("OFFSITE_GCS_BUCKET", "bucket-x")
		t.Setenv("OFFSITE_GCS_ENDPOINT", external)
		db := newOffsiteDB(t)
		err := RunOffsiteEnvSeed(db, &fakeCodec{}, &recordingJournal{})
		if got := ReasonOf(err); got != reasonGCSEndpointNeedsCredential {
			t.Fatalf("拒因 = %q, want %q（err=%v）", got, reasonGCSEndpointNeedsCredential, err)
		}
		if n := profileCount(t, db); n != 0 {
			t.Fatalf("seed 被拒時不得寫入世代，實得 %d", n)
		}
		if markerWritten(t, db) {
			t.Fatal("seed 被拒時不得寫標記")
		}
	})
}

func assertEndpointRejected(t *testing.T, err error, rig *offsiteTestRig) {
	t.Helper()
	if got := ReasonOf(err); got != reasonGCSEndpointNeedsCredential {
		t.Fatalf("拒因 = %q, want %q（err=%v；driver 建構次數=%d）", got, reasonGCSEndpointNeedsCredential, err, rig.factory.count())
	}
	if n := rig.factory.count(); n != 0 {
		t.Fatalf("被拒的設定不得建構 driver，實得 %d 次", n)
	}
}

func assertNoGeneration(t *testing.T, rig *offsiteTestRig) {
	t.Helper()
	if n := generationCount(t, rig); n != 0 {
		t.Fatalf("被拒的儲存不得產生世代，實得 %d", n)
	}
}

// TestGCSEndpointCredentialStateMatrix 既存世代的憑證來源決定「留空」的語義：
// 保存型且同落點沿用＝帶顯式憑證，不受端點限制；其餘三態一律受限。
func TestGCSEndpointCredentialStateMatrix(t *testing.T) {
	const custom = "https://storage.example.net"
	actor := OffsiteActor{ID: 1, Name: "admin"}

	t.Run("保存型_留空沿用_同落點自訂端點_通過", func(t *testing.T) {
		rig := newOffsiteRig(t)
		insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialStored, custom, "bucket-x", serviceAccountJSON(t, ""), false)
		_, err := rig.svc.TestSettings(context.Background(), gcsInput("bucket-x", custom, ""), actor)
		if got := ReasonOf(err); got == reasonGCSEndpointNeedsCredential {
			t.Fatalf("保存型世代沿用憑證不應受端點限制（err=%v）", err)
		}
		if err != nil {
			t.Fatalf("保存型世代沿用應通過驗證，實得 %v", err)
		}
		if n := rig.factory.count(); n != 1 {
			t.Fatalf("driver 建構次數 = %d, want 1", n)
		}
	})
	t.Run("預設憑證鏈_留空_同端點_拒絕", func(t *testing.T) {
		rig := newOffsiteRig(t)
		insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialDefaultChain, custom, "bucket-x", "", false)
		_, err := rig.svc.TestSettings(context.Background(), gcsInput("bucket-x", custom, ""), actor)
		assertEndpointRejected(t, err, rig)
	})
	t.Run("已撤銷_留空_同端點_拒絕", func(t *testing.T) {
		rig := newOffsiteRig(t)
		insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialRevoked, custom, "bucket-x", "", false)
		_, err := rig.svc.TestSettings(context.Background(), gcsInput("bucket-x", custom, ""), actor)
		assertEndpointRejected(t, err, rig)
	})
	t.Run("無世代_留空_拒絕", func(t *testing.T) {
		rig := newOffsiteRig(t)
		_, err := rig.svc.TestSettings(context.Background(), gcsInput("bucket-x", custom, ""), actor)
		assertEndpointRejected(t, err, rig)
	})
	t.Run("官方端點_預設憑證鏈_通過", func(t *testing.T) {
		for _, ep := range []string{"", "https://storage.googleapis.com", "https://storage-psc.p.googleapis.com"} {
			rig := newOffsiteRig(t)
			in := gcsInput("bucket-x", ep, "")
			in.ClearCredentials = true
			if _, err := rig.svc.TestSettings(context.Background(), in, actor); err != nil {
				t.Fatalf("端點 %q 搭配預設憑證鏈應通過，實得 %v", ep, err)
			}
		}
	})
	t.Run("顯式服務帳號憑證_自訂端點_不受限", func(t *testing.T) {
		rig := newOffsiteRig(t)
		if _, err := rig.svc.TestSettings(context.Background(),
			gcsInput("bucket-x", custom, serviceAccountJSON(t, "")), actor); err != nil {
			t.Fatalf("帶顯式憑證時端點維持既有規則，實得 %v", err)
		}
	})
}

// ── 端點限制：客戶端建構面 ────────────────────────────────────────────

// adcFixture 受控的預設憑證：測試用服務帳號檔，權杖位址指向收件端，
// 令 SDK 能取得權杖並對任何端點附上 bearer。
func adcFixture(t *testing.T, tokenURL string) {
	t.Helper()
	path := writeTempFile(t, "adc.json", serviceAccountJSON(t, tokenURL))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
}

// trustServerCert 讓本程序信任 httptest TLS 伺服器的憑證（Linux 讀 SSL_CERT_FILE）。
func trustServerCert(t *testing.T, srv *httptest.Server) {
	t.Helper()
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	t.Setenv("SSL_CERT_FILE", writeTempFile(t, "ca.pem", string(cert)))
}

// TestGCSEndpointNeedsCredentialBuild 無顯式憑證且端點為非官方 https 位址時，
// 客戶端建構失敗；預設憑證鏈取得的存取權杖不會出現在該端點上。
func TestGCSEndpointNeedsCredentialBuild(t *testing.T) {
	tokenSrv, tokenRec := newEgressServer(t)
	endpointSrv, endpointRec := newEgressTLSServer(t)
	trustServerCert(t, endpointSrv)
	adcFixture(t, tokenSrv.URL+"/token")

	c, err := NewGCSClient(context.Background(), GCSParams{Bucket: "bucket-x", Endpoint: endpointSrv.URL})
	if err == nil {
		_, _ = c.ProbeBucket(context.Background())
	}
	if n := endpointRec.bearerCount(); n != 0 {
		t.Fatalf("自訂端點收到 %d 筆帶 Authorization 的請求（預設憑證鏈的權杖外送）；建構 err=%v", n, err)
	}
	if n := tokenRec.tokenCount(); n != 0 {
		t.Fatalf("預設憑證鏈在建構失敗前已取得權杖（%d 次權杖請求）；建構 err=%v", n, err)
	}
	if err == nil {
		t.Fatal("無顯式憑證且端點為非官方 https 位址時，建構應失敗")
	}
}

// TestGCSRetiredGenerationRetrievalExempt 已非現行的歷史世代為取回而建構時，
// 不套「無顯式憑證時端點須為官方網域」的限制，使既有離機證據仍可取回；
// 同樣的設定作為現行世代（上傳、探測、現行世代取回）一律拒絕建構，
// 且略過檢查建出的 client 不會被上傳用途沿用。
func TestGCSRetiredGenerationRetrievalExempt(t *testing.T) {
	tokenSrv, _ := newEgressServer(t)
	endpointSrv, endpointRec := newEgressTLSServer(t)
	trustServerCert(t, endpointSrv)
	adcFixture(t, tokenSrv.URL+"/token")

	t.Run("歷史世代取回可建構並發出請求", func(t *testing.T) {
		rig := newOffsiteRig(t)
		rig.svc.SetClientFactoryForTest(DefaultClientFactory)
		row := insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialDefaultChain, endpointSrv.URL, "bucket-x", "", true)
		before := endpointRec.total()
		c, err := rig.svc.ClientForRetrieval(context.Background(), row.GenerationID)
		if err != nil {
			t.Fatalf("歷史世代取回應可建構，實得 %v", err)
		}
		_, _ = c.ProbeBucket(context.Background())
		if n := endpointRec.total() - before; n == 0 {
			t.Fatal("歷史世代取回建構後應能對該世代的端點發出請求")
		}
	})

	t.Run("歷史世代以上傳用途建構仍被拒且不沿用取回的 client", func(t *testing.T) {
		rig := newOffsiteRig(t)
		rig.svc.SetClientFactoryForTest(DefaultClientFactory)
		row := insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialDefaultChain, endpointSrv.URL, "bucket-x", "", true)
		if _, err := rig.svc.ClientForRetrieval(context.Background(), row.GenerationID); err != nil {
			t.Fatalf("歷史世代取回應可建構，實得 %v", err)
		}
		_, err := rig.svc.ClientFor(context.Background(), row.GenerationID)
		if got := ReasonOf(err); got != reasonGCSEndpointNeedsCredential {
			t.Fatalf("上傳用途拒因 = %q, want %q（err=%v）", got, reasonGCSEndpointNeedsCredential, err)
		}
	})

	t.Run("現行世代的上傳與取回都拒絕建構", func(t *testing.T) {
		rig := newOffsiteRig(t)
		rig.svc.SetClientFactoryForTest(DefaultClientFactory)
		row := insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialDefaultChain, endpointSrv.URL, "bucket-x", "", false)
		before := endpointRec.total()
		for name, build := range map[string]func(context.Context, uint) (Client, error){
			"上傳": rig.svc.ClientFor, "取回": rig.svc.ClientForRetrieval,
		} {
			c, err := build(context.Background(), row.GenerationID)
			if err == nil {
				_, _ = c.ProbeBucket(context.Background())
			}
			if got := ReasonOf(err); got != reasonGCSEndpointNeedsCredential {
				t.Fatalf("%s用途拒因 = %q, want %q（err=%v）", name, got, reasonGCSEndpointNeedsCredential, err)
			}
		}
		if n := endpointRec.total() - before; n != 0 {
			t.Fatalf("現行世代被拒建構時端點不得收到請求，實得 %d", n)
		}
	})

	t.Run("歷史世代的憑證內容檢查仍適用", func(t *testing.T) {
		rig := newOffsiteRig(t)
		rig.svc.SetClientFactoryForTest(DefaultClientFactory)
		subject := writeTempFile(t, "subject.txt", "subject-file-marker")
		row := insertGeneration(t, rig, ProviderGCS, model.OffsiteCredentialStored, endpointSrv.URL, "bucket-x",
			externalAccountJSON(t, subject, "http://127.0.0.1:1/sts"), true)
		_, err := rig.svc.ClientForRetrieval(context.Background(), row.GenerationID)
		if got := ReasonOf(err); got != reasonGCSCredentialInvalid {
			t.Fatalf("拒因 = %q, want %q（err=%v）", got, reasonGCSCredentialInvalid, err)
		}
	})
}

// TestGCSServiceAccountLoaderRejectsOtherTypes SDK 憑證載入層的隔離測試（不經建構前的內容檢查）：
// 帶服務帳號型別的載入函式遇到其他型別的憑證 JSON 時失敗，且不發出任何請求。
func TestGCSServiceAccountLoaderRejectsOtherTypes(t *testing.T) {
	srv, rec := newEgressServer(t)
	subject := writeTempFile(t, "subject.txt", "subject-file-marker")
	cred := externalAccountJSON(t, subject, srv.URL+"/sts")

	for name, load := range map[string]func() (option.ClientOption, error){
		"JSON": func() (option.ClientOption, error) { return gcsServiceAccountOption([]byte(cred)) },
		"檔案": func() (option.ClientOption, error) {
			return gcsServiceAccountFileOption(writeTempFile(t, "cred.json", cred))
		},
	} {
		credOpt, err := load()
		if err == nil {
			c, cerr := storage.NewClient(context.Background(), option.WithEndpoint(srv.URL), credOpt)
			if cerr == nil {
				_, _ = c.Bucket("b").Attrs(context.Background())
			}
		}
		if n := rec.total(); n != 0 {
			t.Fatalf("%s來源：收件端收到 %d 筆請求（本格要求零外送）；err=%v", name, n, err)
		}
		if err == nil {
			t.Fatalf("%s來源：服務帳號型別的載入函式不得接受其他型別的憑證", name)
		}
	}
}

// TestGCSServiceAccountLoaderAuthenticates 載入函式對合法服務帳號仍能取得權杖並附上 bearer
// （權杖位址指向收件端，驗證憑證接線沒有被型別限制改壞）。
func TestGCSServiceAccountLoaderAuthenticates(t *testing.T) {
	srv, rec := newEgressServer(t)
	credOpt, err := gcsServiceAccountOption([]byte(serviceAccountJSON(t, srv.URL+"/token")))
	if err != nil {
		t.Fatalf("合法服務帳號載入失敗: %v", err)
	}
	c, err := storage.NewClient(context.Background(), option.WithEndpoint(srv.URL), credOpt)
	if err != nil {
		t.Fatalf("建構 client 失敗: %v", err)
	}
	_, _ = c.Bucket("b").Attrs(context.Background())
	if n := rec.tokenCount(); n == 0 {
		t.Fatal("合法服務帳號應向其權杖位址取得權杖")
	}
	if n := rec.bearerCount(); n == 0 {
		t.Fatal("取得權杖後的請求應附 Authorization")
	}
}

// TestGCSCredentialErrorsNameFieldOnly 內容檢查的拒絕訊息只指名欄位，不含任何憑證值。
func TestGCSCredentialErrorsNameFieldOnly(t *testing.T) {
	const marker = "marker-value-not-for-output"
	for name, tc := range map[string]struct{ in, field string }{
		"非 JSON":         {marker, "json"},
		"型別不符":           {`{"type":"` + marker + `","client_email":"a","private_key":"b","token_uri":"` + officialTokenURI + `"}`, "type"},
		"缺 client_email": {`{"type":"service_account","private_key":"` + marker + `","token_uri":"` + officialTokenURI + `"}`, "client_email"},
		"缺 private_key":  {`{"type":"service_account","client_email":"` + marker + `","token_uri":"` + officialTokenURI + `"}`, "private_key"},
		"缺 token_uri":    {`{"type":"service_account","client_email":"a","private_key":"` + marker + `"}`, "token_uri"},
		"token_uri 非官方":  {`{"type":"service_account","client_email":"a","private_key":"b","token_uri":"https://` + marker + `.example/token"}`, "token_uri"},
	} {
		err := validateGCSServiceAccountJSON(tc.in)
		if got := ReasonOf(err); got != reasonGCSCredentialInvalid {
			t.Errorf("%s: 拒因 = %q, want %q", name, got, reasonGCSCredentialInvalid)
			continue
		}
		if got := DetailOf(err); got != tc.field {
			t.Errorf("%s: 欄位 = %q, want %q", name, got, tc.field)
		}
		if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: 錯誤訊息回顯了憑證內容：%v", name, err)
		}
	}
	if err := validateGCSServiceAccountJSON(serviceAccountJSON(t, "")); err != nil {
		t.Errorf("合法服務帳號 JSON 應通過，實得 %v", err)
	}
}
