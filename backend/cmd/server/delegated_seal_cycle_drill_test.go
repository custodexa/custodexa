package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"gorm.io/gorm"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awskms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/internal/sshmaterial"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/crypto"
	kmsprovider "github.com/custodexa/backend/pkg/crypto/kms"
	"golang.org/x/crypto/ssh"
)

// 任務 10.1 的 AWS 與 GCP 兩段：封存 → 帳密授權 → 重新提供憑證 → 解封 → 業務可用。
//
// Vault 段在 `TestVaultSealCycleE2E`（真 Transit 靶機）。此處兩段共用同一形狀：
// 先把本部署重包到該服務商，封存，**不重新提供憑證即解不開**，帳密授權後帶著
// 這一次送來的憑證解封，最後以 dev 的 ssh-test 靶機建立一段真 SSH 會話證明
// 「DEK 真的由該服務商解開，且解出來的是對的」。

// drillSSHPassword 是靶機 testuser 的密碼；它會被本部署的資料金鑰包起來落庫，
// 每一圈都得先解回來才建得了線。
const drillSSHPassword = "testpass123"

// sealCycleCredentialFixture 以當下世代的金鑰管理器把靶機密碼包起來落庫。
func sealCycleCredentialFixture(t *testing.T, ctx context.Context, g *appGraph) {
	t.Helper()
	sealed, err := g.keyManager.EncryptBytesFor(ctx, lifecycleProbeRef, []byte(drillSSHPassword))
	if err != nil {
		t.Fatal("ssh credential fixture encryption failed")
	}
	if err := database.DB.Exec("CREATE TABLE drill_credential (id INTEGER PRIMARY KEY, ciphertext TEXT NOT NULL)").Error; err != nil {
		t.Fatal("credential fixture table failed")
	}
	if err := database.DB.Exec("INSERT INTO drill_credential VALUES (1, ?)", sealed).Error; err != nil {
		t.Fatal("credential fixture write failed")
	}
}

// sealCycleSSHSession 解回落庫的憑證並對 ssh-test 靶機實際建線、跑一個指令。
func sealCycleSSHSession(t *testing.T, ctx context.Context, e *sealIntegrationEnv, label string) {
	t.Helper()
	graph, ok := e.machine.Snapshot().Services.(*appGraph)
	if !ok || graph == nil {
		t.Fatal("service graph absent for ssh probe")
	}
	var stored string
	if err := database.DB.Raw("SELECT ciphertext FROM drill_credential WHERE id = 1").Scan(&stored).Error; err != nil {
		t.Fatal("credential fixture read failed")
	}
	secret, err := graph.keyManager.DecryptFor(ctx, lifecycleProbeRef, stored)
	if err != nil || secret != drillSSHPassword {
		t.Fatalf("credential not recoverable in generation %s", label)
	}
	conn, err := sshproxy.Dial(sshproxy.ConnConfig{
		HostKey: ssh.InsecureIgnoreHostKey(), Host: "ssh-test", Port: 2222,
		Username: "testuser", Password: sshmaterial.CopyPassword([]byte(secret)),
		Cols: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("ssh session failed at %s", label)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("echo custodexa-drill-ok\n")); err != nil {
		t.Fatal("ssh write failed")
	}
	var sb strings.Builder
	buf := make([]byte, 4096)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(sb.String(), "custodexa-drill-ok\r\n") {
		n, rerr := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if rerr != nil {
			break
		}
	}
	if !strings.Contains(sb.String(), "custodexa-drill-ok") {
		t.Fatalf("ssh command output missing at %s", label)
	}
	t.Logf("EVIDENCE ssh_session=%s host=ssh-test user=testuser established=true command_echoed=true", label)
}

// sealCycleDigest 取解封請求要帶的拓撲核對摘要（與解封端點同一支算法）。
func sealCycleDigest(t *testing.T) string {
	t.Helper()
	row, err := keyvault.LoadKEKTopology(database.DB)
	if err != nil && !strings.Contains(err.Error(), "未設定") {
		row = nil
	}
	keyRef, kerr := keyvault.CurrentKEKID(database.DB)
	if kerr != nil {
		t.Fatal("current kek ref unreadable")
	}
	return keyvault.TopologyDigest(row, keyRef)
}

// sealCycleRun 走一圈「封存 → 無憑證被拒 → 授權 → 帶憑證解封 → 業務可用」。
func sealCycleRun(t *testing.T, ctx context.Context, e *sealIntegrationEnv, token, label, wantProvider, material string) {
	t.Helper()
	if w := modeRequestMethod(t, e, "POST", "/api/v1/seal/seal", "{}", token); w.Code != http.StatusOK {
		t.Fatalf("seal HTTP=%d (%s)", w.Code, label)
	}
	e.machine.WaitCleanup()
	if e.machine.Snapshot().Services != nil {
		t.Fatalf("services still published after seal (%s)", label)
	}
	if w := modeRequestMethod(t, e, "GET", "/api/v1/keys", "", token); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("sealed business endpoint HTTP=%d (%s)", w.Code, label)
	}
	// 封存後憑證不可用：不重新提供秘密即解不開（鍵集不成立，整筆拒絕）。
	noSecret := sealGrantRequest(t, e, "POST", "/api/v1/seal/unseal",
		fmt.Sprintf(`{"topology_digest":%q}`, sealCycleDigest(t)))
	t.Logf("EVIDENCE handler POST /api/v1/seal/unseal without_secret HTTP=%d (%s)", noSecret.Code, label)
	if noSecret.Code == http.StatusOK || e.machine.Snapshot().Services != nil {
		t.Fatalf("unseal without a freshly supplied credential accepted (%s)", label)
	}
	// 上一次是真的失敗，會啟動解封退避——等完它，不繞過。
	var w *httptest.ResponseRecorder
	for attempt := 0; attempt < 8; attempt++ {
		w = sealGrantRequest(t, e, "POST", "/api/v1/seal/unseal", material)
		if w.Code != http.StatusTooManyRequests {
			break
		}
		t.Logf("EVIDENCE unseal_backoff_wait attempt=%d HTTP=429 (%s)", attempt+1, label)
		time.Sleep(1500 * time.Millisecond)
	}
	t.Logf("EVIDENCE handler POST /api/v1/seal/unseal credential=%s HTTP=%d", label, w.Code)
	if w.Code != http.StatusOK {
		t.Fatalf("delegated unseal HTTP=%d body=%s (%s)", w.Code, w.Body.String(), label)
	}
	graph, ok := e.machine.Snapshot().Services.(*appGraph)
	if !ok || graph == nil {
		t.Fatalf("service graph not rebuilt (%s)", label)
	}
	if got := graph.keyManager.KEKRef().Provider; got != wantProvider {
		t.Fatalf("unsealed generation provider=%s want=%s (%s)", got, wantProvider, label)
	}
	t.Logf("EVIDENCE unseal_cycle=%s state=unsealed kek_provider=%s key_ref=%s",
		label, graph.keyManager.KEKRef().Provider, graph.keyManager.KEKRef().KeyID)
	sealCycleSSHSession(t, ctx, e, label)
}

// TestAWSSealCycleE2E 任務 10.1 的 AWS 段：真 LocalStack KMS。
//
// **真保管處**：每一次 Encrypt／Decrypt 都送到 dev 的 localstack:4566，
// 只是中間過一層計數用的反向代理，好在測試裡數得出「解封確實對外做了 unwrap」。
func TestAWSSealCycleE2E(t *testing.T) {
	endpoint := testgate.Value(t, testgate.EnvKMSEndpoint)
	e, token, _ := modeFixture(t, "env")
	ctx := context.Background()
	if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code != http.StatusOK {
		t.Fatalf("initial unseal HTTP=%d", w.Code)
	}
	old := e.machine.Snapshot().Services.(*appGraph)
	sealCycleCredentialFixture(t, ctx, old)
	sealCycleSSHSession(t, ctx, e, "generation-1-local")

	target, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal("invalid KMS target URL")
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	var decrypts, encrypts atomic.Int64
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Decrypt":
			decrypts.Add(1)
		case "TrentService.Encrypt":
			encrypts.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer remote.Close()

	const region = "us-east-1"
	// build 以「本次送來的存取金鑰對」建 SDK 客戶端——憑證確實被送到 localstack，
	// 不是由環境或預設鏈撿來的。
	build := func(ctx context.Context, s config.KMSSettings) (crypto.KEKProvider, error) {
		if s.AWSAccessKeyID == "" || s.AWSSecretAccessKey == "" {
			return nil, fmt.Errorf("世代持有者未收到 AWS 存取金鑰對")
		}
		cfg, cerr := awsconfig.LoadDefaultConfig(ctx,
			awsconfig.WithRegion(region),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s.AWSAccessKeyID, s.AWSSecretAccessKey, "")))
		if cerr != nil {
			return nil, cerr
		}
		base := remote.URL
		client := awskms.NewFromConfig(cfg, func(o *awskms.Options) { o.BaseEndpoint = &base; o.RetryMaxAttempts = 1 })
		return kmsprovider.New(ctx, kmsprovider.Settings{
			Provider: kmsprovider.ProviderAWS, KeyID: s.KeyID, Region: region, Client: client,
		})
	}

	// 管理者側：建一把測試金鑰（這一步是靶機準備，不是產品路徑）。
	adminCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	if err != nil {
		t.Fatal("SDK config failed")
	}
	base := remote.URL
	created, err := awskms.NewFromConfig(adminCfg, func(o *awskms.Options) { o.BaseEndpoint = &base }).
		CreateKey(ctx, &awskms.CreateKeyInput{})
	if err != nil {
		t.Fatal("localstack CreateKey failed")
	}
	keyARN := *created.KeyMetadata.Arn
	t.Logf("EVIDENCE localstack CreateKey=ok region=%s", region)

	// 重包到 AWS：本部署自此由 localstack 的 KMS 持有 KEK。
	old.deps.keyManagement.SetDelegatedProviderFactory(func(ctx context.Context, mode, ref string) (crypto.KEKProvider, error) {
		return build(ctx, config.KMSSettings{
			KeyID: ref, Region: region,
			AWSAccessKeyID: "test", AWSSecretAccessKey: "test",
		})
	})
	body := fmt.Sprintf(`{"mode":"kms","key_ref":%q,"region":%q}`, keyARN, region)
	if w := modeRequest(t, e, "/api/v1/keys/rewrap", body, token); w.Code != http.StatusOK {
		t.Fatalf("rewrap HTTP=%d body=%s", w.Code, w.Body.String())
	}
	t.Logf("EVIDENCE handler POST /api/v1/keys/rewrap HTTP=200 mode=kms region=%s", region)

	// 拓撲：AWS 的可編輯欄位只有區域。解封要據它判定目的地。
	if _, _, err := keyvault.SaveKEKTopology(database.DB, keyvault.KEKTopologyInput{
		Provider: keyvault.TopologyProviderAWS, Region: region, UpdatedBy: testAdminUser,
	}); err != nil {
		t.Fatalf("topology save failed: %v", err)
	}
	e.s1.kekDecision.Mode = config.KEKModeKMS
	e.s1.kekDecision.KMS.Provider = kmsprovider.ProviderAWS
	e.s1.initialKEKRef = crypto.KeyRef{Provider: crypto.KeyRefProviderKMS, KeyID: keyARN}
	e.handler.SetAuthorizer(string(config.KEKModeKMS), identity.NewSealAuthorizer(e.s1.cfg.Security.JWTSecret, database.DB).Authorize)
	e.s1.delegatedProviderSource = func(ctx context.Context, o *credentialOwner) (crypto.KEKProvider, error) {
		s, serr := o.settings()
		if serr != nil {
			return nil, serr
		}
		s.KeyID = keyARN
		return build(ctx, s)
	}

	before := decrypts.Load()
	sealCycleRun(t, ctx, e, token, "aws-access-key", crypto.KeyRefProviderKMS,
		fmt.Sprintf(`{"access_key_id":"test","secret_access_key":"test","topology_digest":%q}`, sealCycleDigest(t)))
	after := decrypts.Load()
	if after <= before {
		t.Fatal("no outgoing KMS Decrypt during delegated unseal")
	}
	t.Logf("EVIDENCE seal_cycle=PASS custodian=aws remote=localstack outgoing_decrypt=%d,%d outgoing_encrypt=%d",
		before, after, encrypts.Load())
}

// TestGCPSealCycleE2E 任務 10.1 的 GCP 段。
//
// **能力邊界**：GCP 這一段的保管處是行程內的 fake（帶 GCP 形狀的金鑰引用），
// 不是 HTTP 靶機——dev 堆疊沒有 Cloud KMS 模擬器。故此段證明的是「委託解封的
// GCP 分支鍵集、拓撲判準、憑證世代與業務可用」這條路徑，不是 Cloud KMS 的協定保真度；
// 協定面由 `pkg/crypto/gcpkms` 的契約與端點閘測試承擔。
func TestGCPSealCycleE2E(t *testing.T) {
	e, token, _ := modeFixture(t, "env")
	ctx := context.Background()
	if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code != http.StatusOK {
		t.Fatalf("initial unseal HTTP=%d", w.Code)
	}
	old := e.machine.Snapshot().Services.(*appGraph)
	sealCycleCredentialFixture(t, ctx, old)
	sealCycleSSHSession(t, ctx, e, "generation-1-local")

	fake := newGCPWizardFakeProvider(t)
	var builds atomic.Int64
	old.deps.keyManagement.SetDelegatedProviderFactory(func(context.Context, string, string) (crypto.KEKProvider, error) {
		return fake, nil
	})
	if w := modeRequest(t, e, "/api/v1/keys/rewrap",
		fmt.Sprintf(`{"mode":"gcp","key_ref":%q}`, fake.KeyRef().KeyID), token); w.Code != http.StatusOK {
		t.Fatalf("rewrap HTTP=%d body=%s", w.Code, w.Body.String())
	}
	t.Logf("EVIDENCE handler POST /api/v1/keys/rewrap HTTP=200 mode=gcp key_ref=%s", fake.KeyRef().KeyID)

	e.s1.kekDecision.Mode = config.KEKModeKMS
	e.s1.kekDecision.KMS.Provider = "gcp"
	e.s1.initialKEKRef = fake.KeyRef()
	e.handler.SetAuthorizer(string(config.KEKModeKMS), identity.NewSealAuthorizer(e.s1.cfg.Security.JWTSecret, database.DB).Authorize)
	e.s1.delegatedProviderSource = func(_ context.Context, o *credentialOwner) (crypto.KEKProvider, error) {
		s, serr := o.settings()
		if serr != nil {
			return nil, serr
		}
		if len(s.GCPServiceAccountJSON) == 0 {
			return nil, fmt.Errorf("世代持有者未收到 GCP 服務帳號金鑰檔")
		}
		builds.Add(1)
		return fake, nil
	}

	sealCycleRun(t, ctx, e, token, "gcp-service-account", crypto.KeyRefProviderGCP,
		fmt.Sprintf(`{"service_account_json":"{\"type\":\"service_account\"}","topology_digest":%q}`, sealCycleDigest(t)))
	if builds.Load() == 0 {
		t.Fatal("delegated provider never built from the supplied service account key")
	}
	t.Logf("EVIDENCE seal_cycle=PASS custodian=gcp remote=in-process-fake provider_builds=%d", builds.Load())
}

// TestKEKTopologyChangeAuditAndAlertDrill 任務 10.3：改一次 Vault 位址，
// 讀得到審計列的前後值（不被遮罩），且通知管道確實收到告警事件。
//
// **走真正的審計鏈與真正的通知投遞**：審計列自 `audit_logs` 實讀，告警由
// `audit.InitAlertNotifier` 依資料庫裡的通道列投遞到一具測試 webhook 端點。
// 單元測試的 recording sink 驗得了「有沒有留痕」，驗不了「寫進去之後還讀不讀得出來」
// ——遮罩發生在寫入鏈上，那正是本條要看的地方。
func TestKEKTopologyChangeAuditAndAlertDrill(t *testing.T) {
	e, token, _ := modeFixture(t, "env")
	if w := modeRequest(t, e, "/api/v1/seal/unseal", "{}", token); w.Code != http.StatusOK {
		t.Fatalf("initial unseal HTTP=%d", w.Code)
	}
	g := e.machine.Snapshot().Services.(*appGraph)
	g.deps.keyManagement.SetDeploymentKMSProvider(func() string { return keyvault.TopologyProviderVault })

	// 通知通道：一具真的 HTTP 端點，投遞內容原樣收下。
	delivered := make(chan []byte, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case delivered <- body:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()
	// 系統告警落地與投遞需要的表（共用環境只建 schema-parity 清單）。command_alerts 以
	// DATETIME 欄建：sqlite 的 timestamptz 宣告讀回時不轉成時間，投遞程序讀告警列會失敗
	if err := database.DB.Exec(`CREATE TABLE IF NOT EXISTS command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME,
		disposition TEXT NOT NULL DEFAULT 'pending', note TEXT NOT NULL DEFAULT '',
		blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT ''
	)`).Error; err != nil {
		t.Fatalf("告警表建立失敗: %v", err)
	}
	if err := database.DB.AutoMigrate(&model.NotificationChannel{}, &model.SystemAlertDetail{},
		&model.SystemAlertOutbox{}, &model.SystemAlertSeverityOverride{}); err != nil {
		t.Fatalf("通知通道與系統告警表建立失敗: %v", err)
	}
	if err := database.DB.Create(&model.NotificationChannel{
		Name: "drill", Type: model.NotificationChannelTypeWebhook,
		URL: hook.URL, Enabled: true, Language: model.NotificationChannelLanguageZhTW, MinSeverity: "low",
	}).Error; err != nil {
		t.Fatalf("通知通道建立失敗: %v", err)
	}
	if err := audit.InitAlertNotifier(database.DB, nil).LoadChannels(); err != nil {
		t.Fatalf("通道快取載入失敗: %v", err)
	}

	const first = "https://vault-first.internal:8200"
	const second = "https://vault-moved.internal:8200"
	put := func(address string) {
		t.Helper()
		body := fmt.Sprintf(`{"address":%q,"transit_key_name":"custodexa-kek","role_id":"role-drill"}`, address)
		w := modeRequestMethod(t, e, "PUT", "/api/v1/keys/topology", body, token)
		if w.Code != http.StatusOK {
			t.Fatalf("PUT /api/v1/keys/topology HTTP=%d body=%s", w.Code, w.Body.String())
		}
		t.Logf("EVIDENCE handler PUT /api/v1/keys/topology HTTP=200 address=%s", address)
	}
	put(first)
	put(second)

	var rows []model.AuditLog
	if err := database.DB.Where("path = ?", "/api/v1/keys/topology").
		Order("id asc").Find(&rows).Error; err != nil {
		t.Fatalf("審計列讀取失敗: %v", err)
	}
	joined := ""
	for _, row := range rows {
		joined += row.RequestBody + "\n"
	}
	for _, want := range []string{first, second} {
		if !strings.Contains(joined, want) {
			t.Fatalf("審計列讀不到位址 %q——遮罩把目的地一起吃掉了\n%s", want, joined)
		}
	}
	t.Logf("EVIDENCE audit_rows=%d path=/api/v1/keys/topology before_after_readable=true", len(rows))
	for _, row := range rows {
		t.Logf("EVIDENCE audit username=%s status=%s body=%s", row.Username, row.Status, row.RequestBody)
	}

	// 告警改走系統告警持久投遞（取代舊的非持久通知事件）：等第二次變更的
	// key_topology_changed 投遞，且期間不得收到舊的 kek_topology_changed 通知事件。
	// 參數只有變動欄位類別，前後位址由同交易審計列回查（上面已讀到）。
	deadline := time.After(20 * time.Second)
	seen := 0
	for seen < 2 {
		select {
		case body := <-delivered:
			var payload struct {
				Event string `json:"event"`
				Alert struct {
					Type   string         `json:"type"`
					Params map[string]any `json:"params"`
				} `json:"alert"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				continue
			}
			if payload.Event == string(notifycat.EventKEKTopologyChanged) {
				t.Fatalf("仍收到舊的非持久通知事件 %s：同一次變更不得重複發送", payload.Event)
			}
			if payload.Alert.Type != string(port.SystemAlertKeyTopologyChanged) {
				continue
			}
			for _, addr := range []string{first, second} {
				if strings.Contains(string(body), addr) {
					t.Fatalf("系統告警投遞內容帶了位址 %s", addr)
				}
			}
			t.Logf("EVIDENCE system_alert delivered type=%s change_kind=%v", payload.Alert.Type, payload.Alert.Params["change_kind"])
			seen++
		case <-deadline:
			t.Fatalf("20s 內只收到 %d 筆 key_topology_changed 系統告警投遞（want 2）", seen)
		}
	}

	// 重包流程寫拓撲：走正式的 POST /api/v1/keys/rewrap（正式 handler 與 key manager，
	// 外部 KEK 以行程內替身代替）。第一次正常同步拓撲；第二次在拓撲交易注入告警失敗——
	// 重包本身已完成，回應須與第一次同形（不報成重包失敗），拓撲維持原值、不新增成功告警，
	// 並留一筆記下「拓撲未同步」的失敗審計列。
	newFake := func(keyID string) crypto.KEKProvider {
		local, err := crypto.NewEnvKEKProvider([]byte(testOtherKEK))
		if err != nil {
			t.Fatal(err)
		}
		return &awsShapedFakeProvider{KEKProvider: local, ref: crypto.KeyRef{Provider: crypto.KeyRefProviderKMS, KeyID: keyID}}
	}
	rewrap := func(keyID, region string) *httptest.ResponseRecorder {
		t.Helper()
		fake := newFake(keyID)
		g.deps.keyManagement.SetDelegatedProviderFactory(func(context.Context, string, string) (crypto.KEKProvider, error) {
			return fake, nil
		})
		return modeRequest(t, e, "/api/v1/keys/rewrap", fmt.Sprintf(`{"mode":"kms","key_ref":%q,"region":%q}`, keyID, region), token)
	}
	alertCount := func() int64 {
		var n int64
		database.DB.Model(&model.SystemAlertDetail{}).Where("alert_type = ?", string(port.SystemAlertKeyTopologyChanged)).Count(&n)
		return n
	}
	w1 := rewrap("arn:aws:kms:us-east-1:111122223333:key/drill-a", "us-east-1")
	if w1.Code != http.StatusOK {
		t.Fatalf("第一次重包 HTTP=%d body=%s", w1.Code, w1.Body.String())
	}
	var topo model.KEKTopology
	database.DB.First(&topo)
	if topo.Provider != keyvault.TopologyProviderAWS || topo.Region != "us-east-1" {
		t.Fatalf("第一次重包後拓撲應同步為 aws/us-east-1，得 %s/%s", topo.Provider, topo.Region)
	}
	alertsBefore := alertCount()
	// 一次只允許一個待切換的重包：先放棄第一次，再做第二次
	if w := modeRequestMethod(t, e, "DELETE", "/api/v1/keys/rewrap", "", token); w.Code != http.StatusOK {
		t.Fatalf("放棄待切換重包 HTTP=%d body=%s", w.Code, w.Body.String())
	}
	g.deps.keyManagement.SetEvidenceSinks(audit.NewTxSink(), drillFailingAlertSink{})
	t.Cleanup(func() { g.deps.keyManagement.SetEvidenceSinks(audit.NewTxSink(), audit.NewSystemAlertSink(nil)) })
	w2 := rewrap("arn:aws:kms:ap-northeast-1:111122223333:key/drill-b", "ap-northeast-1")
	if w2.Code != w1.Code {
		t.Fatalf("拓撲同步失敗不得改寫重包回應：第一次 %d、第二次 %d body=%s", w1.Code, w2.Code, w2.Body.String())
	}
	var b1, b2 map[string]any
	_ = json.Unmarshal(w1.Body.Bytes(), &b1)
	_ = json.Unmarshal(w2.Body.Bytes(), &b2)
	for k := range b1 {
		if _, ok := b2[k]; !ok {
			t.Fatalf("第二次重包回應缺欄位 %s：%s", k, w2.Body.String())
		}
	}
	database.DB.First(&topo)
	if topo.Region != "us-east-1" {
		t.Fatalf("拓撲交易失敗後應維持原值 us-east-1，得 %s", topo.Region)
	}
	if n := alertCount(); n != alertsBefore {
		t.Fatalf("拓撲交易失敗後不得新增成功告警（%d→%d）", alertsBefore, n)
	}
	var failed []model.AuditLog
	waitUntil := time.Now().Add(10 * time.Second)
	for time.Now().Before(waitUntil) {
		failed = nil
		database.DB.Where("resource = ? AND status = ? AND request_body LIKE ?", string(model.ResourceKeyManagement),
			string(model.StatusFailure), "%rewrap_topology_not_synced%").Find(&failed)
		if len(failed) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(failed) != 1 || !strings.Contains(failed[0].RequestBody, "ap-northeast-1") {
		t.Fatalf("應有 1 筆記下企圖值與拓撲未同步的失敗審計列，得 %d", len(failed))
	}
	t.Logf("EVIDENCE rewrap_topology_failure HTTP=%d same_as_success=%v topology_kept=%s failure_audit=%s",
		w2.Code, w2.Code == w1.Code, topo.Region, failed[0].RequestBody)
}

// awsShapedFakeProvider 行程內 KEK 替身，帶委託服務商形狀的金鑰引用。
type awsShapedFakeProvider struct {
	crypto.KEKProvider
	ref crypto.KeyRef
}

func (p *awsShapedFakeProvider) KeyRef() crypto.KeyRef { return p.ref }
func (p *awsShapedFakeProvider) FormatTag() string     { return crypto.WrappedFormatKMS }

// drillFailingAlertSink 系統告警寫入一律失敗（注入拓撲交易的告警失敗）。
type drillFailingAlertSink struct{}

func (drillFailingAlertSink) RaiseInTx(*gorm.DB, port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return port.SystemAlertReceipt{}, fmt.Errorf("注入告警失敗")
}
