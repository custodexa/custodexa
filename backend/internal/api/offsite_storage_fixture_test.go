package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/offsite"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 離機儲存管理 API 的 HTTP 面守衛。
//
// 全部經**完整 RegisterRoutes**（真 AuthMiddleware＋真 RequireRole＋真
// AuditLogMiddleware＋真服務層＋sqlite），不 mock 服務層：本檔要證明的是
// 「服務層既有的判定確實出得了 HTTP 這道門，且出來時是正確的狀態碼與機器碼」
// ——對著假服務斷言只會證明測試自己。沿 ldap_directory_handler_test.go 的形態。
//
// # 這批端點為何需要這麼多守衛
//
// 11 條路由承載**憑證寫入**與**世代切換**：憑證進得去、出不來（write-only），
// 而世代切換一旦繞過確認，帳冊裡的存量物件就會指向一個沒人知道憑證在哪的世代。
// 故三條紅線各有具名守衛：
//
//   - 拒因對照表三軸窮盡（TestOffsiteReasonCodeTablesExhaustive）
//   - 憑證永不出站（TestOffsiteReadEndpointsNeverExposeCredentials）
//   - 禁 request-body logging（TestOffsiteSettingsHandlersDoNotLogRequestBody）

// ── 假憑證字面（**只出現在本檔**；明顯是假值，避免被誤認為真憑證） ──────────

const (
	// 假鍵與假 PEM 標頭刻意拆成兩段字面：假值的形態與真憑證相同，
	// 拆開可避免憑證特徵掃描把測試夾具誤判為真憑證外洩
	offsiteFakeAccessKey = "AKIA" + "FAKETESTKEY0001"
	offsiteFakeSecret    = "fake-secret-do-not-use-0001"
	// offsiteFakeSAEmail／offsiteFakePEMBody gcs service account JSON 的兩個
	// 敏感成分（`client_email` 與私鑰 PEM），供 grep 斷言逐一指名
	offsiteFakeSAEmail  = "fake-sa-do-not-use-0001@example.invalid"
	offsiteFakePEMBody  = "ZmFrZS1wcml2YXRlLWtleS1kby1ub3QtdXNlLTAwMDE"
	offsiteFakePEMBegin = "-----BEGIN " + "PRIVATE KEY-----"

	// offsiteEndpointHost／offsiteEndpointPathToken 端點的兩段：origin 可顯示，
	// **path 不可**。path 段取一個獨一無二的字串使 grep 不會誤命中
	offsiteEndpointHost      = "minio.example.internal:9000"
	offsiteEndpointPathToken = "gw-path-marker-do-not-display"
)

// offsiteFakeSAJSON 一份形狀完整、值明顯為假的 service account JSON。
func offsiteFakeSAJSON() string {
	return `{"type":"service_account","project_id":"fake-project",` +
		`"client_email":"` + offsiteFakeSAEmail + `",` +
		`"private_key":"` + offsiteFakePEMBegin + `\n` + offsiteFakePEMBody + `\n-----END PRIVATE KEY-----\n"}`
}

// offsiteSecretNeedles 一切「不得出現在任何出站面」的字面，含其 base64 形態。
//
// **base64 形態不可省**：憑證在庫內是信封密文，而本檔的 fake codec 以 base64
// 模擬密文；只驗明文的守衛擋不住「把密文原樣回顯」這種同樣致命的形態。
func offsiteSecretNeedles() []string {
	plains := []string{
		offsiteFakeAccessKey, offsiteFakeSecret, offsiteFakeSAEmail,
		offsiteFakePEMBody, offsiteFakePEMBegin,
		// 服務層落庫前的 s3 憑證明文形狀（codec 的輸入本體）
		`{"access_key_id":"` + offsiteFakeAccessKey + `","secret_access_key":"` + offsiteFakeSecret + `"}`,
	}
	out := make([]string, 0, len(plains)*2)
	for _, p := range plains {
		out = append(out, p, base64.StdEncoding.EncodeToString([]byte(p)))
	}
	return out
}

// offsiteMaskNeedles 遮罩形態——**同樣不得出現**。
//
// 遮罩值仍洩漏長度與前綴（`AKIA****` 說出了這是 AWS 靜態金鑰、`***` 加長度提示
// 說出了 secret 有多長）；write-only DTO 要求的是「沒有值、也沒有遮罩」。
func offsiteMaskNeedles() []string {
	return []string{"AKIA", "***", offsiteEndpointPathToken}
}

// ── 測試裝配 ──────────────────────────────────────────────────────────────

// offsiteAPICodec 可觀測的信封 codec（base64 加前綴模擬）。
//
// **錯誤刻意夾帶明文／密文片段**：服務層的紅線是「codec 的底層錯誤不得 %w 進
// 錯誤鏈」，用一個乾淨的錯誤來測等於什麼都沒測。
type offsiteAPICodec struct {
	mu      sync.Mutex
	encFail bool
	decFail bool
}

const offsiteAPICodecPrefix = "encfake:"

func (c *offsiteAPICodec) EncryptFor(_ context.Context, _ crypto.CipherRef, plaintext string) (string, error) {
	c.mu.Lock()
	fail := c.encFail
	c.mu.Unlock()
	if fail {
		return "", errors.New("fake codec 加密失敗 plaintext_fragment=" + plaintext)
	}
	return offsiteAPICodecPrefix + base64.StdEncoding.EncodeToString([]byte(plaintext)), nil
}

func (c *offsiteAPICodec) DecryptFor(_ context.Context, _ crypto.CipherRef, ciphertext string) (string, error) {
	c.mu.Lock()
	fail := c.decFail
	c.mu.Unlock()
	if fail {
		return "", errors.New("fake codec 解密失敗 ciphertext_fragment=" + ciphertext)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, offsiteAPICodecPrefix))
	if err != nil {
		return "", errors.New("fake codec 密文不成形")
	}
	return string(raw), nil
}

func (c *offsiteAPICodec) setEncFail(v bool) { c.mu.Lock(); c.encFail = v; c.mu.Unlock() }
func (c *offsiteAPICodec) setDecFail(v bool) { c.mu.Lock(); c.decFail = v; c.mu.Unlock() }

// offsiteAPIJournal 記錄保管鏈事件（設定寫入路徑的同交易審計面）。
//
// **不直寫 `audit_logs`**：本包不是審計表的擁有者；中介層產出的審計列由
// database.DB 上的真實列承擔，兩個面在守衛裡都要斷言。
type offsiteAPIJournal struct {
	mu     sync.Mutex
	events []offsite.CustodyEvent
}

func (j *offsiteAPIJournal) Record(ev offsite.CustodyEvent) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = append(j.events, ev)
	return nil
}

func (j *offsiteAPIJournal) RecordInTx(_ *gorm.DB, ev offsite.CustodyEvent) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.events = append(j.events, ev)
	return nil
}

func (j *offsiteAPIJournal) all() []offsite.CustodyEvent {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]offsite.CustodyEvent{}, j.events...)
}

// offsiteAPIFactory 可控的 driver factory（連線測試的階梯由它決定）。
type offsiteAPIFactory struct {
	mu     sync.Mutex
	client offsite.Client
	err    error
	specs  []offsite.ClientBuildSpec
}

func (f *offsiteAPIFactory) build(_ context.Context, spec offsite.ClientBuildSpec) (offsite.Client, error) {
	f.mu.Lock()
	f.specs = append(f.specs, spec)
	c, err := f.client, f.err
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if c == nil {
		c = offsite.NewFakeClient(spec.Bucket)
	}
	return c, nil
}

func (f *offsiteAPIFactory) set(c offsite.Client) { f.mu.Lock(); f.client = c; f.mu.Unlock() }

// offsiteAPIDescriber 擁有者描述面（失敗清單的顯示欄與到期日來源）。
type offsiteAPIDescriber struct {
	kind  string
	descs map[uint]offsite.OwnerDescription
}

func (d *offsiteAPIDescriber) Kind() string { return d.kind }

func (d *offsiteAPIDescriber) Describe(ownerID uint) (offsite.OwnerDescription, error) {
	if v, ok := d.descs[ownerID]; ok {
		return v, nil
	}
	return offsite.OwnerDescription{}, errors.New("查無擁有者")
}

// offsiteAPIEnv 一組接好線的離機儲存 API 測試環境。
type offsiteAPIEnv struct {
	r         *gin.Engine
	mgr       *crypto.JWTManager
	db        *gorm.DB
	svc       *offsite.OffsiteProfileService
	ledger    *offsite.Ledger
	codec     *offsiteAPICodec
	journal   *offsiteAPIJournal
	factory   *offsiteAPIFactory
	describer *offsiteAPIDescriber
}

const offsiteAPIJWTSecret = "offsite-storage-test-secret"

// newOffsiteAPIEnv 建置經完整路由的測試環境。
//
// **檔案型 sqlite ＋多條連線**（沿 setupLDAPDirectoryEnv 的先例）：`:memory:`
// 每條連線是各自獨立的庫，只能配 SetMaxOpenConns(1)；而本檔的設定寫入在
// `WithOffsiteProfileLock` 的交易內，中介層審計與認證閘則在交易外讀寫同一個庫，
// 單一連線一旦被交易佔住即自我死鎖。生產（postgres 連線池）沒有這一格。
func newOffsiteAPIEnv(t *testing.T) *offsiteAPIEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)

	dsn := filepath.Join(t.TempDir(), "offsite.db") + "?_pragma=busy_timeout(5000)"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(4)
	if err := db.AutoMigrate(&model.OffsiteProfile{}, &model.OffsiteObject{},
		&model.AuditLog{}, &model.User{}, &model.Role{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// AuthMiddleware 的憑證世代閘與 AuditLogService 的同步寫入皆現查 database.DB
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })

	codec := &offsiteAPICodec{}
	journal := &offsiteAPIJournal{}
	svc := offsite.NewOffsiteProfileService(db, codec, journal)
	ledger := offsite.NewLedger(db, svc, journal)
	svc.SetLedger(ledger)
	factory := &offsiteAPIFactory{}
	svc.SetClientFactoryForTest(factory.build)

	describer := &offsiteAPIDescriber{
		kind:  offsite.KindRecording,
		descs: map[uint]offsite.OwnerDescription{},
	}

	auditSvc := audit.NewAuditLogService(&config.FeatureFlags{
		AuditLogEnabled: true, AsyncAuditEnabled: false, AuditFallbackToFile: false,
	})

	r := gin.New()
	// 中介層在路由群組之外掛載——本檔的斷言面之一正是「中介層產出的審計列」，
	// 掛在群組內只會驗到 handler 自己
	r.Use(middleware.AuditLogMiddleware(auditSvc))
	group := r.Group("/api/v1")
	NewOffsiteStorageHandler(svc, ledger, describer).RegisterRoutes(group,
		identity.NewAuthService(offsiteAPIJWTSecret, time.Minute))

	return &offsiteAPIEnv{
		r: r, mgr: crypto.NewJWTManager(offsiteAPIJWTSecret, time.Minute), db: db,
		svc: svc, ledger: ledger, codec: codec, journal: journal,
		factory: factory, describer: describer,
	}
}

// seedUser 建出 token 對應的使用者列。
//
// **不可省**：AuthMiddleware 的憑證世代閘現查 DB，查無此人一律 401——沒有這一步，
// 全部斷言都會停在認證層而不是它們要驗的那件事。
func (e *offsiteAPIEnv) seedUser(t *testing.T, userID uint, username string) {
	t.Helper()
	user := &model.User{Username: username, Password: "hashed", Active: true}
	user.ID = userID
	if err := e.db.Create(user).Error; err != nil {
		t.Fatalf("建立測試使用者: %v", err)
	}
}

// adminToken 簽發一枚 admin token 並建出對應使用者。
//
// userID 由呼叫端指定：連線測試的限流以已認證的 actor 為鍵，共用 id 會使各子測試
// 互相吃額度。
func (e *offsiteAPIEnv) adminToken(t *testing.T, userID uint) string {
	t.Helper()
	username := "offsiteadmin" + strconv.FormatUint(uint64(userID), 10)
	e.seedUser(t, userID, username)
	token, err := e.mgr.GenerateToken(userID, username, "admin@example.com", "admin", crypto.AuthContext{})
	if err != nil {
		t.Fatalf("簽發 token: %v", err)
	}
	return token
}

func (e *offsiteAPIEnv) do(t *testing.T, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化請求: %v", err)
		}
		reader = bytes.NewReader(payload)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.r.ServeHTTP(w, req)
	return w
}

// offsiteErrCode 取回應信封的機器碼。
func offsiteErrCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("回應無法解析: %v (body=%s)", err, w.Body.String())
	}
	return env.Code
}

// offsiteBody 解析回應為泛型 map。
func offsiteBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("回應無法解析: %v (body=%s)", err, w.Body.String())
	}
	return body
}

// s3Payload 一組合法的 s3 設定（帶靜態憑證）。
func (e *offsiteAPIEnv) s3Payload(bucket string) map[string]any {
	return map[string]any{
		"provider":          "s3",
		"endpoint":          "https://" + offsiteEndpointHost + "/" + offsiteEndpointPathToken,
		"bucket":            bucket,
		"prefix":            "custodexa",
		"region":            "us-east-1",
		"path_style":        true,
		"access_key_id":     offsiteFakeAccessKey,
		"secret_access_key": offsiteFakeSecret,
	}
}

// seedFailedObject 直接在帳冊插一列失敗件（失敗清單與重試端點的觀測對象）。
func (e *offsiteAPIEnv) seedObject(t *testing.T, generationID, ownerID uint, state string) model.OffsiteObject {
	t.Helper()
	row := model.OffsiteObject{
		Kind: offsite.KindRecording, OwnerID: ownerID, Origin: offsite.OriginLive,
		Provider: offsite.ProviderS3, StorageGenerationID: generationID,
		Bucket: "evidence-bucket-one", ObjectKey: "custodexa/recordings/2026/08/session-" +
			strconv.FormatUint(uint64(ownerID), 10) + ".cast",
		State: state, ErrorCode: offsite.ErrCodeUploadFailed,
	}
	if err := e.db.Create(&row).Error; err != nil {
		t.Fatalf("建立帳冊列失敗: %v", err)
	}
	return row
}

// currentGenerationCount `retired_at IS NULL` 的世代列數（停用態的觀測點）。
func (e *offsiteAPIEnv) currentGenerationCount(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := e.db.Model(&model.OffsiteProfile{}).Where("retired_at IS NULL").Count(&n).Error; err != nil {
		t.Fatalf("計數現行世代失敗: %v", err)
	}
	return n
}

// auditRowsJSON 全部審計列的 JSON 全文（**逐欄**，含 request_body／details／error_msg）。
//
// 序列化整列而非挑欄位：憑證只要出現在**任何一欄**都是洩漏，挑欄位的斷言會隨
// 中介層新增欄位而靜默失去射程。
func (e *offsiteAPIEnv) auditRowsJSON(t *testing.T) string {
	t.Helper()
	var rows []model.AuditLog
	if err := e.db.Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatalf("讀 audit_logs: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("未產生任何審計列——守衛失去觀測對象（中介層未生效？）")
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("序列化審計列: %v", err)
	}
	return string(data)
}

// captureOperationalLog 攔截 `log` 套件輸出，回傳取出全文的函式。
func captureOperationalLog(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return func() string { return buf.String() }
}

// assertNoSecret 逐一指名地斷言 needles 不在 surface 內。
//
// **逐一指名**：一次 `Contains(any)` 的失敗訊息答不出「洩的是哪一個」，
// 而那正是修這種缺陷唯一需要知道的事。
func assertNoSecret(t *testing.T, surfaceName, surface string, needles []string) {
	t.Helper()
	for _, n := range needles {
		if strings.Contains(surface, n) {
			t.Errorf("%s 洩漏 %q（截斷後的面：%s）", surfaceName, n, offsiteTruncate(surface))
		}
	}
}

// assertAuditCarriesMaskedBody 正向控制：審計列必須**真的載了**遮罩後的請求體。
//
// 少了這一條，「中介層根本沒把 body 寫進去」與「寫進去了但遮乾淨了」在
// assertNoSecret 底下完全同形——守衛會在一個空的斷言面上假綠，而真正的破口
// （遮罩清單漏一個鍵）仍舊全開。
func assertAuditCarriesMaskedBody(t *testing.T, env *offsiteAPIEnv, method, path string) {
	t.Helper()
	var rows []model.AuditLog
	if err := env.db.Where("method = ? AND path = ?", method, path).
		Order("id DESC").Find(&rows).Error; err != nil {
		t.Fatalf("讀 audit_logs: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s %s 未產生審計列——斷言面不存在，守衛假綠", method, path)
	}
	if rows[0].RequestBody == "" {
		t.Fatalf("%s %s 的審計列 request_body 為空——斷言面不存在，守衛假綠", method, path)
	}
	if !strings.Contains(rows[0].RequestBody, "***MASKED***") {
		t.Fatalf("%s %s 的審計列 request_body 未見任何遮罩痕跡（%q）："+
			"憑證欄若落進放行清單即逐字入庫，而該表受檢查點鏈保護、寫進去就刪不掉",
			method, path, rows[0].RequestBody)
	}
}

// assertLogCaptureIsLive 正向控制：operational log 的攔截確實收到了東西。
func assertLogCaptureIsLive(t *testing.T, captured string) {
	t.Helper()
	if strings.TrimSpace(captured) == "" {
		t.Fatal("operational log 攔截到空字串——斷言面不存在，守衛假綠")
	}
}

func offsiteTruncate(s string) string {
	const max = 2000
	if len(s) <= max {
		return s
	}
	return s[:max] + "…（已截斷）"
}
