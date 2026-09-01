package offsite

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// 本包的測試裝配：sqlite `:memory:` 庫、可觀測的 codec 與保管鏈落地面。

// newOffsiteDB 建立測試庫。
//
// **SetMaxOpenConns(1) 不可省**：純 Go sqlite driver 的每條連線是**各自獨立的
// 空 DB**（ff51836 的根因）。本包的並發測試會另開 goroutine 寫入，池一旦開出
// 第二條連線，該次寫入就落到一個沒有任何表的新 DB，症狀是
// 「單獨跑綠、整包跑紅」且錯誤訊息是 no such table。
func newOffsiteDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("取底層連線失敗: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.OffsiteProfile{}, &model.OffsiteObject{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// schema_migrations 屬 repository 層；seed 的執行標記借用它，缺表會讓 seed
	// 回報基礎設施失敗（測試環境產物而非受測邏輯）
	if err := db.Exec(
		"CREATE TABLE schema_migrations (version varchar(50) PRIMARY KEY, applied_at datetime NOT NULL)").Error; err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	return db
}

// fakeCodec 可觀測的信封 codec：以 base64 加前綴模擬，並記錄呼叫的 CipherRef。
//
// **密文與明文必須明顯不同**：seed 的斷言之一是「credentials_enc 非空且不等於明文」，
// 用 identity 實作會讓那條斷言恆真而測不到東西。
type fakeCodec struct {
	mu sync.Mutex
	// encFail／decFail 注入格：非 nil 即該方向失敗
	encFail error
	decFail error
	// refs 逐次呼叫記錄的 ref（驗證 AAD 綁定身分沒有寫錯欄）
	refs []crypto.CipherRef
}

const fakeCodecPrefix = "encfake:"

func (c *fakeCodec) EncryptFor(_ context.Context, ref crypto.CipherRef, plaintext string) (string, error) {
	c.mu.Lock()
	c.refs = append(c.refs, ref)
	fail := c.encFail
	c.mu.Unlock()
	if fail != nil {
		// 錯誤刻意夾帶明文片段：服務層必須把它淨化掉，測試才驗得到那條紅線
		return "", errors.New("fake codec 加密失敗 plaintext_fragment=" + plaintext)
	}
	return fakeCodecPrefix + base64.StdEncoding.EncodeToString([]byte(plaintext)), nil
}

func (c *fakeCodec) DecryptFor(_ context.Context, ref crypto.CipherRef, ciphertext string) (string, error) {
	c.mu.Lock()
	c.refs = append(c.refs, ref)
	fail := c.decFail
	c.mu.Unlock()
	if fail != nil {
		return "", errors.New("fake codec 解密失敗 ciphertext_fragment=" + ciphertext)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ciphertext, fakeCodecPrefix))
	if err != nil {
		return "", errors.New("fake codec 密文不成形")
	}
	return string(raw), nil
}

func (c *fakeCodec) Refs() []crypto.CipherRef {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]crypto.CipherRef, len(c.refs))
	copy(out, c.refs)
	return out
}

// recordingJournal 記錄保管鏈事件；可注入失敗（驗「審計失敗整筆回滾」）。
type recordingJournal struct {
	mu       sync.Mutex
	events   []CustodyEvent
	txEvents []CustodyEvent
	// failInTx 非 nil＝RecordInTx 一律失敗
	failInTx error
	// failAsync 非 nil＝Record 一律失敗
	failAsync error
}

func (j *recordingJournal) Record(ev CustodyEvent) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failAsync != nil {
		return j.failAsync
	}
	j.events = append(j.events, ev)
	return nil
}

func (j *recordingJournal) RecordInTx(_ *gorm.DB, ev CustodyEvent) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failInTx != nil {
		return j.failInTx
	}
	j.txEvents = append(j.txEvents, ev)
	return nil
}

func (j *recordingJournal) all() []CustodyEvent {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := append([]CustodyEvent{}, j.events...)
	return append(out, j.txEvents...)
}

func (j *recordingJournal) actions() []string {
	var out []string
	for _, ev := range j.all() {
		out = append(out, ev.Action)
	}
	return out
}

// countingFactory 記錄 driver 建構次數的 ClientFactory。
//
// 「撤銷世代零 driver 建構、零預設鏈探測」只能以計數器證明——
// 「觀察不到網路請求」在單元測試裡不構成證據。
type countingFactory struct {
	mu sync.Mutex
	// builds 逐次建構的參數（長度即建構次數）
	builds []ClientBuildSpec
	// client 回傳的 driver（nil＝現造一個 FakeClient）
	client Client
	// err 非 nil＝建構失敗
	err error
}

func (f *countingFactory) build(_ context.Context, spec ClientBuildSpec) (Client, error) {
	f.mu.Lock()
	f.builds = append(f.builds, spec)
	c, err := f.client, f.err
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if c == nil {
		c = NewFakeClient(spec.Bucket)
	}
	return c, nil
}

func (f *countingFactory) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.builds)
}

func (f *countingFactory) lastSpec(t *testing.T) ClientBuildSpec {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.builds) == 0 {
		t.Fatal("factory 從未被呼叫")
	}
	return f.builds[len(f.builds)-1]
}

// offsiteTestRig 一組接好線的服務＋帳冊。
type offsiteTestRig struct {
	db      *gorm.DB
	svc     *OffsiteProfileService
	ledger  *Ledger
	codec   *fakeCodec
	journal *recordingJournal
	factory *countingFactory
}

func newOffsiteRig(t *testing.T) *offsiteTestRig {
	t.Helper()
	db := newOffsiteDB(t)
	codec := &fakeCodec{}
	journal := &recordingJournal{}
	svc := NewOffsiteProfileService(db, codec, journal)
	ledger := NewLedger(db, svc, journal)
	svc.SetLedger(ledger)
	factory := &countingFactory{}
	svc.SetClientFactoryForTest(factory.build)
	// 每支測試各自重置 pre-write hook，避免跨測試殘留
	t.Cleanup(func() { offsiteProfilePreWriteHook = nil })
	return &offsiteTestRig{db: db, svc: svc, ledger: ledger, codec: codec, journal: journal, factory: factory}
}

// s3Settings 一組合法的 s3 設定（帶靜態憑證）。
func s3Settings(bucket string) SettingsInput {
	return SettingsInput{
		Provider:        ProviderS3,
		Endpoint:        "https://minio.example.internal:9000",
		Bucket:          bucket,
		Prefix:          "custodexa",
		Region:          "us-east-1",
		PathStyle:       true,
		AccessKeyID:     "AKIAEXAMPLEKEY",
		SecretAccessKey: "s3cr3t-example-value",
	}
}

// currentCount `retired_at IS NULL` 的列數（「至多一列」不變式的觀測點）。
func currentCount(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.OffsiteProfile{}).Where("retired_at IS NULL").Count(&n).Error; err != nil {
		t.Fatalf("計數現行世代失敗: %v", err)
	}
	return n
}

func profileRow(t *testing.T, db *gorm.DB, generationID uint) model.OffsiteProfile {
	t.Helper()
	var row model.OffsiteProfile
	if err := db.Where("generation_id = ?", generationID).First(&row).Error; err != nil {
		t.Fatalf("讀取世代 %d 失敗: %v", generationID, err)
	}
	return row
}

// mustSave 儲存並要求不需確認。
func mustSave(t *testing.T, rig *offsiteTestRig, in SettingsInput) SaveResult {
	t.Helper()
	res, err := rig.svc.Save(context.Background(), in, OffsiteActor{ID: 1, Name: "admin"})
	if err != nil {
		t.Fatalf("Save 失敗: %v", err)
	}
	if res.NeedsConfirmation {
		t.Fatalf("非預期的「需確認」回應（本格應直接寫入）")
	}
	return res
}

// seedObject 直接在帳冊插一列（測試世代切換的存量條件時用）。
func seedObject(t *testing.T, db *gorm.DB, generationID uint, ownerID uint, state string) model.OffsiteObject {
	t.Helper()
	row := model.OffsiteObject{
		Kind: KindRecording, OwnerID: ownerID, Origin: OriginLive,
		Provider: ProviderS3, StorageGenerationID: generationID,
		Bucket: "b", ObjectKey: "k", State: state,
	}
	if err := db.Create(&row).Error; err != nil {
		t.Fatalf("建立帳冊列失敗: %v", err)
	}
	return row
}
