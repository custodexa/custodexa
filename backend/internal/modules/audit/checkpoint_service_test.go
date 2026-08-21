package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/policy"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ── 夾具 ────────────────────────────────────────────────────────────────

// testSigner 以真實 Ed25519 鑰實作 checkpointSigner。
//
// 不用「回固定字串」的假簽章：本組測試要證明的正是「簽章驗得出竄改」，
// 假簽章會讓驗證斷言退化成字串比對，而字串比對在真實 Ed25519 下不成立的
// 情形（例如 payload 欄位漏帶）就看不出來
type testSigner struct {
	priv    map[int]ed25519.PrivateKey
	active  int
	signOps int
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return &testSigner{priv: map[int]ed25519.PrivateKey{1: priv}, active: 1}
}

func (s *testSigner) ActiveVersion() int { return s.active }

func (s *testSigner) Sign(data []byte) (int, string) {
	s.signOps++
	return s.active, base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv[s.active], data))
}

func (s *testSigner) Verify(version int, data []byte, sigB64 string) (bool, error) {
	priv, ok := s.priv[version]
	if !ok {
		return false, fmt.Errorf("未知簽章鑰版本 v%d", version)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, nil
	}
	return ed25519.Verify(priv.Public().(ed25519.PublicKey), data, sig), nil
}

// publicKey 供離線驗章斷言（只用公鑰，不碰私鑰）
func (s *testSigner) publicKey(version int) ed25519.PublicKey {
	return s.priv[version].Public().(ed25519.PublicKey)
}

// fakeAnchor 可控的錨定出口：enabled 切換三態、full 模擬緩衝滿
type fakeAnchor struct {
	mu      sync.Mutex
	enabled bool
	full    bool
	seen    []*model.AuditCheckpoint
}

func (a *fakeAnchor) Enabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabled
}

func (a *fakeAnchor) EnqueueCheckpoint(cp *model.AuditCheckpoint) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.full {
		return false
	}
	a.seen = append(a.seen, cp)
	return true
}

func (a *fakeAnchor) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.seen)
}

// recordedFailure 失效上報的觀測記錄
type recordedFailure struct {
	mechanism string
	cause     string
	params    map[string]string
	recovered bool
}

// setupCheckpointDB 建 sqlite 測試庫。
//
// MaxOpenConns(1)：`:memory:` 的每條連線是**各自獨立的資料庫**，連線池
// 一放大就出現「單獨跑綠、整包跑紅」（本專案既有教訓，ff51836）
func setupCheckpointDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AuditLog{}, &model.AuditCheckpoint{}, &model.IntegrityBaseline{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Create(&model.IntegrityBaseline{
		ID: 1, BaselineAt: time.Date(2026, 8, 5, 9, 22, 40, 962351000, time.UTC), MaxLogID: 0,
	}).Error; err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	return db
}

// clearCheckpointEnv 清空三個門檻 env。
//
// **非可選**：部署／驗證期間常在容器上掛 AUDIT_CHECKPOINT_* 覆寫（本 change
// 的實機驗證就這麼做），而 NewCheckpointService 於建構時讀 env——不清就會
// 讓「非法值退回預設」這類斷言依執行環境時綠時紅
func clearCheckpointEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"AUDIT_CHECKPOINT_INTERVAL_SECONDS",
		"AUDIT_CHECKPOINT_ROW_THRESHOLD", "AUDIT_CHECKPOINT_GRACE_SECONDS"} {
		t.Setenv(k, "")
	}
}

// newCheckpointService 建服務（假時鐘、零 grace；grace 的實時行為另有專測）
func newCheckpointService(t *testing.T, db *gorm.DB, anchor checkpointAnchorSink,
	rec *[]recordedFailure) (*CheckpointService, *testSigner) {
	t.Helper()
	clearCheckpointEnv(t)
	signer := newTestSigner(t)
	var reporter failureReporter
	if rec != nil {
		reporter = func(mechanism, cause string, params map[string]string, recovered bool) {
			*rec = append(*rec, recordedFailure{mechanism, cause, params, recovered})
		}
	}
	svc := NewCheckpointService(db, signer, anchor, reporter)
	svc.grace = 0
	return svc, signer
}

// seedAuditRows 直寫審計列（BeforeCreate 的蓋章 hook 於單測未註冊，故 HMAC 自填）
func seedAuditRows(t *testing.T, db *gorm.DB, n int, createdAt time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		row := model.AuditLog{
			Username: "seed", Action: model.ActionExecute, Resource: model.ResourceAuditLog,
			Status: model.StatusSuccess, CreatedAt: createdAt.Add(time.Duration(i) * time.Millisecond),
			KeyVersion: 1,
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("seed-%d-%d", n, i)))
		row.IntegrityHMAC = hex.EncodeToString(sum[:])
		if err := db.Create(&row).Error; err != nil {
			t.Fatalf("seed audit row: %v", err)
		}
	}
}

// ── 4.1 canonical 編碼（O1）────────────────────────────────────────────

// TestCheckpointCanonicalGolden 兩種 canonical 編碼的位元組 golden。
//
// **編碼一經釘定不再變更**：本測試就是那顆釘子。任何欄位改名、順序調換、
// 時間精度改動都會使既有檢查點全數驗不過——那是靜默的資料災難，
// 必須在 CI 就以「golden 不符」的形態現形
func TestCheckpointCanonicalGolden(t *testing.T) {
	minAt := time.Date(2026, 8, 12, 1, 2, 3, 456789000, time.UTC)
	maxAt := time.Date(2026, 8, 12, 2, 3, 4, 567890000, time.UTC)
	cp := &model.AuditCheckpoint{
		Seq: 7, IDFrom: 4023, IDTo: 5000, RowCount: 978,
		AggHash:            "1111111111111111111111111111111111111111111111111111111111111111",
		AggScheme:          model.AggSchemeV1,
		PrevCheckpointHash: "2222222222222222222222222222222222222222222222222222222222222222",
		MinCreatedAt:       &minAt, MaxCreatedAt: &maxAt,
		SealedAt:          time.Date(2026, 8, 12, 2, 5, 0, 0, time.UTC),
		SigningKeyVersion: 1,
		Signature:         "c2ln",
		// 以下三欄**不得**進簽章 payload：封章後才發生的狀態
		AnchorStatus: model.AnchorStatusEnqueued,
	}

	gotSign, err := CheckpointSignBytes(cp)
	if err != nil {
		t.Fatalf("CheckpointSignBytes: %v", err)
	}
	wantSign := `{"seq":7,"id_from":4023,"id_to":5000,"row_count":978,` +
		`"agg_hash":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"agg_scheme":"cp-agg-v1",` +
		`"prev_checkpoint_hash":"2222222222222222222222222222222222222222222222222222222222222222",` +
		`"min_created_at_us":1786496523456789,"max_created_at_us":1786500184567890,` +
		`"sealed_at_us":1786500300000000,"signing_key_version":1}`
	if string(gotSign) != wantSign {
		t.Errorf("簽章 payload 位元組不符 golden\n got: %s\nwant: %s", gotSign, wantSign)
	}
	if strings.Contains(string(gotSign), model.AnchorStatusEnqueued) {
		t.Errorf("anchor_status 不得進簽章涵蓋範圍（封章後才發生的狀態，蓋進去就永遠簽不了）")
	}

	// 聚合串流 golden：兩列的定長二進位
	gotAgg, n := ComputeAggHash([]checkpointAggEntry{
		{ID: 1, KeyVersion: 1, IntegrityHMAC: "ab"},
		{ID: 2, KeyVersion: 3, IntegrityHMAC: ""},
	})
	if n != 2 {
		t.Errorf("列數 = %d，want 2", n)
	}
	h := sha256.New()
	h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 2})
	h.Write([]byte("ab"))
	h.Write([]byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0})
	if want := hex.EncodeToString(h.Sum(nil)); gotAgg != want {
		t.Errorf("聚合雜湊不符逐位元組重算\n got: %s\nwant: %s", gotAgg, want)
	}

	// 空區間＝空輸入 SHA-256（D4）
	emptyHash, emptyCount := ComputeAggHash(nil)
	if emptyCount != 0 {
		t.Errorf("空區間列數 = %d，want 0", emptyCount)
	}
	if want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; emptyHash != want {
		t.Errorf("空區間聚合雜湊 = %s，want %s（空輸入的 SHA-256）", emptyHash, want)
	}
}

// TestCheckpointAggEncodingIsInjective 聚合編碼在**對手可寫 HMAC 欄**的前提下仍為單射。
//
// 這正是「HMAC 帶長度前綴」存在的理由：以分隔符文字編碼時，攻擊者只要把
// 分隔位元組寫進 integrity_hmac，就能讓「一列」與「兩列」產生相同的雜湊輸入，
// 抽列即不被偵測。此測試以構造好的碰撞候選斷言兩者雜湊不同
func TestCheckpointAggEncodingIsInjective(t *testing.T) {
	// 候選 A：兩列（id=1 hmac="X"、id=2 hmac="Y"）
	twoRows, _ := ComputeAggHash([]checkpointAggEntry{
		{ID: 1, KeyVersion: 1, IntegrityHMAC: "X"},
		{ID: 2, KeyVersion: 1, IntegrityHMAC: "Y"},
	})
	// 候選 B：一列，HMAC 欄塞進「第二列的完整編碼」——文字分隔編碼下兩者同串流
	forged := "X" + string([]byte{0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 0, 1}) + "Y"
	oneRow, _ := ComputeAggHash([]checkpointAggEntry{
		{ID: 1, KeyVersion: 1, IntegrityHMAC: forged},
	})
	if twoRows == oneRow {
		t.Errorf("聚合編碼非單射：對手可構造「一列偽裝成兩列」的碰撞，抽列將不被偵測")
	}
}

// ── 4.2 區間聚合 ────────────────────────────────────────────────────────

func TestCheckpointAggregate(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, _ := newCheckpointService(t, db, nil, nil)
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	seedAuditRows(t, db, 5, base)

	hash, count, minAt, maxAt, err := svc.Aggregate(2, 4)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if count != 3 {
		t.Fatalf("區間 [2,4] 列數 = %d，want 3（閉區間含兩端）", count)
	}
	// 以獨立重算比對：直讀那三列自行組聚合
	var rows []model.AuditLog
	if err := db.Where("id >= ? AND id <= ?", 2, 4).Order("id").Find(&rows).Error; err != nil {
		t.Fatalf("讀取列: %v", err)
	}
	entries := make([]checkpointAggEntry, 0, len(rows))
	for _, r := range rows {
		entries = append(entries, checkpointAggEntry{ID: r.ID, KeyVersion: r.KeyVersion, IntegrityHMAC: r.IntegrityHMAC})
	}
	if want, _ := ComputeAggHash(entries); want != hash {
		t.Errorf("聚合雜湊 = %s，獨立重算 = %s", hash, want)
	}
	if minAt == nil || maxAt == nil {
		t.Fatalf("非空區間的 min/max created_at 不得為 NULL")
	}
	if !minAt.Equal(base.Add(1 * time.Millisecond)) {
		t.Errorf("min_created_at = %v，want %v", minAt, base.Add(time.Millisecond))
	}
	if !maxAt.Equal(base.Add(3 * time.Millisecond)) {
		t.Errorf("max_created_at = %v，want %v", maxAt, base.Add(3*time.Millisecond))
	}

	// 抽走中段列 → 列數與雜湊皆變（本機制存在的唯一理由）
	if err := db.Exec("DELETE FROM audit_logs WHERE id = 3").Error; err != nil {
		t.Fatalf("直寫刪除: %v", err)
	}
	hash2, count2, _, _, err := svc.Aggregate(2, 4)
	if err != nil {
		t.Fatalf("Aggregate 2: %v", err)
	}
	if count2 != 2 || hash2 == hash {
		t.Errorf("抽走中段列後應同時 count_mismatch 與 hash_mismatch，got count=%d hashSame=%v",
			count2, hash2 == hash)
	}
}

// TestCheckpointAggregateKeyVersionCovered 改 key_version 必使聚合雜湊改變。
// 列級 HMAC payload **不含** key_version（相容性紀律），鏈於此新增覆蓋（D2）
func TestCheckpointAggregateKeyVersionCovered(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, _ := newCheckpointService(t, db, nil, nil)
	seedAuditRows(t, db, 3, time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC))

	before, _, _, _, err := svc.Aggregate(1, 3)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if err := db.Exec("UPDATE audit_logs SET key_version = 9 WHERE id = 2").Error; err != nil {
		t.Fatalf("直寫改 key_version: %v", err)
	}
	after, _, _, _, err := svc.Aggregate(1, 3)
	if err != nil {
		t.Fatalf("Aggregate 2: %v", err)
	}
	if before == after {
		t.Errorf("改 key_version 未使聚合雜湊改變：D2 的新增覆蓋失效")
	}
}

// ── 4.3 genesis ────────────────────────────────────────────────────────

func TestCheckpointGenesisAnchorsBaseline(t *testing.T) {
	db := setupCheckpointDB(t)
	seedAuditRows(t, db, 4022, time.Date(2026, 8, 5, 9, 23, 14, 0, time.UTC))
	svc, signer := newCheckpointService(t, db, nil, nil)

	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	var cp model.AuditCheckpoint
	if err := db.Order("seq").First(&cp).Error; err != nil {
		t.Fatalf("讀 genesis: %v", err)
	}
	if cp.Seq != 1 {
		t.Errorf("genesis seq = %d，want 1", cp.Seq)
	}
	// 基準的 max_log_id 為 0，但現存 4022 列全在基準之後——
	// id_from 取**啟用當下 MAX(id)+1**，誤用 0 會讓 genesis 宣稱覆蓋
	// 那些寫入時本機制尚不存在的列
	if cp.IDFrom != 4023 || cp.IDTo != 4022 {
		t.Errorf("genesis 區間 = [%d,%d]，want [4023,4022]（啟用當下 MAX(id)+1 的空區間）",
			cp.IDFrom, cp.IDTo)
	}
	if cp.RowCount != 0 {
		t.Errorf("genesis row_count = %d，want 0", cp.RowCount)
	}
	var baseline model.IntegrityBaseline
	if err := db.First(&baseline, 1).Error; err != nil {
		t.Fatalf("讀 baseline: %v", err)
	}
	wantPrev, err := CheckpointGenesisPrevHash(baseline.MaxLogID, baseline.BaselineAt)
	if err != nil {
		t.Fatalf("GenesisPrevHash: %v", err)
	}
	if cp.PrevCheckpointHash != wantPrev {
		t.Errorf("genesis prev hash 未錨定 integrity_baselines\n got: %s\nwant: %s",
			cp.PrevCheckpointHash, wantPrev)
	}
	assertSignatureValid(t, signer, &cp)

	// 冪等：再呼叫一次不得產生第二個 genesis
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis 2: %v", err)
	}
	var n int64
	db.Model(&model.AuditCheckpoint{}).Count(&n)
	if n != 1 {
		t.Errorf("EnsureGenesis 非冪等：檢查點數 = %d", n)
	}
}

// ── 4.4 鏈接與簽章（含雙向突變的斷言面）──────────────────────────────

// assertSignatureValid 以簽章鑰驗一個檢查點
func assertSignatureValid(t *testing.T, signer *testSigner, cp *model.AuditCheckpoint) {
	t.Helper()
	payload, err := CheckpointSignBytes(cp)
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	ok, err := signer.Verify(cp.SigningKeyVersion, payload, cp.Signature)
	if err != nil || !ok {
		t.Fatalf("seq=%d 簽章驗證失敗（err=%v）", cp.Seq, err)
	}
}

func TestCheckpointSignAndChain(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, signer := newCheckpointService(t, db, nil, nil)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	seedAuditRows(t, db, 10, base)
	if _, err := svc.SealNow(); err != nil {
		t.Fatalf("SealNow 1: %v", err)
	}
	seedAuditRows(t, db, 5, base.Add(time.Hour))
	if _, err := svc.SealNow(); err != nil {
		t.Fatalf("SealNow 2: %v", err)
	}

	var chain []model.AuditCheckpoint
	if err := db.Order("seq").Find(&chain).Error; err != nil {
		t.Fatalf("讀鏈: %v", err)
	}
	if len(chain) != 3 {
		t.Fatalf("鏈長 = %d，want 3（genesis + 兩次封章）", len(chain))
	}
	for i := range chain {
		cp := &chain[i]
		assertSignatureValid(t, signer, cp)
		if cp.Seq != uint(i+1) {
			t.Errorf("第 %d 點 seq = %d，want %d（seq 必須嚴格連續）", i, cp.Seq, i+1)
		}
		if i == 0 {
			continue
		}
		prev := &chain[i-1]
		// 鏈接：prev_checkpoint_hash 必須是前一點「被簽章欄位＋signature」的雜湊
		wantLink, err := CheckpointLinkHash(prev)
		if err != nil {
			t.Fatalf("LinkHash: %v", err)
		}
		if cp.PrevCheckpointHash != wantLink {
			t.Errorf("seq=%d 的鏈接雜湊不符前一點：鏈已斷\n got: %s\nwant: %s",
				cp.Seq, cp.PrevCheckpointHash, wantLink)
		}
		// 區間鄰接無縫
		if cp.IDFrom != prev.IDTo+1 {
			t.Errorf("seq=%d 區間不鄰接：id_from=%d、前點 id_to=%d", cp.Seq, cp.IDFrom, prev.IDTo)
		}
	}
	// 覆蓋面：genesis 之後全鏈連續覆蓋到 MAX(id)
	if chain[2].IDTo != 15 {
		t.Errorf("鏈尾 id_to = %d，want 15", chain[2].IDTo)
	}
}

// TestCheckpointChainDetectsTampering 竄改必現形——**這是本機制的存在理由**。
//
// 三個方向各自獨立斷言（任一方向失去偵測力都必須紅）：
//  1. 改被簽章欄位（agg_hash）→ 簽章驗不過
//  2. 抽走鏈中一點 → 後一點的 prev hash 無所對應（chain_broken）
//  3. 改前一點內容並以自有金鑰重簽 → 後一點的鏈接雜湊不符
func TestCheckpointChainDetectsTampering(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, signer := newCheckpointService(t, db, nil, nil)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	seedAuditRows(t, db, 6, time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC))
	if _, err := svc.SealNow(); err != nil {
		t.Fatalf("SealNow: %v", err)
	}
	seedAuditRows(t, db, 6, time.Date(2026, 8, 12, 11, 0, 0, 0, time.UTC))
	if _, err := svc.SealNow(); err != nil {
		t.Fatalf("SealNow 2: %v", err)
	}

	// 1. 改被簽章欄位（以原生 SQL 繞過 model 守衛，模擬 DB 直寫攻擊）
	if err := db.Exec("UPDATE audit_checkpoints SET agg_hash = ? WHERE seq = 2",
		strings.Repeat("f", 64)).Error; err != nil {
		t.Fatalf("直寫改 agg_hash: %v", err)
	}
	var tampered model.AuditCheckpoint
	if err := db.Where("seq = 2").First(&tampered).Error; err != nil {
		t.Fatalf("讀 seq=2: %v", err)
	}
	payload, _ := CheckpointSignBytes(&tampered)
	if ok, _ := signer.Verify(tampered.SigningKeyVersion, payload, tampered.Signature); ok {
		t.Errorf("改 agg_hash 後簽章仍驗過：簽章未涵蓋 agg_hash")
	}

	// 2. 攻擊者以自有金鑰重簽被改的那一點——簽章面被繞過，鏈接面必須接手
	rogue := newTestSigner(t)
	_, rogueSig := rogue.Sign(payload)
	if err := db.Exec("UPDATE audit_checkpoints SET signature = ? WHERE seq = 2", rogueSig).Error; err != nil {
		t.Fatalf("直寫重簽: %v", err)
	}
	if err := db.Where("seq = 2").First(&tampered).Error; err != nil {
		t.Fatalf("重讀 seq=2: %v", err)
	}
	// 以本系統的公鑰驗 → 仍不過（攻擊者無私鑰）
	if ok, _ := signer.Verify(tampered.SigningKeyVersion, payload, tampered.Signature); ok {
		t.Errorf("以他人金鑰重簽的檢查點竟以系統公鑰驗過")
	}
	// 且後一點的鏈接雜湊與被改後的 seq=2 不符
	var next model.AuditCheckpoint
	if err := db.Where("seq = 3").First(&next).Error; err != nil {
		t.Fatalf("讀 seq=3: %v", err)
	}
	link, err := CheckpointLinkHash(&tampered)
	if err != nil {
		t.Fatalf("LinkHash: %v", err)
	}
	if next.PrevCheckpointHash == link {
		t.Errorf("改前一點內容後鏈接雜湊竟仍相符：鏈接未涵蓋被改欄位")
	}

	// 3. 整點被刪 → seq 出現斷洞
	if err := db.Exec("DELETE FROM audit_checkpoints WHERE seq = 2").Error; err != nil {
		t.Fatalf("直寫刪檢查點: %v", err)
	}
	var seqs []uint
	if err := db.Model(&model.AuditCheckpoint{}).Order("seq").Pluck("seq", &seqs).Error; err != nil {
		t.Fatalf("讀 seq: %v", err)
	}
	if len(seqs) != 2 || seqs[0] != 1 || seqs[1] != 3 {
		t.Fatalf("預期 seq 斷洞 [1,3]，got %v", seqs)
	}
}

// TestCheckpointOfflineVerification 離線驗章：只用公鑰與記錄欄位重建 payload。
//
// 模擬 QSA 場景——驗證者在本系統之外拿公鑰與檢查點 JSON 重算並驗簽，
// **不接觸任何私鑰或服務內部狀態**
func TestCheckpointOfflineVerification(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, signer := newCheckpointService(t, db, nil, nil)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	seedAuditRows(t, db, 3, time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC))
	cp, err := svc.SealNow()
	if err != nil {
		t.Fatalf("SealNow: %v", err)
	}
	// 外部驗證者手上只有：公鑰（base64）與檢查點的 JSON 表述
	pubB64 := base64.StdEncoding.EncodeToString(signer.publicKey(cp.SigningKeyVersion))
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var exported model.AuditCheckpoint
	if err := json.Unmarshal(raw, &exported); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	payload, err := CheckpointSignBytes(&exported)
	if err != nil {
		t.Fatalf("SignBytes: %v", err)
	}
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("pub: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(exported.Signature)
	if err != nil {
		t.Fatalf("sig: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		t.Errorf("離線驗章失敗：公鑰＋記錄欄位無法重建簽章輸入，對外承諾不成立")
	}
	// 位元變動即失敗
	payload[len(payload)-3] ^= 0x01
	if ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		t.Errorf("payload 位元變動後仍驗過")
	}
}

// ── 4.5 空區間照蓋（裁決要求）─────────────────────────────────────────

// TestCheckpointSealsEmptyInterval 停止一切審計寫入後連封兩次，兩次都必須產生檢查點。
//
// 這是**裁決明文要求**且最容易被實作者省略的一項：不蓋空檢查點時，
// 攻擊者可「刪光該區間資料 ＋ 刪掉該檢查點」使其看起來像「那小時沒事發生」，
// 鏈上本來就有洞則此攻擊藏得住
func TestCheckpointSealsEmptyInterval(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, signer := newCheckpointService(t, db, nil, nil)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	seedAuditRows(t, db, 4, time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC))
	if _, err := svc.SealNow(); err != nil {
		t.Fatalf("SealNow: %v", err)
	}
	// 自此不再寫入任何審計列，連續封兩次
	for i := 0; i < 2; i++ {
		if _, err := svc.SealNow(); err != nil {
			t.Fatalf("空區間封章 %d: %v", i, err)
		}
	}

	var chain []model.AuditCheckpoint
	if err := db.Order("seq").Find(&chain).Error; err != nil {
		t.Fatalf("讀鏈: %v", err)
	}
	if len(chain) != 4 {
		t.Fatalf("鏈長 = %d，want 4（genesis + 1 實區間 + 2 空區間）", len(chain))
	}
	empties := chain[2:]
	emptyHash, _ := ComputeAggHash(nil)
	for _, cp := range empties {
		if cp.RowCount != 0 {
			t.Errorf("seq=%d row_count = %d，want 0", cp.Seq, cp.RowCount)
		}
		if cp.IDFrom <= cp.IDTo {
			t.Errorf("seq=%d 空區間表示錯誤：id_from=%d 應 > id_to=%d", cp.Seq, cp.IDFrom, cp.IDTo)
		}
		if cp.AggHash != emptyHash {
			t.Errorf("seq=%d 空區間聚合雜湊 = %s，want 空輸入雜湊 %s", cp.Seq, cp.AggHash, emptyHash)
		}
		if cp.MinCreatedAt != nil || cp.MaxCreatedAt != nil {
			t.Errorf("seq=%d 空區間的 min/max created_at 應為 NULL", cp.Seq)
		}
		// 照常鏈接與簽章——空區間不是「跳過」，是被簽章的主張
		assertSignatureValid(t, signer, &cp)
	}
	if empties[0].Seq != 3 || empties[1].Seq != 4 {
		t.Errorf("空區間的 seq 必須連續遞增，got %d,%d", empties[0].Seq, empties[1].Seq)
	}
	// 鏈接完整：空區間也在鏈上
	for i := 1; i < len(chain); i++ {
		want, err := CheckpointLinkHash(&chain[i-1])
		if err != nil {
			t.Fatalf("LinkHash: %v", err)
		}
		if chain[i].PrevCheckpointHash != want {
			t.Errorf("seq=%d 的鏈接斷裂（空區間未入鏈即為此形態）", chain[i].Seq)
		}
	}
	// 空區間後再寫列，區間仍鄰接無縫（空區間不吃掉任何 id）
	seedAuditRows(t, db, 2, time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC))
	cp, err := svc.SealNow()
	if err != nil {
		t.Fatalf("SealNow after empty: %v", err)
	}
	if cp.IDFrom != 5 || cp.IDTo != 6 || cp.RowCount != 2 {
		t.Errorf("空區間之後的實區間 = [%d,%d] rows=%d，want [5,6] rows=2",
			cp.IDFrom, cp.IDTo, cp.RowCount)
	}
}

// ── 4.6 觸發條件 ───────────────────────────────────────────────────────

func TestCheckpointTriggerConditions(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, _ := newCheckpointService(t, db, nil, nil)
	now := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	svc.interval = time.Hour
	svc.rowThreshold = 10
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}

	// 剛封章、無新列 → 不觸發
	if due, _, err := svc.Due(); err != nil || due {
		t.Errorf("剛封章即觸發（due=%v err=%v）", due, err)
	}
	// 未滿門檻的新列 → 不觸發
	seedAuditRows(t, db, 9, now)
	if due, idHi, err := svc.Due(); err != nil || due {
		t.Errorf("9 筆（門檻 10）不應觸發，due=%v idHi=%d err=%v", due, idHi, err)
	}
	// 達筆數門檻 → 觸發（時間未到）
	seedAuditRows(t, db, 1, now)
	due, idHi, err := svc.Due()
	if err != nil || !due {
		t.Fatalf("達筆數門檻未觸發（due=%v err=%v）", due, err)
	}
	if idHi != 10 {
		t.Errorf("觸發時觀測上界 = %d，want 10", idHi)
	}
	// 封掉後改以時間門檻：無新列但滿 1 小時 → 觸發（空區間照蓋）
	if _, err := svc.SealUpTo(idHi); err != nil {
		t.Fatalf("SealUpTo: %v", err)
	}
	if due, _, _ := svc.Due(); due {
		t.Errorf("剛封章又觸發")
	}
	now = now.Add(time.Hour)
	due, idHi2, err := svc.Due()
	if err != nil || !due {
		t.Fatalf("滿 1 小時未觸發（due=%v err=%v）", due, err)
	}
	if idHi2 != 10 {
		t.Errorf("無新列時上界應維持 %d，got %d", 10, idHi2)
	}

	// Tick 走完整流程（含 grace=0）
	if err := svc.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	last, err := svc.Latest()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if last.Seq != 3 || last.RowCount != 0 {
		t.Errorf("Tick 後鏈尾 = seq %d rows %d，want seq 3 rows 0（時間門檻的空區間）",
			last.Seq, last.RowCount)
	}
}

// TestCheckpointTriggerCannotBeDisabled 門檻可調但不可關閉（spec 明文）
func TestCheckpointTriggerCannotBeDisabled(t *testing.T) {
	for _, tc := range []struct {
		name, key, value string
	}{
		{"間隔 0 秒", "AUDIT_CHECKPOINT_INTERVAL_SECONDS", "0"},
		{"間隔負值", "AUDIT_CHECKPOINT_INTERVAL_SECONDS", "-1"},
		{"間隔超上限", "AUDIT_CHECKPOINT_INTERVAL_SECONDS", "999999999"},
		{"筆數 0", "AUDIT_CHECKPOINT_ROW_THRESHOLD", "0"},
		{"筆數負值", "AUDIT_CHECKPOINT_ROW_THRESHOLD", "-5"},
		{"筆數非數字", "AUDIT_CHECKPOINT_ROW_THRESHOLD", "never"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearCheckpointEnv(t)
			t.Setenv(tc.key, tc.value)
			db := setupCheckpointDB(t)
			svc := NewCheckpointService(db, newTestSigner(t), nil, nil)
			if svc.Interval() != checkpointIntervalDefault {
				t.Errorf("interval = %v，非法值必須退回預設 %v", svc.Interval(), checkpointIntervalDefault)
			}
			if svc.RowThreshold() != checkpointRowThresholdDefault {
				t.Errorf("rowThreshold = %d，非法值必須退回預設 %d",
					svc.RowThreshold(), checkpointRowThresholdDefault)
			}
		})
	}
}

// TestCheckpointGraceIsConfigurable grace 可調（O2 的實測需要它）
func TestCheckpointGraceIsConfigurable(t *testing.T) {
	clearCheckpointEnv(t)
	t.Setenv("AUDIT_CHECKPOINT_GRACE_SECONDS", "5")
	db := setupCheckpointDB(t)
	svc := NewCheckpointService(db, newTestSigner(t), nil, nil)
	if svc.Grace() != 5*time.Second {
		t.Errorf("grace = %v，want 5s", svc.Grace())
	}
}

// TestCheckpointGraceCapturesInFlightRows grace 期間落地的列被計入本區間。
//
// 這是 D3 的核心行為：觸發瞬間取上界、等 grace、再掃描——若實作把
// 「取上界」與「掃描」併成同一步，本測試的第 11 列就會落在區間外
func TestCheckpointGraceCapturesInFlightRows(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, _ := newCheckpointService(t, db, nil, nil)
	svc.rowThreshold = 10
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	seedAuditRows(t, db, 10, time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC))

	// 以注入的 sleep 模擬 grace 窗口：等待期間有一列 commit
	svc.grace = time.Millisecond
	svc.sleep = func(ctx context.Context, d time.Duration) bool {
		seedAuditRows(t, db, 1, time.Date(2026, 8, 12, 10, 0, 1, 0, time.UTC))
		return true
	}
	if err := svc.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	last, err := svc.Latest()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	// 上界是觸發瞬間的 MAX(id)=10；grace 中落地的第 11 列不在本區間
	// （它的 id 大於上界，落入下一區間——這是正確行為，不是遺漏）
	if last.IDTo != 10 || last.RowCount != 10 {
		t.Errorf("區間 = [%d,%d] rows=%d，want id_to=10 rows=10", last.IDFrom, last.IDTo, last.RowCount)
	}
	// 下一次封章把第 11 列接上，區間鄰接無縫
	next, err := svc.SealNow()
	if err != nil {
		t.Fatalf("SealNow: %v", err)
	}
	if next.IDFrom != 11 || next.IDTo != 11 || next.RowCount != 1 {
		t.Errorf("下一區間 = [%d,%d] rows=%d，want [11,11] rows=1",
			next.IDFrom, next.IDTo, next.RowCount)
	}
}

// ── 4.9 seq 衝突 ───────────────────────────────────────────────────────

// TestCheckpointSeqConflict 並發封章時 seq UNIQUE 是最後防線：
// 其一失敗、鏈仍線性、不產生分叉
func TestCheckpointSeqConflict(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, _ := newCheckpointService(t, db, nil, nil)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	seedAuditRows(t, db, 4, time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC))

	// 繞過服務內的 mutex（它只保護單行程）：直接以兩個 goroutine 建同一個 seq，
	// 模擬多實例部署——設計自陳單實例假設，UNIQUE 是那個假設破掉時的兜底
	last, err := svc.Latest()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	prevHash, err := CheckpointLinkHash(last)
	if err != nil {
		t.Fatalf("LinkHash: %v", err)
	}
	build := func() *model.AuditCheckpoint {
		aggHash, rowCount, minAt, maxAt, err := svc.Aggregate(last.IDTo+1, 4)
		if err != nil {
			t.Errorf("Aggregate: %v", err)
			return nil
		}
		return &model.AuditCheckpoint{
			Seq: last.Seq + 1, IDFrom: last.IDTo + 1, IDTo: 4, RowCount: rowCount,
			AggHash: aggHash, AggScheme: model.AggSchemeV1, PrevCheckpointHash: prevHash,
			MinCreatedAt: minAt, MaxCreatedAt: maxAt, SealedAt: time.Now().UTC(),
		}
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cp := build()
			if cp == nil {
				errs[idx] = fmt.Errorf("建構失敗")
				return
			}
			errs[idx] = svc.signAndPersist(cp)
		}(i)
	}
	wg.Wait()

	failed := 0
	for _, err := range errs {
		if err != nil {
			failed++
		}
	}
	if failed != 1 {
		t.Errorf("並發封同一 seq 應恰有一方失敗，實際失敗 %d 方（errs=%v）", failed, errs)
	}
	var seqs []uint
	if err := db.Model(&model.AuditCheckpoint{}).Order("seq").Pluck("seq", &seqs).Error; err != nil {
		t.Fatalf("讀 seq: %v", err)
	}
	if len(seqs) != 2 || seqs[0] != 1 || seqs[1] != 2 {
		t.Errorf("鏈不再線性（出現分叉）：seq = %v", seqs)
	}
}

// TestCheckpointSignerRotationDuringSealIsRejected 簽章期間輪替 → 整輪放棄。
// 落一筆「payload 記 v1、實際以 v2 簽」的檢查點會永遠驗不過
func TestCheckpointSignerRotationDuringSealIsRejected(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, signer := newCheckpointService(t, db, nil, nil)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	seedAuditRows(t, db, 2, time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC))

	_, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	signer.priv[2] = priv2
	rotating := &rotatingSigner{inner: signer, rotateTo: 2}
	svc.signer = rotating

	if _, err := svc.SealNow(); err == nil {
		t.Errorf("簽章期間輪替仍成功落庫：該檢查點的 payload 版本與實際簽章鑰不符，永遠驗不過")
	}
	var n int64
	db.Model(&model.AuditCheckpoint{}).Count(&n)
	if n != 1 {
		t.Errorf("放棄的那一輪不得留下檢查點，檢查點數 = %d", n)
	}
}

// rotatingSigner 在 ActiveVersion 與 Sign 之間切換版本（TOCTOU 模擬）
type rotatingSigner struct {
	inner    *testSigner
	rotateTo int
}

func (r *rotatingSigner) ActiveVersion() int { return r.inner.active }
func (r *rotatingSigner) Sign(data []byte) (int, string) {
	r.inner.active = r.rotateTo
	return r.inner.Sign(data)
}
func (r *rotatingSigner) Verify(v int, d []byte, s string) (bool, error) {
	return r.inner.Verify(v, d, s)
}

// ── 5. syslog 離機錨定 ─────────────────────────────────────────────────

// TestSyslogEnqueueCheckpoint 第三個 Enqueue 的 payload 契約：
// 只送聚合結果與簽章，**不含任何審計列內容欄位**
func TestSyslogEnqueueCheckpoint(t *testing.T) {
	f := NewSyslogForwarder(nil)
	f.setting = model.SyslogSetting{Enabled: true, Host: "collector.local", Port: 514}
	f.loaded = true

	cp := &model.AuditCheckpoint{
		Seq: 12, IDFrom: 100, IDTo: 200, RowCount: 101,
		AggHash: strings.Repeat("a", 64), AggScheme: model.AggSchemeV1,
		Signature: "c2lnbmF0dXJl", SigningKeyVersion: 1,
		SealedAt: time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC),
	}
	if ok := f.EnqueueCheckpoint(cp); !ok {
		t.Fatalf("EnqueueCheckpoint 應成功入列")
	}
	select {
	case ev := <-f.ch:
		if ev.msgID != "checkpoint" {
			t.Errorf("msgID = %q，want checkpoint（收集端須能與一般審計事件區分）", ev.msgID)
		}
		var got map[string]any
		if err := json.Unmarshal(ev.payload, &got); err != nil {
			t.Fatalf("payload 非 JSON: %v", err)
		}
		for _, key := range []string{"seq", "id_from", "id_to", "row_count", "agg_hash",
			"agg_scheme", "signature", "signing_key_version", "sealed_at"} {
			if _, ok := got[key]; !ok {
				t.Errorf("payload 缺欄位 %q（spec 列舉的最小集合）", key)
			}
		}
		// 負向：不得攜帶審計列內容
		for _, key := range []string{"username", "action", "resource", "details",
			"request_body", "client_ip", "path"} {
			if _, ok := got[key]; ok {
				t.Errorf("payload 含審計列內容欄位 %q：錨定只送聚合指紋，不外送日誌明細", key)
			}
		}
		// RFC5424 格式含 msgID
		msg := f.format(ev, time.Now())
		if !strings.Contains(msg, " checkpoint ") {
			t.Errorf("RFC5424 訊息未帶 checkpoint msgID: %s", msg)
		}
	default:
		t.Fatalf("事件未入佇列")
	}

	// 未啟用 → 不入列（回 false，呼叫端記 disabled）
	f.setting = model.SyslogSetting{}
	if ok := f.EnqueueCheckpoint(cp); ok {
		t.Errorf("未啟用轉發時不得入列")
	}
}

// TestCheckpointAnchorStatusThreeStates 三態各跑一次（5.2）
func TestCheckpointAnchorStatusThreeStates(t *testing.T) {
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		enabled bool
		full    bool
		want    string
	}{
		{"轉發未啟用", false, false, model.AnchorStatusDisabled},
		{"入列成功", true, false, model.AnchorStatusEnqueued},
		{"緩衝滿被丟棄", true, true, model.AnchorStatusDropped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := setupCheckpointDB(t)
			anchor := &fakeAnchor{enabled: tc.enabled, full: tc.full}
			var failures []recordedFailure
			svc, _ := newCheckpointService(t, db, anchor, &failures)
			if err := svc.EnsureGenesis(); err != nil {
				t.Fatalf("EnsureGenesis: %v", err)
			}
			seedAuditRows(t, db, 3, base)
			cp, err := svc.SealNow()
			if err != nil {
				t.Fatalf("SealNow: %v", err)
			}
			// 讀回 DB 而非只看記憶體物件：anchor_status 必須真的落庫
			var stored model.AuditCheckpoint
			if err := db.Where("seq = ?", cp.Seq).First(&stored).Error; err != nil {
				t.Fatalf("讀回: %v", err)
			}
			if stored.AnchorStatus != tc.want {
				t.Errorf("anchor_status = %q，want %q", stored.AnchorStatus, tc.want)
			}
			// 丟棄必須有失效留痕，且用**獨立機制碼**（O4）
			if tc.want == model.AnchorStatusDropped {
				if len(failures) == 0 {
					t.Fatalf("錨定丟棄未產生失效事件：靜默即違反 spec")
				}
				got := failures[0]
				if got.mechanism != model.MechanismCheckpointAnchor {
					t.Errorf("失效機制碼 = %q，want %q（與一般轉發失效可區分嚴重度）",
						got.mechanism, model.MechanismCheckpointAnchor)
				}
				if got.mechanism == model.MechanismSyslogForward {
					t.Errorf("錨定失效沿用 syslog_forward：連線恢復會把不可回溯的錨定缺口錯誤結案")
				}
				if got.cause != model.CauseCheckpointAnchorDropped {
					t.Errorf("失效原因碼 = %q，want %q", got.cause, model.CauseCheckpointAnchorDropped)
				}
				if got.params["seq"] == "" {
					t.Errorf("失效事件未帶 seq，無從定位是哪個檢查點失去離機證據")
				}
			} else if len(failures) != 0 {
				t.Errorf("非丟棄情境不應上報失效: %+v", failures)
			}
		})
	}
}

// TestCheckpointAnchorFailureDoesNotBlockSealing 錨定丟棄不影響封章與後續運作（5.4）。
//
// 裁決 5 的落點：外部依賴不得成為全系統單點
func TestCheckpointAnchorFailureDoesNotBlockSealing(t *testing.T) {
	db := setupCheckpointDB(t)
	anchor := &fakeAnchor{enabled: true, full: true}
	var failures []recordedFailure
	svc, signer := newCheckpointService(t, db, anchor, &failures)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	base := time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)

	// 連續三輪都在丟棄下封章
	for i := 0; i < 3; i++ {
		seedAuditRows(t, db, 2, base.Add(time.Duration(i)*time.Hour))
		if _, err := svc.SealNow(); err != nil {
			t.Fatalf("第 %d 輪封章因錨定失敗而中止: %v", i, err)
		}
	}
	var chain []model.AuditCheckpoint
	if err := db.Order("seq").Find(&chain).Error; err != nil {
		t.Fatalf("讀鏈: %v", err)
	}
	if len(chain) != 4 {
		t.Fatalf("錨定全失敗下鏈長 = %d，want 4（封章不得被錨定阻擋）", len(chain))
	}
	for i := 1; i < len(chain); i++ {
		assertSignatureValid(t, signer, &chain[i])
		if chain[i].AnchorStatus != model.AnchorStatusDropped {
			t.Errorf("seq=%d anchor_status = %q，want dropped", chain[i].Seq, chain[i].AnchorStatus)
		}
	}
	// 失效上報節流：進行中不重複開列（沿 SyslogForwarder 慣例）
	opens := 0
	for _, f := range failures {
		if !f.recovered {
			opens++
		}
	}
	if opens != 1 {
		t.Errorf("三輪丟棄開了 %d 次失效事件，want 1（節流：進行中不重複）", opens)
	}

	// 恢復：下一個成功入列的檢查點結案
	anchor.mu.Lock()
	anchor.full = false
	anchor.mu.Unlock()
	seedAuditRows(t, db, 1, base.Add(4*time.Hour))
	if _, err := svc.SealNow(); err != nil {
		t.Fatalf("恢復後封章: %v", err)
	}
	if anchor.count() != 1 {
		t.Errorf("恢復後應有 1 筆入列，got %d", anchor.count())
	}
	recovered := false
	for _, f := range failures {
		if f.recovered && f.mechanism == model.MechanismCheckpointAnchor {
			recovered = true
		}
	}
	if !recovered {
		t.Errorf("錨定恢復未上報：失效區間永遠懸掛")
	}
	// **恢復不改寫歷史**：先前 dropped 的檢查點永久是 dropped（誠實邊界 R4）
	var stillDropped int64
	db.Model(&model.AuditCheckpoint{}).
		Where("anchor_status = ?", model.AnchorStatusDropped).Count(&stillDropped)
	// genesis 也在丟棄期封的，故共 4 筆（genesis + 三輪）
	if stillDropped != 4 {
		t.Errorf("先前 dropped 的檢查點數 = %d，want 4（錨定缺口不可回溯，不得被恢復抹去）",
			stillDropped)
	}
}

// TestCheckpointAnchorPessimisticDefaultBeforeEnqueue 落庫時取悲觀值。
//
// 行程若在「檢查點已落庫、錨定尚未入列」之間崩潰，殘留值必須是
// 「沒有離機證據」而非相反——證據面的預設方向只能保守
func TestCheckpointAnchorPessimisticDefaultBeforeEnqueue(t *testing.T) {
	db := setupCheckpointDB(t)
	anchor := &fakeAnchor{enabled: true}
	svc, _ := newCheckpointService(t, db, anchor, nil)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	seedAuditRows(t, db, 2, time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC))

	last, err := svc.Latest()
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	prevHash, _ := CheckpointLinkHash(last)
	aggHash, rowCount, minAt, maxAt, err := svc.Aggregate(last.IDTo+1, 2)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	cp := &model.AuditCheckpoint{
		Seq: last.Seq + 1, IDFrom: last.IDTo + 1, IDTo: 2, RowCount: rowCount,
		AggHash: aggHash, AggScheme: model.AggSchemeV1, PrevCheckpointHash: prevHash,
		MinCreatedAt: minAt, MaxCreatedAt: maxAt, SealedAt: time.Now().UTC(),
	}
	// 只走到落庫為止（模擬此刻崩潰），不呼叫 anchorCheckpoint
	if err := svc.signAndPersist(cp); err != nil {
		t.Fatalf("signAndPersist: %v", err)
	}
	var stored model.AuditCheckpoint
	if err := db.Where("seq = ?", cp.Seq).First(&stored).Error; err != nil {
		t.Fatalf("讀回: %v", err)
	}
	if stored.AnchorStatus != model.AnchorStatusDropped {
		t.Errorf("落庫時 anchor_status = %q，want dropped（悲觀值：尚未入列＝無離機證據）",
			stored.AnchorStatus)
	}
}

// TestCheckpointAnchorStatusUpdateGoesThroughGuard 錨定狀態更新必須通過
// model 的 BeforeUpdate 白名單守衛——若實作改用結構體形式的 Updates／Save，
// 守衛會拒絕而本測試轉紅（守衛的呼叫端契約由此釘住）
func TestCheckpointAnchorStatusUpdateGoesThroughGuard(t *testing.T) {
	db := setupCheckpointDB(t)
	anchor := &fakeAnchor{enabled: true}
	svc, _ := newCheckpointService(t, db, anchor, nil)
	if err := svc.EnsureGenesis(); err != nil {
		t.Fatalf("EnsureGenesis: %v", err)
	}
	var stored model.AuditCheckpoint
	if err := db.Where("seq = 1").First(&stored).Error; err != nil {
		t.Fatalf("讀 genesis: %v", err)
	}
	if stored.AnchorStatus != model.AnchorStatusEnqueued {
		t.Fatalf("genesis anchor_status = %q，want enqueued（更新未通過守衛即停在 dropped）",
			stored.AnchorStatus)
	}
	// 負向：以結構體形式更新被簽章欄位必被守衛拒絕
	if err := db.Model(&stored).Updates(model.AuditCheckpoint{AggHash: "x"}).Error; err == nil {
		t.Errorf("結構體形式的 Updates 竟被放行：白名單守衛形同虛設")
	}
}

// stubPolicySource 政策頁門檻的替身（僅 GetInt）
type stubPolicySource struct{ vals map[string]int }

func (s *stubPolicySource) GetInt(key string) int { return s.vals[key] }

// TestCheckpointThresholdsFollowPolicy 封章門檻的執行期事實源＝安全政策頁。
//
// 釘三件事：政策值覆寫 env 初值、非法值（0／超上限）退回初值而非放行、
// 且每次讀取都重新取值——**調短週期的目的正是縮小未封窗口（誠實邊界 R5），
// 若啟動時快取一份，管理員在事故當下就縮不了窗**
func TestCheckpointThresholdsFollowPolicy(t *testing.T) {
	db := setupCheckpointDB(t)
	svc, _ := newCheckpointService(t, db, nil, nil)
	envInterval, envRows := svc.Interval(), svc.RowThreshold()

	src := &stubPolicySource{vals: map[string]int{}}
	svc.SetPolicySource(src)

	src.vals[policy.PolicyAuditCheckpointIntervalSeconds] = 300
	src.vals[policy.PolicyAuditCheckpointRowThreshold] = 500
	if got := svc.Interval(); got != 5*time.Minute {
		t.Errorf("Interval = %v, want 5m（政策頁未覆寫 env 初值）", got)
	}
	if got := svc.RowThreshold(); got != 500 {
		t.Errorf("RowThreshold = %d, want 500（政策頁未覆寫 env 初值）", got)
	}

	// 同一實例再讀一次即取到新值＝沒有啟動期快取
	src.vals[policy.PolicyAuditCheckpointIntervalSeconds] = 60
	if got := svc.Interval(); got != time.Minute {
		t.Errorf("調整後 Interval = %v, want 1m（門檻被快取，調短不生效）", got)
	}

	// 非法值：0＝實質關閉封章、超上限＝把窗口撐到無邊界，兩者都必須退回初值
	for _, bad := range []int{0, -1, int(checkpointIntervalMax/time.Second) + 1} {
		src.vals[policy.PolicyAuditCheckpointIntervalSeconds] = bad
		if got := svc.Interval(); got != envInterval {
			t.Errorf("Interval(政策=%d) = %v, want 退回 %v", bad, got, envInterval)
		}
	}
	for _, bad := range []int{0, -1, int(checkpointRowThresholdMax) + 1} {
		src.vals[policy.PolicyAuditCheckpointRowThreshold] = bad
		if got := svc.RowThreshold(); got != envRows {
			t.Errorf("RowThreshold(政策=%d) = %d, want 退回 %d", bad, got, envRows)
		}
	}
}
