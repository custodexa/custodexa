package audit

import (
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"gorm.io/gorm"
)

// 蓋章鑰輪替後歷史檢查點仍可驗（audit-checkpoint-chain spec）。
//
// # 這一組補的是哪一層
//
// `TestRotateAuditKeyCrossVersionVerify` 驗的是**列級**：輪替之後，v1 與 v2 兩代
// 審計列各自以自己的版本鑰驗過。檢查點層是另一件事——區間聚合雜湊的輸入含每一列
// 的 `integrity_hmac` 與 `key_version` 本身，所以「歷史檢查點在輪替後仍然驗得過」
// 是從「輪替不重算歷史章」推導出來的，而推導不是測試：哪天輪替改成重蓋歷史列
//（或聚合改成以現行鑰重算），列級測試照樣綠，而所有輪替前的檢查點會在同一刻
// 集體轉成 content_mismatch，且沒有任何測試會指出是這次改動造成的。

// rotationFixture 一條真的檢查點鏈 ＋ 可輪替的版本化蓋章鑰
type rotationFixture struct {
	db        *gorm.DB
	seal      *CheckpointService
	purger    *CheckpointPurger
	integrity *AuditIntegrityService
	km        *keyvault.KeyManagerService
	verifier  *CheckpointVerifier
}

func setupRotationFixture(t *testing.T) *rotationFixture {
	t.Helper()
	db := setupCheckpointDB(t)
	if err := db.AutoMigrate(&model.AuditCheckpointTrim{}, &model.SecurityPolicy{},
		&model.DataKey{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	km := newTestKeyManager(t, db, 7)
	integrity, err := InitAuditIntegrityVersioned(db, km)
	if err != nil {
		t.Fatalf("integrity: %v", err)
	}
	seal, signer := newCheckpointService(t, db, nil, nil)
	if err := seal.EnsureGenesis(); err != nil {
		t.Fatalf("genesis: %v", err)
	}
	purger := NewCheckpointPurger(db, signer)
	return &rotationFixture{db: db, seal: seal, purger: purger, integrity: integrity, km: km,
		verifier: NewCheckpointVerifier(db, seal, purger, integrity, nil)}
}

// stampedRow 以現行版本鑰蓋章並落庫，回傳其 key_version
func (f *rotationFixture) stampedRow(t *testing.T, user string) int {
	t.Helper()
	row := &model.AuditLog{
		CreatedAt: time.Now(), Action: model.ActionExecute, Resource: model.ResourceAuditLog,
		Status: model.StatusSuccess, UserID: 3, Username: user,
	}
	f.integrity.StampOne(row)
	if err := f.db.Create(row).Error; err != nil {
		t.Fatalf("落列: %v", err)
	}
	return row.KeyVersion
}

// contentStatus 對 [seqFrom, seqTo] 跑內容層驗證並回各區間狀態
func (f *rotationFixture) contentStatus(t *testing.T, seqFrom, seqTo uint) []string {
	t.Helper()
	rep, err := f.verifier.VerifyContentBySeq(seqFrom, seqTo)
	if err != nil {
		t.Fatalf("VerifyContentBySeq(%d,%d): %v", seqFrom, seqTo, err)
	}
	out := make([]string, 0, len(rep.Intervals))
	for _, iv := range rep.Intervals {
		out = append(out, iv.Status)
	}
	return out
}

// TestCheckpointContentVerifiesAfterAuditKeyRotation 封章 → 輪替列級蓋章鑰 →
// 輪替前的區間內容層驗證仍 passed
func TestCheckpointContentVerifiesAfterAuditKeyRotation(t *testing.T) {
	f := setupRotationFixture(t)

	// 輪替前的三列 ＋ 一個檢查點
	for _, u := range []string{"a", "b", "c"} {
		if v := f.stampedRow(t, u); v != 1 {
			t.Fatalf("輪替前的列應記 v1，得 v%d", v)
		}
	}
	before, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("封章: %v", err)
	}
	// 前置：輪替之前這個區間是驗得過的（少了它，一個恆回 passed 的驗證器也會綠）
	if got := f.contentStatus(t, before.Seq, before.Seq); len(got) != 1 || got[0] != IntervalStatusPassed {
		t.Fatalf("輪替前 seq=%d 的內容層狀態 = %v, want [%s]",
			before.Seq, got, IntervalStatusPassed)
	}
	storedAgg := before.AggHash

	// 輪替蓋章鑰
	result, err := f.km.RotateAuditKey()
	if err != nil {
		t.Fatalf("輪替: %v", err)
	}
	if result.ToVersion != 2 {
		t.Fatalf("應輪至 v2：%+v", result)
	}

	// 歷史區間仍驗得過，且檢查點的聚合雜湊一個位元組都沒被動
	if got := f.contentStatus(t, before.Seq, before.Seq); len(got) != 1 || got[0] != IntervalStatusPassed {
		t.Fatalf("輪替後 seq=%d 的內容層狀態 = %v, want [%s]：輪替不得使歷史檢查點失效",
			before.Seq, got, IntervalStatusPassed)
	}
	var aggAfter string
	f.db.Raw("SELECT agg_hash FROM audit_checkpoints WHERE seq = ?", before.Seq).Scan(&aggAfter)
	if aggAfter != storedAgg {
		t.Fatalf("agg_hash 由 %s 變為 %s：輪替不得重算歷史檢查點", storedAgg, aggAfter)
	}

	// 輪替後的新列以 v2 蓋章，其檢查點同樣驗得過；跨兩代的整鏈一次驗過
	for _, u := range []string{"d", "e"} {
		if v := f.stampedRow(t, u); v != 2 {
			t.Fatalf("輪替後的列應記 v2，得 v%d", v)
		}
	}
	after, err := f.seal.SealNow()
	if err != nil {
		t.Fatalf("輪替後封章: %v", err)
	}
	got := f.contentStatus(t, before.Seq, after.Seq)
	if len(got) != 2 {
		t.Fatalf("區間數 = %d, want 2", len(got))
	}
	for i, s := range got {
		if s != IntervalStatusPassed {
			t.Fatalf("第 %d 個區間狀態 = %s, want %s（v1／v2 兩代區間皆須驗過）",
				i+1, s, IntervalStatusPassed)
		}
	}

	// 結構層（簽章與鏈接）不受列級輪替影響
	chain, err := f.verifier.VerifyChain()
	if err != nil {
		t.Fatalf("整鏈驗證: %v", err)
	}
	if chain.Status != IntervalStatusPassed {
		t.Fatalf("整鏈狀態 = %s, want passed", chain.Status)
	}
}
