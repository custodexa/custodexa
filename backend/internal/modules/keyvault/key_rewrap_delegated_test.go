package keyvault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// A/B→C 重包的服務層行為。
//
// **為何用替身而非真 KMS provider**：本檔驗的是**服務層**的語義——落庫值的格式
// 標記、kek_id 形式、守衛的判定範圍、切換後可否開機。KMS 的 wire 行為
// （EncryptionContext、顯式 KeyId、ReEncrypt 四參數）屬 pkg/crypto/kms 的職責，
// 已由該套件的 fake client 與 localstack 兩軌覆蓋。在此再連一次外部服務只會讓
// 服務層測試變慢且不確定。
//
// 替身刻意實作 crypto.KeyIDSyntaxValidator 並採與 KMS 相同的 ARN 語法，
// 使 3.1a 的非正規偵測在服務層也是被實際執行的路徑。

const (
	fakeARNPrefix = "arn:aws:kms:ap-northeast-1:123456789012:key/"
	fakeTargetARN = fakeARNPrefix + "11111111-2222-3333-4444-555555555555"
	fakeOtherARN  = fakeARNPrefix + "66666666-7777-8888-9999-000000000000"
)

// fakeDelegatedProvider 委託型 KEK provider 替身：AES 實作 ＋ kms 身分面。
type fakeDelegatedProvider struct {
	aes    *crypto.AESCrypto
	keyARN string
}

func newFakeDelegatedProvider(t *testing.T, arn string, material byte) *fakeDelegatedProvider {
	t.Helper()
	a, err := crypto.NewAESCrypto(kmTestKey(material))
	if err != nil {
		t.Fatalf("AES: %v", err)
	}
	return &fakeDelegatedProvider{aes: a, keyARN: arn}
}

// Wrap 委託語義：空 AAD 一律拒（與 kmsKEKProvider 對齊）
func (p *fakeDelegatedProvider) Wrap(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errors.New("委託 provider 不接受空 AAD")
	}
	return p.aes.EncryptBytesAAD(plaintext, aad)
}

func (p *fakeDelegatedProvider) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	if len(aad) == 0 {
		return nil, errors.New("委託 provider 不接受空 AAD")
	}
	return p.aes.DecryptBytesAAD(wrapped, aad)
}

func (p *fakeDelegatedProvider) KeyRef() crypto.KeyRef {
	return crypto.KeyRef{Provider: crypto.KeyRefProviderKMS, KeyID: p.keyARN}
}
func (p *fakeDelegatedProvider) Mode() string      { return crypto.KEKModeKMS }
func (p *fakeDelegatedProvider) FormatTag() string { return crypto.WrappedFormatKMS }
func (p *fakeDelegatedProvider) ReEncrypt(ctx context.Context, wrapped, aad []byte, from crypto.KEKProvider) ([]byte, error) {
	return crypto.DefaultReEncrypt(ctx, p, wrapped, aad, from)
}

// ValidateKeyIDSyntax 與 kmsKEKProvider 同語法（判語法、不判歸屬）
func (p *fakeDelegatedProvider) ValidateKeyIDSyntax(keyID string) error {
	if strings.HasPrefix(keyID, fakeARNPrefix) && len(keyID) > len(fakeARNPrefix) {
		return nil
	}
	return fmt.Errorf("非正規 ARN: %q", keyID)
}

// delegatedTargetForTest 以注入 factory 建構委託目標
func delegatedTargetForTest(t *testing.T, p crypto.KEKProvider) *RewrapTarget {
	t.Helper()
	factory := func(context.Context, string, string) (crypto.KEKProvider, error) { return p, nil }
	target, err := NewDelegatedRewrapTarget(context.Background(), RewrapTargetModeKMS, p.KeyRef().KeyID, factory)
	if err != nil {
		t.Fatalf("NewDelegatedRewrapTarget: %v", err)
	}
	return target
}

// TestRewrapToDelegatedTargetWritesKMSFormat 重包到委託目標後：
// clone 列的 wrapped_key 帶 **wk:2:kms:** 前綴（非 wk:1:kms）、
// kek_id 為正規 ARN、回應形狀不含任何明文欄
func TestRewrapToDelegatedTargetWritesKMSFormat(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManagerWithMaterial(t, db, newTestKEKMaterial(t))
	target := delegatedTargetForTest(t, newFakeDelegatedProvider(t, fakeTargetARN, 0x11))

	res, err := km.RewrapKEK(context.Background(), target)
	if err != nil {
		t.Fatalf("RewrapKEK（委託目標）: %v", err)
	}
	if res.TargetMode != RewrapTargetModeKMS {
		t.Fatalf("判別子應為 kms，得 %q", res.TargetMode)
	}
	if res.NewKEKID != fakeTargetARN {
		t.Fatalf("new_kek_id 應為正規 ARN，得 %q", res.NewKEKID)
	}
	if res.RewrappedKeys == 0 {
		t.Fatal("應實際重包出列")
	}

	var clones []model.DataKey
	if err := db.Where("kek_id = ?", fakeTargetARN).Find(&clones).Error; err != nil {
		t.Fatalf("find clones: %v", err)
	}
	if len(clones) == 0 {
		t.Fatal("未寫出任何委託 clone 列")
	}
	for _, c := range clones {
		if c.WrappedKey == "" {
			continue // 已清理佔位
		}
		if !strings.HasPrefix(c.WrappedKey, "wk:2:kms:") {
			t.Fatalf("委託 clone 的 wrapped_key 應帶 wk:2:kms: 前綴，得 %.16s", c.WrappedKey)
		}
		if !c.KEKPending {
			t.Fatal("委託 clone 應為待切換 pending")
		}
	}
}

// TestBootWithDelegatedKEKAfterRewrap 切換後開機：以委託 provider 重新
// InitKeyManager MUST 成功解包（＝A/B→C 的完整鏈在服務層閉合）
func TestBootWithDelegatedKEKAfterRewrap(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManagerWithMaterial(t, db, newTestKEKMaterial(t))
	provider := newFakeDelegatedProvider(t, fakeTargetARN, 0x11)
	if _, err := km.RewrapKEK(context.Background(), delegatedTargetForTest(t, provider)); err != nil {
		t.Fatalf("RewrapKEK: %v", err)
	}

	// 以「新 KEK」開機——等同管理員切 KEK_PROVIDER=kms 後重啟
	booted, err := InitKeyManager(db, newFakeDelegatedProvider(t, fakeTargetARN, 0x11))
	if err != nil {
		t.Fatalf("以委託 KEK 開機 MUST 成功: %v", err)
	}
	if booted.KEKRef().KeyID != fakeTargetARN {
		t.Fatalf("開機後金鑰引用不符：%s", booted.KEKRef().KeyID)
	}
	if booted.KEKMode() != crypto.KEKModeKMS {
		t.Fatalf("清冊模式應由 provider 導出為 kms，得 %q", booted.KEKMode())
	}
	// 切換收尾後舊列應軟退役，新列轉正
	var pending int64
	if err := db.Model(&model.DataKey{}).Where("kek_pending = ?", true).Count(&pending).Error; err != nil {
		t.Fatalf("count pending: %v", err)
	}
	if pending != 0 {
		t.Fatalf("開機收尾後不應留 pending，得 %d", pending)
	}
}

// TestDelegatedTargetGuardAllowsAbandonedARN **本項的存在理由**：
// 一次 abandon 過的 ARN 仍可再次被指定為重包目標。
//
// 沿用本地的「曾出現過即拒」會使該 ARN 永久無法再指定＝**永久燒毀該 CMK**
// （ARN 不可重生，錯誤訊息「請改用另一把金鑰」對操作者是死路）。
func TestDelegatedTargetGuardAllowsAbandonedARN(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManagerWithMaterial(t, db, newTestKEKMaterial(t))
	provider := newFakeDelegatedProvider(t, fakeTargetARN, 0x11)

	if _, err := km.RewrapKEK(context.Background(), delegatedTargetForTest(t, provider)); err != nil {
		t.Fatalf("首次重包: %v", err)
	}
	if _, err := km.AbandonRewrap(); err != nil {
		t.Fatalf("AbandonRewrap: %v", err)
	}
	// 再次指定同一把 ARN——**MUST 成功**
	res, err := km.RewrapKEK(context.Background(), delegatedTargetForTest(t, provider))
	if err != nil {
		t.Fatalf("abandon 過的 ARN MUST 可再次指定為目標（否則永久燒毀該 CMK）: %v", err)
	}
	if res.NewKEKID != fakeTargetARN {
		t.Fatalf("new_kek_id 不符：%q", res.NewKEKID)
	}
}

// TestDelegatedTargetGuardRejectsLiveARN 放寬的邊界：存在**未退役**列的 ARN
// 仍拒（否則 partial 唯一索引會擋在更下游，錯誤更難解讀）
func TestDelegatedTargetGuardRejectsLiveARN(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManagerWithMaterial(t, db, newTestKEKMaterial(t))
	provider := newFakeDelegatedProvider(t, fakeTargetARN, 0x11)

	if _, err := km.RewrapKEK(context.Background(), delegatedTargetForTest(t, provider)); err != nil {
		t.Fatalf("首次重包: %v", err)
	}
	// 未 abandon：clone 列仍未退役 → 同一 ARN 再次指定應被守衛 (a) 或 (c) 擋下
	_, err := km.RewrapKEK(context.Background(), delegatedTargetForTest(t, provider))
	if err == nil {
		t.Fatal("存在未退役列的 ARN 不得再次成為目標")
	}
	if !errors.Is(err, ErrRewrapPendingExists) && !errors.Is(err, ErrRewrapTargetSeen) {
		t.Fatalf("錯誤應為 pending 存在或目標衝突，得 %v", err)
	}
}

// TestDelegatedTargetRejectsCurrentKEK 「不得等於現行 kek_id」在委託分支同樣成立
func TestDelegatedTargetRejectsCurrentKEK(t *testing.T) {
	db := newMigrationDB(t)
	provider := newFakeDelegatedProvider(t, fakeTargetARN, 0x11)
	km, err := InitKeyManager(db, provider)
	if err != nil {
		t.Fatalf("InitKeyManager: %v", err)
	}
	same := newFakeDelegatedProvider(t, fakeTargetARN, 0x11)
	if _, err := km.RewrapKEK(context.Background(), delegatedTargetForTest(t, same)); !errors.Is(err, ErrRewrapTargetSameAsCurrent) {
		t.Fatalf("目標等於現行 KEK 應拒絕，得 %v", err)
	}
}

// TestDelegatedRewrapAcceptsForeignCanonicalARN 收窄三的正向面：重包到**第二把**
// 委託金鑰時，庫內留下的第一把 ARN（語法合格但非當前金鑰）不得被判為非正規
func TestDelegatedRewrapAcceptsForeignCanonicalARN(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManagerWithMaterial(t, db, newTestKEKMaterial(t))
	first := newFakeDelegatedProvider(t, fakeTargetARN, 0x11)
	if _, err := km.RewrapKEK(context.Background(), delegatedTargetForTest(t, first)); err != nil {
		t.Fatalf("首次重包: %v", err)
	}
	if _, err := InitKeyManager(db, newFakeDelegatedProvider(t, fakeTargetARN, 0x11)); err != nil {
		t.Fatalf("切換開機: %v", err)
	}
	// 第二次重包到另一把 ARN，再以第二把開機——此時庫內同時存在兩個合法 ARN
	km2, err := InitKeyManager(db, newFakeDelegatedProvider(t, fakeTargetARN, 0x11))
	if err != nil {
		t.Fatalf("InitKeyManager: %v", err)
	}
	second := newFakeDelegatedProvider(t, fakeOtherARN, 0x22)
	if _, err := km2.RewrapKEK(context.Background(), delegatedTargetForTest(t, second)); err != nil {
		t.Fatalf("二次重包: %v", err)
	}
	if _, err := InitKeyManager(db, newFakeDelegatedProvider(t, fakeOtherARN, 0x22)); err != nil {
		t.Fatalf("語法合格的他把 ARN 不得使開機失敗（收窄三的失敗判準）: %v", err)
	}
}

// TestRetiredLocalRowsDoNotTripCanonicalGuard 收窄一：A/B→C 重包留下的**退役
// local 列**其 kek_id 是本地指紋，掃全表必誤判為非正規而使正常遷移後的部署開不了機。
// 本測試把「重包→切換→再開機」整段跑完，退役 local 列必然在場。
func TestRetiredLocalRowsDoNotTripCanonicalGuard(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManagerWithMaterial(t, db, newTestKEKMaterial(t))
	if _, err := km.RewrapKEK(context.Background(), delegatedTargetForTest(t, newFakeDelegatedProvider(t, fakeTargetARN, 0x11))); err != nil {
		t.Fatalf("重包: %v", err)
	}
	if _, err := InitKeyManager(db, newFakeDelegatedProvider(t, fakeTargetARN, 0x11)); err != nil {
		t.Fatalf("切換開機: %v", err)
	}
	// 前提檢查：確實留有本地指紋的退役列（否則本測試沒測到東西）
	var localRows int64
	if err := db.Model(&model.DataKey{}).
		Where("kek_id <> ? AND kek_retired_at IS NOT NULL", fakeTargetARN).
		Count(&localRows).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if localRows == 0 {
		t.Fatal("測試前提不成立：切換後應留有本地指紋的退役列")
	}
	// 再開機一次仍須成功
	if _, err := InitKeyManager(db, newFakeDelegatedProvider(t, fakeTargetARN, 0x11)); err != nil {
		t.Fatalf("退役 local 列不得觸發非正規守衛: %v", err)
	}
}

// TestCanonicalGuardFailsCloseOnTamperedKEKID 偵測到非正規 kek_id（僅限
// wk:2:kms: 列）即 fail-close，且指引 SHALL NOT 是裸 UPDATE
func TestCanonicalGuardFailsCloseOnTamperedKEKID(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManagerWithMaterial(t, db, newTestKEKMaterial(t))
	if _, err := km.RewrapKEK(context.Background(), delegatedTargetForTest(t, newFakeDelegatedProvider(t, fakeTargetARN, 0x11))); err != nil {
		t.Fatalf("重包: %v", err)
	}
	if _, err := InitKeyManager(db, newFakeDelegatedProvider(t, fakeTargetARN, 0x11)); err != nil {
		t.Fatalf("切換開機: %v", err)
	}
	// 以 DB 寫權竄改委託列的 kek_id 為非正規形式
	if err := db.Model(&model.DataKey{}).
		Where("kek_id = ?", fakeTargetARN).
		Update("kek_id", "alias/custodexa-kek").Error; err != nil {
		t.Fatalf("update: %v", err)
	}
	_, err := InitKeyManager(db, newFakeDelegatedProvider(t, "alias/custodexa-kek", 0x11))
	if !errors.Is(err, ErrDelegatedKEKIDNotCanonical) {
		t.Fatalf("非正規 kek_id MUST fail-close，得 %v", err)
	}
	if strings.Contains(err.Error(), "UPDATE data_keys") {
		t.Fatal("指引 SHALL NOT 提供一次性全表 UPDATE 指令")
	}
	if !strings.Contains(err.Error(), "逐列") {
		t.Fatalf("指引須要求逐列驗證材料歸屬：%v", err)
	}
}

// TestCanonicalGuardIsNoOpForLocalProvider 本地 provider 下本檢查為 no-op：
// 本地 KeyID 是材料指紋，「正規語法」對它沒有意義
func TestCanonicalGuardIsNoOpForLocalProvider(t *testing.T) {
	rows := []model.DataKey{
		{Purpose: model.DataKeyPurposeData, Version: 1, KEKID: "alias/whatever", WrappedKey: "wk:2:kms:AAAA"},
	}
	local, err := crypto.NewEnvKEKProvider(kmTestKey(1))
	if err != nil {
		t.Fatalf("local: %v", err)
	}
	if err := guardDelegatedKEKIDCanonical(rows, local); err != nil {
		t.Fatalf("本地 provider 下應為 no-op，得 %v", err)
	}
}

// TestCanonicalGuardIgnoresNonDelegatedRows 收窄一（單元層）：非 wk:2:kms: 列
// 一律不檢查——包含裸 base64（相容窗本地形式）與 wk:1:local:
func TestCanonicalGuardIgnoresNonDelegatedRows(t *testing.T) {
	provider := &fakeDelegatedProvider{keyARN: fakeTargetARN}
	rows := []model.DataKey{
		{Purpose: "data", Version: 1, KEKID: "a1b2c3d4e5f60718", WrappedKey: "QUJDRA=="},
		{Purpose: "data", Version: 2, KEKID: "a1b2c3d4e5f60718", WrappedKey: "wk:1:local:QUJDRA=="},
		{Purpose: "data", Version: 3, KEKID: "a1b2c3d4e5f60718", WrappedKey: "wk:2:local:QUJDRA=="},
		{Purpose: "data", Version: 4, KEKID: fakeTargetARN, WrappedKey: "wk:2:kms:QUJDRA=="},
	}
	if err := guardDelegatedKEKIDCanonical(rows, provider); err != nil {
		t.Fatalf("非委託格式列不得觸發守衛，得 %v", err)
	}
	rows = append(rows, model.DataKey{Purpose: "data", Version: 5, KEKID: "alias/x", WrappedKey: "wk:2:kms:QUJDRA=="})
	if err := guardDelegatedKEKIDCanonical(rows, provider); !errors.Is(err, ErrDelegatedKEKIDNotCanonical) {
		t.Fatalf("wk:2:kms: 列的非正規 kek_id MUST 被偵測，得 %v", err)
	}
}

var _ crypto.KEKProvider = (*fakeDelegatedProvider)(nil)
var _ crypto.KeyIDSyntaxValidator = (*fakeDelegatedProvider)(nil)
var _ *gorm.DB = nil
