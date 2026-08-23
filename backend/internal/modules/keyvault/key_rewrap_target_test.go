package keyvault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 重包目標 union 與伺服端格式驗證的測試。
//
// 本檔同時提供全 service 套件測試共用的重包輔助：伺服端不再有任何 KEK
// 生成器，測試必須自備材料——這正是「明文流向反轉」在測試面的具體表現。

var testKEKMaterialSeq uint64

// newTestKEKMaterial 產生一把合格且互不相同的測試材料（32 字元、KEKAlphabet 值域）。
// 刻意**不使用 CSPRNG**：測試需要的是可重現與唯一性，而非熵；伺服端已無生成器可用。
func newTestKEKMaterial(t *testing.T) string {
	t.Helper()
	m := fmt.Sprintf("TestKEKMaterial%017d", atomic.AddUint64(&testKEKMaterialSeq, 1))
	if len(m) != crypto.KEKMaterialLength {
		t.Fatalf("測試材料長度 %d，應為 %d", len(m), crypto.KEKMaterialLength)
	}
	if v := crypto.ValidateKEKMaterialFormat(m); v != "" {
		t.Fatalf("測試材料不合格式：%s", v)
	}
	return m
}

// localTargetForTest 由材料建構本地重包目標（建構失敗即測試失敗）
func localTargetForTest(t *testing.T, material string) *RewrapTarget {
	t.Helper()
	target, err := NewLocalRewrapTarget(material)
	if err != nil {
		t.Fatalf("NewLocalRewrapTarget(%d 字元): %v", len(material), err)
	}
	return target
}

// rewrapKEKWith 以指定材料重包，錯誤原樣回傳（供守衛測試斷言）
func rewrapKEKWith(t *testing.T, km *KeyManagerService, material string) (*KEKRewrapResult, error) {
	t.Helper()
	return km.RewrapKEK(context.Background(), localTargetForTest(t, material))
}

// mustRewrapKEK 以一把新材料重包，回傳（材料, 結果）。材料即管理員手上那一份
func mustRewrapKEK(t *testing.T, km *KeyManagerService) (string, *KEKRewrapResult) {
	t.Helper()
	material := newTestKEKMaterial(t)
	res, err := rewrapKEKWith(t, km, material)
	if err != nil {
		t.Fatalf("RewrapKEK: %v", err)
	}
	return material, res
}

// TestLocalRewrapTargetValidatesMaterial 伺服端格式驗證：
// 長度／字元集／非出廠預設值皆在**服務層**擋下，不得只靠前端。
func TestLocalRewrapTargetValidatesMaterial(t *testing.T) {
	valid := newTestKEKMaterial(t)
	cases := []struct {
		name     string
		material string
		wantErr  bool
	}{
		{"合格材料", valid, false},
		{"空字串", "", true},
		{"全空白但長度 32", strings.Repeat(" ", 32), true},
		{"過短", valid[:31], true},
		{"過長", valid + "A", true},
		{"字元集外（連字號）", "Test-KEKMaterial0000000000000001", true},
		{"字元集外（加號）", "Test+KEKMaterial0000000000000001", true},
		{"出廠預設值", config.DefaultEncryptionKey, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target, err := NewLocalRewrapTarget(tc.material)
			if tc.wantErr {
				if err == nil {
					t.Fatal("應拒絕不合格材料，卻建構成功")
				}
				if !errors.Is(err, ErrRewrapMaterialFormat) {
					t.Fatalf("錯誤應可辨識為 ErrRewrapMaterialFormat，得 %v", err)
				}
				if target != nil {
					t.Fatal("拒絕時不得回傳目標")
				}
				return
			}
			if err != nil {
				t.Fatalf("合格材料應被接受：%v", err)
			}
			if !target.IsLocal() || target.Mode() != RewrapTargetModeLocal {
				t.Fatalf("目標判別子應為 local，得 %q", target.Mode())
			}
			if target.KeyRef().Provider != crypto.KeyRefProviderLocal || target.KeyRef().KeyID == "" {
				t.Fatalf("金鑰引用形制不符: %+v", target.KeyRef())
			}
		})
	}
}

// TestLocalRewrapTargetRejectsFactoryDefault 出廠預設值（PCI 2.2.2）不得作為
// 重包目標。**與上表分開一格**：預設值的字面由 config 提供，此處釘住的是
// 「服務層的驗證器確實接上了那條規則」，而非某個字面
func TestLocalRewrapTargetRejectsFactoryDefault(t *testing.T) {
	if len(config.DefaultEncryptionKey) != crypto.KEKMaterialLength {
		t.Fatalf("出廠預設值長度 %d，與驗證器要求不符——測試前提已失效", len(config.DefaultEncryptionKey))
	}
	if _, err := NewLocalRewrapTarget(config.DefaultEncryptionKey); !errors.Is(err, ErrRewrapMaterialFormat) {
		t.Fatalf("出廠預設值應被拒絕，得 %v", err)
	}
}

// TestLocalRewrapTargetSameMaterialSameKeyRef 同材料恆得同金鑰引用
// （A↔B 同鑰免遷移承諾在重包目標側的對應面：目標的引用不因建構管道而異）
func TestLocalRewrapTargetSameMaterialSameKeyRef(t *testing.T) {
	m := newTestKEKMaterial(t)
	a := localTargetForTest(t, m)
	envProvider, err := crypto.NewEnvKEKProvider([]byte(m))
	if err != nil {
		t.Fatalf("env provider: %v", err)
	}
	if !a.KeyRef().Equal(envProvider.KeyRef()) {
		t.Fatalf("同材料的重包目標與 env provider 金鑰引用不一致: %v vs %v", a.KeyRef(), envProvider.KeyRef())
	}
}

// TestDelegatedRewrapTargetFailsClosed 委託目標的三類失敗分流：
// factory 未注入＝「尚未提供」、白名單外＝「模式無效」、factory 失敗＝「預檢失敗」，
// 三者**不得**互相混淆，更不得靜默退化為本地目標
func TestDelegatedRewrapTargetFailsClosed(t *testing.T) {
	ctx := context.Background()
	// factory 未注入：已知模式一律「尚未提供」
	for _, mode := range []string{RewrapTargetModeKMS, RewrapTargetModeHSM} {
		target, err := NewDelegatedRewrapTarget(ctx, mode, "arn:aws:kms:ap-northeast-1:1:key/abc", nil)
		if !errors.Is(err, ErrRewrapTargetUnsupported) {
			t.Fatalf("%s 未注入 factory 應回 ErrRewrapTargetUnsupported，得 %v", mode, err)
		}
		if target != nil {
			t.Fatalf("%s 不得回傳可用目標", mode)
		}
	}
	if _, err := NewDelegatedRewrapTarget(ctx, "local", "x", nil); !errors.Is(err, ErrRewrapTargetModeInvalid) {
		t.Fatalf("委託構造入口不得接受 local，得 %v", err)
	}
	if _, err := NewDelegatedRewrapTarget(ctx, "KMS", "x", nil); !errors.Is(err, ErrRewrapTargetModeInvalid) {
		t.Fatalf("大小寫不符應視為模式無效，得 %v", err)
	}
	if _, err := NewDelegatedRewrapTarget(ctx, RewrapTargetModeKMS, "", nil); !errors.Is(err, ErrRewrapTargetModeInvalid) {
		t.Fatalf("委託目標缺 key_ref 應拒絕，得 %v", err)
	}
	// factory 失敗（不可達／無權限）：歸「預檢失敗」而非「尚未提供」——
	// 兩者的處置完全不同（前者補權限、後者換版本）
	failing := func(context.Context, string, string) (crypto.KEKProvider, error) {
		return nil, errors.New("模擬 KMS 不可達")
	}
	if _, err := NewDelegatedRewrapTarget(ctx, RewrapTargetModeKMS, "arn", failing); !errors.Is(err, ErrRewrapTargetUnavailable) {
		t.Fatalf("factory 失敗應歸為連通性預檢失敗，得 %v", err)
	}
	// factory 回傳判別子不符的 provider：建構入口即以不變式擋下
	mismatched := func(context.Context, string, string) (crypto.KEKProvider, error) {
		return crypto.NewEnvKEKProvider(kmTestKey(3))
	}
	if _, err := NewDelegatedRewrapTarget(ctx, RewrapTargetModeKMS, "arn", mismatched); !errors.Is(err, ErrRewrapTargetInvariant) {
		t.Fatalf("判別子與 provider 種類不符應違反不變式，得 %v", err)
	}
}

// TestRewrapKEKRejectsNilAndDelegatedTarget 服務層入口的 fail-close：
// nil 目標與「套件內手寫的空殼委託目標」皆拒絕，且**零 data_keys 寫入**。
//
// 空殼委託目標（無 provider）現在歸為**不變式違反**而非「尚未交付」：
// 3.3 之後委託分支已交付，一個沒有 provider 的委託目標是套件內 struct literal
// 的繞道嘗試，不是版本不支援。
func TestRewrapKEKRejectsNilAndDelegatedTarget(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	before := countDataKeys(t, db)

	if _, err := km.RewrapKEK(context.Background(), nil); !errors.Is(err, ErrRewrapTargetModeInvalid) {
		t.Fatalf("nil 目標應拒絕，得 %v", err)
	}
	// 直接構造一個委託形狀的目標（僅測試可及：外部構造入口已驗不變式）
	delegated := &RewrapTarget{mode: RewrapTargetModeKMS}
	if _, err := km.RewrapKEK(context.Background(), delegated); !errors.Is(err, ErrRewrapTargetInvariant) {
		t.Fatalf("無 provider 的委託目標應違反不變式，得 %v", err)
	}
	if after := countDataKeys(t, db); after != before {
		t.Fatalf("拒絕路徑不得寫入 data_keys：%d → %d", before, after)
	}
}

// TestRewrapKEKRejectsCurrentAndSeenTarget 「非現行 KEK」與既有守衛 (c)
// 「指紋未曾出現過」：兩者皆拒且**零 data_keys 寫入**
func TestRewrapKEKRejectsCurrentAndSeenTarget(t *testing.T) {
	db := newMigrationDB(t)
	// 現行 KEK 亦以合格材料建構，否則測不到「目標＝現行 KEK」這一格
	current := newTestKEKMaterial(t)
	km := newTestKeyManagerWithMaterial(t, db, current)

	before := countDataKeys(t, db)
	if _, err := rewrapKEKWith(t, km, current); !errors.Is(err, ErrRewrapTargetSameAsCurrent) {
		t.Fatalf("目標等於現行 KEK 應拒絕，得 %v", err)
	}
	if after := countDataKeys(t, db); after != before {
		t.Fatalf("拒絕路徑不得寫入 data_keys：%d → %d", before, after)
	}

	// 正向：另一把新材料可通過（證明上面的拒絕不是「什麼都拒」）
	material, res := mustRewrapKEK(t, km)
	if res.RewrappedKeys == 0 {
		t.Fatal("合格目標應實際重包出列")
	}
	// 放棄後該材料已留下指紋史——再次指定同一把即被守衛 (c) 擋下
	if _, err := km.AbandonRewrap(); err != nil {
		t.Fatalf("AbandonRewrap: %v", err)
	}
	before = countDataKeys(t, db)
	if _, err := rewrapKEKWith(t, km, material); !errors.Is(err, ErrRewrapTargetSeen) {
		t.Fatalf("曾出現過的金鑰引用應拒絕，得 %v", err)
	}
	if after := countDataKeys(t, db); after != before {
		t.Fatalf("拒絕路徑不得寫入 data_keys：%d → %d", before, after)
	}
}

// newTestKeyManagerWithMaterial 以**合格 KEK 材料**建 KeyManagerService
// （newTestKeyManager 用的 kmTestKey 為重複位元組，不在 KEKAlphabet 值域內，
// 無法經 NewLocalRewrapTarget 構造為目標）
func newTestKeyManagerWithMaterial(t *testing.T, db *gorm.DB, material string) *KeyManagerService {
	t.Helper()
	kek, err := crypto.NewEnvKEKProvider([]byte(material))
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	km, err := InitKeyManager(db, kek)
	if err != nil {
		t.Fatalf("InitKeyManager: %v", err)
	}
	return km
}

// countDataKeys data_keys 列數（「零寫入」斷言的觀測量）
func countDataKeys(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&model.DataKey{}).Count(&n).Error; err != nil {
		t.Fatalf("count data_keys: %v", err)
	}
	return n
}

// TestRewrapKEKRevalidatesTargetInvariant sink 端重驗不變式。
//
// 「欄位不導出」只擋得住**套件外**的呼叫端：同一個 service 套件內，
// `RewrapTarget{mode: "local", provider: 任意}` 完全合法且不經任何驗證。
// 原註解宣稱的「建構上不可能」因此過強——真正撐住不變式的是本測試釘住的
// sink 端重驗。三種繞道形態各一：不合格材料、材料與 provider 不相干、無 provider。
func TestRewrapKEKRevalidatesTargetInvariant(t *testing.T) {
	db := newMigrationDB(t)
	km := newTestKeyManager(t, db, 1)
	before := countDataKeys(t, db)

	good := newTestKEKMaterial(t)
	goodProvider, err := crypto.NewLocalAESKEKProvider([]byte(good), crypto.KEKModeUI)
	if err != nil {
		t.Fatalf("建構測試 provider 失敗: %v", err)
	}
	other := newTestKEKMaterial(t)

	cases := []struct {
		name   string
		target *RewrapTarget
		want   error
	}{
		{
			"手寫 literal：材料不合格式（繞過格式驗證）",
			&RewrapTarget{mode: RewrapTargetModeLocal, provider: goodProvider, material: []byte("too-short")},
			ErrRewrapMaterialFormat,
		},
		{
			"手寫 literal：合格材料配不相干的 provider",
			&RewrapTarget{mode: RewrapTargetModeLocal, provider: goodProvider, material: []byte(other)},
			ErrRewrapTargetInvariant,
		},
		{
			"手寫 literal：完全沒有 provider",
			&RewrapTarget{mode: RewrapTargetModeLocal, material: []byte(good)},
			ErrRewrapTargetInvariant,
		},
		{
			"手寫 literal：模式不在白名單",
			&RewrapTarget{mode: "bogus", provider: goodProvider, material: []byte(good)},
			ErrRewrapTargetModeInvalid,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := km.RewrapKEK(context.Background(), c.target); !errors.Is(err, c.want) {
				t.Fatalf("得 %v，期望 %v——未經驗證的目標可直達重包路徑", err, c.want)
			}
		})
	}
	if after := countDataKeys(t, db); after != before {
		t.Fatalf("被重驗擋下的路徑不得寫入 data_keys：%d → %d", before, after)
	}

	// 正向：經公開構造入口的目標必須通過重驗（否則重驗把正常路徑一起擋掉了）。
	if err := localTargetForTest(t, newTestKEKMaterial(t)).Validate(); err != nil {
		t.Fatalf("公開構造入口產出的目標未通過重驗: %v", err)
	}
}

// TestRewrapTargetDestroyZeroesMaterial 材料副本可被覆寫且 Destroy 冪等。
//
// 誠實邊界：Destroy 覆寫的是 RewrapTarget 自己配置的那份 buffer；呼叫端傳入的
// string 與 provider 內展開的金鑰表都不在範圍內（見 Destroy 的說明）。
func TestRewrapTargetDestroyZeroesMaterial(t *testing.T) {
	material := newTestKEKMaterial(t)
	target := localTargetForTest(t, material)
	view := target.material[:]
	if len(view) == 0 {
		t.Fatal("本地目標未保留材料副本——sink 端重驗將無從進行")
	}
	target.Destroy()
	for i, b := range view {
		if b != 0 {
			t.Fatalf("Destroy 後材料副本第 %d 個位元組為 %#x，未被覆寫", i, b)
		}
	}
	target.Destroy() // 冪等：handler 與服務層各登記一次 defer
}
