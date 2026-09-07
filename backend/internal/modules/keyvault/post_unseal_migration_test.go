package keyvault

import (
	"context"
	"testing"

	"github.com/custodexa/backend/pkg/crypto"
)

// 重加密入口的冪等性（外部審查批次 2 發現 3）。
//
// 使用時點與 fail-close 語義由 TestRecryptForNewRefThreeUsages 承擔；本檔只管
// 「同一個值被改綁兩次」這一件事。

// TestRecryptForNewRefRebindIsIdempotent 已綁 newRef 的值再跑一次不得失敗，
// 且**原樣返回**。
//
// **為何是真的會發生**：本入口的唯一生產呼叫者是憑證密文轉換的改綁步
//（internal/database/credential_secret_conversion.go），它的重試閘是
// schema_migrations 的執行期 marker。marker 一旦不在——結構回退後重跑、
// 或庫被還原到寫 marker 之前的時點——改綁會對**已經改綁過**的值再跑一次。
// 此時若入口恆以 oldRef 解密，那批值一律解不開、整段回滾、下次啟動再失敗一次，
// 轉換就永遠卡在那裡；而服務照常起來，管理者看不出差別。
func TestRecryptForNewRefRebindIsIdempotent(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	ctx := context.Background()
	oldRef := crypto.CipherRef{Table: "asset_accounts", Column: "password_enc"}
	newRef := crypto.CipherRef{Table: "credential_secret_versions", Column: "password_enc"}

	bound, err := km.EncryptFor(ctx, oldRef, "rebind-me")
	if err != nil {
		t.Fatalf("以來源身分加密: %v", err)
	}
	once, err := RecryptForNewRef(ctx, km, oldRef, newRef, bound)
	if err != nil {
		t.Fatalf("第一次改綁: %v", err)
	}

	twice, err := RecryptForNewRef(ctx, km, oldRef, newRef, once)
	if err != nil {
		t.Fatalf("已綁目標身分的值再跑一次 MUST 成功（入口宣稱冪等）: %v", err)
	}
	if twice != once {
		t.Fatal("已綁目標身分的值 MUST 原樣返回：重新加密會換掉密文而沒有任何收穫，" +
			"且讓「這次改綁動了幾筆」不再可信")
	}
	if got, err := km.DecryptFor(ctx, newRef, twice); err != nil || got != "rebind-me" {
		t.Fatalf("兩次之後仍應以目標身分解回原明文: got=%q err=%v", got, err)
	}
}

// TestRecryptForNewRefRebindStillRefusesForeignIdentity 冪等性不得放寬 fail-close：
// 既非來源身分、也非目標身分的值仍須失敗。
//
// 這是「先試 newRef」這個改法唯一會踩壞的東西——若探測失敗後不再走 oldRef、
// 或探測本身把錯誤吞掉，一個誰都解不開的值會被靜默放行。
func TestRecryptForNewRefRebindStillRefusesForeignIdentity(t *testing.T) {
	db := newAADTestDB(t)
	km := newTestKeyManager(t, db, 1)
	ctx := context.Background()
	oldRef := crypto.CipherRef{Table: "asset_accounts", Column: "password_enc"}
	newRef := crypto.CipherRef{Table: "credential_secret_versions", Column: "password_enc"}
	foreign := crypto.CipherRef{Table: "assets", Column: "private_key_enc"}

	bound, err := km.EncryptFor(ctx, foreign, "not-ours")
	if err != nil {
		t.Fatalf("以第三方身分加密: %v", err)
	}
	if _, err := RecryptForNewRef(ctx, km, oldRef, newRef, bound); err == nil {
		t.Fatal("既非來源亦非目標身分的值 MUST 失敗（不得靜默放行）")
	}
}
