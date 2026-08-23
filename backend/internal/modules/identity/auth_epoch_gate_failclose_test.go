package identity

import (
	"errors"
	"testing"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
)

// 世代閘的兩個 fail-open 分支。
//
// 閘門是**整套撤銷機制的執行點**：provider 停用、密鑰輪替、帳號停用、解綁、
// 改密全都靠它把既簽憑證擋在門外。它若在某些條件下放行，撤銷就只剩下「撤 refresh」
// 這一半，而 access token 是 stateless 的，撤 refresh 對它毫無作用。
//
// 兩個分支各自的失敗場景：
//   - DB 未注入 → 每進程只印一行日誌，然後**全部憑證一律放行**。生產環境確實
//     不該出現，但「不該出現」不是保護；一條漏接 database.DB 的組裝路徑
//     （或未來的多租戶／多 DB 重構）就會讓撤銷靜默失效，且沒有任何測試會紅。
//   - user == nil → 靜默跳過整個使用者維度（credential_epoch 完全不比對）。
//     簽章允許 nil，呼叫端只要少載入一次 user 就換得「改密／停用不再失效既簽憑證」。
//
// 方向一律 fail-close：閘門讀不到判定所需的事實時，證明不了憑證仍有效，就不得放行。
func TestEpochGateFailsCloseWithoutDatabase(t *testing.T) {
	old := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = old })

	authCtx := crypto.AuthContext{AuthMethod: crypto.AuthMethodOIDC, ProviderID: 7, AuthEpoch: 1}

	if err := epochGateForTest.VerifyCredentialGeneration(authCtx, &model.User{}); !errors.Is(err, ErrEpochGateUnavailable) {
		t.Errorf("DB 未注入時 VerifyCredentialGeneration = %v, want ErrEpochGateUnavailable", err)
	}
	if err := epochGateForTest.VerifyCredentialGenerationByUserID(authCtx, 1); !errors.Is(err, ErrEpochGateUnavailable) {
		t.Errorf("DB 未注入時 VerifyCredentialGenerationByUserID = %v, want ErrEpochGateUnavailable", err)
	}
	if err := VerifyCredentialGenerationTx(nil, authCtx, &model.User{}); !errors.Is(err, ErrEpochGateUnavailable) {
		t.Errorf("交易為 nil 時 VerifyCredentialGenerationTx = %v, want ErrEpochGateUnavailable", err)
	}
}

// TestEpochGateFailsCloseOnNilUser user 未載入時不得跳過使用者世代維度
func TestEpochGateFailsCloseOnNilUser(t *testing.T) {
	db := localAdminDB(t)

	// 連零值脈絡都不放行：閘門無法證明「CredEpoch 0 就是現值」
	if err := VerifyCredentialGenerationTx(db, crypto.AuthContext{}, nil); !errors.Is(err, ErrCredentialGenerationStale) {
		t.Errorf("user 為 nil（零值脈絡）= %v, want ErrCredentialGenerationStale", err)
	}
	if err := VerifyCredentialGenerationTx(db, crypto.AuthContext{CredEpoch: 3}, nil); !errors.Is(err, ErrCredentialGenerationStale) {
		t.Errorf("user 為 nil（世代 3）= %v, want ErrCredentialGenerationStale", err)
	}
	// 反面：user 已載入且世代相符者照常通過
	if err := VerifyCredentialGenerationTx(db, crypto.AuthContext{CredEpoch: 3},
		&model.User{CredentialEpoch: 3}); err != nil {
		t.Errorf("世代相符 = %v, want nil", err)
	}
}
