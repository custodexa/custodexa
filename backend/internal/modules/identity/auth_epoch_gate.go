package identity

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// ErrCredentialGenerationStale 憑證世代已過期（idp-oidc-integration D2/D9）：
// 該憑證簽發後，其 provider 或使用者的憑證世代已被推進，故不再有效。
// 對外一律收斂為既有的認證失敗回應，不單獨暴露成因
var ErrCredentialGenerationStale = errors.New("憑證世代已失效")

// ErrEpochGateUnavailable 世代閘無法運作（資料庫未注入）。
//
// **fail-close 而非放行**（批 14 對抗審查 M6）：閘門是整套撤銷機制的執行點，
// 讀不到判定所需的事實時證明不了憑證仍有效。原本此路徑回 nil（每進程印一行
// 日誌後全部放行），一條漏接 database.DB 的組裝路徑即可讓 provider 停用、
// 帳號停用、改密全數靜默失效，且沒有任何測試會紅。
//
// 與 ErrCredentialGenerationStale 分開命名是為了診斷：前者是「憑證真的過期」，
// 後者是「系統組裝錯誤」，兩者的處置完全不同（後者要修部署，不是叫使用者重登）
var ErrEpochGateUnavailable = errors.New("憑證世代閘無法運作：資料庫未初始化")

// VerifyCredentialGeneration 憑證世代閘（idp-oidc-integration 的核心失效機制）。
//
// 七個驗證點共用此判定：認證中介層、ValidateConnectionToken（WS query token 旁路）、
// MFA verify、MFA enrollment 完成、OIDC exchange、OIDC callback、connect token 兌換，
// 外加 RefreshSession。缺任一點即留下該類憑證的復活窗口。
//
// 兩個維度並列比對，任一不符即拒：
//
//	provider 世代（AuthEpoch）——停用、刪除、client secret 輪替時推進，重新啟用不回退。
//	  解決「停用後短時間內重新啟用會使攻擊者手上未過期的憑證全部復活」——
//	  純 stateless JWT 靠撤銷 refresh 救不了既簽的 access token。
//	使用者世代（CredEpoch）——帳號停用/刪除、改為僅外部登入、解除外部身分綁定、
//	  改密時推進。涵蓋與 provider 無關但同樣須失效的情形，尤其是「尚未兌換」的
//	  能力憑證（ticket／MFA pending／connect grant）——僅掃描既有連線管不到它們。
//
// 零值語義（升級期相容，切勿改用指標或哨兵）：
//   - ProviderID == 0 → 本地/LDAP 登入，不受任何 provider 停用影響，跳過 provider 維度。
//   - 世代 0 與 DB default 一致 → 既有 token 天然有效。
//
// fail-close 例外之二：ProviderID == 0 但 EffectiveMethod() == oidc SHALL 拒絕——
// 該組合任何簽發點都產生不出，放行則此類憑證對 provider 維度的撤銷完全免疫。
//
// fail-close 例外：ProviderID 非零但查無該 provider（已軟刪）SHALL 拒絕——
// 「沒有 provider」（零值）與「宣稱某 provider 但它已不存在」是兩件事，
// 後者的憑證失去可驗證的來源，不得視為前者而放行。
//
// **授權關鍵欄位一律現查 DB，不得讀程序快取**：epoch 驗證的整個價值就在於讀到
// 最新狀態；若落入行程快取，多副本部署下攻擊者把舊 token 導向未更新的副本即可
// 繼續使用，停用形同虛設（design D3 明令）。
//
// **方法化（modular-architecture W8 9.3／R3 I2）**：本閘原為包級函式直讀全域
// `database.DB`。改掛 `*AuthService` 後，資料來源改由 `epochDB()` 決定，
// 組裝根顯式注入（`SetEpochGateDB`）。**判定邏輯、呼叫時機與 fail-close 方向
// 逐位未動**——db 為 nil 一律回 `ErrEpochGateUnavailable`（拒），不是放行。
func (s *AuthService) VerifyCredentialGeneration(authCtx crypto.AuthContext, user *model.User) error {
	return VerifyCredentialGenerationTx(s.epochDB(), authCtx, user)
}

// epochDB 世代閘的資料來源。
//
// **回退全域是刻意保留的相容路徑，不是遺漏**：生產組裝根（cmd/server）顯式注入
// 本欄（`stage2.go` 的 `authService.SetEpochGateDB(database.DB)`，由
// `cmd/server/epoch_gate_injection_test.go` 的 `TestAssemblyInjectsEpochGateDB`
// 以「拔掉全域仍能判定」釘住——**不是讀碼推論**）；
// 回退只服務「未經組裝根建構 AuthService」的測試路徑——那些路徑本來就是
// 靠設定全域 `database.DB` 讓閘門讀到資料的。若此處不回退而直接 nil，
// 本波就會夾帶一個「大量既有測試由通過變成 fail-close 拒絕」的行為變更，
// 那與搬檔波的零行為變更前提直接衝突。移除回退需先改造測試夾具，登記 backlog。
func (s *AuthService) epochDB() *gorm.DB {
	if s.epochGateDB != nil {
		return s.epochGateDB
	}
	return database.DB
}

// SetEpochGateDB 注入世代閘的資料來源（組裝根於 stage2 呼叫）。
//
// 用 setter 而非加寬建構子：比照同檔既有的 SetSecurityPolicies／SetLDAPResolver
// ——不需顯式注入的呼叫端（含全部既有測試）零改動，啟用方在組裝階段顯式開啟。
func (s *AuthService) SetEpochGateDB(db *gorm.DB) {
	s.epochGateDB = db
}

// VerifyCredentialGenerationTx 世代閘的**交易內**版本（idp-oidc-integration 3.8b）。
//
// **匯出（modular-architecture W8 9.1／R3.1 §5.3）**：session 模組的
// `CreateWithGenerationGuard`／`JoinWithGenerationGuard` 在 identity 的能力鎖交易內
// 呼叫本函式，跨包後私有即編譯不過。**維持包級函式而非方法**：它的資料來源是
// 呼叫端交出的交易句柄，本來就不讀任何全域，方法化只會逼呼叫端多持一個實例。
//
// 序列化的三步「重查前提 → 讀世代 → 建立」中的第二步必須讀到與第三步同一把鎖、
// 同一個交易的視圖；走 database.DB 會在鎖外另開連線讀，使「讀世代」與「建立」
// 之間重新出現可被停用插入的窗口。
//
// 兩個維度的判定邏輯與 VerifyCredentialGeneration 完全同源（單一實作，
// 由後者以 database.DB 委派），差別僅在資料來源。
func VerifyCredentialGenerationTx(db *gorm.DB, authCtx crypto.AuthContext, user *model.User) error {
	if db == nil {
		warnEpochGateDisabled()
		return ErrEpochGateUnavailable
	}

	// 使用者世代：user 由呼叫端剛自 DB 載入，其 CredentialEpoch 即現行值。
	//
	// **user == nil 一律拒**（M6）：原本靜默跳過整個使用者維度，等於呼叫端只要
	// 少載入一次 user，改密／停用／解綁就不再失效既簽憑證。全部生產呼叫端都在
	// 交易內剛載入 user 後才進來，故此分支不可達——正因不可達，方向必須是拒絕
	if user == nil {
		return ErrCredentialGenerationStale
	}
	if authCtx.CredEpoch != user.CredentialEpoch {
		return ErrCredentialGenerationStale
	}

	if authCtx.ProviderID == 0 {
		// **method 與 provider 不一致一律拒**（codex 對抗審查 F-D）：
		// EffectiveMethod()==oidc 卻沒有 provider 是任何簽發點都產生不出的組合
		//（issueTicket 一律寫入鎖內重讀的 freshProvider.ID）。放行等於讓此組合的
		// 憑證被當成本地登入而跳過**全部** provider 維度的撤銷——provider 停用、
		// 刪除、密鑰輪替對它完全免疫。
		// 不誤傷升級期舊 token：它們的 AuthMethod 為空，EffectiveMethod() 回
		// local_password（見 crypto.AuthContext 的零值語義），不落入本分支
		if authCtx.EffectiveMethod() == crypto.AuthMethodOIDC {
			return ErrCredentialGenerationStale
		}
		return nil
	}

	var p model.OIDCProvider
	err := db.Select("id", "auth_epoch", "enabled").First(&p, authCtx.ProviderID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// 憑證宣稱的 provider 已不存在 → fail-close
		return ErrCredentialGenerationStale
	}
	if err != nil {
		// DB 故障不得放行：此閘是停用機制的執行點，讀不到即無法證明憑證仍有效
		return fmt.Errorf("讀取 provider 憑證世代失敗: %w", err)
	}
	if !p.Enabled {
		return ErrCredentialGenerationStale
	}
	if authCtx.AuthEpoch != p.AuthEpoch {
		return ErrCredentialGenerationStale
	}
	return nil
}

// epochGateWarnOnce 讓「DB 未注入」的告警每進程只印一次（拒絕本身已 fail-close，
// 日誌只是給維運一條可診斷的線索，不需要每次請求都刷一行）
var epochGateWarnOnce sync.Once

func warnEpochGateDisabled() {
	epochGateWarnOnce.Do(func() {
		log.Println("[AuthEpoch] 資料庫未初始化，憑證世代閘無法運作——" +
			"所有憑證一律拒絕（fail-close）；生產環境出現此訊息代表組裝路徑漏接 database.DB")
	})
}

// VerifyCredentialGenerationByUserID 同上，但自行載入使用者。
// 供手上只有 claims 而無 user 實體的驗證點使用（如認證中介層）。
//
// **方法化同 VerifyCredentialGeneration**（W8 9.3）：三個模組外消費點
// （`middleware/auth.go`、`proxy/handler.go`、`sshproxy/handler.go`）手上本來
// 就持有 `*AuthService`，故改為方法呼叫後**呼叫時機與相對順序逐位未動**。
func (s *AuthService) VerifyCredentialGenerationByUserID(authCtx crypto.AuthContext, userID uint) error {
	db := s.epochDB()
	if db == nil {
		warnEpochGateDisabled()
		return ErrEpochGateUnavailable
	}
	var user model.User
	if err := db.Select("id", "credential_epoch").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotFound
		}
		return fmt.Errorf("讀取使用者憑證世代失敗: %w", err)
	}
	return s.VerifyCredentialGeneration(authCtx, &user)
}

// BumpCredentialEpoch 推進使用者憑證世代（idp-oidc-integration D2）。
//
// 呼叫時機限「管理者的顯式動作使該使用者既有憑證應失效」：帳號停用、刪除、
// 改為僅外部登入、解除外部身分綁定、改密。
//
// **自動鎖定刻意不在此列**：鎖定可由未認證第三方觸發（知道 username 連續打錯密碼
// 即可，且可在每個鎖定窗重複），既有設計明訂「協議會話不砍，避免鎖定成為遠端
// 斷線武器」（auth_service.go 的 recordFailedAttempt）。若推進世代，既簽 access
// 會立即失效、按-user 收線會切斷受害者進行中的監看與分享——正是該設計要避免的攻擊面。
//
// 呼叫端須在同一交易/鎖內完成推進與後續掃描，並於鎖外執行實際的連線關閉。
func BumpCredentialEpoch(db *gorm.DB, userID uint, reason string) error {
	res := db.Model(&model.User{}).Where("id = ?", userID).
		UpdateColumn("credential_epoch", gorm.Expr("credential_epoch + 1"))
	if res.Error != nil {
		return fmt.Errorf("推進使用者憑證世代失敗: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrUserNotFound
	}
	log.Printf("[AuthEpoch] 使用者憑證世代已推進 (userID=%d, reason=%s)", userID, reason)
	return nil
}
