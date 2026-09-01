package offsite

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 離機儲存設定世代的服務層。
//
// 五個寫入者（Save／ConfirmGenerationSwitch／RevokeCredentials／Disable／env seed）
// **共用同一把 advisory lock**，且**一切判定於鎖內以 tx 重讀**——鎖外預讀只能當提示。
// 沿 internal/modules/identity/ldap_directory_service.go 的鎖內交易時序逐步對映。
//
// # 憑證的記憶體語義（誠實邊界）
//
// 明文憑證只存在於**受控的程序記憶體生命期**內：解密後只交給 driver 建構函式，
// 不落磁碟、不進日誌、不進 API 回應、不進審計、不進錯誤鏈。
// **明示例外**：SDK 由憑證衍生的簽章材料與存取 token、以及 per-generation client
// cache 內的長存 client 物件，會在該 cache 的生命期內持有等價授權；其收回不靠
// 「明文已離開呼叫棧」，而靠 `credential_revision` 的失效核對。
// 另**不主張**明文位元組於 GC 後即刻歸零（Go 無安全歸零保證）——這是誠實邊界，
// 不是防線。

// ErrCredentialCodecMissing 憑證加解密器未接線（組裝疏漏）。
//
// **不是 panic 也不是靜默明文直通**：生產組裝一律注入 codec；缺席時寫入路徑
// fail-close，否則憑證會以明文落庫而管理面完全看不出來
var ErrCredentialCodecMissing = errors.New("offsite: 憑證加解密器未接線，設定寫入一律拒絕")

// ErrLedgerNotWired 帳冊未接線。
//
// 設定寫入需要帳冊來數存量物件與轉移 foreign；缺席時放行會讓世代切換**跳過確認**
// 並留下一批仍宣稱屬現行世代的舊物件——fail-close
var ErrLedgerNotWired = errors.New("offsite: 保管帳冊未接線，設定寫入一律拒絕")

// OffsiteActor 操作者（handler 自 JWT 填入，比照既有 Actor* 慣例）。
type OffsiteActor struct {
	ID   uint
	Name string
	IP   string
}

// ProfileView 設定的讀取視圖——**write-only 形態**：
// 恆不含憑證與其遮罩，改回 `CredentialMode` 與 `HasCredentials`。
type ProfileView struct {
	// Configured 設定表是否有任何世代（**false＝從未設定**，「行為完全不變」的判準）
	Configured bool
	// Disabled 有歷史世代但零現行世代＝**停用態**（與從未設定分立）
	Disabled bool

	GenerationID       uint
	ProfileFingerprint string
	Provider           string
	// EndpointOrigin 顯示形態，**不含 path**
	EndpointOrigin string
	Bucket         string
	Prefix         string
	Region         string
	PathStyle      bool

	CredentialMode       string
	HasCredentials       bool
	CredentialsClearedAt *time.Time

	CreatedAt   time.Time
	ActivatedAt time.Time
	RetiredAt   *time.Time
	// ObjectCount 該世代的存量物件數（歷史世代列表用；Get 不填）
	ObjectCount int64
}

// SaveResult 儲存的結果。NeedsConfirmation 時**未做任何寫入**。
type SaveResult struct {
	// NeedsConfirmation true＝新指紋與現行世代不同且帳冊有存量物件，
	// 需管理員確認後改走 ConfirmGenerationSwitch
	NeedsConfirmation bool
	// ObjectCount 受影響的存量物件數（**給人看的提示**，不是判定依據——
	// 確認時於鎖內重數）
	ObjectCount int64
	// ExpectedCurrentGenerationID 管理員按下確認時所見的現行世代；
	// **0＝預期目前無現行世代**。確認請求 SHALL 原樣攜回
	ExpectedCurrentGenerationID uint
	// SettingsDigest 新設定正規化後的摘要；確認請求 SHALL 原樣攜回
	SettingsDigest string
	// View 實際寫入後的視圖（NeedsConfirmation 時為零值）
	View ProfileView
}

// ConfirmRequest 世代切換確認請求。
type ConfirmRequest struct {
	Settings SettingsInput
	// ExpectedCurrentGenerationID 前一步回應原樣攜回（0＝預期無現行世代）
	ExpectedCurrentGenerationID uint
	// SettingsDigest 前一步回應原樣攜回
	SettingsDigest string
}

// CredentialState 憑證的三態（沿 policy/ldap_risk.go 的三態形態）。
//
// **禁止把金鑰事故併吞成未設定**：解密失敗時上傳與取回停在 failed 且告警可見。
type CredentialState string

const (
	// CredentialStateUnconfigured 無現行世代（從未設定或已停用）
	CredentialStateUnconfigured CredentialState = "unconfigured"
	// CredentialStateOK 現行世代的憑證可用（stored 已解出，或刻意走預設鏈）
	CredentialStateOK CredentialState = "ok"
	// CredentialStateFailed 讀取或解密失敗＝**金鑰事故**，不是功能關閉
	CredentialStateFailed CredentialState = "failed"
)

// ledgerOps 設定服務對帳冊的窄依賴（同包，但以介面表達使構造順序可解環：
// 帳冊需要設定服務提供現行世代，設定服務需要帳冊數存量與轉 foreign）。
type ledgerOps interface {
	CountByGeneration(tx *gorm.DB, generationID uint) (int64, error)
	MarkForeign(tx *gorm.DB, generationID uint) (int64, int64, error)
	TotalObjects() (int64, error)
}

// OwnerCacheMarker 擁有表快取的批次寫回面（各模組 adapter 實作；
// 與 `Adapter.MarkForeignBatch` 同一方法，此處另立窄介面是為了讓組裝根只交出
// 這一個能力，不把整個 Adapter 的取件面暴露給設定服務）。
//
// **為什麼世代退役時要動擁有表快取**：`offsite_status` 是給 UI 讀的快取欄，
// 決策一律讀帳冊。但快取若停在 `uploaded`／`pending`，會話詳情會在世代切換後
// 繼續顯示「已上傳到現行儲存」——那是錯的，物件在舊世代的 bucket 裡，
// 取回要用舊世代的憑證。快取寫不回去不是可接受的終局，故與帳冊轉移同交易。
type OwnerCacheMarker interface {
	MarkForeignBatch(tx *gorm.DB, generationID uint) error
}

// ClientBuildSpec driver 建構的中立參數（**明文憑證只在這裡出現一次**，
// 由 ClientFor 組出後立即交給 factory）。
type ClientBuildSpec struct {
	Provider string
	// Endpoint 完整正規化端點（含 path）；空＝該 provider 的預設解析
	Endpoint  string
	Bucket    string
	Region    string
	PathStyle bool

	AccessKeyID        string
	SecretAccessKey    string
	ServiceAccountJSON string
}

// ClientFactory 由建構參數產出 driver。**可注入**——測試以計數器實作證明
// 「撤銷世代零 driver 建構、零預設鏈探測」。
type ClientFactory func(ctx context.Context, spec ClientBuildSpec) (Client, error)

// DefaultClientFactory 生產用 factory：依 provider 呼叫既有的兩個建構函式。
func DefaultClientFactory(ctx context.Context, spec ClientBuildSpec) (Client, error) {
	if spec.Provider == ProviderGCS {
		return NewGCSClient(ctx, GCSParams{
			Bucket:          spec.Bucket,
			CredentialsJSON: spec.ServiceAccountJSON,
			Endpoint:        spec.Endpoint,
		})
	}
	return NewS3Client(ctx, S3Params{
		Bucket:          spec.Bucket,
		Endpoint:        spec.Endpoint,
		Region:          spec.Region,
		PathStyle:       spec.PathStyle,
		AccessKeyID:     spec.AccessKeyID,
		SecretAccessKey: spec.SecretAccessKey,
	})
}

// cachedClient per-generation 的 client 快取項。
type cachedClient struct {
	client Client
	// revision 建構當下該世代的 credential_revision；每次取用前與現值核對，
	// 不等即丟棄重建——沿用被撤銷憑證的窗口因此收斂到「同一次呼叫內」
	revision int64
}

// OffsiteProfileService 離機儲存設定世代服務。
type OffsiteProfileService struct {
	db      *gorm.DB
	codec   crypto.ColumnCodec
	journal CustodyJournal
	ledger  ledgerOps
	factory ClientFactory
	now     func() time.Time
	// ownerCaches 擁有表快取的批次寫回面（世代退役時與帳冊轉移同交易）。
	// 空切片＝無擁有者模組接線（單測建構路徑），此時帳冊仍照常轉 foreign
	ownerCaches []OwnerCacheMarker

	mu      sync.Mutex
	clients map[uint]cachedClient
	// testLimiter 連線測試的資源上限（test_ratelimit.go）
	testLimiter *offsiteTestLimiter
}

// offsiteTestActorKey 限流鍵：優先取使用者 id，退回來源位址。
//
// **不以名稱為鍵**：改名即換一個新桶。兩者皆缺時落共用的匿名桶——那是一個
// 不該發生的裝配（handler 一律自 JWT 填 actor），共用桶使它不至於無限制。
func offsiteTestActorKey(a OffsiteActor) string {
	if a.ID != 0 {
		return "uid:" + strconv.FormatUint(uint64(a.ID), 10)
	}
	if a.IP != "" {
		return "ip:" + a.IP
	}
	return "anonymous"
}

// NewOffsiteProfileService 建立設定服務。journal 為 nil 時以 no-op 退路
// （僅單測建構路徑；生產組裝一律注入）。
func NewOffsiteProfileService(db *gorm.DB, codec crypto.ColumnCodec, journal CustodyJournal) *OffsiteProfileService {
	if journal == nil {
		journal = noopCustodyJournal{}
	}
	return &OffsiteProfileService{
		db: db, codec: codec, journal: journal,
		factory:     DefaultClientFactory,
		now:         time.Now,
		clients:     map[uint]cachedClient{},
		testLimiter: newOffsiteTestLimiter(),
	}
}

// SetLedger 注入帳冊（組裝時；兩者互為對方的依賴，以 setter 打環——
// 沿 LDAPDirectoryService.SetTransmissionPolicy 的先例）。
func (s *OffsiteProfileService) SetLedger(l ledgerOps) { s.ledger = l }

// SetOwnerCacheMarkers 注入擁有表快取的批次寫回面（組裝時，adapters 建構之後）。
//
// **可變參數而非逐一 setter**：擁有者模組的數量隨協議擴張，逐一 setter 會讓
// 「新增一個擁有者卻忘了接線」變成一個沒有任何東西看得見的遺漏。
func (s *OffsiteProfileService) SetOwnerCacheMarkers(ms ...OwnerCacheMarker) {
	out := make([]OwnerCacheMarker, 0, len(ms))
	for _, m := range ms {
		if m != nil {
			out = append(out, m)
		}
	}
	s.ownerCaches = out
}

// markOwnerCachesForeign 世代退役時把各擁有表的離機快取欄批次寫成 foreign。
//
// **fail-close（回 error 即整筆回滾）**：世代已退役而快取仍說「已上傳到現行儲存」
// 是一個會誤導調閱者的狀態，且它不會自我修復——帳冊的世代欄已經換人，
// 之後沒有任何一輪迴圈會回頭修這些列。
func (s *OffsiteProfileService) markOwnerCachesForeign(tx *gorm.DB, generationID uint) error {
	for _, m := range s.ownerCaches {
		if err := m.MarkForeignBatch(tx, generationID); err != nil {
			return err
		}
	}
	return nil
}

// SetClientFactoryForTest 覆寫 driver factory（僅測試）。
func (s *OffsiteProfileService) SetClientFactoryForTest(f ClientFactory) { s.factory = f }

// SetClockForTest 覆寫時間源（僅測試）。
func (s *OffsiteProfileService) SetClockForTest(now func() time.Time) { s.now = now }

// ── 讀取 ────────────────────────────────────────────────────────────────

// currentRow 現行世代（`retired_at IS NULL`）；無列回 (nil, nil)。
//
// **>1 列時取 generation_id 最小者**：單元測試庫走 AutoMigrate，partial unique
// index 由 gorm tag 表達不出（沿 idx_assets_name 的既有缺口），故服務層對「多列」
// 必須有確定性行為，不得行為未定。生產由 DB 層保證不會走到這裡。
func currentOffsiteRow(tx *gorm.DB) (*model.OffsiteProfile, error) {
	var rows []model.OffsiteProfile
	if err := tx.Where("retired_at IS NULL").Order("generation_id ASC").Limit(1).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取離機儲存設定失敗: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// Get 讀取現行設定的 write-only 視圖。
//
// 三個終局各自可辨識：設定表零列＝`Configured=false`（從未設定）；
// 有歷史世代而零現行＝`Configured=true, Disabled=true`（停用態）；
// 有現行世代＝完整視圖。
func (s *OffsiteProfileService) Get() (ProfileView, error) {
	row, err := currentOffsiteRow(s.db)
	if err != nil {
		return ProfileView{}, err
	}
	if row != nil {
		return profileViewOf(row), nil
	}
	var total int64
	if err := s.db.Model(&model.OffsiteProfile{}).Count(&total).Error; err != nil {
		return ProfileView{}, fmt.Errorf("計數離機儲存設定世代失敗: %w", err)
	}
	if total == 0 {
		return ProfileView{Configured: false}, nil
	}
	return ProfileView{Configured: true, Disabled: true}, nil
}

// GenerationCount 設定世代的總列數（含已退役者）。
//
// **這是「從未設定」與「已停用」的分界**：零＝設定表零列＝行為完全不變
// （不註冊任何離機指標、不排背景刷新源）；非零而無現行世代＝停用態，
// 存量與失敗面照常曝光（停用態表）。
//
// 不重用 `ListHistory`：它會為每一列各打一次帳冊計數，而這裡只要一個數字，
// 而且它跑在啟動路徑上。
func (s *OffsiteProfileService) GenerationCount() (int64, error) {
	var n int64
	if err := s.db.Model(&model.OffsiteProfile{}).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("計數離機儲存設定世代失敗: %w", err)
	}
	return n, nil
}

// ListHistory 全部世代（新到舊），含各世代的存量物件數。
func (s *OffsiteProfileService) ListHistory() ([]ProfileView, error) {
	var rows []model.OffsiteProfile
	if err := s.db.Order("generation_id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("讀取離機儲存設定世代清單失敗: %w", err)
	}
	out := make([]ProfileView, 0, len(rows))
	for i := range rows {
		v := profileViewOf(&rows[i])
		if s.ledger != nil {
			if n, err := s.ledger.CountByGeneration(s.db, rows[i].GenerationID); err == nil {
				v.ObjectCount = n
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// CurrentGeneration 實作 GenerationSource：以呼叫方的 tx 重讀現行世代。
func (s *OffsiteProfileService) CurrentGeneration(tx *gorm.DB) (GenerationRef, error) {
	row, err := currentOffsiteRow(tx)
	if err != nil {
		return GenerationRef{}, err
	}
	if row == nil {
		return GenerationRef{}, ErrNoCurrentGeneration
	}
	return GenerationRef{
		GenerationID: row.GenerationID,
		Provider:     row.Provider,
		Bucket:       row.Bucket,
		Prefix:       row.Prefix,
	}, nil
}

// CredentialState 現行世代的憑證三態（fail-close）。
func (s *OffsiteProfileService) CredentialState(ctx context.Context) (CredentialState, error) {
	row, err := currentOffsiteRow(s.db)
	if err != nil {
		// 讀取失敗＝故障，**不是未設定**
		return CredentialStateFailed, err
	}
	if row == nil {
		return CredentialStateUnconfigured, nil
	}
	switch row.CredentialMode {
	case model.OffsiteCredentialDefaultChain:
		return CredentialStateOK, nil
	case model.OffsiteCredentialRevoked:
		// 現行世代被撤銷憑證是異常狀態（撤銷的目標通常是歷史世代）：
		// 上傳必然失敗，呈現為 failed 而非「功能關閉」
		return CredentialStateFailed, nil
	}
	if _, err := s.decryptCredentials(ctx, row); err != nil {
		return CredentialStateFailed, err
	}
	return CredentialStateOK, nil
}

// ── 憑證加解密（錯誤一律淨化為靜態拒因）───────────────────────────────

// encryptCredentials 加密憑證明文。
//
// **底層錯誤在此淨化**：codec 的錯誤可能夾帶明文片段，原樣以 %w 包裝會讓明文
// 順著錯誤鏈流進呼叫端，再由各處 log.Printf("%v") 落進 operational log
// ——與「憑證不進日誌」同一條紅線。可辨識性只留錯誤**型別名**（靜態，不含輸入）。
func (s *OffsiteProfileService) encryptCredentials(ctx context.Context, plain string) (string, error) {
	if s.codec == nil {
		return "", ErrCredentialCodecMissing
	}
	enc, err := s.codec.EncryptFor(ctx, keyvault.RefOffsiteCredentials, plain)
	if err != nil {
		log.Printf("[Offsite] 憑證信封加密失敗 error_type=%T（底層錯誤已淨化，不入日誌）", err)
		return "", reject(ReasonEncryptFailed)
	}
	return enc, nil
}

// decryptCredentials 解密某世代的憑證；理由同加密側。
func (s *OffsiteProfileService) decryptCredentials(ctx context.Context, row *model.OffsiteProfile) (string, error) {
	if row.CredentialsEnc == "" {
		return "", nil
	}
	if s.codec == nil {
		return "", ErrCredentialCodecMissing
	}
	plain, err := s.codec.DecryptFor(ctx, keyvault.RefOffsiteCredentials, row.CredentialsEnc)
	if err != nil {
		log.Printf("[Offsite] 憑證信封解密失敗（fail-close，指向金鑰事故非設定錯誤）generation_id=%d error_type=%T",
			row.GenerationID, err)
		return "", reject(ReasonDecryptFailed)
	}
	return plain, nil
}

// ── 寫入（五個寫入者共用 WithOffsiteProfileLock）─────────────────────────

// Save 儲存設定（PUT 語義）。
//
// 鎖內時序（每一步都可能拒絕）：
//
//  1. 憑證輸入衝突 → 靜態拒因（在驗證核心內）
//  2. **共用驗證核心**（provider 枚舉、bucket 非空、端點淨化、s3 端點與 region）
//  3. 落點變更拒絕沿用既存憑證（憑證外送不變式）
//  4. 加密（錯誤淨化為靜態哨兵）
//  5. 寫列（憑證變更或撤銷時 credential_revision + 1）
//  6. 同事務具名事實審計（審計失敗整筆回滾）
//
// 指紋與現行世代相同 → 就地更新現行列；不同且帳冊有存量 → 回「需確認」**且不寫入**。
func (s *OffsiteProfileService) Save(ctx context.Context, in SettingsInput, actor OffsiteActor) (SaveResult, error) {
	if s.ledger == nil {
		return SaveResult{}, ErrLedgerNotWired
	}
	var out SaveResult
	err := WithOffsiteProfileLock(s.db, func(tx *gorm.DB) error {
		norm, err := validateAndNormalizeOffsiteSettings(in)
		if err != nil {
			return err
		}
		// 鎖內重讀：現行世代、既存憑證與落點比較全部以本次讀到的值為準
		current, err := currentOffsiteRow(tx)
		if err != nil {
			return err
		}
		if err := checkCredentialReuse(current, norm); err != nil {
			return err
		}
		fp := norm.fingerprintOf()

		// 指紋相同＝同一個落點：就地更新現行列（憑證輪替走這條，**不觸發世代切換**）
		if current != nil && current.ProfileFingerprint == fp {
			view, err := s.updateInPlaceLocked(ctx, tx, current, norm, actor)
			if err != nil {
				return err
			}
			out.View = view
			return nil
		}

		// 指紋不同（含「現行世代不存在」）：世代切換
		expected := uint(0)
		if current != nil {
			expected = current.GenerationID
		}
		objectCount := int64(0)
		if current != nil {
			if objectCount, err = s.ledger.CountByGeneration(tx, current.GenerationID); err != nil {
				return err
			}
		}
		if objectCount > 0 {
			// **不寫入**：回「需確認」，把管理員所見的現行世代與新設定摘要一併帶回
			out.NeedsConfirmation = true
			out.ObjectCount = objectCount
			out.ExpectedCurrentGenerationID = expected
			out.SettingsDigest = norm.settingsDigest()
			return nil
		}
		view, err := s.switchGenerationLocked(ctx, tx, current, norm, actor)
		if err != nil {
			return err
		}
		out.View = view
		return nil
	})
	if err != nil {
		return SaveResult{}, offsiteProfileWriteError(err)
	}
	return out, nil
}

// ConfirmGenerationSwitch 世代切換的確認流程（防過期確認與 TOCTOU）。
//
// 鎖內依序：
//
//	(1) CAS：重讀現行世代，與攜回的 expected 不符即以靜態拒因拒絕，
//	    **訊息不回顯現行設定的任何細節**
//	(2) 重算請求體的 digest 並與攜回值比對——防「確認畫面顯示 A、送出的卻是 B」
//	(3) 以與 Save **完全相同**的驗證核心重驗全部輸入
//	(4) 鎖內重數存量物件（確認畫面上的數字只是提示，不是判定依據）
//	(5) 才寫入
//
// 兩名管理員並發確認時，先到者成立、後到者必因 CAS 失敗被拒，
// **任何交錯都不可能留下兩列現行世代**。
func (s *OffsiteProfileService) ConfirmGenerationSwitch(ctx context.Context, req ConfirmRequest, actor OffsiteActor) (ProfileView, error) {
	if s.ledger == nil {
		return ProfileView{}, ErrLedgerNotWired
	}
	var view ProfileView
	err := WithOffsiteProfileLock(s.db, func(tx *gorm.DB) error {
		// (1) CAS
		current, err := currentOffsiteRow(tx)
		if err != nil {
			return err
		}
		actual := uint(0)
		if current != nil {
			actual = current.GenerationID
		}
		if actual != req.ExpectedCurrentGenerationID {
			return reject(ReasonStaleConfirmation)
		}
		// (3) 與 Save 共用的**單一驗證核心**（先驗才有 digest 可比）
		norm, err := validateAndNormalizeOffsiteSettings(req.Settings)
		if err != nil {
			return err
		}
		// (2) digest 比對
		if norm.settingsDigest() != req.SettingsDigest {
			return reject(ReasonDigestMismatch)
		}
		if err := checkCredentialReuse(current, norm); err != nil {
			return err
		}
		// (4) 鎖內重數存量（只為審計負載的正確性；判定不依賴確認畫面的數字）
		if current != nil {
			if _, err := s.ledger.CountByGeneration(tx, current.GenerationID); err != nil {
				return err
			}
		}
		// (5) 寫入
		v, err := s.switchGenerationLocked(ctx, tx, current, norm, actor)
		if err != nil {
			return err
		}
		view = v
		return nil
	})
	if err != nil {
		return ProfileView{}, offsiteProfileWriteError(err)
	}
	return view, nil
}

// Disable 停止離機（管理介面動作，破壞性確認由 handler 承擔）。
//
// 鎖內同一交易：現行列填 `retired_at`、**不建新列**、該世代帳冊列轉 foreign
// （其中 pending／failed 者事件 details 註 `never_uploaded=true`——否則 worker 停後
// 它們永遠停在 pending 而佇列指標又缺席＝黑洞）、保管鏈事件。
//
// **不撤銷任何憑證**：歷史取回要用。要撤另走 RevokeCredentials。
func (s *OffsiteProfileService) Disable(ctx context.Context, actor OffsiteActor) error {
	if s.ledger == nil {
		return ErrLedgerNotWired
	}
	err := WithOffsiteProfileLock(s.db, func(tx *gorm.DB) error {
		current, err := currentOffsiteRow(tx)
		if err != nil {
			return err
		}
		if current == nil {
			return reject(ReasonNoCurrentGeneration)
		}
		if offsiteProfilePreWriteHook != nil {
			offsiteProfilePreWriteHook()
		}
		now := s.now()
		if err := tx.Model(&model.OffsiteProfile{}).
			Where("generation_id = ?", current.GenerationID).
			Update("retired_at", now).Error; err != nil {
			return fmt.Errorf("退役離機儲存設定世代失敗: %w", err)
		}
		moved, neverUploaded, err := s.ledger.MarkForeign(tx, current.GenerationID)
		if err != nil {
			return err
		}
		if err := s.markOwnerCachesForeign(tx, current.GenerationID); err != nil {
			return err
		}
		details := map[string]any{
			"old_generation_id":       current.GenerationID,
			"old_profile_fingerprint": current.ProfileFingerprint,
			"bucket":                  current.Bucket,
			"count":                   moved,
			"result":                  "disabled",
		}
		if neverUploaded > 0 {
			details["never_uploaded_count"] = neverUploaded
		}
		return s.journal.RecordInTx(tx, CustodyEvent{
			Action:   CustodyActionProfile,
			Resource: string(model.ResourceSession),
			Status:   string(model.StatusSuccess),
			Details:  details,
		})
	})
	if err != nil {
		return offsiteProfileWriteError(err)
	}
	log.Printf("[Offsite] 已停止離機儲存（現行世代退役、不建新列；歷史世代憑證保留供取回）actor=%d", actor.ID)
	return nil
}

// RevokeCredentials 撤銷某個世代的憑證。
//
// 鎖內同一交易：清空密文＋置 `revoked`＋寫 `credentials_cleared_at`＋
// `credential_revision + 1`＋保管鏈事件；同交易後該世代的 client cache 立即失效。
//
// 跨程序與重啟的正確性**不靠行程內事件**：`ClientFor` 每次取用前核對 cache 內
// 記載的 revision 與該列現值，不等即丟棄重建。
func (s *OffsiteProfileService) RevokeCredentials(ctx context.Context, generationID uint, actor OffsiteActor) error {
	err := WithOffsiteProfileLock(s.db, func(tx *gorm.DB) error {
		var row model.OffsiteProfile
		if err := tx.Where("generation_id = ?", generationID).First(&row).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return reject(ReasonGenerationNotFound)
			}
			return fmt.Errorf("讀取離機儲存設定世代失敗: %w", err)
		}
		if row.CredentialMode == model.OffsiteCredentialRevoked {
			return reject(ReasonCredentialsAlreadyRevoked)
		}
		if offsiteProfilePreWriteHook != nil {
			offsiteProfilePreWriteHook()
		}
		now := s.now()
		if err := tx.Model(&model.OffsiteProfile{}).
			Where("generation_id = ?", generationID).
			Updates(map[string]any{
				"credentials_enc":        "",
				"credential_mode":        model.OffsiteCredentialRevoked,
				"credentials_cleared_at": now,
				"credential_revision":    gorm.Expr("credential_revision + 1"),
			}).Error; err != nil {
			return fmt.Errorf("撤銷離機儲存憑證失敗: %w", err)
		}
		return s.journal.RecordInTx(tx, CustodyEvent{
			Action:   CustodyActionCredRevoke,
			Resource: string(model.ResourceSession),
			Status:   string(model.StatusSuccess),
			Details: map[string]any{
				"generation_id": generationID,
				"provider":      row.Provider,
				"bucket":        row.Bucket,
			},
		})
	})
	if err != nil {
		return offsiteProfileWriteError(err)
	}
	s.invalidateClient(generationID)
	log.Printf("[Offsite] 已撤銷世代 %d 的憑證（該世代物件自此不可取回，且不會回退到雲端預設憑證鏈）actor=%d",
		generationID, actor.ID)
	return nil
}

// ── 鎖內寫入的兩條分支 ──────────────────────────────────────────────────

// updateInPlaceLocked 指紋相同：就地更新現行列。
func (s *OffsiteProfileService) updateInPlaceLocked(ctx context.Context, tx *gorm.DB,
	current *model.OffsiteProfile, norm normalizedSettings, actor OffsiteActor) (ProfileView, error) {
	mode, enc, bumped, err := s.resolveCredentialsLocked(ctx, current, norm)
	if err != nil {
		return ProfileView{}, err
	}
	if offsiteProfilePreWriteHook != nil {
		offsiteProfilePreWriteHook()
	}
	fields := map[string]any{
		"provider":        norm.Provider,
		"endpoint":        norm.EndpointFull,
		"bucket":          norm.Bucket,
		"prefix":          norm.Prefix,
		"region":          norm.Region,
		"path_style":      norm.PathStyle,
		"credential_mode": mode,
		"credentials_enc": enc,
	}
	if bumped {
		fields["credential_revision"] = gorm.Expr("credential_revision + 1")
		if mode != model.OffsiteCredentialStored {
			fields["credentials_cleared_at"] = s.now()
		}
	}
	if err := tx.Model(&model.OffsiteProfile{}).
		Where("generation_id = ?", current.GenerationID).Updates(fields).Error; err != nil {
		return ProfileView{}, fmt.Errorf("更新離機儲存設定失敗: %w", err)
	}
	var updated model.OffsiteProfile
	if err := tx.Where("generation_id = ?", current.GenerationID).First(&updated).Error; err != nil {
		return ProfileView{}, fmt.Errorf("回讀離機儲存設定失敗: %w", err)
	}
	if err := s.auditSaveInTx(tx, &updated, norm, actor, "update"); err != nil {
		return ProfileView{}, err
	}
	if bumped {
		s.invalidateClient(current.GenerationID)
	}
	return profileViewOf(&updated), nil
}

// switchGenerationLocked 指紋不同：退役現行列、建立並啟用新列、舊世代帳冊轉 foreign、
// 審計——**同一交易，任一步失敗整筆回滾**。
func (s *OffsiteProfileService) switchGenerationLocked(ctx context.Context, tx *gorm.DB,
	current *model.OffsiteProfile, norm normalizedSettings, actor OffsiteActor) (ProfileView, error) {
	mode, enc, _, err := s.resolveCredentialsLocked(ctx, current, norm)
	if err != nil {
		return ProfileView{}, err
	}
	if offsiteProfilePreWriteHook != nil {
		offsiteProfilePreWriteHook()
	}
	now := s.now()
	var moved, neverUploaded int64
	if current != nil {
		if err := tx.Model(&model.OffsiteProfile{}).
			Where("generation_id = ?", current.GenerationID).
			Update("retired_at", now).Error; err != nil {
			return ProfileView{}, fmt.Errorf("退役離機儲存設定世代失敗: %w", err)
		}
		if moved, neverUploaded, err = s.ledger.MarkForeign(tx, current.GenerationID); err != nil {
			return ProfileView{}, err
		}
		if err := s.markOwnerCachesForeign(tx, current.GenerationID); err != nil {
			return ProfileView{}, err
		}
	}
	row := &model.OffsiteProfile{
		ProfileFingerprint: norm.fingerprintOf(),
		Singleton:          1,
		Provider:           norm.Provider,
		Endpoint:           norm.EndpointFull,
		Bucket:             norm.Bucket,
		Prefix:             norm.Prefix,
		Region:             norm.Region,
		PathStyle:          norm.PathStyle,
		CredentialMode:     mode,
		CredentialsEnc:     enc,
		CreatedAt:          now,
		ActivatedAt:        now,
	}
	if err := tx.Create(row).Error; err != nil {
		return ProfileView{}, err
	}
	if current != nil {
		details := map[string]any{
			"old_generation_id":       current.GenerationID,
			"old_profile_fingerprint": current.ProfileFingerprint,
			"bucket":                  current.Bucket,
			"count":                   moved,
			"new_generation_id":       row.GenerationID,
		}
		if neverUploaded > 0 {
			details["never_uploaded_count"] = neverUploaded
		}
		if err := s.journal.RecordInTx(tx, CustodyEvent{
			Action:   CustodyActionProfile,
			Resource: string(model.ResourceSession),
			Status:   string(model.StatusSuccess),
			Details:  details,
		}); err != nil {
			return ProfileView{}, err
		}
	}
	if err := s.auditSaveInTx(tx, row, norm, actor, "create"); err != nil {
		return ProfileView{}, err
	}
	return profileViewOf(row), nil
}

// resolveCredentialsLocked 決定落庫的 (credential_mode, credentials_enc) 與是否
// 遞增 revision。
//
// 三個意圖對應三種結果：
//
//	new    加密新值 → stored，revision +1
//	clear  清空 → default_chain（部署方**刻意**改走 SDK 預設鏈／ADC），revision +1
//	reuse  沿用既存世代的密文與模式；無既存（首次設定）→ default_chain
//
// **`revoked` 不由本路徑產生**：撤銷是獨立的管理動作（RevokeCredentials），
// 混進儲存路徑會使「改個 prefix 順手撤銷了歷史憑證」成為可能。
func (s *OffsiteProfileService) resolveCredentialsLocked(ctx context.Context,
	current *model.OffsiteProfile, norm normalizedSettings) (mode, enc string, bumped bool, err error) {
	switch norm.credentialIntent {
	case credIntentNew:
		e, err := s.encryptCredentials(ctx, norm.credentialPlain)
		if err != nil {
			return "", "", false, err
		}
		return model.OffsiteCredentialStored, e, true, nil
	case credIntentClear:
		return model.OffsiteCredentialDefaultChain, "", true, nil
	default: // reuse
		if current == nil || current.CredentialMode == model.OffsiteCredentialRevoked {
			// 首次設定或既存世代已撤銷：沒有可沿用的憑證。
			// **不繼承 revoked**——那是對「該世代不再需要取回」的宣告，
			// 新世代繼承它會製造一個一出生就不可用的世代
			return model.OffsiteCredentialDefaultChain, "", false, nil
		}
		return current.CredentialMode, current.CredentialsEnc, false, nil
	}
}

// checkCredentialReuse 落點變更時拒絕沿用既存憑證（憑證外送不變式）。
//
// 判準＝provider／正規化端點／bucket **任一變更**且憑證欄留空。
// prefix 與 region 的變更不觸發——它們不改變憑證要送到哪台主機、哪個 bucket。
// 既存世代無憑證（default_chain／revoked）時不套此規則：那時根本沒有憑證可被沿用。
func checkCredentialReuse(current *model.OffsiteProfile, norm normalizedSettings) error {
	if current == nil || norm.credentialIntent != credIntentReuse {
		return nil
	}
	if current.CredentialMode != model.OffsiteCredentialStored {
		return nil
	}
	if current.Provider != norm.Provider ||
		current.Endpoint != norm.EndpointFull ||
		current.Bucket != norm.Bucket {
		return reject(ReasonCredentialReuseOnMove)
	}
	return nil
}

// auditSaveInTx 同事務的**具名事實投影**審計。
//
// 記 provider、canonical origin、bucket、credential_mode、has_credentials、
// credentials_cleared——**不記值、不記遮罩值**。審計失敗即整筆回滾：
// 離機落點被改寫卻無審計紀錄不是可接受的終局。
func (s *OffsiteProfileService) auditSaveInTx(tx *gorm.DB, row *model.OffsiteProfile,
	norm normalizedSettings, actor OffsiteActor, action string) error {
	gen := row.GenerationID
	return s.journal.RecordInTx(tx, CustodyEvent{
		Action:     CustodyActionProfile,
		Resource:   string(model.ResourceSession),
		ResourceID: &gen,
		Status:     string(model.StatusSuccess),
		Details: map[string]any{
			"event":               "offsite_settings_" + action,
			"generation_id":       row.GenerationID,
			"profile_fingerprint": row.ProfileFingerprint,
			"provider":            row.Provider,
			"endpoint_origin":     norm.EndpointOrigin,
			"bucket":              row.Bucket,
			"credential_mode":     row.CredentialMode,
			"has_credentials":     row.CredentialsEnc != "",
			"credentials_cleared": norm.credentialIntent == credIntentClear,
			"actor_id":            actor.ID,
			"actor_name":          actor.Name,
		},
	})
}

// ── driver factory 與 per-generation cache ────────────────────────────────

// ClientFor 依**帳冊列所記的世代**建 driver（跨世代取回）。
//
// 憑證直接取自**該世代自己的**列——切 provider 後舊物件的取回因此可達，
// 且不依賴任何 env 殘留。
//
//	世代查無                 → offsite.profile_missing（fail-close，不退回「用現行設定猜」）
//	credential_mode=revoked  → offsite.foreign_credentials_missing，
//	                           **零 driver 建構、零預設鏈探測**（絕不 fallback）
//	default_chain            → 以空憑證建構，交由 SDK 預設鏈／ADC
//	stored                   → 解密後交給建構函式
//
// per-generation cache 於**每次取用前**核對 `credential_revision` 與該列現值，
// 不等即丟棄重建——沿用被撤銷憑證的窗口因此收斂到「同一次呼叫內」，
// 而不是某個 cache TTL。
func (s *OffsiteProfileService) ClientFor(ctx context.Context, generationID uint) (Client, error) {
	var row model.OffsiteProfile
	if err := s.db.Where("generation_id = ?", generationID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s：帳冊指向的離機儲存設定世代 %d 不存在",
				ErrCodeProfileMissing, generationID)
		}
		return nil, fmt.Errorf("讀取離機儲存設定世代失敗: %w", err)
	}

	// **早退在任何 driver 建構之前**：revoked 的語義是「這個世代不再可取回」，
	// 落入預設鏈等於用另一組憑證去讀本該讀不到的物件
	if row.CredentialMode == model.OffsiteCredentialRevoked {
		s.invalidateClient(generationID)
		return nil, fmt.Errorf("%s：世代 %d（provider=%s）的憑證已撤銷",
			ErrCodeForeignCredentialsMissing, generationID, row.Provider)
	}

	s.mu.Lock()
	if hit, ok := s.clients[generationID]; ok && hit.revision == row.CredentialRevision {
		s.mu.Unlock()
		return hit.client, nil
	}
	s.mu.Unlock()

	spec := ClientBuildSpec{
		Provider:  row.Provider,
		Endpoint:  row.Endpoint,
		Bucket:    row.Bucket,
		Region:    row.Region,
		PathStyle: row.PathStyle,
	}
	if row.CredentialMode == model.OffsiteCredentialStored {
		plain, err := s.decryptCredentials(ctx, &row)
		if err != nil {
			return nil, err
		}
		sc, saJSON, ok := unmarshalCredentials(row.Provider, plain)
		if !ok {
			// 密文解得開但內容不成形＝資料損壞；訊息不含明文片段
			return nil, fmt.Errorf("%s：世代 %d 的憑證內容不完整", ErrCodeCredentialsUnavailable, generationID)
		}
		spec.AccessKeyID = sc.AccessKeyID
		spec.SecretAccessKey = sc.SecretAccessKey
		spec.ServiceAccountJSON = saJSON
	}

	c, err := s.factory(ctx, spec)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.clients[generationID] = cachedClient{client: c, revision: row.CredentialRevision}
	s.mu.Unlock()
	return c, nil
}

// invalidateClient 丟棄某世代的 client 快取（撤銷與憑證輪替的同交易後動作；
// 跨程序的正確性另由 ClientFor 的 revision 核對承擔）。
func (s *OffsiteProfileService) invalidateClient(generationID uint) {
	s.mu.Lock()
	delete(s.clients, generationID)
	s.mu.Unlock()
}

// CachedClientCountForTest 目前快取的 client 數（僅測試）。
func (s *OffsiteProfileService) CachedClientCountForTest() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clients)
}

// profileViewOf 由資料列產生 write-only 視圖（**恆不含憑證與其遮罩**）。
func profileViewOf(row *model.OffsiteProfile) ProfileView {
	return ProfileView{
		Configured:           true,
		Disabled:             row.RetiredAt != nil,
		GenerationID:         row.GenerationID,
		ProfileFingerprint:   row.ProfileFingerprint,
		Provider:             row.Provider,
		EndpointOrigin:       NormalizeEndpointOrigin(row.Endpoint),
		Bucket:               row.Bucket,
		Prefix:               row.Prefix,
		Region:               row.Region,
		PathStyle:            row.PathStyle,
		CredentialMode:       row.CredentialMode,
		HasCredentials:       row.CredentialsEnc != "",
		CredentialsClearedAt: row.CredentialsClearedAt,
		CreatedAt:            row.CreatedAt,
		ActivatedAt:          row.ActivatedAt,
		RetiredAt:            row.RetiredAt,
	}
}

// ── 測試連線（test-then-save） ────────────────────────────────────────────

// TestResult 連線測試的結果（兩段）。
//
// **兩種失敗語義分立**：本結構只在「測試已執行」時回傳（HTTP 200）；
// 測試**未能執行**（驗證失敗、憑證不可解）一律以 error 回傳，由 handler 收斂成
// 4xx／5xx。把「bucket 不可達」回成 4xx 會讓前端無從呈現「探測跑完但某一步失敗」
// 這種部分成功的階梯結果，而分階段定位正是這個端點存在的理由。
type TestResult struct {
	// Steps 逐步結果（ok／warn／fail 三類，機器碼見 testconnection.go）
	Steps []StepResult
	// Passed 全部步驟皆非 fail
	Passed bool
}

// TestSettings 以**表單當下值**執行連線測試（未儲存）。
//
// 憑證沿用的三條件：欄位皆空 ∧ 未帶 clear ∧ **與現行世代同落點**。
// 「先證同落點才解密」的順序是紅線：反過來會讓「把 bucket 改成自控位址再按測試」
// 成為一條把既存憑證送往任意端點的路徑——而測試端點不需要任何確認流程。
func (s *OffsiteProfileService) TestSettings(ctx context.Context, in SettingsInput, actor OffsiteActor) (TestResult, error) {
	// 限流在**任何解析與解密之前**：解析失敗不豁免限流，否則送壞輸入即可無限打。
	// 限流事件只進 operational log、**不入審計**——審計寫入正是本界線要保護的
	// 資源之一，在此落審計等於把防護本身變成放大器（沿 LDAP probe 的裁決）
	release, ok := s.testLimiter.acquire(offsiteTestActorKey(actor))
	if !ok {
		log.Printf("[OffsiteTest] 限流拒絕 actor=%s", offsiteTestActorKey(actor))
		return TestResult{}, ErrOffsiteTestRateLimited
	}
	defer release()

	current, err := currentOffsiteRow(s.db)
	if err != nil {
		return TestResult{}, err
	}
	norm, err := validateAndNormalizeOffsiteSettings(in)
	if err != nil {
		return TestResult{}, err
	}
	// **先證同落點**（checkCredentialReuse 已在驗證核心內做過，此處是型別上的
	// 再確認：沿用意圖只可能在同落點成立）
	if err := checkCredentialReuse(current, norm); err != nil {
		return TestResult{}, err
	}

	spec := ClientBuildSpec{
		Provider: norm.Provider, Endpoint: norm.EndpointFull, Bucket: norm.Bucket,
		Region: norm.Region, PathStyle: norm.PathStyle,
	}
	switch norm.credentialIntent {
	case credIntentNew:
		sc, saJSON, ok := unmarshalCredentials(norm.Provider, norm.credentialPlain)
		if !ok {
			return TestResult{}, reject(ReasonCredentialHalfSet)
		}
		spec.AccessKeyID, spec.SecretAccessKey, spec.ServiceAccountJSON = sc.AccessKeyID, sc.SecretAccessKey, saJSON
	case credIntentReuse:
		if current != nil && current.CredentialMode == model.OffsiteCredentialStored {
			plain, err := s.decryptCredentials(ctx, current)
			if err != nil {
				return TestResult{}, err
			}
			sc, saJSON, ok := unmarshalCredentials(current.Provider, plain)
			if !ok {
				return TestResult{}, reject(ReasonDecryptFailed)
			}
			spec.AccessKeyID, spec.SecretAccessKey, spec.ServiceAccountJSON = sc.AccessKeyID, sc.SecretAccessKey, saJSON
		}
	}

	client, err := s.factory(ctx, spec)
	if err != nil {
		return TestResult{}, err
	}
	steps := RunConnectionTest(ctx, client, norm.Prefix, s.now)
	res := TestResult{Steps: steps, Passed: true}
	for _, st := range steps {
		if st.Outcome == StepFail {
			res.Passed = false
		}
	}
	return res, nil
}

// ProbeCurrentGovernance 現行世代 bucket 的治理現況揭露（狀態頁的資訊性欄位）。
//
// **best-effort**：無現行世代、client 建不起來、探測失敗，一律回
// `(BucketGovernance{Unknown,Unknown}, false)` 而**不是** error——狀態頁不該
// 因為一次探測失敗而整頁 500，那會讓管理員在遠端出事時連佇列都看不到。
func (s *OffsiteProfileService) ProbeCurrentGovernance(ctx context.Context) (BucketGovernance, bool) {
	unknown := BucketGovernance{Versioning: VersioningUnknown, Retention: RetentionUnknown}
	row, err := currentOffsiteRow(s.db)
	if err != nil || row == nil {
		return unknown, false
	}
	client, err := s.ClientFor(ctx, row.GenerationID)
	if err != nil {
		return unknown, false
	}
	gov, err := client.ProbeBucket(ctx)
	if err != nil {
		return unknown, false
	}
	return gov, true
}
