package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/policy"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"log"
	"strings"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// LDAP 目錄設定的 singleton CRUD、執行期解析與存檔閘
// （ldap-settings-migration D1／D2／D3／D6／D7／D11；tasks 2.1／2.4／2.7）。
//
// 本檔是設定面自 env 遷入 DB 後的服務層核心，三件事：
//
//  1. **兩型分離的執行期解析**（2.7）：`LDAPRiskView`（無密碼，給傳輸政策／
//     清冊等非撥號消費端）與 `LDAPDialSnapshot`（含解密後 bind 密碼，只給登入
//     撥號路徑）。後者內嵌前者，使「閘與撥號同一次解析」在型別上成立。
//  2. **singleton CRUD**（2.1）：Get／Upsert（PUT 語義）／Delete（軟刪）。
//     無集合式建立端點、無「建第二列 409」——單列語義由資源形狀＋DB 守衛表達，
//     不靠服務層計數。
//  3. **存檔閘**（2.4）：沿用既有三通道共用契約 `CheckSettingSave`，零新形狀。
//
// # 為什麼寫入路徑要交易範圍互斥
//
// DB 約束保資料正確，不保 upsert 語義：兩個並發 PUT（或 PUT 與 seed）同時讀到
// 空表，其一撞 partial unique index 而對 admin 回 500。故寫入路徑一律經
// `WithLDAPDirectoryLock`，**一切判定（既有列、密碼沿用、端點比較）於鎖內重讀**
// ——鎖外預讀只是提示，不得作為寫入依據。取不到鎖與 unique violation 皆轉哨兵
// 錯誤（可重試機器碼），不外洩為 500。
//
// # 執行期解析的三態與風險視圖已遷入 policy
//
// `LDAPResolveState`＋3 常數、`LDAPRiskView`、`LDAPRiskResult` 與純函式
// `LDAPRisksOf` 已於 modular-architecture W3 3.2 遷入
// `internal/modules/policy`（R3.1 §3.5：只搬兩型不足以斷 D↔B 環）。本檔以
// `policy.` 限定名消費，`LDAPDialSnapshot` 仍內嵌 `policy.LDAPRiskView`。

// LDAPDialSnapshot 登入撥號路徑專用的 immutable 快照（含解密後的 bind 密碼）。
//
// 內嵌 LDAPRiskView 使閘檢查（LDAPRisksOf(snap.LDAPRiskView)）與撥號用的是
// **同一次解析結果**，不存在「檢查新值、撥號舊值」的窗口。
type LDAPDialSnapshot struct {
	policy.LDAPRiskView

	// DirectoryID 來源列 id（供 log／審計關聯，不對外呈現）
	DirectoryID uint
	// ParsedURL URL 的解析結果；供 egress 與端點比較共用。
	//
	// 欄名刻意不叫 Endpoint（同 LDAPDirectoryValidation.ParsedURL 的理由）：
	// kms 的 endpoint_gate_test.go 以 AST 攔截所有名為 Endpoint 的欄位寫入。
	//
	// URL 文法不合法時為零值——**這不算解析故障**：那是設定內容問題，撥號層
	// （egress 政策）會拒；三態的「故障」專指讀取與解密失敗
	ParsedURL LDAPEndpoint

	BindDN       string
	BindPassword string
	BaseDN       string
	UserFilter   string
	AttrEmail    string
	AttrFullName string
}

// LDAPDialResult 登入路徑的三態解析結果
type LDAPDialResult struct {
	State    policy.LDAPResolveState
	Snapshot LDAPDialSnapshot
	Err      error
}

// ── 服務型別與 wire 形狀 ─────────────────────────────────────────────────

// LDAPTransmissionGate 存檔閘所需的能力（*TransmissionPolicyService 實作之）。
//
// **以介面而非具體型別接收**：TransmissionPolicyService 的建構子於 2.9 才改
// （現仍持 config.LDAPConfig），以介面接線使該批次只需 SetTransmissionPolicy
// 一行、不必回頭改本檔。
type LDAPTransmissionGate interface {
	CheckSettingSave(channel string, risks []policy.RiskItem, acknowledged bool) error
	ChannelLevel(channel string) string
}

// LDAPDirectoryActor 操作者（handler 自 JWT 填入，比照既有 Actor* 慣例）
type LDAPDirectoryActor struct {
	ID   uint
	Name string
	IP   string
}

// LDAPDirectoryRequest PUT upsert 的請求形狀。
//
// wire 欄名沿本地既有慣例（`has_bind_password`／`clear_bind_password`／
// `risk_acknowledged`），與 notification channel、OIDC provider 同款
type LDAPDirectoryRequest struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	BindDN       string `json:"bind_dn"`
	BaseDN       string `json:"base_dn"`
	UserFilter   string `json:"user_filter"`
	AttrEmail    string `json:"attr_email"`
	AttrFullName string `json:"attr_fullname"`

	// BindPassword 空＝沿用既存（write-only 欄位，回應不回填故前端無從送回）
	BindPassword string `json:"bind_password"`
	// ClearBindPassword 顯式清除；與非空 BindPassword 併用即拒
	ClearBindPassword bool `json:"clear_bind_password"`

	SkipTLSVerify bool `json:"skip_tls_verify"`
	Enabled       bool `json:"enabled"`

	// RiskAcknowledged 傳輸風險確認聲明（D6，欄名與 syslog/notify 一致）
	RiskAcknowledged bool `json:"risk_acknowledged"`

	// Actor 操作者；由 handler 填入，不接受請求端指定
	Actor LDAPDirectoryActor `json:"-"`
}

// LDAPDirectoryView 讀取回應形狀：**不含密碼**，改回 HasBindPassword 旗標
type LDAPDirectoryView struct {
	// Configured 是否已有設定列；false 時其餘欄位為零值
	Configured bool `json:"configured"`

	ID           uint   `json:"id,omitempty"`
	Name         string `json:"name"`
	URL          string `json:"url"`
	BindDN       string `json:"bind_dn"`
	BaseDN       string `json:"base_dn"`
	UserFilter   string `json:"user_filter"`
	AttrEmail    string `json:"attr_email"`
	AttrFullName string `json:"attr_fullname"`

	SkipTLSVerify bool `json:"skip_tls_verify"`
	Enabled       bool `json:"enabled"`

	HasBindPassword bool `json:"has_bind_password"`
}

// ErrLDAPBindPasswordConflict 同時提供非空密碼與清除旗標
var ErrLDAPBindPasswordConflict = errors.New("不可同時提供 bind 密碼與清除旗標")

// ErrLDAPBindPasswordRequired 端點已變更且既存列有密碼，卻未重新提供密碼。
//
// **為何不能讓「空=沿用」跨端點生效**（D3／D11）：攻擊者（或被劫持的 admin
// session）可先 PUT 把 url 改成自控伺服器並沿用既存密碼，再由登入或連線測試
// 路徑把既存的 service bind 憑證送往新位址。**既存列無密碼時不套此規則**——
// 草稿改 URL 是正常路徑，且當下根本沒有憑證可被沿用
var ErrLDAPBindPasswordRequired = errors.New("目錄位址已變更，必須重新提供 bind 密碼或顯式清除")

// ErrLDAPDirectoryNotFound 無設定列
var ErrLDAPDirectoryNotFound = errors.New("LDAP 目錄設定不存在")

// ErrLDAPBindPasswordDecrypt bind 密碼解密失敗的**靜態哨兵**。
//
// **codec 的底層錯誤一律不外傳、不入日誌**：信封解密的錯誤可能夾帶輸入片段
// （密文、AAD、長度資訊）。原樣以 %w 包裝會讓密文順著解析結果流進呼叫端的
// 錯誤鏈，再由各處 log.Printf("%v") 落進 operational log——與「密文不進日誌」
// 同一條紅線。可辨識性由本哨兵（指向金鑰事故而非帳密錯誤）＋錯誤型別名承擔
var ErrLDAPBindPasswordDecrypt = errors.New("LDAP bind 密碼解密失敗（金鑰事故，非帳密錯誤）")

// ErrLDAPBindPasswordEncrypt bind 密碼加密失敗的靜態哨兵（理由同解密側：
// 加密錯誤可能夾帶明文片段）
var ErrLDAPBindPasswordEncrypt = errors.New("LDAP bind 密碼加密失敗")

// ErrLDAPDirectoryServiceUnavailable 目錄服務未接線（nil service／nil DB）。
//
// factory 產出的 closure 在依賴缺席時**必須落入既有的 failed 三態**而非 panic：
// 三態的存在理由就是「故障要可辨識」，用 panic 表達依賴缺席等於讓組裝疏漏
// 變成執行期崩潰，而非一個可被閘與清冊看見的故障
var ErrLDAPDirectoryServiceUnavailable = errors.New("LDAP 目錄設定服務未接線")

// ErrLDAPTransmissionGateUnavailable 傳輸政策閘未接線。
//
// **nil gate 一律 fail-close**（不是靜默放行）：閘缺席時放行等於讓一個組裝疏漏
// 靜默地停掉 strict／warn 檔位——明文 LDAP 與跳過 TLS 驗證都會照樣存檔並撥號，
// 而管理面完全看不出檔位沒生效。測試若需放行須注入明確的 allow-all 閘
var ErrLDAPTransmissionGateUnavailable = errors.New("傳輸政策閘未接線，LDAP 目錄設定操作一律拒絕")

// LDAPDirectoryService LDAP 目錄設定服務（singleton 資源）
type LDAPDirectoryService struct {
	db *gorm.DB
	// auditTx 交易內審計落地面（W4 4.4，AP-50）。**六條呼叫路徑語義二分**：
	// auditSave／auditURLChange／auditDelete 在 WithLDAPDirectoryLock 的交易閉包內，
	// 審計失敗即回滾整筆設定變更；auditRejection 與 probe 兩處傳根 DB、失敗只記 log。
	// 兩者共用同一個落地面，差別只在呼叫端怎麼處置回傳的 error——收口未改變其中任何一條
	auditTx port.TxSink
	// codec bind 密碼的信封加解密器。nil＝明文直通（僅單測建構路徑，
	// 生產組裝一律注入），沿 NotificationChannelService 的既有取捨
	codec crypto.ColumnCodec
	// gate 傳輸政策存檔閘；nil＝閘不生效（未接線的單測路徑）
	gate LDAPTransmissionGate
}

// NewLDAPDirectoryService 建立目錄設定服務
func NewLDAPDirectoryService(db *gorm.DB, codec crypto.ColumnCodec, auditTx port.TxSink) *LDAPDirectoryService {
	return &LDAPDirectoryService{db: db, codec: codec, auditTx: auditTx}
}

// SetTransmissionPolicy 注入傳輸政策閘（組裝時；沿 auth_service 的 setter 先例——
// LDAPDirectoryService 與 TransmissionPolicyService 互為對方的依賴，須以 setter 打環）
func (s *LDAPDirectoryService) SetTransmissionPolicy(gate LDAPTransmissionGate) {
	s.gate = gate
}

// ── 解析（2.7）──────────────────────────────────────────────────────────

// ldapDirectoryLiveRow 取唯一的 live 列；無列回 (nil, nil)。
//
// **>1 live 列時取 id 最小者**（D1／R2-opus N13）：單元測試庫走 AutoMigrate，
// 不會建 versioned migration 的 CHECK 與 partial unique index，故服務層對
// 「多列」必須有確定性行為，不得行為未定。生產由 DB 層保證不會走到這裡。
func ldapDirectoryLiveRow(tx *gorm.DB) (*model.LDAPDirectory, error) {
	var rows []model.LDAPDirectory
	if err := tx.Order("id ASC").Limit(1).Find(&rows).Error; err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// ResolveDialSnapshot 單次解析為 immutable 撥號快照（一次 DB 讀取＋一次解密）。
//
// 登入路徑於觸發當下呼叫一次，閘判定與撥號共用回傳的同一份結果——保持
// 「判定基於撥號當下的實際撥號參數」不變式（D2）。明文密碼僅存活於該次登入
// 的呼叫棧，不快取。
func (s *LDAPDirectoryService) ResolveDialSnapshot(ctx context.Context) LDAPDialResult {
	// 依賴缺席落 failed 三態而非 panic（見 ErrLDAPDirectoryServiceUnavailable）。
	// nil 接收者在 Go 是合法呼叫，故本檢查同時涵蓋 nil service 與 nil DB
	if s == nil || s.db == nil {
		log.Print("[LDAPDirectory] 目錄服務未接線（fail-close，非未設定）")
		return LDAPDialResult{State: policy.LDAPResolveFailed, Err: ErrLDAPDirectoryServiceUnavailable}
	}

	row, err := ldapDirectoryLiveRow(s.db)
	if err != nil {
		log.Printf("[LDAPDirectory] 設定讀取失敗（fail-close，非帳密錯誤）: %v", err)
		return LDAPDialResult{State: policy.LDAPResolveFailed, Err: fmt.Errorf("讀取 LDAP 目錄設定失敗: %w", err)}
	}
	if row == nil {
		return LDAPDialResult{State: policy.LDAPResolveUnconfigured}
	}

	password := ""
	if row.BindPasswordEnc != "" {
		password, err = s.decryptBindPassword(ctx, row.BindPasswordEnc)
		if err != nil {
			// 解密失敗＝金鑰事故，**不得偽裝為未啟用**：對外收斂為憑證錯誤，
			// 對內留可辨識的 log 供排錯指向金鑰而非帳號。
			// err 恆為靜態哨兵（底層錯誤已於 decryptBindPassword 淨化）
			log.Printf("[LDAPDirectory] bind 密碼解密失敗（fail-close，指向金鑰事故非帳密錯誤）directory_id=%d", row.ID)
			return LDAPDialResult{State: policy.LDAPResolveFailed, Err: err}
		}
	}

	snapshot := LDAPDialSnapshot{
		LDAPRiskView: policy.LDAPRiskView{
			Enabled:       row.Enabled,
			URL:           row.URL,
			SkipTLSVerify: row.SkipTLSVerify,
		},
		DirectoryID:  row.ID,
		BindDN:       row.BindDN,
		BindPassword: password,
		BaseDN:       row.BaseDN,
		UserFilter:   row.UserFilter,
		AttrEmail:    row.AttrEmail,
		AttrFullName: row.AttrFullName,
	}
	// URL 文法失敗不改變三態（見 ParsedURL 欄註解）
	if endpoint, perr := ParseLDAPURL(row.URL); perr == nil {
		snapshot.ParsedURL = endpoint
	}

	// **啟用態的完整性於 hydrated snapshot 上重驗**（fail-close）：migration、
	// 手工 SQL 或資料損壞可留下「enabled=true 但密文為空／必要欄位缺漏」的列。
	// 該列在解密路徑上完全無異常（沒有密文就不會解密失敗），卻會一路回 OK 而
	// 讓登入 resolver 判為 ready——形成設計只承認三態之外的第四狀態「存在但
	// 無效」。回 failed 而**非 unconfigured**：後者會把損壞偽裝成「未啟用」，
	// 正是 D2 明令禁止的併吞形態
	if row.Enabled {
		if missing := ldapDialSnapshotMissingField(snapshot); missing != "" {
			log.Printf("[LDAPDirectory] 啟用態設定缺必要欄位（fail-close，非未設定）directory_id=%d field=%s",
				row.ID, missing)
			return LDAPDialResult{
				State: policy.LDAPResolveFailed,
				Err:   fmt.Errorf("%w: 啟用態缺 %s", ErrLDAPSettingsIncomplete, missing),
			}
		}
	}
	return LDAPDialResult{State: policy.LDAPResolveOK, Snapshot: snapshot}
}

// ldapDialSnapshotMissingField 回傳啟用態下第一個缺漏的必要欄位名（齊全時回空）。
//
// 欄位清單與 ValidateLDAPDirectoryInput 的啟用態必填集**同一組**，差別只在
// 這裡驗的是**解密後的執行期值**：bind_password 檢查的是明文非空，而非密文
// 存在——空字串密文在解密路徑上不會報錯，唯有在此才擋得住。
// 回傳靜態欄名（非值），供 log 與錯誤鏈使用時不夾帶設定內容
func ldapDialSnapshotMissingField(snap LDAPDialSnapshot) string {
	for _, field := range []struct{ name, value string }{
		{"url", snap.URL},
		{"bind_dn", snap.BindDN},
		{"base_dn", snap.BaseDN},
		{"user_filter", snap.UserFilter},
		{"attr_email", snap.AttrEmail},
		{"attr_fullname", snap.AttrFullName},
		{"bind_password", snap.BindPassword},
	} {
		if strings.TrimSpace(field.value) == "" {
			return field.name
		}
	}
	return ""
}

// ResolveRiskView 非撥號消費端的三態解析。
//
// **實作上仍走完整解析（含解密）後丟棄密碼**，而非只 SELECT 三個欄位：
// spec 要求「金鑰事故時清冊顯示『設定讀取失敗』而非『未啟用』」，只讀三欄
// 便無從得知密文是否可解，清冊會顯示「已啟用」而登入其實全數失敗——正是
// 兩個管理面互相打臉的那一格。明文於本函式內即被丟棄，不進入呼叫端（型別上
// 亦不可能：回傳的 LDAPRiskView 沒有密碼欄位）。
//
// 成本可接受：解密走行程內 DEK 快取，KMS 模式不會每次往返 KMS。
func (s *LDAPDirectoryService) ResolveRiskView(ctx context.Context) policy.LDAPRiskResult {
	result := s.ResolveDialSnapshot(ctx)
	return policy.LDAPRiskResult{
		State: result.State,
		View:  result.Snapshot.LDAPRiskView,
		Err:   result.Err,
	}
}

// RiskViewProvider 供 TransmissionPolicyService 於 2.9 注入的 provider。
//
// 回傳三態結果而非 (view, bool)——nil 併吞故障正是 D2 明令禁止的形態
func (s *LDAPDirectoryService) RiskViewProvider() func() policy.LDAPRiskResult {
	return func() policy.LDAPRiskResult {
		// closure 入口即檢查：nil service 在 factory 呼叫當下不會失敗（Go 允許
		// nil 接收者），錯誤要嘛在此收斂為 failed，要嘛在解參考時 panic
		if s == nil || s.db == nil {
			log.Print("[LDAPDirectory] 風險視圖 provider 的目錄服務未接線（fail-close）")
			return policy.LDAPRiskResult{State: policy.LDAPResolveFailed, Err: ErrLDAPDirectoryServiceUnavailable}
		}
		return s.ResolveRiskView(context.Background())
	}
}

// decryptBindPassword 解密 bind 密碼；codec 為 nil 時明文直通（僅單測路徑）。
//
// **底層錯誤在此淨化為靜態哨兵**（見 ErrLDAPBindPasswordDecrypt）：codec 的
// 錯誤可能夾帶密文片段，放行到呼叫端的錯誤鏈即等同開一條「密文進日誌」的
// 管道。可辨識性只留錯誤**型別名**（靜態，不含輸入內容）
func (s *LDAPDirectoryService) decryptBindPassword(ctx context.Context, enc string) (string, error) {
	if s.codec == nil {
		return enc, nil
	}
	plaintext, err := s.codec.DecryptFor(ctx, keyvault.RefLDAPBindPassword, enc)
	if err != nil {
		log.Printf("[LDAPDirectory] bind 密碼信封解密失敗 error_type=%T（底層錯誤已淨化，不入日誌）", err)
		return "", ErrLDAPBindPasswordDecrypt
	}
	return plaintext, nil
}

// encryptBindPassword 加密 bind 密碼；codec 為 nil 時明文直通（僅單測路徑）。
// 錯誤淨化理由同解密側（加密錯誤可能夾帶明文片段）
func (s *LDAPDirectoryService) encryptBindPassword(ctx context.Context, plaintext string) (string, error) {
	if s.codec == nil {
		return plaintext, nil
	}
	enc, err := s.codec.EncryptFor(ctx, keyvault.RefLDAPBindPassword, plaintext)
	if err != nil {
		log.Printf("[LDAPDirectory] bind 密碼信封加密失敗 error_type=%T（底層錯誤已淨化，不入日誌）", err)
		return "", ErrLDAPBindPasswordEncrypt
	}
	return enc, nil
}

// ── CRUD（2.1）──────────────────────────────────────────────────────────

// Get 讀取現行設定；無列時回 Configured=false 的形狀（非錯誤）。
// 回應恆不含密碼，改回 HasBindPassword
func (s *LDAPDirectoryService) Get(ctx context.Context) (LDAPDirectoryView, error) {
	row, err := ldapDirectoryLiveRow(s.db)
	if err != nil {
		return LDAPDirectoryView{}, fmt.Errorf("讀取 LDAP 目錄設定失敗: %w", err)
	}
	return ldapDirectoryViewOf(row), nil
}

// Upsert PUT 語義：無列建、有列改。
//
// 鎖內的判定順序（每一步都可能拒絕，拒絕亦入審計）：
//
//  1. 密碼輸入衝突（非空密碼＋清除旗標）
//  2. 存檔驗證（欄位完整性、URL 文法、user_filter 兩層）
//  3. 端點變更時的密碼重供規則（僅當既存列有密碼且本次沿用）
//  4. 傳輸存檔閘（僅「儲存後啟用且含風險」須過）
//  5. 加密 → 寫列 → 審計（同一事務）
func (s *LDAPDirectoryService) Upsert(ctx context.Context, req LDAPDirectoryRequest) (LDAPDirectoryView, error) {
	var (
		view     LDAPDirectoryView
		rejected *ldapDirectoryRejection
	)
	err := WithLDAPDirectoryLock(s.db, func(tx *gorm.DB) error {
		// 鎖內重讀：既有列、既存密碼與端點比較全部以本次讀到的值為準
		existing, err := ldapDirectoryLiveRow(tx)
		if err != nil {
			return fmt.Errorf("讀取 LDAP 目錄設定失敗: %w", err)
		}
		v, rej, err := s.upsertLocked(ctx, tx, existing, req)
		rejected = rej
		if err != nil {
			return err
		}
		view = v
		return nil
	})

	// **拒絕的審計必須寫在事務外**：拒絕路徑整個交易已回滾，寫在裡面等於沒寫。
	// 審計失敗只記 log——拒絕本身已由回傳值傳達，不因審計不可寫而把「已拒絕」
	// 變成「未知結果」
	if rejected != nil {
		s.auditRejection(req, *rejected)
	}
	if err != nil {
		return LDAPDirectoryView{}, ldapDirectoryWriteError(err)
	}
	return view, nil
}

// ldapDirectoryRejection 被拒嘗試的審計負載（恆為靜態碼，不回填使用者輸入）
type ldapDirectoryRejection struct {
	// Reason 靜態拒絕原因碼
	Reason string
	// Detail 次級原因（欄名／文法原因／閘碼），恆取自既有靜態常數
	Detail string
	// Risks 傳輸風險項（僅存檔閘拒絕時非空）
	Risks []policy.RiskItem
	// CanonicalURL 已成功解析的目標 canonical origin；**解析失敗時恆為空**
	// ——原始輸入可能含 userinfo 憑證，不得進審計
	CanonicalURL string
}

// 拒絕原因碼（供 3.1 對應機器碼與 i18n；恆為靜態字串）
const (
	LDAPRejectBindPasswordConflict = "bind_password_conflict"
	LDAPRejectBindPasswordRequired = "bind_password_required_url_changed"
	LDAPRejectValidation           = "validation"
	LDAPRejectTransmissionGate     = "transmission_gate"
	// LDAPRejectTransmissionGateUnavailable 傳輸政策閘未接線（組裝疏漏）。
	// 與 LDAPRejectTransmissionGate 分開：前者是「檔位判定拒絕」（設定內容問題，
	// admin 可自行修正），本碼是「防護本身不存在」（部署問題，需維運介入）
	LDAPRejectTransmissionGateUnavailable = "transmission_gate_unavailable"
)

// upsertLocked 鎖內的 upsert 本體。
// 回傳的 rejection 非 nil 即表示本次被拒（呼叫端於事務外補寫審計）
func (s *LDAPDirectoryService) upsertLocked(
	ctx context.Context, tx *gorm.DB, existing *model.LDAPDirectory, req LDAPDirectoryRequest,
) (LDAPDirectoryView, *ldapDirectoryRejection, error) {
	// (1) 密碼輸入衝突：兩個互斥意圖同時出現，服務層無從裁決哪個是使用者真意
	if req.BindPassword != "" && req.ClearBindPassword {
		return LDAPDirectoryView{}, &ldapDirectoryRejection{Reason: LDAPRejectBindPasswordConflict},
			ErrLDAPBindPasswordConflict
	}

	existingHasPassword := existing != nil && existing.BindPasswordEnc != ""
	// reusing＝本次沿用既存密碼（既沒給新密碼、也沒要求清除）
	reusing := req.BindPassword == "" && !req.ClearBindPassword
	// 存檔後是否會有密碼——驗證只消費此結果，不自行查 DB
	hasBindPasswordAfter := req.BindPassword != "" || (reusing && existingHasPassword)

	// (2) 存檔驗證（D7）：草稿只驗格式，啟用態驗完整性
	validation, err := ValidateLDAPDirectoryInput(LDAPDirectoryInput{
		Name:            req.Name,
		URL:             req.URL,
		BindDN:          req.BindDN,
		BaseDN:          req.BaseDN,
		UserFilter:      req.UserFilter,
		AttrEmail:       req.AttrEmail,
		AttrFullName:    req.AttrFullName,
		SkipTLSVerify:   req.SkipTLSVerify,
		Enabled:         req.Enabled,
		HasBindPassword: hasBindPasswordAfter,
	})
	if err != nil {
		return LDAPDirectoryView{}, &ldapDirectoryRejection{
			Reason: LDAPRejectValidation,
			Detail: ldapValidationDetail(err),
		}, err
	}
	input := validation.Input

	// (3) 端點變更 ⇒ 空密碼不得沿用（D3）。只在「既存有密碼且本次沿用」時成立
	if existingHasPassword && reusing {
		if !ldapSameStoredEndpoint(existing.URL, validation.ParsedURL) {
			return LDAPDirectoryView{}, &ldapDirectoryRejection{
				Reason:       LDAPRejectBindPasswordRequired,
				CanonicalURL: validation.ParsedURL.CanonicalOrigin(),
			}, ErrLDAPBindPasswordRequired
		}
	}

	// (4) 存檔閘（D6／2.4）：以「儲存後生效的狀態」判定。
	// enabled=false 的草稿由 LDAPRisksOf 回 nil 風險而自然放行——停用的設定
	// 不會撥號，不需要在存檔當下逼使用者確認
	afterView := policy.LDAPRiskView{Enabled: input.Enabled, URL: input.URL, SkipTLSVerify: input.SkipTLSVerify}
	risks := policy.LDAPRisksOf(afterView)
	// **閘缺席 fail-close**（見 ErrLDAPTransmissionGateUnavailable）：以 nil 表達
	// 「完全放行」會讓組裝漏一行 setter 就靜默停掉 strict／warn 檔位
	if s.gate == nil {
		log.Print("[LDAPDirectory] 傳輸政策閘未接線，拒絕存檔（fail-close）")
		return LDAPDirectoryView{}, &ldapDirectoryRejection{
			Reason:       LDAPRejectTransmissionGateUnavailable,
			Risks:        risks,
			CanonicalURL: validation.ParsedURL.CanonicalOrigin(),
		}, ErrLDAPTransmissionGateUnavailable
	}
	if gateErr := s.gate.CheckSettingSave(policy.TransportChannelLDAP, risks, req.RiskAcknowledged); gateErr != nil {
		detail := ""
		var typed *policy.TransmissionGateError
		if errors.As(gateErr, &typed) {
			detail = typed.Code
		}
		return LDAPDirectoryView{}, &ldapDirectoryRejection{
			Reason:       LDAPRejectTransmissionGate,
			Detail:       detail,
			Risks:        risks,
			CanonicalURL: validation.ParsedURL.CanonicalOrigin(),
		}, gateErr
	}

	// (5) 密碼落庫值
	encAfter := ""
	switch {
	case req.ClearBindPassword:
		// 顯式清除：密文於同一事務被抹除，tombstone 不留可解密密文
		encAfter = ""
	case req.BindPassword != "":
		// err 恆為靜態哨兵（底層錯誤已於 encryptBindPassword 淨化），原樣上拋
		encAfter, err = s.encryptBindPassword(ctx, req.BindPassword)
		if err != nil {
			return LDAPDirectoryView{}, nil, err
		}
	case existing != nil:
		encAfter = existing.BindPasswordEnc
	}

	if ldapDirectoryPreWriteHook != nil {
		ldapDirectoryPreWriteHook()
	}

	action := model.ActionUpdate
	row := existing
	if row == nil {
		action = model.ActionCreate
		row = &model.LDAPDirectory{Singleton: 1}
	}
	oldURL := ""
	if existing != nil {
		oldURL = existing.URL
	}

	row.Name = input.Name
	row.URL = input.URL
	row.BindDN = input.BindDN
	row.BaseDN = input.BaseDN
	row.UserFilter = input.UserFilter
	row.AttrEmail = input.AttrEmail
	row.AttrFullName = input.AttrFullName
	row.SkipTLSVerify = input.SkipTLSVerify
	row.Enabled = input.Enabled
	row.BindPasswordEnc = encAfter
	row.Singleton = 1

	if existing == nil {
		if err := tx.Create(row).Error; err != nil {
			return LDAPDirectoryView{}, nil, err
		}
	} else if err := tx.Save(row).Error; err != nil {
		return LDAPDirectoryView{}, nil, err
	}

	// 審計與寫列同事務：外部認證來源被建立／改指向卻無審計紀錄，不是可接受的
	// 終局（沿 seed 路徑的同一裁決）
	if err := s.auditSave(tx, req, action, row, risks); err != nil {
		return LDAPDirectoryView{}, nil, err
	}
	// URL 變更為高權重事件（D11）：admin 對外部身分來源的指向權是被信任的，
	// 代償控制就是事後可稽核「哪一刻目錄被改指向」
	if existing != nil {
		if err := s.auditURLChange(tx, req, row, oldURL, validation.ParsedURL); err != nil {
			return LDAPDirectoryView{}, nil, err
		}
	}
	return ldapDirectoryViewOf(row), nil, nil
}

// Delete 軟刪設定；同一事務抹除密文（tombstone 不留可解密密文）
func (s *LDAPDirectoryService) Delete(ctx context.Context, actor LDAPDirectoryActor) error {
	err := WithLDAPDirectoryLock(s.db, func(tx *gorm.DB) error {
		row, err := ldapDirectoryLiveRow(tx)
		if err != nil {
			return fmt.Errorf("讀取 LDAP 目錄設定失敗: %w", err)
		}
		if row == nil {
			return ErrLDAPDirectoryNotFound
		}
		if ldapDirectoryPreWriteHook != nil {
			ldapDirectoryPreWriteHook()
		}
		// 先抹密文再軟刪：兩步同事務，金鑰引用掃描（含軟刪列）不會再看到
		// 已無主的密文
		if err := tx.Model(&model.LDAPDirectory{}).Where("id = ?", row.ID).
			Update("bind_password_enc", "").Error; err != nil {
			return err
		}
		if err := tx.Delete(&model.LDAPDirectory{}, row.ID).Error; err != nil {
			return err
		}
		return s.auditDelete(tx, actor, row)
	})
	if err != nil {
		return ldapDirectoryWriteError(err)
	}
	return nil
}

// ── 輔助 ────────────────────────────────────────────────────────────────

// ldapDirectoryViewOf 由資料列產生讀取視圖（恆不含密碼）
func ldapDirectoryViewOf(row *model.LDAPDirectory) LDAPDirectoryView {
	if row == nil {
		return LDAPDirectoryView{Configured: false}
	}
	return LDAPDirectoryView{
		Configured:      true,
		ID:              row.ID,
		Name:            row.Name,
		URL:             row.URL,
		BindDN:          row.BindDN,
		BaseDN:          row.BaseDN,
		UserFilter:      row.UserFilter,
		AttrEmail:       row.AttrEmail,
		AttrFullName:    row.AttrFullName,
		SkipTLSVerify:   row.SkipTLSVerify,
		Enabled:         row.Enabled,
		HasBindPassword: row.BindPasswordEnc != "",
	}
}

// ldapSameStoredEndpoint 既存列的 URL 與新解析結果是否為同一端點。
//
// **既存 URL 無法解析時一律視為不同端點**（fail-close）：既存值可能來自 seed
// （env 值未經本 change 的文法驗證），無法證明兩者同源時，要求重供密碼是安全
// 的一邊——代價僅是 admin 多填一次密碼。
func ldapSameStoredEndpoint(storedURL string, next LDAPEndpoint) bool {
	stored, err := ParseLDAPURL(storedURL)
	if err != nil {
		return false
	}
	return SameLDAPEndpoint(stored, next)
}

// ldapValidationDetail 由驗證錯誤取靜態次級原因碼（不含使用者輸入）
func ldapValidationDetail(err error) string {
	var fieldErr *LDAPFieldError
	if errors.As(err, &fieldErr) {
		return fieldErr.Field + ":" + fieldErr.Reason
	}
	var urlErr *LDAPURLError
	if errors.As(err, &urlErr) {
		return "url:" + urlErr.Reason
	}
	var filterErr *LDAPFilterError
	if errors.As(err, &filterErr) {
		return "user_filter:" + filterErr.Reason
	}
	return ""
}

// ── 審計（D11：URL 變更為高權重事件）────────────────────────────────────

// ldapDirectoryAuditEvent 審計事件碼（Details.event；供前端查譯與稽核檢索）
const (
	LDAPAuditEventSave         = "ldap_directory_save"
	LDAPAuditEventDelete       = "ldap_directory_delete"
	LDAPAuditEventURLChanged   = "ldap_directory_url_changed"
	LDAPAuditEventSaveRejected = "ldap_directory_save_rejected"
)

// ldapDirectoryAuditLog 寫一筆審計列。
//
// resource 沿用既有的 model.ResourceAuth（同 seed 路徑）——不新增 resource
// 常數，前端審計頁的枚舉查譯即無新增無譯文機器碼的風險
//
// **W4 4.4 收口（AP-50）**：改掛型別方法只為取得 s.auditTx——六個呼叫點全都已經
// 在 *LDAPDirectoryService 的方法內。`db` 參數保留且仍是第一參數：它承載的正是
// 「這次寫入屬於哪一筆交易」——三條 fail-close 路徑傳鎖內的 tx、三條 fail-open
// 路徑傳 s.db，收口前後逐條相同。
func (s *LDAPDirectoryService) ldapDirectoryAuditLog(db *gorm.DB, actor LDAPDirectoryActor, action model.AuditAction,
	status model.AuditStatus, resourceID *uint, details map[string]any) error {
	payload, err := json.Marshal(details)
	if err != nil {
		return fmt.Errorf("序列化 LDAP 目錄設定審計內容失敗: %w", err)
	}
	if err := port.WriteInTx(s.auditTx, db, port.AuditEvent{
		Action:     string(action),
		Resource:   string(model.ResourceAuth),
		ResourceID: resourceID,
		Status:     string(status),
		Actor:      gatewayapi.Actor{UserID: actor.ID, Username: actor.Name},
		Request:    gatewayapi.RequestMeta{ClientIP: actor.IP},
		Details:    string(payload),
	}); err != nil {
		return fmt.Errorf("寫入 LDAP 目錄設定審計失敗: %w", err)
	}
	return nil
}

// auditSave 建立／更新事件（不記密碼與密文）
func (s *LDAPDirectoryService) auditSave(tx *gorm.DB, req LDAPDirectoryRequest,
	action model.AuditAction, row *model.LDAPDirectory, risks []policy.RiskItem) error {
	id := row.ID
	return s.ldapDirectoryAuditLog(tx, req.Actor, action, model.StatusSuccess, &id, map[string]any{
		"event":                 LDAPAuditEventSave,
		"directory_id":          row.ID,
		"url":                   ldapCanonicalOrEmpty(row.URL),
		"enabled":               row.Enabled,
		"skip_tls_verify":       row.SkipTLSVerify,
		"has_bind_password":     row.BindPasswordEnc != "",
		"bind_password_cleared": req.ClearBindPassword,
		"transmission_risks":    risks,
		"risk_acknowledged":     req.RiskAcknowledged,
	})
}

// auditURLChange URL 變更的高權重事件（D11）。
//
// 記錄舊值與新值的 **canonical origin** 及 host 是否變更——「設定被更新」這種
// 粒度無法回答「哪一刻目錄被改指向哪裡」，而那正是 admin 指向權被信任時唯一
// 的代償控制。端點未變即不記（避免每次存檔都產生一筆高權重雜訊）。
//
// 舊值無法解析時只記旗標不記原始字串：既存值可能來自未經文法驗證的 seed，
// 原樣寫入審計等於開一條「憑證進日誌」的管道
func (s *LDAPDirectoryService) auditURLChange(tx *gorm.DB, req LDAPDirectoryRequest,
	row *model.LDAPDirectory, oldURL string, next LDAPEndpoint) error {
	oldEndpoint, oldErr := ParseLDAPURL(oldURL)
	oldOrigin := ""
	if oldErr == nil {
		oldOrigin = oldEndpoint.CanonicalOrigin()
	}
	newOrigin := next.CanonicalOrigin()
	if oldErr == nil && oldOrigin == newOrigin {
		return nil
	}
	hostChanged := true
	if oldErr == nil {
		hostChanged = oldEndpoint.Host != next.Host
	}
	id := row.ID
	return s.ldapDirectoryAuditLog(tx, req.Actor, model.ActionUpdate, model.StatusSuccess, &id, map[string]any{
		"event":             LDAPAuditEventURLChanged,
		"directory_id":      row.ID,
		"old_url":           oldOrigin,
		"old_url_unparsed":  oldErr != nil,
		"new_url":           newOrigin,
		"host_changed":      hostChanged,
		"enabled":           row.Enabled,
		"has_bind_password": row.BindPasswordEnc != "",
	})
}

// auditDelete 刪除事件
func (s *LDAPDirectoryService) auditDelete(tx *gorm.DB, actor LDAPDirectoryActor, row *model.LDAPDirectory) error {
	id := row.ID
	return s.ldapDirectoryAuditLog(tx, actor, model.ActionDelete, model.StatusSuccess, &id, map[string]any{
		"event":        LDAPAuditEventDelete,
		"directory_id": row.ID,
		"url":          ldapCanonicalOrEmpty(row.URL),
		"enabled":      row.Enabled,
	})
}

// auditRejection 被拒嘗試入審計（事務外；審計失敗只記 log 不改變拒絕結果）
func (s *LDAPDirectoryService) auditRejection(req LDAPDirectoryRequest, rej ldapDirectoryRejection) {
	details := map[string]any{
		"event":             LDAPAuditEventSaveRejected,
		"reason":            rej.Reason,
		"enabled":           req.Enabled,
		"risk_acknowledged": req.RiskAcknowledged,
	}
	if rej.Detail != "" {
		details["detail"] = rej.Detail
	}
	if rej.CanonicalURL != "" {
		details["url"] = rej.CanonicalURL
	}
	if len(rej.Risks) > 0 {
		details["transmission_risks"] = rej.Risks
	}
	if err := s.ldapDirectoryAuditLog(s.db, req.Actor, model.ActionUpdate,
		model.StatusDenied, nil, details); err != nil {
		log.Printf("[LDAPDirectory] 被拒嘗試審計寫入失敗（拒絕結果不受影響）: %v", err)
	}
}

// ldapCanonicalOrEmpty 取 canonical origin；無法解析即回空字串
// （原始輸入可能含 userinfo 憑證，一律不進審計）
func ldapCanonicalOrEmpty(raw string) string {
	origin, err := LDAPCanonicalOrigin(raw)
	if err != nil {
		return ""
	}
	return origin
}
