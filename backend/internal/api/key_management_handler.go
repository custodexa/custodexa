package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/identity"
	"github.com/custodexa/backend/internal/modules/policy"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/sourceip"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// KeyManagementHandler 金鑰清冊與換鑰精靈 API。
// 整組 admin only；讀取經 audit middleware 以 key_management 資源入審計；
// **任何回應不含金鑰材料與 wrapped 值，無例外**——明文流向反轉後，重包的
// 新 KEK 由呼叫端提供而非伺服端回傳，原本「重包一次性回傳」的例外已消失
type KeyManagementHandler struct {
	db             *gorm.DB
	km             *keyvault.KeyManagerService
	policy         *policy.SecurityPolicyService
	jwtFingerprint string                         // JWT_SECRET 指紋（main 算好注入，handler 不接觸 secret）
	signing        *keyvault.ExportSigningService // Ed25519 canonical 公鑰來源
	// checkpointSigning 檢查點鏈簽章鑰（audit-checkpoint-chain 3.4）：
	// 清冊只曝露公鑰指紋與版本，私鑰無任何出口
	checkpointSigning *keyvault.CheckpointSigningService
	auditService   *audit.AuditLogService         // 清理退役資料的顯式留痕
	sealState      SealStateProbe                 // 封印狀態探針（組裝根注入）
	// delegatedProvider 委託重包目標的 provider 建構器（組裝根注入）。
	// 未注入時委託分支回「尚未提供」，SHALL NOT 靜默退化為本地目標。
	delegatedProvider keyvault.DelegatedProviderFactory
}

// SetDelegatedProviderFactory 注入委託重包目標的 provider 建構器（組裝根呼叫）。
//
// 以注入而非讓 handler 直接讀部署組態：讀組態是組裝根的職責，且注入使測試能在
// 不污染行程 env、不連任何雲端服務的前提下覆蓋委託分支。
func (h *KeyManagementHandler) SetDelegatedProviderFactory(f keyvault.DelegatedProviderFactory) {
	h.delegatedProvider = f
}

// SetAuditService 注入審計服務（main 組裝；nil 容忍——測試環境）
func (h *KeyManagementHandler) SetAuditService(a *audit.AuditLogService) {
	h.auditService = a
}

// SealStateProbe 回報封印狀態機的當前態與解封時點（自證循環防線）。
//
// 以閉包注入而非讓 handler 直接持有狀態機：組裝根是唯一知道「這個行程實際
// 跑的是哪一台狀態機」的地方，而清冊的用途正是稽核那件事。
// A／C 模式恆回 unsealed＋啟動時點——狀態查詢在各模式下形狀一致是 spec 明文要求。
type SealStateProbe func() (state string, unsealedAt time.Time)

// SetSealStateProbe 注入封印狀態探針（組裝根呼叫；未注入時清冊省略該兩欄）。
func (h *KeyManagementHandler) SetSealStateProbe(fn SealStateProbe) { h.sealState = fn }

// NewKeyManagementHandler 創建金鑰管理 handler
func NewKeyManagementHandler(db *gorm.DB, km *keyvault.KeyManagerService, policy *policy.SecurityPolicyService, jwtFingerprint string, signing *keyvault.ExportSigningService) *KeyManagementHandler {
	return &KeyManagementHandler{db: db, km: km, policy: policy, jwtFingerprint: jwtFingerprint, signing: signing}
}

// SetCheckpointSigning 注入檢查點簽章鑰（清冊項用；未注入即該項不出現）。
//
// 以 setter 而非建構子參數：建構子已有五個參數且被多處測試呼叫，
// 加參數會讓與本 change 無關的呼叫點全部改動
func (h *KeyManagementHandler) SetCheckpointSigning(s *keyvault.CheckpointSigningService) {
	h.checkpointSigning = s
}

// keyView 清冊項（DB 側金鑰）
type keyView struct {
	Purpose   string     `json:"purpose"`
	Version   int        `json:"version"`
	Status    string     `json:"status"`
	KEKID     string     `json:"kek_id"`
	CreatedAt time.Time  `json:"created_at"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
	AgeDays   int        `json:"age_days"`
	// OverCryptoperiod active 鑰年齡逾提醒政策（政策 0＝恆 false）
	OverCryptoperiod bool `json:"over_cryptoperiod"`
	// MaterialPurged 材料已經顯式清理銷毀（佔位列指紋仍列）
	MaterialPurged bool `json:"material_purged"`
}

// envKeyView 清冊項（env 側金鑰：部署方管理，僅存在性/指紋，無輪替入口）。
// Name/Note 為 zh 顯示字串（wire fallback）；NameCode/NoteCode 為穩定機器碼，
// 前端 keyEnvName/keyEnvNote getter 查譯，缺譯降級 zh。
type envKeyView struct {
	Name string `json:"name"`
	// NameCode 名稱機器碼（僅描述型名稱需要，如 audit_export；技術識別字如 ENCRYPTION_KEY 留空用 Name）
	NameCode string `json:"name_code,omitempty"`
	// Fingerprint 三鑰一致顯示：KEK/JWT 為 secret 摘要指紋、
	// Ed25519 為公鑰指紋。單向摘要，不外洩金鑰材料
	Fingerprint string `json:"fingerprint,omitempty"`
	// PublicKey Ed25519 匯出簽章鑰之公鑰（base64，非機密）供複製/下載；其他鑰無
	PublicKey string `json:"public_key,omitempty"`
	// ManagedBy deployer（JWT/KEK）或 system（Ed25519 匯出簽章鑰）
	ManagedBy string `json:"managed_by"`
	// Version 鑰版本（僅自始帶版本欄的鑰有值，如檢查點簽章鑰）
	Version int `json:"version,omitempty"`
	Note      string `json:"note"`
	// NoteCode 說明機器碼（前端查譯 keyEnvNote.<code>）
	NoteCode string `json:"note_code,omitempty"`
}

// Inventory 金鑰清冊
func (h *KeyManagementHandler) Inventory(c *gin.Context) {
	rows, err := h.km.ListKeys()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeyInventoryQuery, err)
		return
	}
	reminderDays := 0
	if h.policy != nil {
		reminderDays = h.policy.GetInt(policy.PolicyKeyCryptoperiodReminderDays)
	}
	now := time.Now()
	keys := make([]keyView, 0, len(rows))
	for _, r := range rows {
		ageDays := int(now.Sub(r.CreatedAt).Hours() / 24)
		keys = append(keys, keyView{
			Purpose: r.Purpose, Version: r.Version, Status: r.Status,
			KEKID: r.KEKID, CreatedAt: r.CreatedAt, RetiredAt: r.RetiredAt,
			AgeDays: ageDays,
			OverCryptoperiod: reminderDays > 0 && r.Status == model.DataKeyStatusActive &&
				ageDays > reminderDays,
			MaterialPurged: r.MaterialPurged,
		})
	}

	// env 側鑰：三鑰一致顯示指紋
	envKeys := []envKeyView{
		{Name: "ENCRYPTION_KEY (KEK)", Fingerprint: h.km.KEKKeyID(), ManagedBy: "deployer",
			Note: "信封主鑰：換鑰走精靈的 KEK 重包流程", NoteCode: "encryption_key"},
		{Name: "JWT_SECRET", Fingerprint: h.jwtFingerprint, ManagedBy: "deployer",
			Note: "登入簽章鑰：輪替=改 env 重啟（全員重登）；審計驗章已解耦不受影響", NoteCode: "jwt_secret"},
	}
	// Ed25519 匯出簽章鑰：canonical 公鑰來源為 signing service（與 /audit-export/public-key
	// 端點同源），顯示公鑰指紋並帶公鑰供複製/下載
	if h.signing != nil {
		pubB64 := h.signing.PublicKeyBase64()
		ev := envKeyView{Name: "匯出簽章鑰 (Ed25519)", NameCode: "audit_export", ManagedBy: "system",
			Note: "私鑰信封加密落庫；輪替需重發公鑰給外部驗證者（runbook）", NoteCode: "audit_export",
			PublicKey: pubB64}
		if raw, err := base64.StdEncoding.DecodeString(pubB64); err == nil && len(raw) == ed25519.PublicKeySize {
			ev.Fingerprint = crypto.Fingerprint(raw)
		}
		envKeys = append(envKeys, ev)
	}

	// Ed25519 檢查點簽章鑰（audit-checkpoint-chain）：與匯出簽章鑰刻意分立
	// （共用會使任一鑰的輪替／洩漏綁死兩個信任面），故在清冊上也是獨立一項。
	// **自始帶版本**：匯出簽章鑰無版本欄是已知缺陷，本鑰不回頭補課但不重蹈
	if h.checkpointSigning != nil {
		version := h.checkpointSigning.ActiveVersion()
		pubB64 := h.checkpointSigning.ActivePublicKeyBase64()
		ev := envKeyView{Name: "檢查點簽章鑰 (Ed25519)", NameCode: "audit_checkpoint", ManagedBy: "system",
			Note: "審計檢查點鏈的簽章鑰；私鑰信封加密落庫、無匯出入口，公鑰供離線驗章",
			NoteCode: "audit_checkpoint", PublicKey: pubB64, Version: version}
		if fp, err := h.checkpointSigning.PublicKeyFingerprint(version); err == nil {
			ev.Fingerprint = fp
		}
		envKeys = append(envKeys, ev)
	}

	// KEK 退役史：from→to 聚合，不含 wrapped_key
	kekHistory, err := h.km.ListRetiredKEKs()
	if err != nil {
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeyKEKHistoryQuery, err)
		return
	}

	rotationPending, _ := h.km.RotationPendingCount()
	// 切換收尾待收斂狀態：收尾 best-effort 失敗時 env pending 未轉正
	// 或退役 backlog 殘留——清冊暴露筆數供管理員知悉需重啟收斂（>0 才需關注）
	env := h.km.KEKKeyID()
	// 收斂狀態讀取失敗時不得以 0 呈現＝假健康：
	// converge_state_error=true 供前端保守處置（顯示未知態、禁用清理按鈕）
	convergeStateErr := false
	var finalizePending int64
	if err := h.db.Model(&model.DataKey{}).
		Where("kek_id = ? AND kek_pending = ?", env, true).Count(&finalizePending).Error; err != nil {
		log.Printf("[KeyManagement] 讀取待切換筆數失敗（收斂狀態未知）: %v", err)
		convergeStateErr = true
	}
	// retire backlog 走 service 的單一謂詞方法：
	// 清冊標示與 degraded 告警偵測必須是同一個判定，不得各寫一份 SQL
	retireBacklog, err := h.km.RetireBacklogCount()
	if err != nil {
		log.Printf("[KeyManagement] 讀取退役 backlog 失敗（收斂狀態未知）: %v", err)
		convergeStateErr = true
	}
	body := gin.H{
		"keys":     keys,
		"env_keys": envKeys,
		// provider／key_ref：**由執行期 provider 物件導出**（自證循環防線）。
		//
		// SHALL NOT 重讀 os.Getenv：清冊的用途是稽核「這個行程**實際**跑的是哪一個
		// KEK provider」。若它自己去讀環境變數，回答的就只是「環境變數寫了什麼」
		// ——那正是被稽核的對象自己宣稱自己的身分，形成自證循環。
		// 兩者同源於 km 持有的 provider：KEKMode() 取 provider.Mode()，
		// key_ref 取 provider.KeyRef()（本地模式的 KeyID 是指紋，非機密）。
		"provider": h.km.KEKMode(),
		"key_ref":  h.km.KEKRef().String(),

		"kek_id":         h.km.KEKKeyID(),
		"rewrap_pending": h.km.RewrapPending(),
		// kek_history KEK 退役史：[{from_kek_id, to_kek_id, retired_at, rows}]
		"kek_history": kekHistory,
		// finalize_pending/retire_backlog 切換收尾待收斂筆數（>0 表需重啟收斂）；
		// converge_state_error=true 表任一讀取失敗、數字不可信（前端保守禁用清理）
		"finalize_pending":     finalizePending,
		"retire_backlog":       retireBacklog,
		"converge_state_error": convergeStateErr,
		// migration／migration_pending 欄位已隨 legacy 信封化遷移一同拆除
		// 清冊 SHALL NOT 含任何 legacy
		// 遷移狀態欄位——終態下無存量可遷，該欄位恆為 0/null 只會誤導。
		// rotation_pending 現行 data DEK 版本尚未覆蓋的值數（partial 續跑提示）
		"rotation_pending": rotationPending,
		"reminder_days":    reminderDays,
	}
	// seal_state／unsealed_at：封印狀態機的四態與解封時點。
	// 未注入探針時整組省略而非以預設值頂替——「未知」與「已解封」在稽核面
	// 是完全不同的事實，回一個猜測值會讓清冊自己成為錯誤來源。
	if h.sealState != nil {
		state, unsealedAt := h.sealState()
		body["seal_state"] = state
		if !unsealedAt.IsZero() {
			body["unsealed_at"] = unsealedAt.UTC().Format(time.RFC3339)
		}
	}
	c.JSON(http.StatusOK, body)
}

// rotateRequest 輪替請求
type rotateRequest struct {
	Purpose string `json:"purpose" binding:"required"`
}

// Rotate DEK/蓋章鑰輪替（手動觸發；系統永不自動輪換）
func (h *KeyManagementHandler) Rotate(c *gin.Context) {
	var req rotateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeBadParams, nil)
		return
	}
	var result *keyvault.DEKRotationResult
	var err error
	switch req.Purpose {
	case model.DataKeyPurposeData:
		result, err = h.km.RotateDataDEK()
	case model.DataKeyPurposeAuditIntegrity:
		result, err = h.km.RotateAuditKey()
	default:
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyRotatePurposeInvalid, nil)
		return
	}
	if err != nil {
		if errors.Is(err, keyvault.ErrKeyOpBusy) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyOpBusy, nil)
			return
		}
		if errors.Is(err, keyvault.ErrRewrapPending) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyRewrapPending, nil)
			return
		}
		if errors.Is(err, keyvault.ErrStaleKeyCache) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyStaleCache, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeyRotate, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// Rewrap KEK 重包（明文流向反轉後）。
//
// **明文只朝一個方向流動**：材料由請求體帶入，僅存活於本次請求處理期間；
// 回應不含任何 KEK 明文欄，只回金鑰引用（指紋，非機密）與重包列數。
// 伺服端不生成、不落庫、不落日誌。
//
// 請求體為 discriminated union，混合 payload 一律 fail-close（見
// key_rewrap_payload.go）。`Cache-Control: no-store` 保留——現在保護的是
// **請求重放**而非回應洩漏。
//
// **請求體不入審計**：捕獲欄位是 audit_logs.request_body，現行
// MaskSensitiveFields 為 allowlist（new_kek／new_kek_confirm 不在其中，故已被
// 遮罩）。該行為由 TestRewrapRequestBodyMaskedInAudit 釘住，防日後有人把
// new_kek 加進 allowlist。
func (h *KeyManagementHandler) Rewrap(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	target, payload, ok := h.buildRewrapTarget(c)
	if !ok {
		return
	}
	// 材料在本函式結束前不再被持有（誠實界定見 rewrapPayload.Zeroize）。
	// target 的材料副本亦一併銷毀：RewrapKEK 正常路徑會自行 Destroy，
	// 但本函式提前 return 的分支（錯誤映射）不會走到那裡，故此處再登記一次
	// ——Destroy 為冪等。
	defer payload.Zeroize()
	defer target.Destroy()

	result, err := h.km.RewrapKEK(c.Request.Context(), target)
	if err != nil {
		if errors.Is(err, keyvault.ErrKeyOpBusy) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyOpBusy, nil)
			return
		}
		// 目標側衝突（「非現行 KEK」／既有守衛 c「指紋未曾出現」）：
		// 皆為可由操作者改用另一把新鑰即恢復的前置狀態衝突
		switch {
		case errors.Is(err, keyvault.ErrRewrapTargetSameAsCurrent):
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyRewrapTargetCurrent, nil)
			return
		case errors.Is(err, keyvault.ErrRewrapTargetSeen):
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyRewrapTargetSeen, nil)
			return
		case errors.Is(err, keyvault.ErrRewrapTargetUnsupported):
			apierror.Respond(c, http.StatusNotImplemented, apierror.CodeKeyRewrapTargetUnsupported, nil)
			return
		}
		// 409＋恢復指引：已有待切換 pending（先完成或放棄）／退役 backlog 未收斂
		// （先重啟收斂）——皆為可恢復的前置狀態衝突。
		// **遷移未完成（ErrMigrationPending）一族已拆除**：無 legacy 遷移即無母體
		switch {
		case errors.Is(err, keyvault.ErrRewrapPendingExists):
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyRewrapPendingExists, nil)
			return
		case errors.Is(err, keyvault.ErrRetireBacklog):
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyRetireBacklog, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeyRewrap, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// buildRewrapTarget 解析 union 請求體並構造重包目標；任一驗證失敗即就地回應
// 並回傳 ok=false（呼叫端不得再進入任何 data_keys 寫入路徑）。
//
// 回傳的 payload 恆非 nil（失敗時為空殼），使呼叫端的 defer Zeroize 不必判空。
func (h *KeyManagementHandler) buildRewrapTarget(c *gin.Context) (*keyvault.RewrapTarget, *rewrapPayload, bool) {
	empty := &rewrapPayload{}
	// 上限 +1 byte：讀滿即代表超限，交由 decode 拒絕（不預先信任 Content-Length）
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxRewrapBodyBytes+1))
	// **原始請求體逐位元組覆寫**：它是承載 new_kek 明文的第一份，且是本流程中
	// 少數真的可以被覆寫的一份（解析後的 string 副本不可覆寫，見下方誠實界定）。
	// 覆寫涵蓋全部返回路徑，包含解析失敗與格式違規。
	defer zeroRewrapBody(body)
	if err != nil {
		apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyRewrapPayload, nil)
		return nil, empty, false
	}
	payload, err := decodeRewrapPayload(body)
	if err != nil {
		switch {
		case errors.Is(err, errRewrapModeInvalid):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyRewrapMode, nil)
		case errors.Is(err, errRewrapPayloadMixed):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyRewrapPayloadMixed, nil)
		case errors.Is(err, errRewrapConfirmMismatch):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyRewrapConfirm, nil)
		case errors.Is(err, errRewrapNotSaved):
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyRewrapNotSaved, nil)
		default:
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyRewrapPayload, nil)
		}
		return nil, empty, false
	}

	if payload.Mode == rewrapModeLocal {
		target, err := keyvault.NewLocalRewrapTarget(payload.NewKEK)
		if err != nil {
			// 格式違規原因不回傳給呼叫端（避免以錯誤訊息逐步試探材料），
			// 只回單一機器碼；細節留在伺服端日誌之外的 nil——不落日誌
			payload.Zeroize()
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyRewrapMaterial, nil)
			return nil, empty, false
		}
		return target, payload, true
	}

	// 委託目標（Phase C 3.1／3.3）：provider 建構即連通性預檢，
	// 三類失敗各有專屬機器碼——「版本不支援」「組態／權限問題」「判別子打錯」
	// 的處置完全不同，合併成一個碼等於要操作者猜。
	target, err := keyvault.NewDelegatedRewrapTarget(c.Request.Context(), payload.Mode, payload.KeyRef, h.delegatedProvider)
	if err != nil {
		switch {
		case errors.Is(err, keyvault.ErrRewrapTargetUnsupported):
			apierror.Respond(c, http.StatusNotImplemented, apierror.CodeKeyRewrapTargetUnsupported, nil)
		case errors.Is(err, keyvault.ErrRewrapTargetUnavailable):
			// 預檢失敗的細節（雲端錯誤碼／ARN）不回傳給呼叫端：它是外部系統的
			// 內部狀態，屬伺服端日誌的範疇
			log.Printf("[KeyManagement] 委託重包目標預檢失敗（模式 %s）: %v", payload.Mode, err)
			apierror.Respond(c, http.StatusBadGateway, apierror.CodeKeyRewrapTargetUnavailable, nil)
		default:
			apierror.Respond(c, http.StatusBadRequest, apierror.CodeKeyRewrapMode, nil)
		}
		return nil, empty, false
	}
	return target, payload, true
}

// AbandonRewrap 放棄尚未切換的 KEK 重包：軟退役未切換的新 KEK 包裹列（材料
// 保留至顯式清理）、清待切換狀態。回應鍵 deleted 保留 wire 相容（值＝軟退役筆數）
func (h *KeyManagementHandler) AbandonRewrap(c *gin.Context) {
	abandoned, err := h.km.AbandonRewrap()
	if err != nil {
		if errors.Is(err, keyvault.ErrKeyOpBusy) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyOpBusy, nil)
			return
		}
		if errors.Is(err, keyvault.ErrNoRewrapPending) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyNoRewrapPending, nil)
			return
		}
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeyAbandonRewrap, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": abandoned})
}

// CleanupRetired 清理退役金鑰資料：
// 唯一材料銷毀點。全收斂閘＋退役 DEK 版本引用掃描閘於 service 層鎖內執行；
// 指紋與退役軌跡永久保留。清理明細顯式留痕審計。
func (h *KeyManagementHandler) CleanupRetired(c *gin.Context) {
	result, err := h.km.CleanupRetiredMaterial()
	if err != nil {
		if errors.Is(err, keyvault.ErrKeyOpBusy) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyOpBusy, nil)
			return
		}
		if errors.Is(err, keyvault.ErrCleanupNotConverged) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyCleanupNotConverged, nil)
			return
		}
		// 不可歸屬殘值：保守拒清。
		// 與「未收斂」同屬可恢復的前置狀態衝突，故 409＋機器碼
		if errors.Is(err, keyvault.ErrCleanupResidueDetected) {
			apierror.Respond(c, http.StatusConflict, apierror.CodeKeyCleanupResidueDetected, nil)
			return
		}
		// 中止原因必落 log：清理中止代表差點發生不可逆銷毀
		// 錯誤，診斷訊號不得消失於無資訊 500（RespondInternal 內部落 log）
		apierror.RespondInternal(c, http.StatusInternalServerError, apierror.CodeInternalKeyCleanupRetired, err)
		return
	}
	// 顯式留痕：清理列數＋逐項 purpose/version/kek_id 指紋（金鑰銷毀是
	// 有紀錄的主動操作——PCI 3.7.5 對標；無材料、僅指紋）
	if h.auditService != nil {
		userID, _ := middleware.GetCurrentUserID(c)
		username, _ := middleware.GetCurrentUsername(c)
		detail, _ := json.Marshal(gin.H{
			"purged_count": len(result.Purged), "purged": result.Purged,
			"skipped_count": len(result.Skipped), "skipped": result.Skipped,
		})
		h.auditService.Log(&audit.AuditLogEntry{
			UserID: userID, Username: username,
			Action: model.ActionDelete, Resource: model.ResourceKeyManagement,
			Status: model.StatusSuccess, Method: c.Request.Method,
			Path: c.Request.URL.Path, ClientIP: sourceip.Of(c),
			StatusCode: http.StatusOK, RequestBody: string(detail),
		})
	}
	c.JSON(http.StatusOK, result)
}

// RegisterRoutes 註冊金鑰管理路由（admin 限定；路徑段 keys 由 audit
// middleware 歸類為 key_management 資源）
func (h *KeyManagementHandler) RegisterRoutes(r *gin.RouterGroup, authService *identity.AuthService) {
	keys := r.Group("/keys")
	keys.Use(middleware.AuthMiddleware(authService))
	keys.Use(middleware.RequireRole("admin"))
	{
		keys.GET("", h.Inventory)
		keys.POST("/rotate", h.Rotate)
		keys.POST("/rewrap", h.Rewrap)
		keys.DELETE("/rewrap", h.AbandonRewrap)
		keys.DELETE("/retired-material", h.CleanupRetired)
	}
}
