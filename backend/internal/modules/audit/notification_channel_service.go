package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/custodexa/backend/internal/modules/policy"
	"log"
	"net/url"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 通道驗證錯誤：handler 以 errors.Is 區分 400（輸入問題）與 500（系統問題）
var (
	ErrChannelNotFound   = errors.New("通知通道不存在")
	ErrInvalidChannelURL = errors.New("URL 必須為 http 或 https")
	ErrInvalidChannelTyp = errors.New("通道類型必須為 webhook 或 slack")
	// ErrInvalidChannelLanguage 語系非白名單三值；
	// Update 顯式給空字串或白名單外值都回此錯——省略（nil）才是「保留舊值」
	ErrInvalidChannelLanguage = errors.New("語系必須為 zh-TW、en-US 或 ja-JP")
)

// NotificationChannelRequest 通道建立/更新請求（Create 與 Update 欄位相同，共用一個結構）。
// URL 不再 binding 必填：回應已遮罩、前端無從回填，
// Update 時空字串＝沿用既有（與 secret 同語義）；Create 時空 URL 由 validate 擋下
type NotificationChannelRequest struct {
	Name        string `json:"name" binding:"required"`
	Type        string `json:"type"` // 未傳預設 webhook
	URL         string `json:"url"`
	Secret      string `json:"secret"`       // Update 時空字串＝沿用既有（secret 不回傳，前端無從回填）
	ClearSecret bool   `json:"clear_secret"` // Update 時顯式清除簽名（改為不簽名推送）；Create 忽略
	Enabled     *bool  `json:"enabled"`      // 指標區分「未傳」與「false」；未傳預設啟用

	// Language per-channel 語系。指標區分「未傳」
	// 與「顯式空字串」——與 URL/secret 的「空字串＝沿用既有」語義不同：
	// nil＝省略＝Create 預設 zh-TW／Update 保留舊值；非 nil 一律驗證，
	// 空字串或白名單外值都拒（ErrInvalidChannelLanguage），不可能靜默留下非法值
	Language *string `json:"language"`

	// RiskAcknowledged 傳輸風險確認聲明：
	// warn 檔存 http URL 時必須為 true，聲明入審計
	RiskAcknowledged bool `json:"risk_acknowledged"`
	// Actor* 操作者（handler 從 JWT 填入，比照 CreateAssetRequest.CreatedBy 慣例）
	ActorID   uint   `json:"-"`
	ActorName string `json:"-"`
	ActorIP   string `json:"-"`
}

// ChannelInventoryProvider 的實作在 audit 側（環相依拆解）：介面由 policy
// 宣告、由本型別滿足，方向 audit→policy 單向合法。編譯期斷言寫在此處而非 policy 側，
// 理由同 audit_failure_service.go 的 keyvault.AuditFailureReporter 斷言。
var _ policy.ChannelInventoryProvider = (*NotificationChannelService)(nil)

// NotificationChannelService 通知通道 CRUD 服務。
// secret 與 url 信封加密落庫：url 本身即
// bearer secret（Slack webhook），API 回應一律遮罩、DB 不落明文
type NotificationChannelService struct {
	db *gorm.DB
	// codec 信封加解密。**ColumnCodec**：介面上**沒有**
	// Encrypt(plaintext)，故持有者在**建構上**不可能
	// 寫出無 AAD 的 enc:v 密文。**建構時注入、無 SetCodec 事後覆寫**——
	// 消除「組裝順序錯置時以錯誤 codec 寫出密文」的窗口。
	// nil＝明文直通（僅單測建構路徑，生產組裝一律注入）
	codec crypto.ColumnCodec
	// transmission 傳輸政策閘；nil＝閘不生效
	transmission *policy.TransmissionPolicyService
}

// NewNotificationChannelService 創建通知通道服務；codec 為 secret/url 的信封
// 加解密器（ColumnCodec），單測可傳 nil＝明文直通
func NewNotificationChannelService(db *gorm.DB, codec crypto.ColumnCodec) *NotificationChannelService {
	return &NotificationChannelService{db: db, codec: codec}
}

// SetTransmissionPolicy 注入傳輸政策閘（main 組裝時）
func (s *NotificationChannelService) SetTransmissionPolicy(tp *policy.TransmissionPolicyService) {
	s.transmission = tp
}

// checkTransmissionGate 存檔閘：以「存檔後生效的 URL」判定；
// 通過且屬 warn 確認情境時把聲明入審計
func (s *NotificationChannelService) checkTransmissionGate(effectiveURL string, req *NotificationChannelRequest, channelName string) error {
	if s.transmission == nil {
		return nil
	}
	risks := s.transmission.NotifyRisks(effectiveURL)
	if err := s.transmission.CheckSettingSave(policy.TransportChannelNotify, risks, req.RiskAcknowledged); err != nil {
		return err
	}
	if len(risks) > 0 && req.RiskAcknowledged &&
		s.transmission.ChannelLevel(policy.TransportChannelNotify) == policy.TransportLevelWarn {
		s.auditAcknowledgment(req, channelName, risks)
	}
	return nil
}

// auditAcknowledgment warn 確認聲明入審計（管理員/時間/設定摘要/風險項；
// URL 屬 secret 不落審計，僅記通道名）
func (s *NotificationChannelService) auditAcknowledgment(req *NotificationChannelRequest, channelName string, risks []policy.RiskItem) {
	details, err := json.Marshal(map[string]interface{}{
		"event":   "setting_ack",
		"channel": policy.TransportChannelNotify,
		"name":    channelName,
		"risks":   risks,
	})
	if err != nil {
		details = []byte(`{"event":"setting_ack","channel":"notify"}`)
	}
	entry := &model.AuditLog{
		Action:   model.ActionUpdate,
		Resource: model.ResourceTransmission,
		Status:   model.StatusSuccess,
		UserID:   req.ActorID,
		Username: req.ActorName,
		ClientIP: req.ActorIP,
		Details:  string(details),
	}
	if err := s.db.Create(entry).Error; err != nil {
		log.Printf("[NotificationChannel] 傳輸確認聲明審計寫入失敗: %v", err)
	}
}

// sealChannelValue 加密落庫值；codec 未注入時明文直通（單測路徑）。
// ref 為欄位身分（keyvault.RefChannelURL／keyvault.RefChannelSecret），AAD 綁 table|column——
// 故 url 的密文搬到 secret 欄（或反之）即解不開
func sealChannelValue(codec crypto.ColumnCodec, ref crypto.CipherRef, v string) (string, error) {
	if v == "" || codec == nil {
		return v, nil
	}
	return codec.EncryptFor(context.Background(), ref, v)
}

// readChannelValue 讀出明文：信封格式解密；非信封（遷移前殘留或單測明文）原樣回傳。
// **plaintext: true 登記語義不變**（envelopeMigrationTargets：notification_channels
// 的 url／secret 遷移前現值為明文）——非 `enc:` 前綴者一律原樣回傳，不送解密
func readChannelValue(codec crypto.ColumnCodec, ref crypto.CipherRef, v string) (string, error) {
	if v == "" || !crypto.IsEnvelope(v) {
		return v, nil
	}
	if codec == nil {
		return "", errors.New("通道值為信封格式但未注入解密器")
	}
	return codec.DecryptFor(context.Background(), ref, v)
}

// maskChannelURL 遮罩顯示（G8/spec）：保留 scheme+host
// 與末 4 碼，路徑整段以 **** 取代——url 可能整段等同密碼（Slack webhook）
func maskChannelURL(plain string) string {
	parsed, err := url.Parse(plain)
	if err != nil || parsed.Host == "" {
		// 不可解析的殘值不外洩原文
		return "****"
	}
	rest := plain[len(parsed.Scheme)+3+len(parsed.Host):]
	if rest == "" || rest == "/" {
		return parsed.Scheme + "://" + parsed.Host
	}
	tail := rest
	if len(tail) > 4 {
		tail = tail[len(tail)-4:]
	}
	return parsed.Scheme + "://" + parsed.Host + "/****" + tail
}

// toDisplay 轉為 API 回應形（就地）：url 遮罩、has_secret 以儲存值判定
func (s *NotificationChannelService) toDisplay(ch *model.NotificationChannel) error {
	ch.HasSecret = ch.Secret != ""
	plainURL, err := readChannelValue(s.codec, keyvault.RefChannelURL, ch.URL)
	if err != nil {
		// 解不開的 url 不阻列表，以全遮罩呈現（清冊/遷移告警另行提示）
		ch.URL = "****"
		return nil
	}
	// 傳輸偏離標示（3.1）：存量 http 通道誠實標示，不回溯停用
	if s.transmission != nil {
		ch.TransmissionDeviation = len(s.transmission.NotifyRisks(plainURL)) > 0
	}
	ch.URL = maskChannelURL(plainURL)
	return nil
}

// validateChannelURL URL 僅允許 http/https scheme——
// 擋掉 file:// 等非 web 協議與格式錯誤；內網位址首版信任 admin 輸入（design 風險註記）
func validateChannelURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ErrInvalidChannelURL
	}
	return nil
}

// validateChannel Create 用全量驗證（URL 必填）
func validateChannel(req *NotificationChannelRequest) error {
	if req.Type != "" && !model.ValidNotificationChannelType(req.Type) {
		return ErrInvalidChannelTyp
	}
	return validateChannelURL(req.URL)
}

// validateChannelLanguage 語系合法性檢查：嚴格匹配三值，
// 空字串與白名單外一律拒。呼叫端以 *string 是否為 nil 判別「省略」
// （不呼叫本函式、沿用既有語義）與「顯式提供」（呼叫本函式驗證）
func validateChannelLanguage(lang string) error {
	if !model.ValidNotificationChannelLanguage(lang) {
		return ErrInvalidChannelLanguage
	}
	return nil
}

// List 列出所有通道（量級個位數到數十，不分頁）；url 一律遮罩
func (s *NotificationChannelService) List() ([]model.NotificationChannel, error) {
	var channels []model.NotificationChannel
	if err := s.db.Order("id ASC").Find(&channels).Error; err != nil {
		return nil, fmt.Errorf("查詢通知通道失敗: %w", err)
	}
	for i := range channels {
		_ = s.toDisplay(&channels[i])
	}
	return channels, nil
}

// getStored 取原始儲存列（內部用，url/secret 為落庫密文）
func (s *NotificationChannelService) getStored(id uint) (*model.NotificationChannel, error) {
	var channel model.NotificationChannel
	if err := s.db.First(&channel, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrChannelNotFound
		}
		return nil, fmt.Errorf("查詢通知通道失敗: %w", err)
	}
	return &channel, nil
}

// GetByID 取得單一通道（API 顯示用；url 遮罩、secret 不外洩）
func (s *NotificationChannelService) GetByID(id uint) (*model.NotificationChannel, error) {
	channel, err := s.getStored(id)
	if err != nil {
		return nil, err
	}
	_ = s.toDisplay(channel)
	return channel, nil
}

// GetForDelivery 取得投遞用通道（url/secret 解密為明文）：僅供測試發送
// 與推送路徑，不得作為 API 回應
func (s *NotificationChannelService) GetForDelivery(id uint) (*model.NotificationChannel, error) {
	channel, err := s.getStored(id)
	if err != nil {
		return nil, err
	}
	plainURL, err := readChannelValue(s.codec, keyvault.RefChannelURL, channel.URL)
	if err != nil {
		return nil, fmt.Errorf("解密通道 URL 失敗: %w", err)
	}
	plainSecret, err := readChannelValue(s.codec, keyvault.RefChannelSecret, channel.Secret)
	if err != nil {
		return nil, fmt.Errorf("解密通道 secret 失敗: %w", err)
	}
	channel.URL = plainURL
	channel.Secret = plainSecret
	channel.HasSecret = plainSecret != ""
	return channel, nil
}

// Create 建立通道；成功後刷新推送快取
func (s *NotificationChannelService) Create(req *NotificationChannelRequest) (*model.NotificationChannel, error) {
	if err := validateChannel(req); err != nil {
		return nil, err
	}
	// language 未給＝預設 zh-TW；顯式提供則驗證
	language := model.NotificationChannelLanguageDefault
	if req.Language != nil {
		if err := validateChannelLanguage(*req.Language); err != nil {
			return nil, err
		}
		language = *req.Language
	}

	channelType := req.Type
	if channelType == "" {
		channelType = model.NotificationChannelTypeWebhook
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	// slack 不簽名，secret 對其無意義——強制清空使 has_secret 恆 false
	secret := req.Secret
	if channelType == model.NotificationChannelTypeSlack {
		secret = ""
	}
	// 傳輸政策閘：驗證之後、落庫之前
	if err := s.checkTransmissionGate(req.URL, req, req.Name); err != nil {
		return nil, err
	}

	sealedURL, err := sealChannelValue(s.codec, keyvault.RefChannelURL, req.URL)
	if err != nil {
		return nil, fmt.Errorf("加密通道 URL 失敗: %w", err)
	}
	sealedSecret, err := sealChannelValue(s.codec, keyvault.RefChannelSecret, secret)
	if err != nil {
		return nil, fmt.Errorf("加密通道 secret 失敗: %w", err)
	}
	channel := model.NotificationChannel{
		Name:     req.Name,
		Type:     channelType,
		URL:      sealedURL,
		Secret:   sealedSecret,
		Enabled:  enabled,
		Language: language,
	}
	if err := s.db.Create(&channel).Error; err != nil {
		return nil, fmt.Errorf("建立通知通道失敗: %w", err)
	}

	_ = s.toDisplay(&channel)
	ReloadAlertNotifier()
	return &channel, nil
}

// Update 更新通道；成功後刷新推送快取。
// url 空字串＝沿用既有（G8：回應已遮罩，前端無從回填，
// 語義與 secret 一致），有帶值才驗證、加密、落庫
func (s *NotificationChannelService) Update(id uint, req *NotificationChannelRequest) (*model.NotificationChannel, error) {
	if req.Type != "" && !model.ValidNotificationChannelType(req.Type) {
		return nil, ErrInvalidChannelTyp
	}
	if req.URL != "" {
		if err := validateChannelURL(req.URL); err != nil {
			return nil, err
		}
	}
	// language：nil＝省略＝保留舊值；非 nil 一律驗證（空字串或白名單外都拒）
	if req.Language != nil {
		if err := validateChannelLanguage(*req.Language); err != nil {
			return nil, err
		}
	}

	channel, err := s.getStored(id)
	if err != nil {
		return nil, err
	}

	// 傳輸政策閘：以存檔後生效的 URL 判定——
	// 未帶 URL＝沿用既有（解密評估；解不開的殘留列跳過閘，缺陷已由列表全遮罩呈現）。
	// 存量不安全通道不被回溯停用，但「再次存檔」即受閘（spec 場景鎖定此語義）
	effectiveURL := req.URL
	if effectiveURL == "" {
		if plain, readErr := readChannelValue(s.codec, keyvault.RefChannelURL, channel.URL); readErr == nil {
			effectiveURL = plain
		}
	}
	if err := s.checkTransmissionGate(effectiveURL, req, req.Name); err != nil {
		return nil, err
	}

	updates := map[string]interface{}{
		"name": req.Name,
	}
	if req.URL != "" {
		sealedURL, err := sealChannelValue(s.codec, keyvault.RefChannelURL, req.URL)
		if err != nil {
			return nil, fmt.Errorf("加密通道 URL 失敗: %w", err)
		}
		updates["url"] = sealedURL
	}
	if req.Type != "" {
		updates["type"] = req.Type
	}
	// 更新後的生效類型（未帶 type 則沿用既有）決定 secret 處理
	effectiveType := channel.Type
	if req.Type != "" {
		effectiveType = req.Type
	}
	// slack 恆無 secret（含 webhook→slack 轉換時清掉殘留）；
	// webhook 則：空字串＝沿用既有（secret 不回傳、編輯表單無從回填，避免任何編輯靜默清空），
	// clear_secret＝顯式清除
	switch {
	case effectiveType == model.NotificationChannelTypeSlack:
		updates["secret"] = ""
	case req.ClearSecret:
		updates["secret"] = ""
	case req.Secret != "":
		sealedSecret, err := sealChannelValue(s.codec, keyvault.RefChannelSecret, req.Secret)
		if err != nil {
			return nil, fmt.Errorf("加密通道 secret 失敗: %w", err)
		}
		updates["secret"] = sealedSecret
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.Language != nil {
		updates["language"] = *req.Language
	}
	if err := s.db.Model(channel).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新通知通道失敗: %w", err)
	}

	// channel 欄位在 Updates 後反映新落庫值（沿用時保留 getStored 讀到的舊值）
	_ = s.toDisplay(channel)
	ReloadAlertNotifier()
	return channel, nil
}

// Delete 刪除通道；成功後刷新推送快取
func (s *NotificationChannelService) Delete(id uint) error {
	result := s.db.Delete(&model.NotificationChannel{}, id)
	if result.Error != nil {
		return fmt.Errorf("刪除通知通道失敗: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrChannelNotFound
	}

	ReloadAlertNotifier()
	return nil
}
