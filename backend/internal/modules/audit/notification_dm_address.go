package audit

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/crypto"
	"gorm.io/gorm"
)

// 個人訊息的收件位址：以收件人的電子郵件向通道保存的網址查平台帳號，再以帳號識別碼為目的地送出。
//
// 順序（每次嘗試）：讀收件人當下的電子郵件 → 正規化 → 確認沒有另一個未刪除帳號的電子郵件相同 → 查記憶體快取 →
// 未命中時以通道當下的 token 呼叫查詢方法 → 查詢之後再跑一次送出前檢查（認領之後，取消時不回減次數）→
// 以帳號識別碼為目的地送出。查詢與送出用同一個 client（不跟隨轉址）。
//
// 電子郵件只出現在查詢請求的本文：不進網址、紀錄、事件、log 與 API 回應；錯誤文字另做電子郵件樣式的遮蔽。
//
// 對個人派送只能在通道網址的主機屬允許清單時開啟與送出：預設只有平台官方的 API 主機，部署者以環境變數
// NOTIFY_DM_EXTRA_HOSTS（逗號分隔的主機名）加入其他主機。比對完整主機名，不比對子網域。

// dmExtraHostsEnv 對個人派送允許清單的擴充環境變數。
const dmExtraHostsEnv = "NOTIFY_DM_EXTRA_HOSTS"

// dmDefaultHost 允許清單的預設主機（slack_app 預設網址的主機）。
const dmDefaultHost = "slack.com"

// directMessageHostAllowed 網址的主機是否屬對個人派送的允許清單（每次呼叫重讀環境變數）。
func directMessageHostAllowed(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == dmDefaultHost {
		return true
	}
	for _, h := range strings.Split(os.Getenv(dmExtraHostsEnv), ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" && h == host {
			return true
		}
	}
	return false
}

// DirectMessageURLAllowed 已保存的通道網址（明文）是否可用於對個人派送（通道服務與畫面用）。
func DirectMessageURLAllowed(rawURL string) bool { return directMessageHostAllowed(rawURL) }

// directMessageDisabledReason 通道列（明文網址）目前能否送個人訊息；不能時回非空的說明（只記 log，不出站）。
// 網址仍是信封格式（解不開）時不在這裡判定，交給送出時的「通道設定無法讀取」單筆失敗。
func directMessageDisabledReason(ch model.NotificationChannel) string {
	if !ch.DirectMessageEnabled {
		return "對個人派送未開啟"
	}
	desc, ok := ChannelType(destinationFromChannel(&ch).Type)
	if !ok || !desc.Caps.CanTargetUser || desc.lookupUser == nil {
		return "通道型別不能以個人為對象"
	}
	if crypto.IsEnvelope(ch.URL) {
		return ""
	}
	if !directMessageHostAllowed(ch.URL) {
		return "網址不在對個人派送的允許清單內"
	}
	return ""
}

// ---- 對應快取 ----

const (
	dmCachePositiveTTL = time.Hour
	dmCacheNegativeTTL = 10 * time.Minute
)

// dmCacheKey 鍵含通道識別碼與目的地版本：換 token 或網址後舊結果不再使用。
type dmCacheKey struct {
	ChannelID uint
	Version   int
	Email     string
}

type dmCacheEntry struct {
	userID   string
	negative bool
	expires  time.Time
}

// dmAddressCache 個人訊息的帳號對應快取（記憶體、不落庫；多個執行個體各一份）。
var dmAddressCache = struct {
	mu sync.Mutex
	m  map[dmCacheKey]dmCacheEntry
}{m: map[dmCacheKey]dmCacheEntry{}}

func dmCacheGet(k dmCacheKey, now time.Time) (dmCacheEntry, bool) {
	dmAddressCache.mu.Lock()
	defer dmAddressCache.mu.Unlock()
	e, ok := dmAddressCache.m[k]
	if !ok {
		return dmCacheEntry{}, false
	}
	if !now.Before(e.expires) {
		delete(dmAddressCache.m, k)
		return dmCacheEntry{}, false
	}
	return e, true
}

func dmCachePut(k dmCacheKey, e dmCacheEntry) {
	dmAddressCache.mu.Lock()
	dmAddressCache.m[k] = e
	dmAddressCache.mu.Unlock()
}

func dmCacheDrop(k dmCacheKey) {
	dmAddressCache.mu.Lock()
	delete(dmAddressCache.m, k)
	dmAddressCache.mu.Unlock()
}

// invalidateDMAddressCache 清掉某個通道的正負快取（通道任何更新或刪除時呼叫）。
func invalidateDMAddressCache(channelID uint) {
	dmAddressCache.mu.Lock()
	for k := range dmAddressCache.m {
		if k.ChannelID == channelID {
			delete(dmAddressCache.m, k)
		}
	}
	dmAddressCache.mu.Unlock()
}

// ---- 電子郵件 ----

// normalizeRecipientEmail 與使用者服務的正規化相同：去頭尾空白、轉小寫。
func normalizeRecipientEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// errRecipientMissing 收件人的使用者列不存在（硬刪）。
var errRecipientMissing = errors.New("收件人不存在")

// recipientEmail 收件人當下的電子郵件（正規化後；未填為空字串）。使用者列不存在時回 errRecipientMissing。
func recipientEmail(db *gorm.DB, userID uint) (string, error) {
	var rows []struct{ Email *string }
	if err := db.Unscoped().Model(&model.User{}).Select("email").Where("id = ?", userID).Limit(1).Find(&rows).Error; err != nil {
		return "", fmt.Errorf("讀取收件人失敗: %w", err)
	}
	if len(rows) == 0 {
		return "", errRecipientMissing
	}
	if rows[0].Email == nil {
		return "", nil
	}
	return normalizeRecipientEmail(*rows[0].Email), nil
}

// emailAmbiguous 是否有另一個未刪除帳號（不論是否啟用）的正規化電子郵件相同（範圍與使用者表的電子郵件唯一索引相同）。
func emailAmbiguous(db *gorm.DB, userID uint, normalized string) (bool, error) {
	var n int64
	if err := db.Model(&model.User{}).
		Where("id <> ? AND email IS NOT NULL AND LOWER(TRIM(email)) = ?", userID, normalized).
		Count(&n).Error; err != nil {
		return false, fmt.Errorf("檢查電子郵件唯一性失敗: %w", err)
	}
	return n > 0, nil
}

// emailPattern 錯誤文字中電子郵件樣式的遮蔽（平台回應可能回顯查詢參數）。
var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

func scrubEmails(s string) string { return emailPattern.ReplaceAllString(s, "[email]") }

// sanitizeDisplayName 平台顯示名稱的對外版本：去格式、遮蔽電子郵件樣式。
func sanitizeDisplayName(s string) string { return scrubEmails(notifycat.SanitizeOpaque(s)) }

// ---- 查詢的判讀 ----

// slackLookupNotFoundCode 官方文件明載的查無此人錯誤碼（涵蓋已停用的使用者）。
const slackLookupNotFoundCode = "users_not_found"

// slackRateLimitedCodes 平台以錯誤碼表示限流（與 HTTP 429 同類）。
var slackRateLimitedCodes = map[string]bool{"ratelimited": true, "rate_limited": true}

// slackInvalidDestinationCodes 送訊息時表示目的地使用者無效的錯誤碼（清掉正快取、下一次重新查詢）。
var slackInvalidDestinationCodes = map[string]bool{"channel_not_found": true}

// lookupOutcome 查詢一次的判讀。
type lookupOutcome struct {
	outcome    AddressOutcome
	text       string
	retryAfter time.Duration
	userID     string
	display    string
	// negative 明確查無、已停用或為機器人（寫負快取）。
	negative bool
}

// classifyLookup 依決策 6 的失敗分類判讀查詢回應。
func classifyLookup(r UserLookupResult, now time.Time) lookupOutcome {
	switch {
	case r.Status == http.StatusTooManyRequests:
		ra, _ := parseRetryAfterHeader(r.RetryAfter, now)
		return lookupOutcome{outcome: AddressRateLimited, text: "HTTP 429", retryAfter: ra}
	case r.Status >= 500:
		return lookupOutcome{outcome: AddressDestinationFailure, text: fmt.Sprintf("HTTP %d", r.Status)}
	case r.Status >= 300 && r.Status < 400:
		return lookupOutcome{outcome: AddressRetryable, text: notifyRedirectNotFollowedText}
	case r.PlatformError == slackLookupNotFoundCode && r.Status >= 200 && r.Status < 300:
		return lookupOutcome{outcome: AddressNotFound, text: "platform error: " + r.PlatformError, negative: true}
	case slackRateLimitedCodes[r.PlatformError]:
		ra, _ := parseRetryAfterHeader(r.RetryAfter, now)
		return lookupOutcome{outcome: AddressRateLimited, text: "platform error: " + r.PlatformError, retryAfter: ra}
	case r.PlatformError != "" && r.Status >= 200 && r.Status < 300:
		return lookupOutcome{outcome: AddressRetryable, text: "platform error: " + r.PlatformError}
	case r.PlatformError != "":
		return lookupOutcome{outcome: AddressRetryable, text: fmt.Sprintf("HTTP %d, platform error: %s", r.Status, r.PlatformError)}
	case r.Status < 200 || r.Status >= 300:
		return lookupOutcome{outcome: AddressRetryable, text: fmt.Sprintf("HTTP %d", r.Status)}
	case r.Deleted || r.IsBot:
		return lookupOutcome{outcome: AddressNotFound, text: "平台帳號已停用或為機器人", negative: true}
	}
	return lookupOutcome{outcome: AddressResolved, userID: r.UserID, display: r.DisplayName}
}

// lookupSlackUser 向通道保存的網址查一次（不使用也不寫入快取）。client 錯誤（連線、逾時、轉址規則）回 err。
func lookupSlackUser(client *http.Client, dest ChannelDestination, email string, now time.Time) (lookupOutcome, error) {
	desc, ok := ChannelType(dest.Type)
	if !ok {
		return lookupOutcome{}, fmt.Errorf("通道型別 %q 不在登錄中", dest.Type)
	}
	req, err := desc.NewLookupRequest(dest, email)
	if err != nil {
		return lookupOutcome{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return lookupOutcome{}, err
	}
	r := desc.ReadLookupResult(resp)
	_ = resp.Body.Close()
	return classifyLookup(r, now), nil
}

// ---- 投遞程序的個人訊息送出 ----

// attemptSendToUser 個人訊息的一次嘗試（已認領、次數已加一）：解析位址、必要時查詢後再檢查一次、送出並判讀。
func (w *SystemAlertOutboxWorker) attemptSendToUser(row model.NotificationDelivery, pre preRead) sendResult {
	if row.RecipientUserID == nil {
		return sendResult{kind: sendCanceled, endReason: model.NotificationEndRecipientIneligible}
	}
	email, err := recipientEmail(w.db, *row.RecipientUserID)
	switch {
	case errors.Is(err, errRecipientMissing):
		return sendResult{kind: sendCanceled, endReason: model.NotificationEndRecipientIneligible}
	case err != nil:
		return sendResult{kind: sendSingleFailure, text: err.Error()}
	case email == "":
		return sendResult{kind: sendImpossible, endReason: model.NotificationEndNoEmail}
	}
	amb, err := emailAmbiguous(w.db, *row.RecipientUserID, email)
	if err != nil {
		return sendResult{kind: sendSingleFailure, text: err.Error()}
	}
	if amb {
		return sendResult{kind: sendImpossible, endReason: model.NotificationEndEmailAmbiguous}
	}

	dest := pre.dest
	key := dmCacheKey{ChannelID: pre.channel.ID, Version: pre.channel.DestinationVersion, Email: email}
	client := newNotificationHTTPClient(dest.Type, dest.URL, w.httpTimeout, w.risks, w.transport)
	userID := ""
	if entry, ok := dmCacheGet(key, w.now()); ok {
		if entry.negative {
			return sendResult{kind: sendImpossible, endReason: model.NotificationEndRecipientNotFound}
		}
		userID = entry.userID
	} else {
		out, err := lookupSlackUser(client, dest, email, w.now())
		if err != nil {
			if text := redirectFailureText(err); text != "" {
				return sendResult{kind: sendSingleFailure, text: text, requested: true}
			}
			return sendResult{kind: sendDestinationFailure, text: scrubEmails(SanitizeChannelError(err, dest.URL, dest.Secret)), requested: true}
		}
		switch out.outcome {
		case AddressNotFound:
			dmCachePut(key, dmCacheEntry{negative: true, expires: w.now().Add(dmCacheNegativeTTL)})
			return sendResult{kind: sendImpossible, endReason: model.NotificationEndRecipientNotFound, text: out.text, requested: true}
		case AddressRateLimited:
			return sendResult{kind: sendRateLimited, text: out.text, retryAfter: out.retryAfter, hasRetry: out.retryAfter > 0, requested: true}
		case AddressDestinationFailure:
			return sendResult{kind: sendDestinationFailure, text: out.text, requested: true}
		case AddressRetryable:
			return sendResult{kind: sendSingleFailure, text: out.text, requested: true}
		}
		userID = out.userID
		dmCachePut(key, dmCacheEntry{userID: userID, expires: w.now().Add(dmCachePositiveTTL)})

		// 查詢之後再跑一次送出前檢查（認領之後）：取消是終態，已計的次數不回減；檢查無法完成時以一次失敗收尾。
		if res, failed := w.recheckAfterLookup(row, pre); failed {
			// 下一次嘗試重新查詢並再檢查一次，不以快取跳過查詢之後的檢查
			dmCacheDrop(key)
			return sendResult{kind: sendSingleFailure, text: "送出前檢查失敗", requested: true}
		} else if res.Cancel {
			reason := res.Reason
			if reason == "" {
				reason = model.NotificationEndPrecheckCanceled
			}
			return sendResult{kind: sendCanceled, endReason: reason, requested: true}
		}
	}
	if err := w.db.Model(&model.NotificationDelivery{}).Where("id = ?", row.ID).Update("dest_target", userID).Error; err != nil {
		log.Printf("[NotificationOutbox] 記錄個人訊息的平台帳號失敗 (outbox_id=%d): %v", row.ID, err)
	}
	dest.Target = userID
	res := w.postRendered(row, pre, dest)
	res.requested = true
	if res.kind == sendSingleFailure {
		code := ""
		if m := deliveryPlatformErrorPattern.FindStringSubmatch(res.text); m != nil {
			code = m[1]
		}
		switch {
		case slackRateLimitedCodes[code]:
			res.kind = sendRateLimited
		case slackInvalidDestinationCodes[code]:
			// 目的地使用者無效（例如帳號已停用）：清掉正快取，下一次嘗試重新查詢
			dmCacheDrop(key)
		}
	}
	res.text = scrubEmails(res.text)
	return res
}

// recheckAfterLookup 查詢之後的第二次送出前檢查；failed 為真表示檢查 panic 或無法完成。
func (w *SystemAlertOutboxWorker) recheckAfterLookup(row model.NotificationDelivery, pre preRead) (DeliveryPrecheckResult, bool) {
	if w.hooks.afterLookup != nil {
		w.hooks.afterLookup(row.ID)
	}
	fn := deliveryPrecheckFor(notifycat.Event(pre.msg.EventKey))
	if fn == nil {
		return DeliveryPrecheckResult{}, false
	}
	res, panicked := runDeliveryPrecheck(fn, DeliveryPrecheckInput{Stage: PrecheckAfterClaim, Delivery: row, Message: pre.msg, Channel: pre.channel})
	if panicked || res.Err != nil {
		if res.Err != nil {
			log.Printf("[NotificationOutbox] 查詢之後的送出前檢查無法完成 (outbox_id=%d): %v", row.ID, res.Err)
		}
		return DeliveryPrecheckResult{}, true
	}
	return res, false
}

// abandonImpossible 不可能成功的個人訊息：記下原因文字（若有）後立即放棄，放棄交易內觸發未能送達事件。
func (w *SystemAlertOutboxWorker) abandonImpossible(row model.NotificationDelivery, res sendResult, now time.Time) {
	if res.text != "" {
		msg := truncateRunes(scrubEmails(ScrubChannelTokens(res.text)), systemAlertErrMax)
		if err := w.db.Model(&model.NotificationDelivery{}).Where("id = ?", row.ID).
			Updates(map[string]any{"last_error": msg, "last_failed_at": now}).Error; err != nil {
			log.Printf("[NotificationOutbox] 登記失敗原因失敗 (id=%d): %v", row.ID, err)
		}
	}
	w.abandon(row, res.endReason, now, false)
}

// ---- 傳給我自己 ----

// 「傳給我自己」的結果。
const (
	SelfTestDelivered         = "delivered"
	SelfTestNoEmail           = model.NotificationEndNoEmail
	SelfTestEmailAmbiguous    = model.NotificationEndEmailAmbiguous
	SelfTestRecipientNotFound = model.NotificationEndRecipientNotFound
	SelfTestPlatformError     = "platform_error"
)

// SelfTestResult 「傳給我自己」的同步結果。不含電子郵件與平台使用者識別碼。
type SelfTestResult struct {
	Outcome       string
	Status        int
	PlatformError string
	// DisplayName 成功時對到的平台顯示名稱（請求者本人的，已淨化）。
	DisplayName string
}

// ErrSelfTestUnsupported 通道型別不能以個人為對象，或網址不在允許清單內。
var (
	ErrSelfTestUnsupportedType = errors.New("這個通道型別不能傳給個人")
	ErrSelfTestURLNotAllowed   = errors.New("這個通道的網址不在對個人派送的允許清單內")
)

// TestToSelf 以請求者自己在資料庫的電子郵件與通道已存設定，走一次完整的對應與私訊（不使用也不寫入快取、不重試、
// 不排入）。ch 為投遞用的明文通道（GetForDelivery）。連線層失敗（DNS、逾時、轉址規則）以 err 回報。
func (s *NotificationChannelService) TestToSelf(ch *model.NotificationChannel, requesterID uint) (SelfTestResult, error) {
	dest := destinationFromChannel(ch)
	desc, ok := ChannelType(dest.Type)
	if !ok || !desc.Caps.CanTargetUser || desc.lookupUser == nil {
		return SelfTestResult{}, ErrSelfTestUnsupportedType
	}
	if !directMessageHostAllowed(dest.URL) {
		return SelfTestResult{}, ErrSelfTestURLNotAllowed
	}
	email, err := recipientEmail(s.db, requesterID)
	if errors.Is(err, errRecipientMissing) || (err == nil && email == "") {
		return SelfTestResult{Outcome: SelfTestNoEmail}, nil
	}
	if err != nil {
		return SelfTestResult{}, err
	}
	amb, err := emailAmbiguous(s.db, requesterID, email)
	if err != nil {
		return SelfTestResult{}, err
	}
	if amb {
		return SelfTestResult{Outcome: SelfTestEmailAmbiguous}, nil
	}
	client := newNotificationHTTPClient(dest.Type, dest.URL, notifyHTTPTimeout, nil, nil)
	out, err := lookupSlackUser(client, dest, email, time.Now())
	if err != nil {
		return SelfTestResult{}, fmt.Errorf("%s", scrubEmails(SanitizeChannelError(err, dest.URL, dest.Secret)))
	}
	switch out.outcome {
	case AddressNotFound:
		return SelfTestResult{Outcome: SelfTestRecipientNotFound}, nil
	case AddressResolved:
	default:
		return selfTestPlatformResult(out.text), nil
	}
	target := *ch
	target.Target = out.userID
	status, err := SendTestNotificationShape(&target, "")
	var platformErr *ChannelPlatformError
	if errors.As(err, &platformErr) {
		return SelfTestResult{Outcome: SelfTestPlatformError, Status: platformErr.Status, PlatformError: platformErr.Code}, nil
	}
	if err != nil {
		return SelfTestResult{}, err
	}
	if status < 200 || status >= 300 {
		return SelfTestResult{Outcome: SelfTestPlatformError, Status: status}, nil
	}
	return SelfTestResult{Outcome: SelfTestDelivered, Status: status, DisplayName: out.display}, nil
}

// selfTestPlatformResult 查詢失敗（非查無）時的結果：平台錯誤碼與 HTTP 狀態取自判讀文字。
func selfTestPlatformResult(text string) SelfTestResult {
	r := SelfTestResult{Outcome: SelfTestPlatformError}
	if m := deliveryPlatformErrorPattern.FindStringSubmatch(text); m != nil {
		r.PlatformError = m[1]
	}
	if m := deliveryHTTPStatusPattern.FindStringSubmatch(text); m != nil {
		fmt.Sscanf(m[1], "%d", &r.Status)
	}
	return r
}
