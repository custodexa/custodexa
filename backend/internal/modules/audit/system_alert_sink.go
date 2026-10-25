package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// 系統告警落地面。
//
// 一次 RaiseInTx 在呼叫方交易內寫三樣東西：一筆告警列（來源類別 system_security）、
// 一筆結構化明細、對每個目的地一筆持久投遞佇列列。三者與業務變更同交易提交，任一步失敗
// 整筆回滾。提交後不需要生產端做任何動作：離機轉發與通道投遞都由背景投遞程序讀到已提交的列
// 才執行，所以沒有「忘記補呼叫」這種漏洞。
//
// 目的地決定：產生當下每個啟用中的通道各一筆，**不看推送門檻**——門檻只過濾一般告警。
// 沒有啟用通道時佇列為零筆，告警列照常存在，也不事後補送。
// 設定解不開的通道（KEK 變更後舊密文解不開之類）不讓業務操作失敗：告警列與明細照常落地、其他通道照常排入，
// 該通道留一筆立即放棄、帶原因的投遞紀錄，明細與伺服器日誌都看得到。

// systemAlertDestination 一個投遞目的地的明文快照（只在記憶體內短暫存在，落庫前即信封加密）。
type systemAlertDestination struct {
	Type            string
	Name            string
	Language        string
	SourceChannelID *uint
	URL             string
	Secret          string
}

func (d systemAlertDestination) key() string {
	return d.Type + "\x00" + d.URL + "\x00" + d.Secret
}

type systemAlertSink struct {
	codec crypto.ColumnCodec
	now   func() time.Time
}

var _ port.SystemAlertSink = (*systemAlertSink)(nil)

// NewSystemAlertSink 建立系統告警落地面。codec 是通道網址與簽章密鑰的信封加解密器，
// nil＝明文直通（只給單測）。回傳介面、實作型別不匯出。
func NewSystemAlertSink(codec crypto.ColumnCodec) port.SystemAlertSink {
	return &systemAlertSink{codec: codec, now: time.Now}
}

// RaiseInTx 見 port.SystemAlertSink。
func (s *systemAlertSink) RaiseInTx(tx *gorm.DB, ev port.SystemAlertEvent) (port.SystemAlertReceipt, error) {
	return s.raise(tx, ev, nil)
}

// raise 與 RaiseInTx 相同，另可加入額外的目的地快照（通道變更時的變更前後快照）。
// 額外目的地與啟用中通道以（類型、網址、密鑰）去重。
func (s *systemAlertSink) raise(tx *gorm.DB, ev port.SystemAlertEvent, extra []systemAlertDestination) (port.SystemAlertReceipt, error) {
	if s == nil || tx == nil {
		return port.SystemAlertReceipt{}, errors.New("系統告警落地面未取得交易控制代碼")
	}
	def, err := validateSystemAlertEvent(ev)
	if err != nil {
		return port.SystemAlertReceipt{}, err
	}
	severity, err := effectiveSystemAlertSeverity(tx, def)
	if err != nil {
		return port.SystemAlertReceipt{}, err
	}
	params, err := sanitizeSystemAlertParams(ev, severity)
	if err != nil {
		return port.SystemAlertReceipt{}, err
	}
	occurred := ev.OccurredAt
	if occurred.IsZero() {
		occurred = s.now()
	}

	// 落地面不持有交易句柄（句柄只作為參數傳遞，不存進 struct 欄位）：RecordAlertInTx 只用傳入的 tx。
	rec := &alertRecorder{}
	row, err := rec.RecordAlertInTx(tx, gatewayapi.CommandAlert{
		OccurredAt:  occurred,
		Actor:       gatewayapi.Actor{UserID: ev.Actor.UserID, Username: ev.Actor.Username},
		AssetID:     ev.AssetID,
		RuleName:    string(ev.Type),
		Kind:        model.AlertKindSystemSecurity,
		ReasonCode:  string(ev.Type),
		Level:       severity,
		Disposition: model.AlertDispositionPending,
	})
	if err != nil {
		return port.SystemAlertReceipt{}, fmt.Errorf("寫入系統告警列失敗: %w", err)
	}

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return port.SystemAlertReceipt{}, fmt.Errorf("編碼系統告警參數失敗: %w", err)
	}
	detail := model.SystemAlertDetail{
		AlertID:       row.ID,
		AlertType:     string(ev.Type),
		TargetKind:    string(ev.Target.Kind),
		TargetID:      ev.Target.ID,
		Params:        string(paramsJSON),
		CorrelationID: ev.CorrelationID,
		CreatedAt:     occurred,
	}
	if err := tx.Create(&detail).Error; err != nil {
		return port.SystemAlertReceipt{}, fmt.Errorf("寫入系統告警明細失敗: %w", err)
	}

	dests, unreadable, err := s.enabledDestinations(tx)
	if err != nil {
		return port.SystemAlertReceipt{}, err
	}
	dests = mergeSystemAlertDestinations(dests, extra)
	now := s.now()
	for _, d := range dests {
		sealedURL, err := sealChannelValue(s.codec, keyvault.RefSystemAlertOutboxURL, d.URL)
		if err != nil {
			return port.SystemAlertReceipt{}, fmt.Errorf("加密投遞目的地失敗: %w", err)
		}
		sealedSecret, err := sealChannelValue(s.codec, keyvault.RefSystemAlertOutboxSecret, d.Secret)
		if err != nil {
			return port.SystemAlertReceipt{}, fmt.Errorf("加密投遞目的地失敗: %w", err)
		}
		key, err := newDeliveryKey()
		if err != nil {
			return port.SystemAlertReceipt{}, err
		}
		out := model.SystemAlertOutbox{
			AlertID:         row.ID,
			DestType:        d.Type,
			DestName:        truncateRunes(d.Name, 100),
			DestLanguage:    d.Language,
			SourceChannelID: d.SourceChannelID,
			URLEnc:          sealedURL,
			SecretEnc:       sealedSecret,
			State:           model.SystemAlertOutboxPending,
			NextAttemptAt:   now,
			CreatedAt:       now,
			DeliveryKey:     key,
		}
		if err := tx.Create(&out).Error; err != nil {
			return port.SystemAlertReceipt{}, fmt.Errorf("寫入系統告警投遞佇列失敗: %w", err)
		}
	}
	// 設定解不開的通道：不擋業務操作、不投遞，但各留一筆立即放棄、帶原因的紀錄，
	// 讓明細看得到「這個目的地沒送」。快照欄留空，不把解不開的密文殘值搬進來。
	for _, u := range unreadable {
		key, err := newDeliveryKey()
		if err != nil {
			return port.SystemAlertReceipt{}, err
		}
		id := u.ch.ID
		out := model.SystemAlertOutbox{
			AlertID:         row.ID,
			DestType:        u.ch.Type,
			DestName:        truncateRunes(u.ch.Name, 100),
			DestLanguage:    u.ch.Language,
			SourceChannelID: &id,
			State:           model.SystemAlertOutboxAbandoned,
			NextAttemptAt:   now,
			CreatedAt:       now,
			LastError:       truncateRunes(u.reason, systemAlertErrMax),
			DeliveryKey:     key,
		}
		if err := tx.Create(&out).Error; err != nil {
			return port.SystemAlertReceipt{}, fmt.Errorf("寫入系統告警投遞佇列失敗: %w", err)
		}
		log.Printf("[SystemAlert] 通道 %d（%s）的設定無法解讀，告警 %d 對它的投遞已標記放棄: %v", u.ch.ID, u.ch.Name, row.ID, u.cause)
	}
	return port.SystemAlertReceipt{AlertID: row.ID, Severity: severity, Destinations: len(dests), Unreadable: len(unreadable)}, nil
}

// unreadableChannel 啟用中但網址或密鑰解不開的通道；reason 是落庫的原因（不含任何密文或底層錯誤原文），
// cause 只進伺服器日誌。
type unreadableChannel struct {
	ch     model.NotificationChannel
	reason string
	cause  error
}

// enabledDestinations 讀出目前啟用中的全部通道並解開明文快照。
// 解不開的通道不讓整個呼叫失敗（那會讓一個壞掉的通知設定擋下所有會產生系統告警的業務操作），
// 另列回傳，由呼叫端留下放棄紀錄。
func (s *systemAlertSink) enabledDestinations(tx *gorm.DB) ([]systemAlertDestination, []unreadableChannel, error) {
	var channels []model.NotificationChannel
	if err := tx.Where("enabled = ?", true).Order("id").Find(&channels).Error; err != nil {
		return nil, nil, fmt.Errorf("讀取啟用中的通知通道失敗: %w", err)
	}
	out := make([]systemAlertDestination, 0, len(channels))
	var unreadable []unreadableChannel
	for _, ch := range channels {
		d, err := channelDestination(s.codec, ch)
		if err != nil {
			unreadable = append(unreadable, unreadableChannel{
				ch:     ch,
				reason: fmt.Sprintf("通道設定無法解讀 (channel_id=%d)，未投遞", ch.ID),
				cause:  err,
			})
			continue
		}
		out = append(out, d)
	}
	return out, unreadable, nil
}

// newDeliveryKey 產生投遞識別：128 位元 CSPRNG、32 個十六進位字元。
func newDeliveryKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("產生投遞識別失敗: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// channelDestination 把通道列轉成明文目的地快照。
func channelDestination(codec crypto.ColumnCodec, ch model.NotificationChannel) (systemAlertDestination, error) {
	plainURL, err := readChannelValue(codec, keyvault.RefChannelURL, ch.URL)
	if err != nil {
		return systemAlertDestination{}, fmt.Errorf("解開通道網址失敗 (channel_id=%d): %w", ch.ID, err)
	}
	plainSecret, err := readChannelValue(codec, keyvault.RefChannelSecret, ch.Secret)
	if err != nil {
		return systemAlertDestination{}, fmt.Errorf("解開通道密鑰失敗 (channel_id=%d): %w", ch.ID, err)
	}
	id := ch.ID
	return systemAlertDestination{
		Type: ch.Type, Name: ch.Name, Language: ch.Language,
		SourceChannelID: &id, URL: plainURL, Secret: plainSecret,
	}, nil
}

// mergeSystemAlertDestinations 依序併入並以（類型、網址、密鑰）去重，保留先出現者。
func mergeSystemAlertDestinations(base, extra []systemAlertDestination) []systemAlertDestination {
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]systemAlertDestination, 0, len(base)+len(extra))
	for _, list := range [][]systemAlertDestination{base, extra} {
		for _, d := range list {
			if d.URL == "" || seen[d.key()] {
				continue
			}
			seen[d.key()] = true
			out = append(out, d)
		}
	}
	return out
}

// effectiveSystemAlertSeverity 有效分級＝覆寫或登錄的預設。
func effectiveSystemAlertSeverity(tx *gorm.DB, def SystemAlertTypeDef) (string, error) {
	var rows []model.SystemAlertSeverityOverride
	if err := tx.Where("alert_type = ?", string(def.Type)).Limit(1).Find(&rows).Error; err != nil {
		return "", fmt.Errorf("讀取系統告警分級覆寫失敗: %w", err)
	}
	if len(rows) == 1 && ValidSystemAlertSeverity(rows[0].Severity) {
		return rows[0].Severity, nil
	}
	return def.DefaultSeverity, nil
}

// sanitizeSystemAlertParams 經出站通知規格驗證並淨化參數（opaque 值去格式限長），
// 回傳只含宣告參數的 map；落地與出站用同一份淨化後的值。
func sanitizeSystemAlertParams(ev port.SystemAlertEvent, severity string) (map[string]string, error) {
	event, ok := notifycat.SystemAlertEvent(string(ev.Type))
	if !ok {
		return nil, fmt.Errorf("系統告警 %s 沒有對應的出站通知事件", ev.Type)
	}
	in := make(map[string]string, len(ev.Params)+2)
	for k, v := range ev.Params {
		in[k] = v
	}
	in["actor"] = ev.Actor.Username
	in["severity"] = severity
	clean, err := notifycat.Validate(event, in)
	if err != nil {
		return nil, fmt.Errorf("系統告警 %s 參數未通過出站規格: %w", ev.Type, err)
	}
	// 操作者名留在明細參數內（告警列只存使用者編號），投遞時由投遞程序拆出為 actor 欄；
	// 分級已在告警列上，不重複存。
	delete(clean, "severity")
	return clean, nil
}

func truncateRunes(s string, max int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}
