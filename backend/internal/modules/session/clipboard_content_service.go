package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

// 單筆剪貼簿內容調閱。
//
// 讀取面兩條、粒度不同的留痕並存：List（既有端點）回事實投影、中介層記
// 頁面級留痕；本服務解密單筆並**逐筆留痕**（操作者、會話、事件識別），
// 滿足 audit-workflows spec 的既有粒度要求。
//
// **fail-close：留痕成功是回內容的前置條件**——審計寫入不可用即拒絕、
// 不交付明文。此處不沿 timeline 讀取審計的不阻斷慣例（那是查列表，
// 這是解密機密，層級不同）。失敗經既有審計失敗告警鏈揭露。

// ErrClipboardEventNotFound 事件不存在**或**不屬於指定會話（收斂，不區分）。
var ErrClipboardEventNotFound = errors.New("剪貼簿記錄不存在或不屬於該會話")

// clipboardAuditFailureReporter 審計失敗告警鏈的消費者側窄介面
// （由 audit.AuditFailureService 滿足；組裝根注入）。
type clipboardAuditFailureReporter interface {
	Report(mechanism, causeCode string, params map[string]string)
}

// ClipboardReadOperator 調閱操作者與請求中繼資料（逐筆留痕欄位來源）。
type ClipboardReadOperator struct {
	UserID    uint
	Username  string
	ClientIP  string
	RequestID string
	Path      string
}

// ClipboardContentView 單筆調閱結果。Content 僅於
// Event.ContentStatus == model.ClipboardContentAvailable 時有值；
// 缺口紀錄（failed）只回事實，內容欄由呈現端缺席處理（不以空字串冒充）。
type ClipboardContentView struct {
	Event   model.ClipboardEvent
	Content string
}

// ClipboardContentService 單筆剪貼簿內容的解密與逐筆留痕。
type ClipboardContentService struct {
	db       *gorm.DB
	codec    crypto.ColumnCodec
	auditTx  port.TxSink
	failures clipboardAuditFailureReporter
}

// NewClipboardContentService 建立服務。auditTx 為 nil 時 port.WriteInTx 回
// ErrTxSinkMissing——fail-close 語義原樣生效（拒絕交付），不靜默略過。
func NewClipboardContentService(db *gorm.DB, codec crypto.ColumnCodec, auditTx port.TxSink,
	failures clipboardAuditFailureReporter) *ClipboardContentService {
	return &ClipboardContentService{db: db, codec: codec, auditTx: auditTx, failures: failures}
}

// ReadContent 解密單筆剪貼簿內容並逐筆留痕。
//
// 事件識別與會話歸屬以**單一受權查詢**同時約束：eventID 不屬
// sessionID 者與「不存在」收斂為同一拒絕，不洩存在性細節，也不產生歸屬
// 錯誤的審計紀錄（審計欄位一律取自查得的真實紀錄）。
func (s *ClipboardContentService) ReadContent(ctx context.Context, sessionID, eventID uint,
	op ClipboardReadOperator) (*ClipboardContentView, error) {
	var ev model.ClipboardEvent
	if err := s.db.Where("id = ? AND session_id = ?", eventID, sessionID).First(&ev).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrClipboardEventNotFound
		}
		return nil, fmt.Errorf("查詢剪貼簿記錄失敗: %w", err)
	}

	content := ""
	if ev.ContentStatus == model.ClipboardContentAvailable {
		plain, err := s.codec.DecryptFor(ctx, keyvault.RefClipboardContent, ev.ContentEnc)
		if err != nil {
			return nil, fmt.Errorf("解密剪貼簿內容失敗: %w", err)
		}
		content = plain
	}

	// 資產主體鍵（audit_logs.asset_id，納入原則）：剪貼簿事件不帶資產欄，
	// 經所屬會話解析——缺這一鍵，「這台資產的剪貼簿內容被誰調閱過」在資產
	// 樞紐上與「沒有人調閱過」不可分辨。解析失敗即拒絕：主體鍵是本留痕的
	// 完整性要件，不做「查不到就留空」的靜默降級
	var sessionSubject struct{ AssetID *uint }
	if err := s.db.Model(&model.Session{}).Select("asset_id").
		Where("id = ?", ev.SessionID).Take(&sessionSubject).Error; err != nil {
		return nil, fmt.Errorf("解析剪貼簿事件的資產主體失敗: %w", err)
	}

	// 逐筆留痕（伺服器端，前端上報可被繞過）。語義＝「伺服器端已解密並交付
	// 回應」（缺口紀錄則為交付事實與缺口狀態），不宣稱無法保證的客戶端收件。
	// resource_id 沿 ResourceClipboardEvent 的範圍鍵慣例（連線 id），
	// 事件識別走 details.event_id
	details, err := json.Marshal(map[string]string{
		"session_id":     strconv.FormatUint(uint64(ev.SessionID), 10),
		"event_id":       strconv.FormatUint(uint64(ev.ID), 10),
		"direction":      ev.Direction,
		"content_status": ev.ContentStatus,
		"content_length": strconv.Itoa(ev.ContentLength),
	})
	if err != nil {
		return nil, fmt.Errorf("組裝調閱審計欄位失敗: %w", err)
	}
	sessionRef := ev.SessionID
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
			Action:     string(model.ActionRead),
			Resource:   string(model.ResourceClipboardEvent),
			ResourceID: &sessionRef,
			AssetID:    sessionSubject.AssetID,
			Status:     string(model.StatusSuccess),
			Actor:      gatewayapi.Actor{UserID: op.UserID, Username: op.Username},
			Request: gatewayapi.RequestMeta{
				Method: "GET", Path: op.Path,
				ClientIP: op.ClientIP, RequestID: op.RequestID, StatusCode: 200,
			},
			Details: string(details),
		})
	}); err != nil {
		// fail-close：留痕不成即不交付。拒絕對外收斂（原因只進 log 與告警鏈），
		// 審計機制失效本身經既有告警鏈揭露（PCI 10.7.2）
		if s.failures != nil {
			s.failures.Report(model.MechanismAuditWrite, model.CauseAuditWriteSyncRefused,
				map[string]string{"detail": err.Error(), "surface": "clipboard_content"})
		}
		return nil, fmt.Errorf("調閱留痕失敗，拒絕交付內容: %w", err)
	}
	return &ClipboardContentView{Event: ev, Content: content}, nil
}
