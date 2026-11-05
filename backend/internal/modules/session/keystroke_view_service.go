package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/reader"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/internal/seal"
	"github.com/custodexa/backend/pkg/gatewayapi"
)

// 鍵盤紀錄的中繼資料與帶理由查看。
//
// 中繼資料不解密；查看是調查動作：解密前於交易內同步寫「查看嘗試」審計（fail-close），
// 之後才解封檔案金鑰與讀檔。明文按鍵只存在於回傳值，不進 log、錯誤訊息或審計欄位。

// 查看狀態值（中繼資料 state 欄）。紀錄列存在時沿用該列 status。
const (
	KeystrokeStatePreFeature    = "pre_feature"
	KeystrokeStateRecordMissing = "record_missing"
)

// KeystrokeMaxPage 查看一頁的事件數上限。
const KeystrokeMaxPage = 5000

var (
	// ErrKeystrokeNotViewable 沒有可查看的內容；State 為當下判定的狀態。
	ErrKeystrokeNotViewable = errors.New("keystroke: not viewable")
	// ErrKeystrokeVaultSealed 平台金鑰材料未解封。
	ErrKeystrokeVaultSealed = errors.New("keystroke: vault sealed")
	// ErrKeystrokeRecordRejected 標頭與資料庫不符或路徑越界。
	ErrKeystrokeRecordRejected = errors.New("keystroke: record rejected")
	// ErrKeystrokeAuditUnavailable 查看嘗試留痕失敗，不交付內容。
	ErrKeystrokeAuditUnavailable = errors.New("keystroke: audit unavailable")
)

// KeystrokeNotViewableError 帶狀態的不可查看錯誤。
type KeystrokeNotViewableError struct{ State string }

func (e *KeystrokeNotViewableError) Error() string {
	return ErrKeystrokeNotViewable.Error() + ": " + e.State
}
func (e *KeystrokeNotViewableError) Unwrap() error { return ErrKeystrokeNotViewable }

// KeystrokeMeta 中繼資料回應（不含任何內容）。
type KeystrokeMeta struct {
	State          string     `json:"state"`
	Viewable       bool       `json:"viewable"`
	FeatureSince   *time.Time `json:"feature_since,omitempty"`
	CoverageReason string     `json:"coverage_reason,omitempty"`
	FailureCause   string     `json:"failure_cause,omitempty"`
	Protocol       string     `json:"protocol,omitempty"`
	EventCount     *int64     `json:"event_count,omitempty"`
	ByteSize       *int64     `json:"byte_size,omitempty"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	LastWriteAt    *time.Time `json:"last_write_at,omitempty"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
	PurgedAt       *time.Time `json:"purged_at,omitempty"`
}

// KeystrokeViewOperator 查看者與請求中繼資料。
type KeystrokeViewOperator struct {
	UserID    uint
	Username  string
	ClientIP  string
	RequestID string
	Path      string
}

// KeystrokeViewRequest 查看請求（理由已由呼叫端驗證）。
type KeystrokeViewRequest struct {
	Reason    string
	FromEvent int
	Limit     int
}

// KeystrokeViewEvent 一筆事件。Kind 為事件種類；位元組流與未知種類帶 DataB64，標記帶 Marker。
type KeystrokeViewEvent struct {
	Seq     int    `json:"seq"`
	TMs     uint64 `json:"t_ms"`
	At      string `json:"at"`
	Kind    byte   `json:"kind"`
	Source  string `json:"source"`
	Blocked bool   `json:"blocked"`
	DataB64 string `json:"data_b64,omitempty"`
	Marker  string `json:"marker,omitempty"`
}

// KeystrokeView 查看結果。
type KeystrokeView struct {
	Events          []KeystrokeViewEvent
	NextEvent       *int
	Integrity       string
	LastEventMs     uint64
	FailedSegment   *int
	RecordStatus    string
	RecordID        uint
	SessionID       uint
	AssetID         *uint
	AccessRequestID *uint
}

// KeystrokeViewService 中繼資料判定與帶理由查看。
type KeystrokeViewService struct {
	db       *gorm.DB
	codec    material.BytesColumnCodec
	root     string
	auditTx  port.TxSink
	failures clipboardAuditFailureReporter
}

// NewKeystrokeViewService 建立服務。auditTx 為 nil 時留痕必然失敗，fail-close 原樣生效。
func NewKeystrokeViewService(db *gorm.DB, codec material.BytesColumnCodec, root string,
	auditTx port.TxSink, failures clipboardAuditFailureReporter) *KeystrokeViewService {
	return &KeystrokeViewService{db: db, codec: codec, root: root, auditTx: auditTx, failures: failures}
}

func (s *KeystrokeViewService) loadSession(sessionID uint) (*model.Session, error) {
	var sess model.Session
	if err := s.db.Select("id", "start_time", "asset_id", "access_request_id").
		Where("id = ?", sessionID).Take(&sess).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("查詢連線失敗: %w", err)
	}
	return &sess, nil
}

func (s *KeystrokeViewService) loadRecord(sessionID uint) (*model.KeystrokeRecord, error) {
	var rec model.KeystrokeRecord
	err := s.db.Where("session_id = ?", sessionID).Take(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查詢鍵盤紀錄失敗: %w", err)
	}
	return &rec, nil
}

// featureSince 鍵盤紀錄上線時間（migration 的 applied_at）；查不到回 nil。
func (s *KeystrokeViewService) featureSince() (*time.Time, error) {
	var row database.SchemaMigration
	err := s.db.Where("version = ?", database.KeystrokeFeatureMigrationVersion).Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("查詢鍵盤紀錄上線時間失敗: %w", err)
	}
	t := row.AppliedAt
	return &t, nil
}

// recordViewable 紀錄列是否有可查看的內容：必須有檔案路徑與封存金鑰，且未清除、非不產生。
func recordViewable(rec *model.KeystrokeRecord) bool {
	if rec == nil || rec.FilePath == "" || rec.FileKeyEnc == "" {
		return false
	}
	switch rec.Status {
	case model.KeystrokeStatusRecording, model.KeystrokeStatusComplete,
		model.KeystrokeStatusIncomplete, model.KeystrokeStatusFailed:
		return true
	}
	return false
}

func metaOf(sess *model.Session, rec *model.KeystrokeRecord, since *time.Time) KeystrokeMeta {
	if rec == nil {
		if since != nil && sess.StartTime.Before(*since) {
			return KeystrokeMeta{State: KeystrokeStatePreFeature, FeatureSince: since}
		}
		return KeystrokeMeta{State: KeystrokeStateRecordMissing}
	}
	m := KeystrokeMeta{State: rec.Status, Viewable: recordViewable(rec), Protocol: rec.Protocol}
	switch rec.Status {
	case model.KeystrokeStatusNotCovered:
		m.CoverageReason = rec.CoverageReason
		return m
	case model.KeystrokeStatusFailed:
		m.FailureCause = rec.FailureCause
	}
	ev, bs, st := rec.EventCount, rec.ByteSize, rec.StartedAt
	m.EventCount, m.ByteSize, m.StartedAt = &ev, &bs, &st
	m.LastWriteAt, m.EndedAt, m.PurgedAt = rec.LastWriteAt, rec.EndedAt, rec.PurgedAt
	return m
}

// Meta 回傳會話層級的中繼資料；會話不存在回 ErrSessionNotFound。不解密。
func (s *KeystrokeViewService) Meta(sessionID uint) (*KeystrokeMeta, error) {
	sess, err := s.loadSession(sessionID)
	if err != nil {
		return nil, err
	}
	rec, err := s.loadRecord(sessionID)
	if err != nil {
		return nil, err
	}
	var since *time.Time
	if rec == nil {
		if since, err = s.featureSince(); err != nil {
			return nil, err
		}
	}
	m := metaOf(sess, rec, since)
	return &m, nil
}

// View 帶理由查看。順序固定：判定可查看 → 解析資產主體 → 交易內同步留痕 → 解封 → 讀取。
func (s *KeystrokeViewService) View(ctx context.Context, sessionID uint, req KeystrokeViewRequest,
	op KeystrokeViewOperator) (*KeystrokeView, error) {
	sess, err := s.loadSession(sessionID)
	if err != nil {
		return nil, err
	}
	rec, err := s.loadRecord(sessionID)
	if err != nil {
		return nil, err
	}
	if !recordViewable(rec) {
		var since *time.Time
		if rec == nil {
			if since, err = s.featureSince(); err != nil {
				return nil, err
			}
		}
		return nil, &KeystrokeNotViewableError{State: metaOf(sess, rec, since).State}
	}

	limit := req.Limit
	if limit <= 0 || limit > KeystrokeMaxPage {
		limit = KeystrokeMaxPage
	}
	from := req.FromEvent
	if from < 0 {
		from = 0
	}

	// 留痕：理由與範圍只進審計本文欄位，不含任何內容
	details, err := json.Marshal(map[string]string{
		"session_id":    strconv.FormatUint(uint64(sess.ID), 10),
		"reason":        req.Reason,
		"from_event":    strconv.Itoa(from),
		"limit":         strconv.Itoa(limit),
		"record_status": rec.Status,
		"phase":         "attempt",
		"outcome":       "see_request_row",
	})
	if err != nil {
		return nil, fmt.Errorf("組裝查看稽核欄位失敗: %w", err)
	}
	sessionRef := sess.ID
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
			Action:     string(model.ActionRead),
			Resource:   string(model.ResourceKeystrokeRecord),
			ResourceID: &sessionRef,
			AssetID:    sess.AssetID,
			Status:     string(model.StatusSuccess),
			Actor:      gatewayapi.Actor{UserID: op.UserID, Username: op.Username},
			Request: gatewayapi.RequestMeta{
				Method: "POST", Path: op.Path,
				ClientIP: op.ClientIP, RequestID: op.RequestID, StatusCode: 200,
			},
			Details: string(details),
		})
	}); err != nil {
		if s.failures != nil {
			s.failures.Report(model.MechanismAuditWrite, model.CauseAuditWriteSyncRefused,
				map[string]string{"detail": err.Error(), "surface": "keystroke_view"})
		}
		return nil, fmt.Errorf("%w: %v", ErrKeystrokeAuditUnavailable, err)
	}

	if s.codec == nil {
		return nil, ErrKeystrokeVaultSealed
	}
	secret, err := s.codec.DecryptBytesFor(ctx, keyvault.RefKeystrokeFileKey, rec.FileKeyEnc)
	if err != nil {
		if errors.Is(err, seal.ErrMaterialSealed) {
			return nil, ErrKeystrokeVaultSealed
		}
		return nil, fmt.Errorf("解封鍵盤紀錄檔案金鑰失敗: %w", err)
	}
	defer secret.Destroy()

	var res reader.Result
	if err := secret.Borrow(func(fek []byte) error {
		res = reader.Read(s.root, reader.Record{
			UUID: rec.RecordUUID, SessionID: uint64(rec.SessionID),
			Protocol: rec.Protocol, FilePath: rec.FilePath,
			ExpectComplete: rec.Status == model.KeystrokeStatusComplete, SegmentCount: rec.SegmentCount,
		}, fek, reader.Options{FromEvent: from, Limit: limit})
		return nil
	}); err != nil {
		return nil, fmt.Errorf("讀取鍵盤紀錄失敗: %w", err)
	}
	if res.Status == reader.StatusHeaderMismatch || res.Status == reader.StatusPathRejected {
		return nil, ErrKeystrokeRecordRejected
	}

	view := &KeystrokeView{
		Integrity: string(res.Status), LastEventMs: res.LastDeltaMs, RecordStatus: rec.Status,
		RecordID: rec.ID, SessionID: sess.ID, AssetID: sess.AssetID, AccessRequestID: sess.AccessRequestID,
		Events: make([]KeystrokeViewEvent, 0, len(res.Events)),
	}
	if res.FailedSegment >= 0 {
		fs := res.FailedSegment
		view.FailedSegment = &fs
	}
	start := time.Unix(0, res.Header.StartUnixNs).UTC()
	for i, ev := range res.Events {
		view.Events = append(view.Events, eventView(from+i, start, ev))
	}
	if next := from + len(res.Events); len(res.Events) > 0 && next < res.TotalEvents {
		view.NextEvent = &next
	}
	return view, nil
}

func eventView(seq int, start time.Time, ev format.Event) KeystrokeViewEvent {
	out := KeystrokeViewEvent{
		Seq: seq, TMs: ev.DeltaMs, Kind: ev.Kind, Source: "user",
		At:      start.Add(time.Duration(ev.DeltaMs) * time.Millisecond).Format(time.RFC3339Nano),
		Blocked: ev.Flags&format.FlagBlocked != 0,
	}
	if ev.Flags&format.FlagPlatform != 0 {
		out.Source = "platform"
	}
	if ev.Kind == format.KindMarker {
		out.Marker = string(ev.Payload)
		return out
	}
	out.DataB64 = base64.StdEncoding.EncodeToString(ev.Payload)
	return out
}
