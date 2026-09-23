package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// AgentToolCallInput is assembled from authenticated server context, never bound from a request body.
type AgentToolCallInput struct {
	PrincipalKind                                string
	UserID, AgentTokenID, OwnerUserID            uint
	AccessRequestID, SessionID, OnBehalfOfUserID *uint
	Tool                                         string
	Args                                         map[string]interface{}
}

type AgentToolCallLedger struct {
	db        *gorm.DB
	integrity *AuditIntegrityService
}

func NewAgentToolCallLedger(db *gorm.DB, integrity *AuditIntegrityService) *AgentToolCallLedger {
	return &AgentToolCallLedger{db: db, integrity: integrity}
}

// Begin commits the pending evidence before its caller may forward any operation.
// The sequence is serialized in PostgreSQL, and a UNIQUE index is the final concurrency guard.
func (s *AgentToolCallLedger) Begin(ctx context.Context, in AgentToolCallInput) (*model.AgentToolCall, error) {
	if in.PrincipalKind != model.KindAgent || s.integrity == nil {
		return nil, errors.New("authenticated agent and integrity service required")
	}
	args, err := json.Marshal(MaskSensitiveFields("", in.Args))
	if err != nil {
		return nil, err
	}
	var row model.AgentToolCall
	for attempt := 0; attempt < 20; attempt++ {
		row = model.AgentToolCall{UserID: in.UserID, AgentTokenID: in.AgentTokenID, OwnerUserID: in.OwnerUserID,
			AccessRequestID: in.AccessRequestID, SessionID: in.SessionID, OnBehalfOfUserID: in.OnBehalfOfUserID,
			Tool: in.Tool, ArgsRedacted: string(args), Decision: model.ToolCallPending}
		err = s.db.WithContext(model.WithToolCallStamp(ctx, s.integrity.StampToolCall)).Transaction(func(tx *gorm.DB) error {
			if tx.Dialector.Name() == "postgres" {
				if e := tx.Exec("SELECT pg_advisory_xact_lock(hashtextextended('agent_tool_seq:' || CAST(? AS text), 0))", strconv.FormatUint(uint64(in.UserID), 10)).Error; e != nil {
					return e
				}
			}
			var max uint
			if e := tx.Model(&model.AgentToolCall{}).Where("user_id = ?", in.UserID).Select("COALESCE(MAX(seq),0)").Scan(&max).Error; e != nil {
				return e
			}
			row.Seq = max + 1
			return tx.Create(&row).Error
		})
		if err == nil {
			return &row, nil
		}
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "locked") && !strings.Contains(msg, "busy") && !strings.Contains(msg, "unique") {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * time.Millisecond):
		}
	}
	return nil, err
}

type AgentToolCallFilter struct {
	AccessRequestID, UserID, SessionID *uint
	From, To                           *time.Time
	Decision                           string
	Offset, Limit                      int
}

func (s *AgentToolCallLedger) Query(ctx context.Context, f AgentToolCallFilter) ([]model.AgentToolCall, int64, error) {
	q := s.db.WithContext(ctx).Model(&model.AgentToolCall{})
	if f.AccessRequestID != nil {
		q = q.Where("access_request_id = ?", *f.AccessRequestID)
	}
	if f.SessionID != nil {
		q = q.Where("session_id = ?", *f.SessionID)
	}
	if f.UserID != nil {
		q = q.Where("user_id = ?", *f.UserID)
	}
	if f.From != nil {
		q = q.Where("created_at >= ?", *f.From)
	}
	if f.To != nil {
		q = q.Where("created_at < ?", *f.To)
	}
	if f.Decision != "" {
		q = q.Where("decision = ?", f.Decision)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	var n int64
	if err := q.Count(&n).Error; err != nil {
		return nil, 0, err
	}
	rows := []model.AgentToolCall{}
	if err := q.Order("id DESC").Offset(f.Offset).Limit(f.Limit).Find(&rows).Error; err != nil {
		return nil, 0, err
	}
	if err := s.fillToolCallTargets(ctx, rows); err != nil {
		return nil, 0, err
	}
	return rows, n, nil
}

// fillToolCallTargets projects the session's target asset and account onto each row in one
// query. The ledger stores only session_id; a call made outside a session has no target and
// keeps both fields empty rather than borrowing one from elsewhere.
func (s *AgentToolCallLedger) fillToolCallTargets(ctx context.Context, rows []model.AgentToolCall) error {
	ids := make([]uint, 0, len(rows))
	seen := map[uint]bool{}
	for i := range rows {
		id := rows[i].SessionID
		if id == nil || *id == 0 || seen[*id] {
			continue
		}
		seen[*id] = true
		ids = append(ids, *id)
	}
	if len(ids) == 0 {
		return nil
	}
	type target struct {
		ID              uint
		AssetName       string
		AccountUsername string
	}
	targets := []target{}
	if err := s.db.WithContext(ctx).Table("sessions s").
		Select("s.id AS id, COALESCE(a.name, '') AS asset_name, COALESCE(s.account_username, '') AS account_username").
		Joins("LEFT JOIN assets a ON a.id = s.asset_id").
		Where("s.id IN ?", ids).Scan(&targets).Error; err != nil {
		return err
	}
	byID := make(map[uint]target, len(targets))
	for _, t := range targets {
		byID[t.ID] = t
	}
	for i := range rows {
		if rows[i].SessionID == nil {
			continue
		}
		if t, ok := byID[*rows[i].SessionID]; ok {
			rows[i].AssetName, rows[i].AccountUsername = t.AssetName, t.AccountUsername
		}
	}
	return nil
}

// RedactedOutput must be exactly the caller-visible, already-redacted output.
// There is deliberately no recovery job: an interrupted call remains pending.
type AgentToolCallResult struct {
	Decision, DenialCode, Status, RedactedOutput string
	DurationMS                                   int64
	MaskedCount                                  int
}

func (s *AgentToolCallLedger) Complete(ctx context.Context, id uint, result AgentToolCallResult) (*model.AgentToolCall, error) {
	if result.Decision == model.ToolCallPending || !utf8.ValidString(result.RedactedOutput) {
		return nil, errors.New("invalid final result")
	}
	var row model.AgentToolCall
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.First(&row, id).Error; err != nil {
			return err
		}
		if row.Decision != model.ToolCallPending || !s.integrity.VerifyToolCall(&row) {
			return errors.New("ledger is not a valid pending row")
		}
		prior := row.IntegrityHMAC
		row.Decision, row.DenialCode, row.ResultStatus = result.Decision, result.DenialCode, result.Status
		sum := sha256.Sum256([]byte(result.RedactedOutput))
		row.ResultDigest = hex.EncodeToString(sum[:])
		excerpt := result.RedactedOutput
		if len(excerpt) > model.ToolCallExcerptBytes {
			excerpt = excerpt[:model.ToolCallExcerptBytes]
			for !utf8.ValidString(excerpt) {
				excerpt = excerpt[:len(excerpt)-1]
			}
		}
		row.ResultExcerpt, row.DurationMS, row.MaskedCount = excerpt, result.DurationMS, result.MaskedCount
		if err := row.Validate(); err != nil {
			return err
		}
		if err := s.integrity.restampToolCall(&row); err != nil {
			return err
		}
		update := tx.WithContext(model.WithToolCallCompletion(ctx)).Model(&model.AgentToolCall{}).
			Where("id = ? AND decision = ? AND integrity_hmac = ?", id, model.ToolCallPending, prior).
			Updates(map[string]interface{}{"decision": row.Decision, "denial_code": row.DenialCode, "result_status": row.ResultStatus,
				"result_digest": row.ResultDigest, "result_excerpt": row.ResultExcerpt, "duration_ms": row.DurationMS, "masked_count": row.MaskedCount, "integrity_hmac": row.IntegrityHMAC})
		if update.Error != nil {
			return update.Error
		}
		if update.RowsAffected != 1 {
			return errors.New("ledger result already changed")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}
