package model

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"gorm.io/gorm"
)

const (
	ToolCallPending      = "pending"
	ToolCallAllowed      = "allowed"
	ToolCallDenied       = "denied"
	ToolCallBreaker      = "breaker"
	ToolCallRateLimited  = "rate_limited"
	ToolCallExcerptBytes = 2048
)

// AgentToolCall retains the caller's redacted view, not the host's original output.
type AgentToolCall struct {
	// Target of the call's session, projected on read: the ledger stores only session_id, and a
	// call made outside a session has no target. Never part of the integrity payload.
	AssetName       string `gorm:"-" json:"asset_name,omitempty"`
	AccountUsername string `gorm:"-" json:"account_username,omitempty"`

	ID               uint      `gorm:"primarykey" json:"id"`
	Seq              uint      `gorm:"not null;uniqueIndex:idx_agent_tool_calls_user_seq,priority:2" json:"seq"`
	UserID           uint      `gorm:"not null;uniqueIndex:idx_agent_tool_calls_user_seq,priority:1" json:"user_id"`
	AgentTokenID     uint      `gorm:"not null" json:"agent_token_id"`
	AccessRequestID  *uint     `gorm:"index:idx_agent_tool_calls_request" json:"access_request_id"`
	SessionID        *uint     `json:"session_id"`
	OnBehalfOfUserID *uint     `json:"on_behalf_of_user_id"`
	OwnerUserID      uint      `gorm:"not null" json:"owner_user_id"`
	Tool             string    `gorm:"size:64;not null" json:"tool"`
	ArgsRedacted     string    `gorm:"type:jsonb;not null" json:"args_redacted"`
	Decision         string    `gorm:"size:16;not null" json:"decision"`
	DenialCode       string    `gorm:"size:100;not null" json:"denial_code"`
	ResultStatus     string    `gorm:"size:32;not null" json:"result_status"`
	ResultDigest     string    `gorm:"size:64;not null" json:"result_digest"`
	ResultExcerpt    string    `gorm:"type:text;not null" json:"result_excerpt"`
	MaskedCount      int       `gorm:"not null" json:"masked_count"`
	DurationMS       int64     `gorm:"not null" json:"duration_ms"`
	CreatedAt        time.Time `gorm:"not null;index:idx_agent_tool_calls_created_at" json:"created_at"`
	IntegrityHMAC    string    `gorm:"size:64;not null" json:"-"`
	KeyVersion       int       `gorm:"not null" json:"-"`
}

func (AgentToolCall) TableName() string { return "agent_tool_calls" }

func (a *AgentToolCall) Validate() error {
	if a.Seq == 0 || a.UserID == 0 || a.AgentTokenID == 0 || a.OwnerUserID == 0 || a.Tool == "" || len(a.Tool) > 64 {
		return errors.New("tool call identity is required")
	}
	if a.AccessRequestID == nil && a.Tool != "list_assets" && a.Tool != "request_access" && a.Tool != "check_request" {
		return errors.New("tool call requires access_request_id")
	}
	if a.AccessRequestID != nil && *a.AccessRequestID == 0 {
		return errors.New("invalid access_request_id")
	}
	switch a.Decision {
	case ToolCallPending, ToolCallAllowed, ToolCallDenied, ToolCallBreaker, ToolCallRateLimited:
	default:
		return errors.New("invalid tool call decision")
	}
	if len(a.ResultExcerpt) > ToolCallExcerptBytes || len(a.ResultDigest) > 64 || len(a.ResultStatus) > 32 || len(a.DenialCode) > 100 || a.MaskedCount < 0 || a.DurationMS < 0 || !json.Valid([]byte(a.ArgsRedacted)) {
		return errors.New("invalid tool call result or arguments")
	}
	return nil
}

var toolCallHook struct {
	sync.RWMutex
	stamp func(*AgentToolCall) error
}

// SetAgentToolCallStampHook installs the same versioned key source used by audit_logs.
func SetAgentToolCallStampHook(stamp func(*AgentToolCall) error) {
	toolCallHook.Lock()
	defer toolCallHook.Unlock()
	toolCallHook.stamp = stamp
}

type toolCallStampKey struct{}

func WithToolCallStamp(ctx context.Context, stamp func(*AgentToolCall) error) context.Context {
	return context.WithValue(ctx, toolCallStampKey{}, stamp)
}

func (a *AgentToolCall) BeforeCreate(tx *gorm.DB) error {
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	}
	if err := a.Validate(); err != nil {
		return err
	}
	if stamp, ok := tx.Statement.Context.Value(toolCallStampKey{}).(func(*AgentToolCall) error); ok {
		return stamp(a)
	}
	toolCallHook.RLock()
	stamp := toolCallHook.stamp
	toolCallHook.RUnlock()
	if stamp == nil {
		return errors.New("tool call integrity is unavailable")
	}
	return stamp(a)
}

// WithToolCallCompletion authorizes only result-column maps, never first-phase edits.
type toolCallCompletionKey struct{}

func WithToolCallCompletion(ctx context.Context) context.Context {
	return context.WithValue(ctx, toolCallCompletionKey{}, true)
}
func (*AgentToolCall) BeforeUpdate(tx *gorm.DB) error {
	if tx.Statement.Context.Value(toolCallCompletionKey{}) != true {
		return gorm.ErrInvalidValue
	}
	fields, ok := tx.Statement.Dest.(map[string]interface{})
	if !ok || len(fields) == 0 {
		return gorm.ErrInvalidValue
	}
	for k := range fields {
		switch k {
		case "decision", "denial_code", "result_status", "result_digest", "result_excerpt", "masked_count", "duration_ms", "integrity_hmac":
		default:
			return gorm.ErrInvalidValue
		}
	}
	return nil
}
func (*AgentToolCall) BeforeDelete(*gorm.DB) error { return gorm.ErrInvalidValue }

// The generated ID becomes known after INSERT; bind it before the create
// transaction commits. Begin always supplies an explicit transaction.
func (a *AgentToolCall) AfterCreate(tx *gorm.DB) error {
	if err := a.BeforeCreate(tx); err != nil {
		return err
	}
	return tx.Exec("UPDATE agent_tool_calls SET integrity_hmac = ? WHERE id = ?", a.IntegrityHMAC, a.ID).Error
}
