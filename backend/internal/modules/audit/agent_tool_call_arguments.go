package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
	"github.com/custodexa/backend/pkg/gatewayapi"
	"gorm.io/gorm"
)

var ErrToolCallArgumentsNotFound = errors.New("tool call arguments unavailable")

type ToolCallArgumentsOperator struct {
	Actor   gatewayapi.Actor
	Request gatewayapi.RequestMeta
	Reason  string
}

type ToolCallArgumentsView struct {
	ID              uint            `json:"id"`
	SessionID       *uint           `json:"session_id"`
	AccessRequestID *uint           `json:"access_request_id"`
	Arguments       json.RawMessage `json:"arguments"`
	AssetID         *uint           `json:"-"`
}

// ToolCallArgumentsService commits the mandatory audit before decrypting.
type ToolCallArgumentsService struct {
	db       *gorm.DB
	codec    crypto.ColumnCodec
	auditTx  port.TxSink
	failures sensitiveRevealFailures
}

func NewToolCallArgumentsService(db *gorm.DB, codec crypto.ColumnCodec, sink port.TxSink, failures sensitiveRevealFailures) *ToolCallArgumentsService {
	return &ToolCallArgumentsService{db: db, codec: codec, auditTx: sink, failures: failures}
}

func (s *ToolCallArgumentsService) ReadArguments(ctx context.Context, id uint, op ToolCallArgumentsOperator) (*ToolCallArgumentsView, error) {
	var row model.AgentToolCall
	if err := s.db.WithContext(ctx).First(&row, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrToolCallArgumentsNotFound
		}
		return nil, fmt.Errorf("query tool call arguments: %w", err)
	}
	if len(row.ArgsSealed) == 0 {
		return nil, ErrToolCallArgumentsNotFound
	}
	view := &ToolCallArgumentsView{ID: row.ID, SessionID: row.SessionID, AccessRequestID: row.AccessRequestID}
	if row.SessionID != nil {
		var subject struct{ AssetID *uint }
		if err := s.db.WithContext(ctx).Model(&model.Session{}).Select("asset_id").Where("id = ?", *row.SessionID).Take(&subject).Error; err != nil {
			return nil, fmt.Errorf("resolve tool call subject: %w", err)
		}
		view.AssetID = subject.AssetID
	}
	details, _ := json.Marshal(map[string]any{"tool_call_id": row.ID, "session_id": row.SessionID, "access_request_id": row.AccessRequestID, "reason": op.Reason})
	request := op.Request
	request.StatusCode = http.StatusOK
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return port.WriteInTx(s.auditTx, tx, port.AuditEvent{
			Action: string(model.ActionAgentToolCallArgsViewed), Resource: string(model.ResourceAgentToolCall),
			ResourceID: &row.ID, AssetID: view.AssetID, Status: string(model.StatusSuccess),
			Actor: op.Actor, Request: request, Details: string(details),
		})
	}); err != nil {
		if s.failures != nil {
			s.failures.Report(model.MechanismAuditWrite, model.CauseAuditWriteSyncRefused, map[string]string{"detail": err.Error(), "surface": "agent_tool_call_arguments"})
		}
		return nil, fmt.Errorf("tool call arguments audit refused: %w", err)
	}
	if s.codec == nil {
		return nil, errors.New("tool call arguments codec unavailable")
	}
	plain, err := s.codec.DecryptFor(ctx, keyvault.RefAgentToolCallArgs, string(row.ArgsSealed))
	if err != nil {
		return nil, fmt.Errorf("decrypt tool call arguments: %w", err)
	}
	// Stored arguments must be a JSON object; never emit an invalid raw response.
	var args map[string]json.RawMessage
	if err := json.Unmarshal([]byte(plain), &args); err != nil || args == nil {
		return nil, errors.New("invalid tool call arguments payload")
	}
	view.Arguments = json.RawMessage(plain)
	return view, nil
}
