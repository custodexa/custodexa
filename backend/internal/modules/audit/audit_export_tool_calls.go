package audit

import (
	"archive/zip"
	"encoding/json"
	"io"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// Explicit SQL projection keeps encrypted arguments out of batch exports.
func (s *AuditExportService) writeToolCalls(zw *zip.Writer, f *ExportFilter, m *ExportManifest) error {
	base := func() *gorm.DB {
		q := s.db.Model(&model.AgentToolCall{}).Select("agent_tool_calls.id, agent_tool_calls.seq, agent_tool_calls.user_id, agent_tool_calls.agent_token_id, agent_tool_calls.access_request_id, agent_tool_calls.session_id, agent_tool_calls.on_behalf_of_user_id, agent_tool_calls.owner_user_id, agent_tool_calls.tool, agent_tool_calls.args_redacted, agent_tool_calls.args_retained, agent_tool_calls.decision, agent_tool_calls.denial_code, agent_tool_calls.result_status, agent_tool_calls.result_digest, agent_tool_calls.result_excerpt, agent_tool_calls.masked_count, agent_tool_calls.duration_ms, agent_tool_calls.created_at")
		if f.SessionID != nil {
			return q.Where("agent_tool_calls.session_id = ?", *f.SessionID)
		}
		if f.UserID != nil {
			q = q.Where("agent_tool_calls.user_id = ?", *f.UserID)
		}
		if f.AssetID != nil {
			q = q.Joins("JOIN sessions ON sessions.id = agent_tool_calls.session_id").Where("sessions.asset_id = ?", *f.AssetID)
		}
		if f.StartTime != nil {
			q = q.Where("agent_tool_calls.created_at >= ?", *f.StartTime)
		}
		if f.EndTime != nil {
			q = q.Where("agent_tool_calls.created_at <= ?", *f.EndTime)
		}
		return q
	}
	var total int64
	if err := base().Count(&total).Error; err != nil {
		return err
	}
	n := 0
	truncated := false
	err := s.writeEntry(zw, "agent_tool_calls.json", m, func(out io.Writer) error {
		if _, err := io.WriteString(out, "[\n"); err != nil {
			return err
		}
		var err error
		n, truncated, err = pageExportN(base, "agent_tool_calls.created_at", "agent_tool_calls.id", maxExportAuditLogs,
			func(row *model.AgentToolCall) (time.Time, uint) { return row.CreatedAt, row.ID },
			func(rows []model.AgentToolCall) error {
				for _, row := range rows {
					if n > 0 {
						if _, err := io.WriteString(out, ",\n"); err != nil {
							return err
						}
					}
					entry := struct {
						model.AgentToolCall
						ArgsRedacted json.RawMessage `json:"args_redacted"`
					}{row, json.RawMessage(row.ArgsRedacted)}
					if err := json.NewEncoder(out).Encode(entry); err != nil {
						return err
					}
					n++
				}
				return nil
			})
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, "]\n")
		return err
	})
	if err != nil {
		return err
	}
	m.Counts["agent_tool_calls"] = n
	m.Truncated["agent_tool_calls"] = truncated
	if m.Totals == nil {
		m.Totals = map[string]int64{}
	}
	m.Totals["agent_tool_calls"] = total
	return nil
}
