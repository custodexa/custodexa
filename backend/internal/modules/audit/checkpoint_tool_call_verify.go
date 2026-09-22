package audit

import (
	"fmt"
	"gorm.io/gorm"
	"time"

	"github.com/custodexa/backend/internal/model"
)

func (s *CheckpointService) AggregateToolCalls(from, to uint) (string, int64, error) {
	return aggregateToolCalls(s.db, from, to)
}

func aggregateToolCalls(db *gorm.DB, from, to uint) (string, int64, error) {
	w := newToolCallAggWriter()
	if from > to {
		return w.Sum()
	}
	rows, err := db.Model(&model.AgentToolCall{}).Select("id,seq,user_id,agent_token_id,access_request_id,session_id,on_behalf_of_user_id,owner_user_id,tool,args_redacted,created_at,key_version").Where("id >= ? AND id <= ?", from, to).Order("id").Rows()
	if err != nil {
		return "", 0, fmt.Errorf("ledger aggregate read: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e model.AgentToolCall
		if err := db.ScanRows(rows, &e); err != nil {
			return "", 0, err
		}
		w.Add(e)
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	return w.Sum()
}

type ToolCallIntervalResult struct {
	IDFrom         uint   `json:"id_from"`
	IDTo           uint   `json:"id_to"`
	RowCount       int64  `json:"row_count"`
	RemainRows     int64  `json:"remain_rows"`
	Status         string `json:"status"`
	Detail         string `json:"detail,omitempty"`
	InvalidHMACIDs []uint `json:"invalid_hmac_ids,omitempty"`
}

func (v *CheckpointVerifier) verifyToolCallInterval(cp *model.AuditCheckpoint) (*ToolCallIntervalResult, error) {
	if cp.AggScheme != model.AggSchemeV3 {
		return &ToolCallIntervalResult{Status: "not_covered"}, nil
	}
	r := &ToolCallIntervalResult{IDFrom: *cp.ToolCallIDFrom, IDTo: *cp.ToolCallIDTo, RowCount: *cp.ToolCallRowCount, Status: IntervalStatusPassed}
	h, n, err := v.seal.AggregateToolCalls(r.IDFrom, r.IDTo)
	if err != nil {
		return nil, err
	}
	r.RemainRows = n
	if n != r.RowCount {
		r.Status = IntervalStatusCountMismatch
		r.Detail = "agent_tool_calls row count differs from signed interval"
		return r, nil
	}
	if h != *cp.ToolCallAggHash {
		r.Status = IntervalStatusHashMismatch
		r.Detail = "agent_tool_calls aggregate differs from signed interval"
		return r, nil
	}
	// An empty, matching interval has no row stamps to verify.
	if n == 0 {
		return r, nil
	}
	if v.integrity == nil {
		return nil, fmt.Errorf("ledger row integrity unavailable")
	}
	rows, err := v.integrity.verifyToolCallQuery(v.db.Where("id >= ? AND id <= ?", r.IDFrom, r.IDTo), time.Time{}, time.Time{})
	if err != nil {
		return nil, err
	}
	if rows.Checked != n {
		r.Status = IntervalStatusCountMismatch
		r.Detail = "agent_tool_calls row count changed during verification"
		return r, nil
	}
	if rows.Mismatched > 0 {
		r.Status = "row_hmac_mismatch"
		r.Detail = "agent_tool_calls row content stamp invalid"
		r.InvalidHMACIDs = rows.MismatchedIDs
	}
	return r, nil
}
