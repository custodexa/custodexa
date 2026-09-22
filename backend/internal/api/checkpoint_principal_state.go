package api

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
)

type principalStateView struct {
	Covered      bool                `json:"covered"`
	State        string              `json:"state"`
	SinceSeq     uint                `json:"since_seq,omitempty"`
	ExpectedHash string              `json:"expected_hash,omitempty"`
	ActualHash   string              `json:"actual_hash,omitempty"`
	Missing      []uint64            `json:"missing,omitempty"`
	Extra        []uint64            `json:"extra,omitempty"`
	LastEvent    *roleStateEventView `json:"last_event,omitempty"`
}
type stateTableEventSource interface {
	LatestByStateTable(string) (*model.AuditFailureEvent, error)
}

func projectPrincipalState(reports []audit.StateTableReport, table string, lookup roleStateNameLookup) *principalStateView {
	for _, report := range reports {
		if report.Table != table {
			continue
		}
		view := &principalStateView{Covered: report.Covered, State: report.State, SinceSeq: report.SinceSeq, ExpectedHash: report.ExpectedHash, ActualHash: report.ActualHash}
		ids := func(rows []string) []uint64 {
			out := []uint64{}
			for _, row := range rows {
				var fields []json.RawMessage
				if json.Unmarshal([]byte(row), &fields) == nil && len(fields) > 0 {
					var id uint64
					if json.Unmarshal(fields[0], &id) == nil {
						out = append(out, id)
					}
				}
			}
			return out
		}
		view.Missing = ids(report.Missing)
		view.Extra = ids(report.Extra)
		if report.State == audit.RoleStateMismatch {
			if names, ok := lookup.(*roleStateLookup); ok {
				if events, ok := names.events.(stateTableEventSource); ok {
					if ev, err := events.LatestByStateTable(table); err == nil && ev != nil {
						view.LastEvent = &roleStateEventView{ID: ev.ID, Mechanism: ev.Mechanism, CauseCode: ev.CauseCode, StartedAt: ev.StartedAt, EndedAt: ev.EndedAt}
					}
				}
			}
		}
		return view
	}
	return nil
}
