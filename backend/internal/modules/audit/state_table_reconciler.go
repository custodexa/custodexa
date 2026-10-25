package audit

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/custodexa/backend/internal/model"
)

const StateTableUnknown = "unknown"

type StateTableReport struct {
	Table        string   `json:"table"`
	Covered      bool     `json:"covered"`
	State        string   `json:"state"`
	SinceSeq     uint     `json:"since_seq,omitempty"`
	ExpectedHash string   `json:"expected_hash,omitempty"`
	ActualHash   string   `json:"actual_hash,omitempty"`
	Missing      []string `json:"missing,omitempty"`
	Extra        []string `json:"extra,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// ReconcileTables always returns an entry for every registered projection,
// including unknown entries. One broken source cannot suppress other results.
func (r *RoleStateReconciler) ReconcileTables(ctx context.Context) []StateTableReport {
	reports, _ := r.reconcileAll(ctx)
	return reports
}

// reconcileAll 同 ReconcileTables，另回傳權限附證維度的結果（未注入來源時為 nil）。
// 權限維度不併入清單：清單的讀者（封章合取、簽發前檢查、既有三列）語意不變。
func (r *RoleStateReconciler) reconcileAll(ctx context.Context) ([]StateTableReport, *PermissionReport) {
	reports := make([]StateTableReport, 0, len(StateTableRegistry()))
	for _, table := range StateTableRegistry() {
		report, err := r.computeTable(ctx, table)
		if err != nil {
			report = StateTableReport{Table: table.Name, State: StateTableUnknown, Error: err.Error()}
		}
		if table.Name == StateTableUserRoles {
			if err == nil {
				r.settle(roleReport(report))
			}
		} else {
			r.settleTable(report)
		}
		reports = append(reports, report)
	}
	// 權限附證維度：沿既有失效事件通道回報，但不併入回傳清單（既有三列呈現與基礎對帳合取不變）
	if PermissionSourcesWired() {
		rep := r.ReconcilePermission(ctx)
		return reports, &rep
	}
	return reports, nil
}
func roleReport(report StateTableReport) *RoleStateReport {
	out := &RoleStateReport{Covered: report.Covered, State: report.State, SinceSeq: report.SinceSeq, ExpectedHash: report.ExpectedHash, ActualHash: report.ActualHash}
	for _, row := range report.Missing {
		p, _ := DecodeRolePairs([]byte("[" + row + "]"))
		out.Missing = append(out.Missing, p...)
	}
	for _, row := range report.Extra {
		p, _ := DecodeRolePairs([]byte("[" + row + "]"))
		out.Extra = append(out.Extra, p...)
	}
	sortRolePairs(out.Missing)
	sortRolePairs(out.Extra)
	return out
}
func (r *RoleStateReconciler) computeTable(ctx context.Context, st StateTable) (StateTableReport, error) {
	report := StateTableReport{Table: st.Name, State: RoleStateNotCovered}
	base, err := r.baselineForTable(ctx, st.Name)
	if err != nil {
		return report, err
	}
	if base == nil {
		return report, nil
	}
	tables, err := DecodeStateSnapshotColumn(*base.RoleStateSnapshot)
	if err != nil {
		return report, err
	}
	body, ok := tables[st.Name]
	if !ok {
		if st.Name == StateTableUserRoles {
			return report, fmt.Errorf("檢查點 seq=%d 的快照欄缺 %s：基準不可用", base.Seq, st.Name)
		}
		return report, nil
	}
	baseline, err := st.Decode(body)
	if err != nil {
		return report, err
	}
	var events []model.AuditLog
	query := r.db.WithContext(ctx).Unscoped().Where("resource = ? AND id > ?", st.EventResource, base.IDTo)
	if st.EventMarker != "" {
		query = query.Where("details LIKE ?", "%"+st.EventMarker+"%")
	}
	if err := query.Order("id ASC").Find(&events).Error; err != nil {
		return report, err
	}
	expected, err := st.Apply(baseline, events)
	if err != nil {
		return report, err
	}
	expectedSet, err := st.Decode(expected.Body)
	if err != nil {
		return report, err
	}
	actual, err := st.Snapshot(ctx, r.db)
	if err != nil {
		return report, err
	}
	actualSet, err := st.Decode(actual.Body)
	if err != nil {
		return report, err
	}
	report.Covered = true
	report.SinceSeq = base.Seq
	report.ExpectedHash = expected.Hash
	report.ActualHash = actual.Hash
	report.State = RoleStateMatch
	report.Missing, report.Extra = st.Diff(expectedSet, actualSet)
	if len(report.Missing) > 0 || len(report.Extra) > 0 {
		report.State = RoleStateMismatch
	}
	return report, nil
}

// StateFailureSink adds an item dimension without changing the legacy role
// failure contract. The event-service adapter is wired in group 5.
type StateFailureSink interface {
	ReportStateMismatch(table string, params map[string]string) error
	ResolveStateMismatch(table string) error
}

func (r *RoleStateReconciler) SetStateFailureSink(sink StateFailureSink) { r.stateFailure = sink }
// settleTable 每次對帳都經持久通道開單或結案：去重以資料庫中同識別且未結案的列為準
// （ReportStateMismatch／ResolveStateMismatch 對同識別為 no-op），不以行程記憶代替，
// 因此告警列被刪除或被填上結案時間，下一次對帳就重建並重新通知。
func (r *RoleStateReconciler) settleTable(report StateTableReport) {
	if r.stateFailure == nil || !report.Covered || report.State == StateTableUnknown {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if report.State == RoleStateMatch {
		if err := r.stateFailure.ResolveStateMismatch(report.Table); err != nil {
			log.Printf("[PrincipalState] resolve failed: %v", err)
		}
		return
	}
	ids := func(rows []string) string {
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			out = append(out, strconv.FormatUint(elementID(row), 10))
		}
		return strings.Join(out, ",")
	}
	if err := r.stateFailure.ReportStateMismatch(report.Table, map[string]string{"table": report.Table, "since_seq": strconv.FormatUint(uint64(report.SinceSeq), 10), "actual_hash": report.ActualHash, "missing": ids(report.Missing), "extra": ids(report.Extra)}); err != nil {
		log.Printf("[PrincipalState] report failed: %v", err)
	}
}

// Select the same three-stage baseline independently for each registered item.
// A legacy true checkpoint without this key cannot hide a newer coverage anchor.
func (r *RoleStateReconciler) baselineForTable(ctx context.Context, name string) (*model.AuditCheckpoint, error) {
	if name == StateTableUserRoles {
		return r.baselineCheckpoint(ctx)
	}
	var candidates []model.AuditCheckpoint
	if err := r.db.WithContext(ctx).Where("agg_scheme IN ? AND role_state_snapshot IS NOT NULL", []string{model.AggSchemeV3, model.AggSchemeV4}).Order("seq DESC").Find(&candidates).Error; err != nil {
		return nil, err
	}
	var tainted uint
	for _, cp := range candidates {
		if cp.RoleStateReconciled != nil && !*cp.RoleStateReconciled && (tainted == 0 || cp.Seq < tainted) {
			tainted = cp.Seq
		}
	}
	for _, matched := range []bool{true, false} {
		for i := range candidates {
			cp := &candidates[i]
			if matched {
				if cp.RoleStateReconciled == nil || !*cp.RoleStateReconciled {
					continue
				}
			} else {
				if cp.RoleStateReconciled != nil || (tainted > 0 && cp.Seq >= tainted) {
					continue
				}
			}
			tables, err := DecodeStateSnapshotColumn(*cp.RoleStateSnapshot)
			if err != nil {
				return nil, err
			}
			if _, ok := tables[name]; ok {
				return cp, nil
			}
		}
	}
	return nil, nil
}

// ReconcileBeforeTokenIssue may write failure evidence, never principal/token state.
func (r *RoleStateReconciler) ReconcileBeforeTokenIssue(ctx context.Context) error {
	var problems []string
	for _, report := range r.ReconcileTables(ctx) {
		if report.State == StateTableUnknown {
			problems = append(problems, report.Table+": "+report.Error)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}
