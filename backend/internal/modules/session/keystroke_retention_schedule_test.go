package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/policy"
)

type ksAuditSink struct{ entries []*audit.AuditLogEntry }

func (f *ksAuditSink) Log(e *audit.AuditLogEntry) { f.entries = append(f.entries, e) }

type ksAcceptAlerts struct{}

func (ksAcceptAlerts) RaiseHighRiskInTx(*gorm.DB, policy.HighRiskAlert) error { return nil }

// 保留排程依 retention_keystroke_days 呼叫鍵盤紀錄清除：到期列轉 purged、
// 檔案刪除、FEK 欄清空（crypto-shred），並寫一列清除審計（目標與筆數）。
func TestRetentionScheduleInvokesKeystrokePurgeAndAudits(t *testing.T) {
	r := newKsRig(t)
	if err := r.db.AutoMigrate(&model.AuditLog{}, &model.SecurityPolicy{}); err != nil {
		t.Fatal(err)
	}
	pol := policy.NewSecurityPolicyService(r.db)
	pol.SetHighRiskAlertRaiser(ksAcceptAlerts{})
	sink := &ksAuditSink{}
	ret := audit.NewRetentionService(r.db, pol, nil, sink)
	ret.SetKeystrokeRetention(r.svc)

	now := time.Now()
	old := now.AddDate(0, 0, -40)
	fresh := now.AddDate(0, 0, -2)
	oldRel := ksRow(t, r, 1, model.KeystrokeStatusComplete, old, &old, &old)
	freshRel := ksRow(t, r, 2, model.KeystrokeStatusComplete, fresh, &fresh, &fresh)

	// 出廠預設 0＝永久：不清除、不留痕
	if res := ret.PurgeAll(); len(res) != 0 || len(sink.entries) != 0 {
		t.Fatalf("default must not purge: results=%+v audit=%d", res, len(sink.entries))
	}
	if _, err := pol.Update(policy.PolicyRetentionKeystrokeDays, "30", "test"); err != nil {
		t.Fatal(err)
	}

	results := ret.PurgeAll()
	if len(results) != 1 || results[0].Target != "keystroke_records" || results[0].Deleted != 1 || results[0].Days != 30 {
		t.Fatalf("results=%+v", results)
	}
	if row := r.row(t, 1); row.Status != model.KeystrokeStatusPurged || row.FileKeyEnc != "" || row.PurgedAt == nil {
		t.Fatalf("expired row must be purged with key cleared: %+v", row)
	}
	if row := r.row(t, 2); row.Status != model.KeystrokeStatusComplete || row.FileKeyEnc == "" {
		t.Fatalf("fresh row must be untouched: %+v", row)
	}
	if _, err := os.Stat(filepath.Join(r.root, oldRel)); !os.IsNotExist(err) {
		t.Fatalf("expired file must be removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(r.root, freshRel)); err != nil {
		t.Fatalf("fresh file must stay: %v", err)
	}
	if len(sink.entries) != 1 {
		t.Fatalf("audit entries=%d, want 1", len(sink.entries))
	}
	e := sink.entries[0]
	if e.Resource != model.ResourceRetention || e.Action != model.ActionDelete || e.Status != model.StatusSuccess ||
		!strings.Contains(e.Details, `"keystroke_records"`) {
		t.Fatalf("audit entry wrong: resource=%s action=%s status=%s details=%s", e.Resource, e.Action, e.Status, e.Details)
	}
}
