package audit

import (
	"encoding/json"
	"github.com/custodexa/backend/internal/model"
	"testing"
)

func TestCoverageCommandIntegrityAndBundleManifest(t *testing.T) {
	svc, db := setupReportEnv(t)
	from, to, at := reportWindow()
	uid := uint(1)
	q := TimelineQuery{Subject: SubjectUser, SubjectID: uid, From: from, To: to, Types: []TimelineEventType{TimelineTypeCommand}}
	clean, err := svc.timeline.buildCoverage(q)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(clean)
	if string(raw) != `[{"type":"command","state":"present"}]` {
		t.Fatal("clean response changed", string(raw))
	}
	before := toExportCoverage(clean)
	raw, _ = json.Marshal(before)

	// One eligible degradation, one qualified command, and two records outside the pivot/window.
	for _, r := range []model.SessionCommand{
		{SessionID: 1, UserID: uid, Seq: 1, ExecutedAt: at, Degraded: true, DegradeReason: model.DegradeInputNoCommand},
		{SessionID: 1, UserID: uid, Seq: 2, ExecutedAt: at, Command: "pwd", DegradeReason: model.QualifyReplayFallback},
		{SessionID: 2, UserID: 99, Seq: 1, ExecutedAt: at, Degraded: true, DegradeReason: model.DegradeInputNoCommand},
		{SessionID: 1, UserID: uid, Seq: 3, ExecutedAt: to, Degraded: true, DegradeReason: model.DegradeInputNoCommand},
	} {
		if err := db.Select("session_id", "user_id", "seq", "executed_at", "command", "degraded", "degrade_reason").Create(&r).Error; err != nil {
			t.Fatal(err)
		}
	}
	result, err := svc.timeline.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Coverage) != 1 || !result.Coverage[0].Incomplete || result.Coverage[0].DegradedCount != 1 || result.Coverage[0].State != CoveragePresent {
		t.Fatal(result.Coverage)
	}
	m, files := exportReport(t, svc, bundleFilter(&ExportFilter{UserID: &uid, StartTime: &from, EndTime: &to, Subject: SubjectUser, Types: q.Types}))
	if len(m.Coverage) != 1 || !m.Coverage[0].Incomplete || m.Coverage[0].DegradedCount != result.Coverage[0].DegradedCount {
		t.Fatal(m.Coverage)
	}
	var onDisk ExportManifest
	if err := json.Unmarshal(files["manifest.json"], &onDisk); err != nil {
		t.Fatal(err)
	}
	if len(onDisk.Coverage) != 1 || !onDisk.Coverage[0].Incomplete || onDisk.Coverage[0].DegradedCount != 1 {
		t.Fatal(onDisk.Coverage)
	}
	// Omitting the optional integrity fields leaves every historical export field unchanged.
	for i := range m.Coverage {
		m.Coverage[i].Incomplete = false
		m.Coverage[i].DegradedCount = 0
	}
	got, _ := json.Marshal(m.Coverage)
	want, _ := json.Marshal(before)
	if string(got) != string(want) {
		t.Fatal(string(got), string(want))
	}
}

// 不含指令文字的降級（含截斷回顯、回顯關閉）都必須讓覆蓋度呈現不完整；
// 全螢幕類降級維持不計。
func TestCoverageCountsEveryTextlessDegradeReason(t *testing.T) {
	cases := []struct {
		reason string
		want   int64
	}{
		{model.DegradeInputNoCommand, 1},
		{model.DegradeNoEcho, 1},
		{model.DegradeEchoIncompleteAtClose, 1},
		{model.DegradeAltScreen, 0},
	}
	for _, c := range cases {
		t.Run(c.reason, func(t *testing.T) {
			svc, db := setupReportEnv(t)
			from, to, at := reportWindow()
			uid := uint(1)
			r := model.SessionCommand{SessionID: 1, UserID: uid, Seq: 1, ExecutedAt: at, Degraded: true, DegradeReason: c.reason}
			if err := db.Select("session_id", "user_id", "seq", "executed_at", "command", "degraded", "degrade_reason").Create(&r).Error; err != nil {
				t.Fatal(err)
			}
			q := TimelineQuery{Subject: SubjectUser, SubjectID: uid, From: from, To: to, Types: []TimelineEventType{TimelineTypeCommand}}
			cov, err := svc.timeline.buildCoverage(q)
			if err != nil {
				t.Fatal(err)
			}
			if cov[0].DegradedCount != c.want || cov[0].Incomplete != (c.want > 0) {
				t.Fatalf("reason %s: %+v", c.reason, cov[0])
			}
		})
	}
}
