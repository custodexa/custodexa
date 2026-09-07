package audit

import (
	"context"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
)

// 基準只取簽章載荷涵蓋狀態摘要的檢查點（agg_scheme v2）。
//
// 威脅：升級前的 v1 檢查點簽章不涵蓋快照欄。能寫資料庫的人直寫提權後，再把「現況」
// 快照與 reconciled=true 補到一個 v1 檢查點上（序號可以比真基準新）：鏈驗證照過
// （v1 載荷本來就沒有 state），對帳若只看「快照欄非空且相符」就會拿它當基準，
// 直寫的指派被洗白。發版前跨模型審查抓到的第 1 條
func TestRoleStateBaselineIgnoresForgedV1Checkpoint(t *testing.T) {
	f := setupRoleFixture(t)
	f.legalAssign(t, 1, 1)
	trusted := f.sealWithRoles(t)
	if got := f.reconcile(t); got.State != RoleStateMatch || got.SinceSeq != trusted {
		t.Fatalf("前置對帳 = %s since=%d, want match since=%d", got.State, got.SinceSeq, trusted)
	}

	// 直寫提權
	f.mustExec(t, "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", 7, 1)
	if got := f.reconcile(t); got.State != RoleStateMismatch {
		t.Fatalf("直寫後對帳 = %s, want mismatch", got.State)
	}

	// 偽造：一個更新的 v1 檢查點，補上「現況」快照與 reconciled=true
	now, err := SnapshotUserRoles(context.Background(), f.db)
	if err != nil {
		t.Fatalf("現況快照: %v", err)
	}
	body := `{"user_roles":` + string(now.Body) + `}`
	yes := true
	forged := model.AuditCheckpoint{
		Seq: trusted + 1, IDFrom: 1, IDTo: 1, RowCount: 1,
		AggHash: "forged", AggScheme: model.AggSchemeV1, PrevCheckpointHash: "x",
		SealedAt: time.Now(), SigningKeyVersion: 1, Signature: "forged",
		AnchorStatus:        model.AnchorStatusEnqueued,
		RoleStateSnapshot:   &body,
		RoleStateHash:       &now.Hash,
		RoleStateCount:      &now.Count,
		RoleStateReconciled: &yes,
	}
	if err := f.db.Create(&forged).Error; err != nil {
		t.Fatalf("落偽造檢查點: %v", err)
	}

	got := f.reconcile(t)
	if got.State != RoleStateMismatch {
		t.Fatalf("偽造 v1 檢查點後對帳 = %s, want mismatch：v1 載荷不涵蓋快照欄，不得成為基準", got.State)
	}
	if got.SinceSeq != trusted {
		t.Fatalf("基準序號 = %d, want %d（真正簽章涵蓋 state 的那一點）", got.SinceSeq, trusted)
	}
}
