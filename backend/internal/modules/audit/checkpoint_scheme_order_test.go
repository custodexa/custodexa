package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
)

// 鏈上載荷版本序（v1 < v2 < v3 < v4）不得遞減；帳本四欄自 v3 起必備，v3→v4 交界的帳本區間照常鄰接。
func TestCheckpointSchemeOrder(t *testing.T) {
	addToolCalls := func(t *testing.T, f *verifyFixture, n int) {
		t.Helper()
		if err := f.db.AutoMigrate(&model.AgentToolCall{}); err != nil {
			t.Fatal(err)
		}
		var have int64
		f.db.Model(&model.AgentToolCall{}).Count(&have)
		for i := 0; i < n; i++ {
			a := model.AgentToolCall{Seq: uint(have) + uint(i) + 1, UserID: 1, AgentTokenID: 2, OwnerUserID: 3, Tool: "list_assets", ArgsRedacted: "{}", Decision: model.ToolCallAllowed, ResultExcerpt: "r"}
			if err := f.db.WithContext(model.WithToolCallStamp(context.Background(), f.integrity.StampToolCall)).Create(&a).Error; err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("v4 接在 v3 之後正常；帳本區間在交界鄰接", func(t *testing.T) {
		f := setupVerifyFixture(t)
		// 夾具的 genesis 以現行版本封出；改以第三版封章器重建 genesis（升級前的鏈）
		f.mustExec(t, "DELETE FROM audit_checkpoints")
		f.seal.scheme = model.AggSchemeV3
		if err := f.seal.EnsureGenesis(); err != nil {
			t.Fatal(err)
		}
		addToolCalls(t, f, 2)
		v3, err := f.seal.SealNow()
		if err != nil {
			t.Fatal(err)
		}
		addToolCalls(t, f, 3)
		f.seal.scheme = ""
		v4, err := f.seal.SealNow()
		if err != nil {
			t.Fatal(err)
		}
		if v3.AggScheme != model.AggSchemeV3 || v4.AggScheme != model.AggSchemeV4 {
			t.Fatalf("schemes %s %s", v3.AggScheme, v4.AggScheme)
		}
		if *v4.ToolCallIDFrom != *v3.ToolCallIDTo+1 || *v4.ToolCallRowCount != 3 {
			t.Fatalf("交界帳本區間不鄰接：v3 to=%d、v4 from=%d count=%d", *v3.ToolCallIDTo, *v4.ToolCallIDFrom, *v4.ToolCallRowCount)
		}
		rep, err := f.verifier.VerifyChain()
		if err != nil || rep.Status != IntervalStatusPassed {
			t.Fatalf("混版本鏈應通過：%+v %v", rep, err)
		}
		if got := f.statusOf(t, v4.Seq); got.Status != IntervalStatusPassed || got.ToolCalls == nil || got.ToolCalls.Status != IntervalStatusPassed {
			t.Fatalf("v4 內容層：%+v", got)
		}
	})

	t.Run("v3 接在 v4 之後：payload_invalid（降版）", func(t *testing.T) {
		f := setupVerifyFixture(t)
		if _, err := f.seal.SealNow(); err != nil {
			t.Fatal(err)
		}
		f.seal.scheme = model.AggSchemeV3
		cp, err := f.seal.SealNow()
		if err != nil {
			t.Fatal(err)
		}
		got := f.statusOf(t, cp.Seq)
		if got.Status != IntervalStatusPayloadInvalid || !strings.Contains(got.Detail, "downgrade") {
			t.Fatalf("降版應為 payload_invalid：%+v", got.ChainPointResult)
		}
	})

	t.Run("v1 接在 v4 之後：payload_invalid（降版）", func(t *testing.T) {
		f := setupVerifyFixture(t)
		last, err := f.seal.SealNow()
		if err != nil {
			t.Fatal(err)
		}
		link, err := CheckpointLinkHash(last)
		if err != nil {
			t.Fatal(err)
		}
		empty, n := ComputeAggHash(nil)
		legacy := model.AuditCheckpoint{Seq: last.Seq + 1, IDFrom: last.IDTo + 1, IDTo: last.IDTo, RowCount: n, AggHash: empty,
			AggScheme: model.AggSchemeV1, PrevCheckpointHash: link, SealedAt: last.SealedAt, SigningKeyVersion: 1, AnchorStatus: model.AnchorStatusDisabled}
		payload, err := CheckpointSignBytes(&legacy)
		if err != nil {
			t.Fatal(err)
		}
		_, legacy.Signature = f.signer.Sign(payload)
		if err := f.db.Create(&legacy).Error; err != nil {
			t.Fatal(err)
		}
		if got := f.statusOf(t, legacy.Seq); got.Status != IntervalStatusPayloadInvalid {
			t.Fatalf("v1 接在 v4 之後應為 payload_invalid：%+v", got.ChainPointResult)
		}
	})
}
