package audit_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 攻擊與升級的完整生命週期（子測試本體；由既有頂層測試 TestPermissionUnknownAlertAndRebase 呼叫）。
//
// 每個情境記同一張時間表：權限對帳狀態、鏈尾的起點旗標與對帳結果、結構層失敗數與狀態、
// 未結案單數、確認（accept）事件數、審計列增量、修剪結果。「結構」與「權限」分開斷言。

const lifeClearPerm = `UPDATE audit_checkpoints SET perm_state_snapshot = NULL, perm_origin = NULL, perm_format = NULL, perm_event_seq = NULL, perm_event_head = NULL, perm_reconciled = NULL`

type lifeEnv struct {
	*permEnv
	t     *testing.T
	rec   *audit.RoleStateReconciler
	p     *audit.CheckpointPurger
	v     *audit.CheckpointVerifier
	audit int64 // 起始審計列數
}

func newLifeEnv(t *testing.T) *lifeEnv {
	e := newPermEnv(t)
	require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}, &model.AuditFailureEvent{}, &model.SecurityPolicy{}))
	seedPerm(t, e.db, false)
	rec := audit.NewRoleStateReconciler(e.db, nil)
	rec.SetPermissionAttestSigner(e.signer)
	rec.SetStateFailureSink(audit.NewAuditFailureServiceForTest(e.db))
	p := audit.NewCheckpointPurger(e.db, e.signer)
	v := audit.NewCheckpointVerifier(e.db, e.svc, p, nil, nil)
	v.SetRoleStateReconciler(rec)
	return &lifeEnv{permEnv: e, t: t, rec: rec, p: p, v: v, audit: e.count(t, "audit_logs")}
}

func (l *lifeEnv) at(ago time.Duration) { audit.SetSealClockForTest(l.svc, time.Now().UTC().Add(-ago)) }

func (l *lifeEnv) genesis() {
	require.NoError(l.t, l.svc.EnsureGenesis())
}

func (l *lifeEnv) seal() *model.AuditCheckpoint {
	cp, err := l.svc.SealNow()
	require.NoError(l.t, err, "封章不被擋")
	return cp
}

func (l *lifeEnv) open() int64 {
	var n int64
	require.NoError(l.t, l.db.Model(&model.AuditFailureEvent{}).
		Where("ended_at IS NULL AND cause_params LIKE ?", `%"table":"`+audit.StateTablePermission+`"%`).Count(&n).Error)
	return n
}

func (l *lifeEnv) accepts() int64 {
	var n int64
	require.NoError(l.t, l.db.Model(&model.PermissionStateEvent{}).Where("kind = ?", model.PermEventAccept).Count(&n).Error)
	return n
}

// row 記一列時間表並回傳權限對帳結果。
func (l *lifeEnv) row(step string) audit.PermissionReport {
	l.t.Helper()
	rep := l.rec.ReconcilePermission(context.Background())
	chain, err := l.v.VerifyChain()
	require.NoError(l.t, err)
	var tail model.AuditCheckpoint
	_ = l.db.Order("seq DESC").Limit(1).Find(&tail).Error
	tri := func(p *bool) string {
		if p == nil {
			return "null"
		}
		return fmt.Sprint(*p)
	}
	var trim model.AuditCheckpointTrim
	trimDesc := "無"
	if l.db.Migrator().HasTable(&model.AuditCheckpointTrim{}) {
		if err := l.db.Order("last_trimmed_seq DESC").Limit(1).Find(&trim).Error; err == nil && trim.ID != 0 {
			ok, _ := l.p.VerifyTrim(&trim)
			h := "-"
			if trim.PermHistory != nil {
				h = *trim.PermHistory
			}
			var c int64 = -1
			if trim.UnverifiedCount != nil {
				c = *trim.UnverifiedCount
			}
			trimDesc = fmt.Sprintf("至 seq=%d format=%d history=%s count=%d 驗章=%v", trim.LastTrimmedSeq, trim.Format, h, c, ok)
		}
	}
	l.t.Logf("TIMELINE | %-16s | 權限=%-9s | 鏈尾 seq=%d origin=%s reconciled=%s | 結構 Failed=%d 狀態=%s | 未結案=%d | accept=%d | 審計列增量=%d | 修剪錨 %s",
		step, rep.State, tail.Seq, tri(tail.PermOrigin), tri(tail.PermReconciled), chain.Failed, chain.Status,
		l.open(), l.accepts(), l.count(l.t, "audit_logs")-l.audit, trimDesc)
	return rep
}

func (l *lifeEnv) directWrite() {
	require.NoError(l.t, l.db.Exec(`UPDATE group_role_mappings SET role_id = 1`).Error)
}

func (l *lifeEnv) directWriteAgain() {
	require.NoError(l.t, l.db.Exec(`UPDATE group_role_mappings SET role_id = 2`).Error)
}

func (l *lifeEnv) trimDays(days int) *model.AuditCheckpointTrim {
	l.t.Helper()
	_, tr, err := l.p.TrimChain(days)
	require.NoError(l.t, err)
	require.NotNil(l.t, tr)
	ok, err := l.p.VerifyTrim(tr)
	require.NoError(l.t, err)
	require.True(l.t, ok)
	return tr
}

func (l *lifeEnv) rebase(reason string) {
	svc := audit.NewPermissionAcceptService(l.db, audit.NewTxSink(), l.rec)
	_, err := svc.Accept(context.Background(), acceptWho, reason)
	require.NoError(l.t, err)
}

// 清空＋刪事件 → 封一點 → 再清空＋刪事件 → 封三點 → 修剪 → 重設 → 直寫（第一次是否刪事件由 deleteFirst 決定）。
func lifeClearTwiceThenTrim(t *testing.T, deleteFirst bool) {
	l := newLifeEnv(t)
	l.at(72 * time.Hour)
	l.genesis()
	l.seal()
	l.seal()
	require.Equal(t, "match", l.row("攻擊前").State)
	l.directWrite()
	require.NoError(t, l.db.Exec(lifeClearPerm).Error)
	if deleteFirst {
		require.NoError(t, l.db.Exec(`DELETE FROM permission_state_events`).Error)
	}
	require.Equal(t, "unknown", l.row("破壞後").State)
	c4 := l.seal()
	require.True(t, isFalse(c4.PermOrigin), "攻擊後封出的點，起點旗標為 false")
	require.Nil(t, c4.PermReconciled)
	require.NoError(t, l.db.Exec(lifeClearPerm+` WHERE seq = 4`).Error)
	require.NoError(t, l.db.Exec(`DELETE FROM permission_state_events`).Error)
	require.Equal(t, "unknown", l.row("再破壞後").State, "仍無法判定（不是尚未涵蓋）")
	l.at(0)
	for i := 0; i < 3; i++ {
		cp := l.seal()
		require.True(t, isFalse(cp.PermOrigin))
		require.Nil(t, cp.PermReconciled)
	}
	require.Equal(t, "unknown", l.row("再封章後").State)
	tr := l.trimDays(1)
	require.EqualValues(t, 4, tr.LastTrimmedSeq)
	require.Equal(t, model.TrimPermHistoryUnverified, *tr.PermHistory)
	require.EqualValues(t, 4, *tr.UnverifiedCount)
	rep := l.row("修剪後")
	require.Equal(t, "unknown", rep.State)
	require.EqualValues(t, 1, l.open())
	require.Zero(t, l.accepts())
	chain, err := l.v.VerifyChain()
	require.NoError(t, err)
	require.Equal(t, audit.IntervalStatusPassed, chain.Status, "殘鏈結構通過（結構通過不代表權限相符）")
	l.rebase("附證與變更紀錄遭清除，已與維運核對現況")
	require.Equal(t, "match", l.row("重設後").State)
	require.Zero(t, l.open())
	require.EqualValues(t, 1, l.accepts())
	require.True(t, isTrue(l.seal().PermReconciled), "重設後的封章相符")
	l.directWriteAgain()
	require.Equal(t, "mismatch", l.row("再直寫").State)
}

// 修剪保留 keep 點：清空＋刪事件後封三點，修剪到期段（含攻擊後重建啟用的點與否由 keep 決定）。
func lifeClearThenTrimKeep(t *testing.T, keep int) {
	l := newLifeEnv(t)
	l.at(72 * time.Hour)
	l.genesis()
	l.seal()
	l.seal()
	require.Equal(t, "match", l.row("攻擊前").State)
	l.directWrite()
	require.NoError(t, l.db.Exec(lifeClearPerm).Error)
	require.NoError(t, l.db.Exec(`DELETE FROM permission_state_events`).Error)
	require.Equal(t, "unknown", l.row("破壞後").State)
	cut := 6 - keep
	for seq := 4; seq <= 6; seq++ {
		if seq > cut {
			l.at(0)
		}
		cp := l.seal()
		require.True(t, isFalse(cp.PermOrigin))
	}
	require.Equal(t, "unknown", l.row("再封章後").State)
	tr := l.trimDays(1)
	require.EqualValues(t, cut, tr.LastTrimmedSeq)
	require.Equal(t, model.TrimPermHistoryUnverified, *tr.PermHistory)
	require.EqualValues(t, 3, *tr.UnverifiedCount, "被剪段裡被清空的三點")
	require.Equal(t, "unknown", l.row("修剪後").State, "殘鏈各點起點旗標為 false、對帳結果為空")
	require.EqualValues(t, 1, l.open())
	require.Zero(t, l.accepts())
	l.rebase("附證與變更紀錄遭清除，已與維運核對現況")
	require.Equal(t, "match", l.row("重設後").State)
	l.directWriteAgain()
	require.Equal(t, "mismatch", l.row("再直寫").State)
}

// 升級混合鏈：第四版點改標第三版並清空附證（保留所有列）。
func lifeRelabelV3(t *testing.T) {
	l := newLifeEnv(t)
	l.at(10 * 24 * time.Hour)
	audit.SetPermissionSources(nil, nil)
	audit.SetSealSchemeForTest(l.svc, model.AggSchemeV3)
	l.genesis()
	l.seal()
	l.seal()
	audit.SetSealSchemeForTest(l.svc, "")
	newPermDBWire(t)
	c4 := l.seal()
	require.True(t, isTrue(c4.PermOrigin), "升級後首個第四版點是起點")
	l.seal()
	l.seal()
	require.Equal(t, "match", l.row("攻擊前").State)
	l.directWrite()
	require.Equal(t, "mismatch", l.row("直寫後").State)
	require.NoError(t, l.db.Exec(`UPDATE audit_checkpoints SET agg_scheme = 'cp-agg-v3', perm_state_snapshot = NULL, perm_origin = NULL, perm_format = NULL, perm_event_seq = NULL, perm_event_head = NULL, perm_reconciled = NULL WHERE seq >= 4`).Error)
	require.NoError(t, l.db.Exec(`DELETE FROM permission_state_events`).Error)
	rep := l.row("改標清欄後")
	require.Equal(t, "unknown", rep.State, "改標的點以第三版形狀重建、簽章驗不過：不是尚未涵蓋")
	require.Contains(t, rep.Error, "現存鏈結構驗證失敗")
	l.at(3 * 24 * time.Hour)
	c7 := l.seal()
	require.True(t, isFalse(c7.PermOrigin))
	require.Nil(t, c7.PermReconciled)
	l.seal()
	l.seal()
	require.Equal(t, "unknown", l.row("再封章後").State)
	require.EqualValues(t, 1, l.open())
	require.Zero(t, l.accepts())
	tr := l.trimDays(5) // 剪 C1–C6
	require.EqualValues(t, 6, tr.LastTrimmedSeq)
	require.Equal(t, model.TrimPermHistoryUnverified, *tr.PermHistory)
	require.EqualValues(t, 3, *tr.UnverifiedCount, "C4–C6")
	require.Equal(t, c7.PrevCheckpointHash, tr.LastTrimmedLinkHash, "C6 驗不過：錨值取 C7 簽章內的 prev")
	rep = l.row("修剪後")
	require.Equal(t, "unknown", rep.State)
	chain, err := l.v.VerifyChain()
	require.NoError(t, err)
	require.Equal(t, audit.IntervalStatusPassed, chain.Status)
	require.NoError(t, l.db.Exec(lifeClearPerm).Error)
	require.NoError(t, l.db.Exec(`DELETE FROM permission_state_events`).Error)
	require.Equal(t, "unknown", l.row("再清空後").State)
	l.at(0)
	c10 := l.seal()
	require.True(t, isFalse(c10.PermOrigin))
	tr = l.trimDays(1) // 剪 C7–C9
	require.Equal(t, model.TrimPermHistoryUnverified, *tr.PermHistory, "承接前錨，單調不回退")
	require.Equal(t, "unknown", l.row("再修剪後").State)
	l.rebase("混合鏈遭改標並清空附證，已與維運核對現況")
	require.Equal(t, "match", l.row("重設後").State)
	l.directWriteAgain()
	require.Equal(t, "mismatch", l.row("再直寫").State)
}

// 修剪到只剩一點與鏈被刪空：每一步的拒絕原因；最後一步（證據全刪）如實記為會自動成為起點。
func lifeSinglePoint(t *testing.T) {
	l := newLifeEnv(t)
	l.at(72 * time.Hour)
	l.genesis()
	l.seal()
	l.seal()
	l.at(0)
	tr := l.trimDays(1)
	require.EqualValues(t, 2, tr.LastTrimmedSeq)
	require.EqualValues(t, 1, l.count(t, "audit_checkpoints"), "修剪到只剩一點")
	require.Equal(t, "match", l.row("修剪後").State)
	require.NoError(t, l.db.Exec(lifeClearPerm).Error)
	require.Equal(t, "unknown", l.row("清空唯一點").State)
	cp := l.seal()
	require.True(t, isFalse(cp.PermOrigin))
	require.NoError(t, l.db.Exec(`DELETE FROM audit_checkpoints`).Error)
	_, err := l.svc.SealNow()
	require.ErrorIs(t, err, audit.ErrCheckpointNoChain, "鏈為空時例行封章失敗（吵）")
	l.genesis()
	var g model.AuditCheckpoint
	require.NoError(t, l.db.First(&g, "seq = 1").Error)
	require.True(t, isFalse(g.PermOrigin), "修剪錨仍在：重建的 genesis 不是起點")
	require.Equal(t, "unknown", l.row("錨在時重建").State)
	// 刪 genesis 與修剪錨、留事件：事件表非空是唯一的拒絕原因
	require.NoError(t, l.db.Exec(`DELETE FROM audit_checkpoints`).Error)
	require.NoError(t, l.db.Exec(`DELETE FROM audit_checkpoint_trims`).Error)
	require.Positive(t, l.count(t, "permission_state_events"))
	l.genesis()
	g = model.AuditCheckpoint{}
	require.NoError(t, l.db.First(&g, "seq = 1").Error)
	require.True(t, isFalse(g.PermOrigin), "只剩事件：事件表非空就不是乾淨起點")
	require.Equal(t, "unknown", l.row("只剩事件時重建").State)
	// 證據全刪（檢查點、修剪錨、事件）：本機沒有任何可阻止的錨，下一次封章把當時狀態當成新的乾淨起點
	require.NoError(t, l.db.Exec(`DELETE FROM audit_checkpoints`).Error)
	require.NoError(t, l.db.Exec(`DELETE FROM permission_state_events`).Error)
	l.genesis()
	g = model.AuditCheckpoint{}
	require.NoError(t, l.db.First(&g, "seq = 1").Error)
	require.True(t, isTrue(g.PermOrigin), "已揭露邊界：自啟用以來的本機證據全刪時自動成為起點，只有離機見證能辨識")
	require.Equal(t, "match", l.row("證據全刪後").State)
}

// 合法修剪過、啟用後的鏈：刪啟用後的點、刪修剪錨與事件，殘鏈接不上任何錨。
func lifeHeadAnchorDeleted(t *testing.T) {
	l := newLifeEnv(t)
	l.at(72 * time.Hour)
	audit.SetPermissionSources(nil, nil)
	audit.SetSealSchemeForTest(l.svc, model.AggSchemeV3)
	l.genesis()
	l.seal()
	l.at(0)
	l.seal()
	l.seal()
	l.seal()
	tr := l.trimDays(1) // 合法修剪 C1–C2
	require.EqualValues(t, 2, tr.LastTrimmedSeq)
	audit.SetSealSchemeForTest(l.svc, "")
	newPermDBWire(t)
	c6 := l.seal()
	require.True(t, isTrue(c6.PermOrigin))
	l.seal()
	require.Equal(t, "match", l.row("啟用後").State)
	require.NoError(t, l.db.Exec(`DELETE FROM audit_checkpoints WHERE seq >= 6`).Error)
	require.NoError(t, l.db.Exec(`DELETE FROM audit_checkpoint_trims`).Error)
	require.NoError(t, l.db.Exec(`DELETE FROM permission_state_events`).Error)
	rep := l.row("刪尾段與錨後")
	require.Equal(t, "unknown", rep.State, "殘鏈 C3–C5 鏈頭接不上任何錨：不是乾淨起點")
	chain, err := l.v.VerifyChain()
	require.NoError(t, err)
	require.Equal(t, audit.ChainStatusSeqGap, chain.Status, "結構層鏈頭 seq_gap")
}

// 升級：中段壞簽章、頭尾有效、鏈接連續、無附證無事件——中段驗章是唯一的拒絕原因。
func lifeUpgradeMiddleBadSignature(t *testing.T) {
	l := newLifeEnv(t)
	audit.SetPermissionSources(nil, nil)
	audit.SetSealSchemeForTest(l.svc, model.AggSchemeV3)
	l.genesis()
	l.seal()
	l.seal()
	// 改壞 C2 的簽章欄（不改載荷）。C3 的鏈接涵蓋 C2 的簽章，只持資料庫帳密者改了 C2 就會讓 C3 斷鏈；
	// 為了讓「中段驗章」成為唯一的拒絕原因，夾具以持鑰者身分把 C3 重接到改壞後的 C2 並重簽。
	require.NoError(t, l.db.Exec(`UPDATE audit_checkpoints SET signature = ? WHERE seq = 2`, strings.Repeat("A", 88)).Error)
	var c2, c3 model.AuditCheckpoint
	require.NoError(t, l.db.First(&c2, "seq = 2").Error)
	require.NoError(t, l.db.First(&c3, "seq = 3").Error)
	link, err := audit.CheckpointLinkHash(&c2)
	require.NoError(t, err)
	c3.PrevCheckpointHash = link
	payload, err := audit.CheckpointSignBytes(&c3)
	require.NoError(t, err)
	_, c3.Signature = l.signer.Sign(payload)
	require.NoError(t, l.db.Exec(`UPDATE audit_checkpoints SET prev_checkpoint_hash = ?, signature = ? WHERE seq = 3`, c3.PrevCheckpointHash, c3.Signature).Error)
	l.seal() // 舊版封章器正常封出 C4：鏈接著 C3
	audit.SetSealSchemeForTest(l.svc, "")
	newPermDBWire(t)
	cp := l.seal()
	require.True(t, isFalse(cp.PermOrigin), "現存鏈中段驗不過：首個第四版點不是起點")
	require.Equal(t, "unknown", l.row("升級後").State)
	chain, err := l.v.VerifyChain()
	require.NoError(t, err)
	got := map[uint]string{}
	for _, f := range chain.Failures {
		got[f.Seq] = f.Status
	}
	require.Equal(t, map[uint]string{2: audit.IntervalStatusSignatureInvalid}, got)
}

// 升級：最後一個第三版點對帳相符、首個第四版點為起點、鏈接單一規則；舊格式修剪錨的升級鏈同樣；
// 升級前已斷鏈的鏈首個第四版點不是起點，需一次重設。
func lifeUpgrade(t *testing.T, variant string) {
	l := newLifeEnv(t)
	audit.SetPermissionSources(nil, nil)
	audit.SetSealSchemeForTest(l.svc, model.AggSchemeV3)
	l.svc.SetRoleStateReconciler(l.rec)
	l.genesis()
	l.seal()
	last := l.seal()
	require.True(t, isTrue(last.RoleStateReconciled), "最後一個第三版點基礎對帳相符")
	switch variant {
	case "舊格式修剪錨":
		var cps []model.AuditCheckpoint
		require.NoError(t, l.db.Order("seq").Find(&cps).Error)
		link, err := audit.CheckpointLinkHash(&cps[0])
		require.NoError(t, err)
		tr := &model.AuditCheckpointTrim{FromSeq: 1, LastTrimmedSeq: 1, TrimmedCount: 1, LastTrimmedLinkHash: link,
			GenesisIDFrom: cps[0].IDFrom, PolicyDays: 1, TrimmedAt: time.Now().UTC().Truncate(time.Microsecond), Format: model.CheckpointTrimFormatV1}
		payload, err := audit.CheckpointTrimSignBytes(tr)
		require.NoError(t, err)
		tr.SigningKeyVersion, tr.Signature = l.signer.Sign(payload)
		require.NoError(t, l.db.Exec(`DELETE FROM audit_checkpoints WHERE seq = 1`).Error)
		require.NoError(t, l.db.Create(tr).Error)
	case "升級前已斷鏈":
		require.NoError(t, l.db.Exec(`UPDATE audit_checkpoints SET prev_checkpoint_hash = ? WHERE seq = 2`, strings.Repeat("0", 64)).Error)
	}
	audit.SetSealSchemeForTest(l.svc, "")
	newPermDBWire(t)
	cp := l.seal()
	require.Equal(t, model.AggSchemeV4, cp.AggScheme)
	link, err := audit.CheckpointLinkHash(last)
	require.NoError(t, err)
	require.Equal(t, link, cp.PrevCheckpointHash, "第一個第四版點以單一鏈接規則接在最後一個第三版點後")
	if variant == "升級前已斷鏈" {
		require.True(t, isFalse(cp.PermOrigin))
		require.Equal(t, "unknown", l.row("升級後").State)
		require.EqualValues(t, 1, l.open())
		l.rebase("升級前鏈已在告警，已核對")
		require.Equal(t, "match", l.row("重設後").State)
		return
	}
	require.True(t, isTrue(cp.PermOrigin))
	require.True(t, isTrue(cp.RoleStateReconciled), "基礎三項：首個第四版點仍自最後一個相符的第三版點起算")
	require.Equal(t, "match", l.row("升級後").State)
	require.Zero(t, l.open())
	require.True(t, isTrue(l.seal().PermReconciled))
}

// 標記竄改：每一種改動在結構層的去向；權限維度上，唯一基準被動→無法判定，另有基準→相符且結構告警開。
func lifeTamperMarks(t *testing.T) {
	tampers := []struct {
		name, sql, status string
	}{
		{"改起點旗標", `UPDATE audit_checkpoints SET perm_origin = NOT perm_origin WHERE seq = ?`, audit.IntervalStatusSignatureInvalid},
		{"改對帳結果", `UPDATE audit_checkpoints SET perm_reconciled = false WHERE seq = ?`, audit.IntervalStatusSignatureInvalid},
		{"改快照本體", `UPDATE audit_checkpoints SET perm_state_snapshot = REPLACE(perm_state_snapshot, '"generation_fp":""', '"generation_fp":"x"') WHERE seq = ?`, audit.IntervalStatusSignatureInvalid},
		{"改事件界標", `UPDATE audit_checkpoints SET perm_event_seq = perm_event_seq + 1, perm_origin = false WHERE seq = ?`, audit.IntervalStatusSignatureInvalid},
		{"改載荷版本", `UPDATE audit_checkpoints SET agg_scheme = 'cp-agg-v3' WHERE seq = ?`, audit.IntervalStatusSignatureInvalid},
		{"整組清空", lifeClearPerm + ` WHERE seq = ?`, audit.IntervalStatusSignatureInvalid},
		{"部分清空", `UPDATE audit_checkpoints SET perm_event_head = NULL WHERE seq = ?`, audit.IntervalStatusPayloadInvalid},
	}
	for _, tc := range tampers {
		t.Run(tc.name+"：另有基準→相符且結構告警開", func(t *testing.T) {
			l := newLifeEnv(t)
			l.genesis()
			l.seal()
			l.seal()
			require.NoError(t, l.db.Exec(tc.sql, 3).Error)
			rep := l.row("竄改鏈尾後")
			require.Equal(t, "match", rep.State, "較早的基準仍在")
			chain, err := l.v.VerifyChain()
			require.NoError(t, err)
			require.EqualValues(t, 1, chain.Failed)
			require.Equal(t, tc.status, chain.Failures[0].Status)
			require.EqualValues(t, 3, chain.Failures[0].Seq)
		})
		t.Run(tc.name+"：唯一基準被動→無法判定", func(t *testing.T) {
			l := newLifeEnv(t)
			l.genesis()
			require.NoError(t, l.db.Exec(tc.sql, 1).Error)
			rep := l.row("竄改唯一基準後")
			require.Equal(t, "unknown", rep.State)
			chain, err := l.v.VerifyChain()
			require.NoError(t, err)
			require.Equal(t, tc.status, chain.Status)
		})
	}
}

// 只損壞一個附證：鏈尾整組清空、鏈尾部分清空（下一次封章停擺）、非鏈尾整組清空、唯一基準被清空。
func lifeSingleDamage(t *testing.T) {
	t.Run("鏈尾部分清空：載荷建不出、現況相符、下一次封章失敗", func(t *testing.T) {
		l := newLifeEnv(t)
		l.genesis()
		l.seal()
		l.seal()
		require.NoError(t, l.db.Exec(`UPDATE audit_checkpoints SET perm_origin = NULL WHERE seq = 3`).Error)
		require.Equal(t, "match", l.row("部分清空後").State)
		chain, err := l.v.VerifyChain()
		require.NoError(t, err)
		require.Equal(t, audit.IntervalStatusPayloadInvalid, chain.Status)
		_, err = l.svc.SealNow()
		require.Error(t, err, "重算鏈尾鏈接時載荷建不出：封章停擺（可用性邊界，需還原備份）")
	})
	t.Run("非鏈尾整組清空：該點驗不過、下一點斷鏈", func(t *testing.T) {
		l := newLifeEnv(t)
		l.genesis()
		l.seal()
		l.seal()
		require.NoError(t, l.db.Exec(lifeClearPerm+` WHERE seq = 2`).Error)
		l.row("清空非鏈尾後")
		chain, err := l.v.VerifyChain()
		require.NoError(t, err)
		got := map[uint]string{}
		for _, f := range chain.Failures {
			got[f.Seq] = f.Status
		}
		require.Equal(t, map[uint]string{2: audit.IntervalStatusSignatureInvalid, 3: audit.ChainStatusChainBroken}, got)
	})
	t.Run("唯一基準被清空：無法判定", func(t *testing.T) {
		l := newLifeEnv(t)
		l.genesis()
		require.NoError(t, l.db.Exec(lifeClearPerm).Error)
		require.Equal(t, "unknown", l.row("清空唯一基準後").State)
	})
}

// 只刪啟用事件（附證保留）再封章：錨定事件不在 → 無法判定；新點起點旗標為 false。
// 改壞事件差集並照公開算法重算摘要：驗證碼失效、事件不可信 → 不相符。
func lifeEventTamper(t *testing.T) {
	t.Run("只刪啟用事件、保留附證、再封章：無法判定，新點不是起點", func(t *testing.T) {
		l := newLifeEnv(t)
		l.genesis()
		require.NoError(t, l.db.Exec(`DELETE FROM permission_state_events WHERE kind = 'activate'`).Error)
		require.Equal(t, "unknown", l.row("刪啟用事件後").State)
		cp := l.seal()
		require.True(t, isFalse(cp.PermOrigin))
		require.Equal(t, "unknown", l.row("再封章後").State)
	})
	t.Run("差集改壞並重算公開摘要：事件不可信，不相符", func(t *testing.T) {
		l := newLifeEnv(t)
		l.genesis()
		require.NoError(t, l.change(t, func(tx *gorm.DB) error {
			return tx.Exec(`UPDATE users SET active = NOT active WHERE id = 2`).Error
		}))
		var ev model.PermissionStateEvent
		require.NoError(t, l.db.First(&ev, "seq = 2").Error)
		ev.Delta = `{"add":{"user_roles":[[2,1,"global","manual"]]},"meta":` + ev.Delta[strings.Index(ev.Delta, `"meta":`)+7:]
		ev.Digest = audit.PermissionEventDigestForTest(&ev)
		require.NoError(t, l.db.Exec(`UPDATE permission_state_events SET delta = ?, digest = ? WHERE seq = 2`, ev.Delta, ev.Digest).Error)
		require.NotEqual(t, "match", l.row("差集改壞後").State)
	})
}
