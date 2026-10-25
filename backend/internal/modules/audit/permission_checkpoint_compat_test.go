package audit_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/stretchr/testify/require"
)

func TestPermissionCheckpointCompatibility(t *testing.T) {
	e := newPermEnv(t)
	seedPerm(t, e.db, false)

	// 升級前的封章：第三版載荷（以 v3 版本常數封出，不是來源未接線的第四版 null 點）。
	audit.SetPermissionSources(nil, nil)
	audit.SetSealSchemeForTest(e.svc, model.AggSchemeV3)
	require.NoError(t, e.svc.EnsureGenesis())
	audit.SetSealSchemeForTest(e.svc, "")
	var legacy model.AuditCheckpoint
	require.NoError(t, e.db.First(&legacy, "seq = 1").Error)
	require.Nil(t, legacy.PermStateSnapshot)
	legacyBytes, err := audit.CheckpointSignBytes(&legacy)
	require.NoError(t, err)

	// 接線後的下一次封章是啟用界標。
	newPermDBWire(t)
	cp2, err := e.svc.SealNow()
	require.NoError(t, err)
	var att model.AuditCheckpoint
	require.NoError(t, e.db.First(&att, "seq = ?", cp2.Seq).Error)

	t.Run("舊封章仍可驗、新維度 not_covered、原 bytes 不變", func(t *testing.T) {
		require.Equal(t, audit.PermAttestNotCovered, audit.VerifyPermissionAttestation(e.db, &legacy, e.signer).State)
		again, err := audit.CheckpointSignBytes(&legacy)
		require.NoError(t, err)
		require.Equal(t, string(legacyBytes), string(again))
		payload, err := audit.CheckpointSignBytes(&legacy)
		require.NoError(t, err)
		ok, err := e.signer.Verify(legacy.SigningKeyVersion, payload, legacy.Signature)
		require.NoError(t, err)
		require.True(t, ok, "舊封章的原簽章不受附證影響")
	})

	t.Run("新附證可驗，且附證在檢查點簽章載荷之內", func(t *testing.T) {
		require.Equal(t, model.AggSchemeV4, att.AggScheme)
		require.Equal(t, audit.PermAttestValid, audit.VerifyPermissionAttestation(e.db, &att, e.signer).State)
		base, err := audit.CheckpointSignBytes(&att)
		require.NoError(t, err)
		require.Contains(t, string(base), `"perm":{"format":`)
		stripped := att
		stripped.PermStateSnapshot, stripped.PermFormat, stripped.PermEventSeq = nil, nil, nil
		stripped.PermEventHead, stripped.PermReconciled, stripped.PermOrigin = nil, nil, nil
		sb, err := audit.CheckpointSignBytes(&stripped)
		require.NoError(t, err)
		require.True(t, strings.HasSuffix(string(sb), `"perm":null}`), "整組清空重建為 perm:null")
		ok, _ := e.signer.Verify(att.SigningKeyVersion, sb, att.Signature)
		require.False(t, ok, "清空附證使該點自己的簽章驗不過")
		ok, _ = e.signer.Verify(att.SigningKeyVersion, base, att.Signature)
		require.True(t, ok)
	})

	mutate := func(f func(c *model.AuditCheckpoint)) audit.PermissionAttestStatus {
		c := att
		f(&c)
		return audit.VerifyPermissionAttestation(e.db, &c, e.signer)
	}
	t.Run("修改快照或版本、移貼、刪附證、未知版本皆失敗", func(t *testing.T) {
		other := "{}"
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) { c.PermStateSnapshot = &other }).State, "快照被改")
		seq := *att.PermEventSeq + 1
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) { c.PermEventSeq = &seq }).State, "事件界標被改")
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) { c.Seq += 10 }).State, "移貼到另一封章")
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) { c.Signature = legacy.Signature }).State, "原簽章換掉")
		v := 99
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) { c.PermFormat = &v }).State, "未知格式版本不回退")
		f := false
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) { c.PermReconciled = &f }).State, "對帳結果被改")
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) {
			c.PermStateSnapshot, c.PermFormat, c.PermEventSeq, c.PermEventHead, c.PermReconciled, c.PermOrigin = nil, nil, nil, nil, nil, nil
		}).State, "啟用後刪附證不得回退成 not_covered")
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) { c.PermOrigin = nil }).State, "部分清空")
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) { c.AggScheme = model.AggSchemeV3 }).State,
			"第四版改標成第三版：附證欄不在第三版簽章內，帶附證欄的第三版點不被當成合法舊點")
		require.Equal(t, audit.PermAttestInvalid, mutate(func(c *model.AuditCheckpoint) {
			c.AggScheme = model.AggSchemeV3
			c.PermStateSnapshot, c.PermFormat, c.PermEventSeq, c.PermEventHead, c.PermReconciled, c.PermOrigin = nil, nil, nil, nil, nil, nil
		}).State, "第四版改標成第三版並清空附證：以第三版形狀重建，簽章驗不過")
	})

	t.Run("model 序列化不外送任何附證欄（列表 API 另以 perm 物件外送）", func(t *testing.T) {
		raw, err := json.Marshal(att)
		require.NoError(t, err)
		require.NotContains(t, string(raw), "perm_", "附證欄一律不經 model 序列化外送")
		require.NotContains(t, string(raw), "permission")
		raw, err = json.Marshal(legacy)
		require.NoError(t, err)
		require.NotContains(t, string(raw), "perm_", "沒有附證的檢查點回應位元組不變")
	})

	// 附證在檢查點簽章之內：清空任一點（含鏈尾）的附證，該點自己簽章驗不過；
	// 非鏈尾者另使下一點的前一雜湊對不上。鏈接雜湊所有版本同一條規則。
	t.Run("清空鏈尾附證：該點簽章驗不過；清空非鏈尾附證：該點驗不過且下一點斷鏈", func(t *testing.T) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		require.NoError(t, e.svc.EnsureGenesis())
		for i := 0; i < 2; i++ {
			_, err := e.svc.SealNow()
			require.NoError(t, err)
		}
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetPermissionAttestSigner(e.signer)
		v := audit.NewCheckpointVerifier(e.db, e.svc, audit.NewCheckpointPurger(e.db, e.signer), nil, nil)
		v.SetRoleStateReconciler(rec)
		statuses := func(t *testing.T) map[uint]string {
			rep, err := v.VerifyChain()
			require.NoError(t, err)
			out := map[uint]string{}
			for _, f := range rep.Failures {
				out[f.Seq] = f.Status
			}
			require.EqualValues(t, len(out), rep.Failed)
			return out
		}
		require.Empty(t, statuses(t), "三點附證完好時全鏈通過")
		// 離線規格：鏈接輸入以字串串接重建（signed＋signature），等於下一點簽章內的前一雜湊
		var cps []model.AuditCheckpoint
		require.NoError(t, e.db.Order("seq").Find(&cps).Error)
		for i := 0; i+1 < len(cps); i++ {
			require.NotNil(t, cps[i].PermStateSnapshot)
			signed, err := audit.CheckpointSignBytes(&cps[i])
			require.NoError(t, err)
			raw := `{"signed":` + string(signed) + `,"signature":"` + cps[i].Signature + `"}`
			sum := sha256.Sum256([]byte(raw))
			require.Equal(t, hex.EncodeToString(sum[:]), cps[i+1].PrevCheckpointHash, "seq=%d", cps[i].Seq)
		}
		const clear = `UPDATE audit_checkpoints SET perm_state_snapshot = NULL, perm_origin = NULL, perm_format = NULL, perm_event_seq = NULL, perm_event_head = NULL, perm_reconciled = NULL WHERE seq = ?`
		require.NoError(t, e.db.Exec(clear, 3).Error)
		require.Equal(t, map[uint]string{3: audit.IntervalStatusSignatureInvalid}, statuses(t), "鏈尾：該點自己驗不過")
		require.NoError(t, e.db.Exec(clear, 2).Error)
		require.Equal(t, map[uint]string{2: audit.IntervalStatusSignatureInvalid, 3: audit.IntervalStatusSignatureInvalid}, statuses(t),
			"非鏈尾：該點驗不過（下一點本身也已被清空）")
	})

	t.Run("第三版點帶附證欄：結構層判附證無效，不被當成乾淨的舊點", func(t *testing.T) {
		e := newPermEnv(t)
		require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
		seedPerm(t, e.db, false)
		audit.SetSealSchemeForTest(e.svc, model.AggSchemeV3)
		require.NoError(t, e.svc.EnsureGenesis())
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_reconciled = true WHERE seq = 1`).Error)
		rec := audit.NewRoleStateReconciler(e.db, nil)
		rec.SetPermissionAttestSigner(e.signer)
		v := audit.NewCheckpointVerifier(e.db, e.svc, audit.NewCheckpointPurger(e.db, e.signer), nil, nil)
		v.SetRoleStateReconciler(rec)
		rep, err := v.VerifyChain()
		require.NoError(t, err)
		require.Equal(t, audit.IntervalStatusAttestationInvalid, rep.Status)
		lin, err := audit.ReadPermissionLineageForTest(e.db, e.signer)
		require.NoError(t, err)
		require.False(t, lin.Clean, "帶附證痕跡的第三版點使起點不成立")
		require.Contains(t, lin.Reason, "第四版之前的檢查點帶附證欄 1 點")
	})

	t.Run("彙整：舊封章與附證分別標明", func(t *testing.T) {
		sum, err := audit.SummarizePermissionAttestations(e.db, e.signer)
		require.NoError(t, err)
		require.Equal(t, 1, sum.Valid)
		require.Equal(t, 1, sum.NotCover)
		require.True(t, sum.Covered)
	})
}
