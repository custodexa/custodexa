package audit_test

import (
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// 第二版修剪錨：以簽章帶走被剪段的累計權限事實，並承接前一錨。
//
// 累計單調（none < attested < unverified）；只承接驗過章且接得上現存鏈頭的前錨，缺錨、壞錨、
// 換錨、未知格式一律保守帶 unverified；錨值取自簽章可驗的邊界；簽章失敗整筆回滾。

type trimEnv struct {
	*permEnv
	p *audit.CheckpointPurger
}

var trimPast = time.Now().UTC().Add(-72 * time.Hour)

func newTrimEnv(t *testing.T) *trimEnv {
	e := newPermEnv(t)
	require.NoError(t, e.db.AutoMigrate(&model.AuditCheckpointTrim{}))
	seedPerm(t, e.db, false)
	return &trimEnv{permEnv: e, p: audit.NewCheckpointPurger(e.db, e.signer)}
}

// sealV3 以第三版封章器封 n 點（含 genesis 時先建 genesis），封章時刻在過去（可修剪）。
func (e *trimEnv) sealV3(t *testing.T, n int) {
	audit.SetPermissionSources(nil, nil)
	audit.SetSealSchemeForTest(e.svc, model.AggSchemeV3)
	audit.SetSealClockForTest(e.svc, trimPast)
	for i := 0; i < n; i++ {
		if e.count(t, "audit_checkpoints") == 0 {
			require.NoError(t, e.svc.EnsureGenesis())
			continue
		}
		_, err := e.svc.SealNow()
		require.NoError(t, err)
	}
	audit.SetSealSchemeForTest(e.svc, "")
	newPermDBWire(t)
}

// sealV4 以現行封章器封 n 點；past 為真時封章時刻在過去。
func (e *trimEnv) sealV4(t *testing.T, n int, past bool) {
	at := time.Now().UTC()
	if past {
		at = trimPast
	}
	audit.SetSealClockForTest(e.svc, at)
	for i := 0; i < n; i++ {
		if e.count(t, "audit_checkpoints") == 0 {
			require.NoError(t, e.svc.EnsureGenesis())
			continue
		}
		_, err := e.svc.SealNow()
		require.NoError(t, err)
	}
}

func (e *trimEnv) trim(t *testing.T) *model.AuditCheckpointTrim {
	t.Helper()
	_, trim, err := e.p.TrimChain(1)
	require.NoError(t, err)
	require.NotNil(t, trim, "應有到期的點被剪")
	ok, err := e.p.VerifyTrim(trim)
	require.NoError(t, err)
	require.True(t, ok, "錨簽章有效")
	return trim
}

func (e *trimEnv) latestTrim(t *testing.T) model.AuditCheckpointTrim {
	var tr model.AuditCheckpointTrim
	require.NoError(t, e.db.Order("last_trimmed_seq DESC").First(&tr).Error)
	return tr
}

// 讓還在鏈上、尚未到期的點也到期（把封章時刻改到過去；sealed_at 在簽章內，故重簽）。
func (e *trimEnv) ageAll(t *testing.T) {
	var cps []model.AuditCheckpoint
	require.NoError(t, e.db.Order("seq").Find(&cps).Error)
	for i := range cps {
		cp := &cps[i]
		cp.SealedAt = trimPast
		if i > 0 {
			link, err := audit.CheckpointLinkHash(&cps[i-1])
			require.NoError(t, err)
			cp.PrevCheckpointHash = link
		}
		payload, err := audit.CheckpointSignBytes(cp)
		require.NoError(t, err)
		_, cp.Signature = e.signer.Sign(payload)
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET sealed_at = ?, prev_checkpoint_hash = ?, signature = ? WHERE seq = ?`,
			cp.SealedAt, cp.PrevCheckpointHash, cp.Signature, cp.Seq).Error)
	}
}

func TestCheckpointTrimPermHistory(t *testing.T) {
	t.Run("累計單調：舊鏈段 none → 含附證段 attested → 含驗不過點 unverified → 之後全有效段仍 unverified 且本次計數 0", func(t *testing.T) {
		e := newTrimEnv(t)
		e.sealV3(t, 3)
		e.sealV4(t, 1, false)
		tr := e.trim(t) // 剪 v3 段（seq 1–3）
		require.Equal(t, model.CheckpointTrimFormatV2, tr.Format)
		require.Equal(t, model.TrimPermHistoryNone, *tr.PermHistory, "第三版段無附證")
		require.Zero(t, *tr.UnverifiedCount)

		e.sealV4(t, 2, false)
		e.ageAll(t)
		e.sealV4(t, 1, false)
		tr = e.trim(t)
		require.Equal(t, model.TrimPermHistoryAttested, *tr.PermHistory, "被剪段曾有附證")

		e.sealV4(t, 2, false)
		e.ageAll(t)
		var head model.AuditCheckpoint
		require.NoError(t, e.db.Order("seq ASC").First(&head).Error)
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_reconciled = false WHERE seq = ?`, head.Seq+1).Error)
		e.sealV4(t, 1, false)
		tr = e.trim(t)
		require.Equal(t, model.TrimPermHistoryUnverified, *tr.PermHistory, "被剪段有驗不過的點")
		require.EqualValues(t, 1, *tr.UnverifiedCount)

		e.sealV4(t, 2, false)
		e.ageAll(t)
		e.sealV4(t, 1, false)
		tr = e.trim(t)
		require.Equal(t, model.TrimPermHistoryUnverified, *tr.PermHistory, "承接前錨，不回退")
		require.Zero(t, *tr.UnverifiedCount, "只計本次")
	})

	// 前錨被動過：錨記載的歷史證明不了，新錨一律帶 unverified
	tamperPrev := map[string]func(t *testing.T, e *trimEnv){
		"刪前錨": func(t *testing.T, e *trimEnv) {
			require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoint_trims`).Error)
		},
		"改前錨的累計事實": func(t *testing.T, e *trimEnv) {
			require.NoError(t, e.db.Exec(`UPDATE audit_checkpoint_trims SET perm_history = 'none'`).Error)
		},
		"前錨改成未知格式": func(t *testing.T, e *trimEnv) {
			require.NoError(t, e.db.Exec(`UPDATE audit_checkpoint_trims SET format = 7`).Error)
		},
		"最新錨被刪、留下不接鏈頭的較早有效錨": func(t *testing.T, e *trimEnv) {
			// 再剪一次，留下兩個錨，刪掉最新的那個
			e.sealV4(t, 1, false)
			e.ageAll(t)
			e.sealV4(t, 1, false)
			e.trim(t)
			tr := e.latestTrim(t)
			require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoint_trims WHERE id = ?`, tr.ID).Error)
		},
	}
	for name, tamper := range tamperPrev {
		t.Run("前錨承接："+name+"→新錨 unverified", func(t *testing.T) {
			e := newTrimEnv(t)
			e.sealV4(t, 3, true)
			e.sealV4(t, 1, false)
			tr := e.trim(t)
			require.Equal(t, model.TrimPermHistoryAttested, *tr.PermHistory)
			tamper(t, e)
			e.sealV4(t, 1, false)
			e.ageAll(t)
			e.sealV4(t, 1, false)
			tr = e.trim(t)
			require.Equal(t, model.TrimPermHistoryUnverified, *tr.PermHistory, "證明不了前一段歷史")
			require.Zero(t, *tr.UnverifiedCount, "本段全有效")
		})
	}

	t.Run("最後被剪點驗不過、新鏈頭驗得過：錨值取新鏈頭簽章內的 prev、計數 1", func(t *testing.T) {
		e := newTrimEnv(t)
		e.sealV4(t, 3, true)
		e.sealV4(t, 1, false)
		var cps []model.AuditCheckpoint
		require.NoError(t, e.db.Order("seq").Find(&cps).Error)
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_reconciled = false WHERE seq = 3`).Error)
		tr := e.trim(t)
		require.EqualValues(t, 3, tr.LastTrimmedSeq)
		require.Equal(t, cps[3].PrevCheckpointHash, tr.LastTrimmedLinkHash, "錨值取新鏈頭簽章內的 prev")
		require.EqualValues(t, 1, *tr.UnverifiedCount)
		require.Equal(t, model.TrimPermHistoryUnverified, *tr.PermHistory)
		rec, _ := permRec(e.permEnv)
		v := audit.NewCheckpointVerifier(e.db, e.svc, e.p, nil, nil)
		v.SetRoleStateReconciler(rec)
		rep, err := v.VerifyChain()
		require.NoError(t, err)
		require.Equal(t, audit.IntervalStatusPassed, rep.Status, "殘鏈接在有效錨後")
		require.Equal(t, model.TrimPermHistoryUnverified, rep.TrimmedPermHistory)
	})

	t.Run("最後被剪點與新鏈頭皆驗不過：本輪不剪", func(t *testing.T) {
		e := newTrimEnv(t)
		e.sealV4(t, 4, true)
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_reconciled = false WHERE seq IN (3, 4)`).Error)
		e.sealV4(t, 1, false)
		// seq 1–4 到期；最後可剪點為 4（驗不過），新鏈頭 5 驗得過 → 取 5 的 prev。改讓 5 也驗不過：
		require.NoError(t, e.db.Exec(`UPDATE audit_checkpoints SET perm_reconciled = false WHERE seq = 5`).Error)
		n, tr, err := e.p.TrimChain(1)
		require.NoError(t, err)
		require.Zero(t, n)
		require.Nil(t, tr)
		require.EqualValues(t, 5, e.count(t, "audit_checkpoints"), "檢查點仍在")
	})

	t.Run("錨簽章失敗：整筆回滾、檢查點仍在、無錨", func(t *testing.T) {
		e := newTrimEnv(t)
		e.sealV4(t, 3, true)
		e.sealV4(t, 1, false)
		p := audit.NewCheckpointPurger(e.db, trimFailingSigner{e.signer})
		_, tr, err := p.TrimChain(1)
		require.Error(t, err)
		require.Nil(t, tr)
		require.EqualValues(t, 4, e.count(t, "audit_checkpoints"))
		require.Zero(t, e.count(t, "audit_checkpoint_trims"))
	})

	t.Run("第二版錨的載荷 golden 與 format 分派", func(t *testing.T) {
		h, n := model.TrimPermHistoryAttested, int64(2)
		tr := &model.AuditCheckpointTrim{FromSeq: 1, LastTrimmedSeq: 3, TrimmedCount: 3, LastTrimmedLinkHash: strings.Repeat("a", 64),
			GenesisIDFrom: 5, PolicyDays: 30, TrimmedAt: time.Unix(1, 0).UTC(), Format: model.CheckpointTrimFormatV2, PermHistory: &h, UnverifiedCount: &n}
		got, err := audit.CheckpointTrimSignBytes(tr)
		require.NoError(t, err)
		require.Equal(t, `{"kind":"checkpoint_trim_v2","from_seq":1,"last_trimmed_seq":3,"trimmed_count":3,"last_trimmed_link_hash":"`+
			strings.Repeat("a", 64)+`","genesis_id_from":5,"policy_days":30,"trimmed_at_us":1000000,"perm_history":"attested","unverified_count":2}`, string(got))
		tr.Format = model.CheckpointTrimFormatV1
		got, err = audit.CheckpointTrimSignBytes(tr)
		require.NoError(t, err)
		require.Equal(t, `{"kind":"checkpoint_trim","from_seq":1,"last_trimmed_seq":3,"trimmed_count":3,"last_trimmed_link_hash":"`+
			strings.Repeat("a", 64)+`","genesis_id_from":5,"policy_days":30,"trimmed_at_us":1000000}`, string(got), "第一版位元組不變")
		for _, bad := range []func(){
			func() { tr.Format = 0 },
			func() { tr.Format = 7 },
			func() { tr.Format = model.CheckpointTrimFormatV2; tr.PermHistory = nil },
			func() { tr.Format = model.CheckpointTrimFormatV2; x := "maybe"; tr.PermHistory = &x },
			func() { tr.Format = model.CheckpointTrimFormatV2; tr.PermHistory = &h; m := int64(-1); tr.UnverifiedCount = &m },
		} {
			bad()
			_, err := audit.CheckpointTrimSignBytes(tr)
			require.ErrorIs(t, err, audit.ErrCheckpointPayloadInvalid)
		}
	})

	// 讀取端契約：殘鏈全有效、無附證欄、事件表空，最新錨驗過且接得上鏈頭但記載 unverified——
	// 在現行封章不變量下這個形狀不會自然出現（啟用後每個新點都帶附證），所以修剪歷史在讀取端是
	// 冗餘防線；本子測試直接建構輸入，斷言它仍讓起點不成立。
	t.Run("讀取端契約：錨記載曾有驗不過的點時起點不成立", func(t *testing.T) {
		e := newTrimEnv(t)
		e.sealV3(t, 3)
		var cps []model.AuditCheckpoint
		require.NoError(t, e.db.Order("seq").Find(&cps).Error)
		link, err := audit.CheckpointLinkHash(&cps[0])
		require.NoError(t, err)
		h, n := model.TrimPermHistoryUnverified, int64(1)
		tr := &model.AuditCheckpointTrim{FromSeq: 1, LastTrimmedSeq: 1, TrimmedCount: 1, LastTrimmedLinkHash: link,
			GenesisIDFrom: cps[0].IDFrom, PolicyDays: 1, TrimmedAt: time.Now().UTC().Truncate(time.Microsecond),
			Format: model.CheckpointTrimFormatV2, PermHistory: &h, UnverifiedCount: &n}
		payload, err := audit.CheckpointTrimSignBytes(tr)
		require.NoError(t, err)
		tr.SigningKeyVersion, tr.Signature = e.signer.Sign(payload)
		require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoints WHERE seq = 1`).Error)
		require.NoError(t, e.db.Create(tr).Error)
		lin, err := audit.ReadPermissionLineageForTest(e.db, e.signer)
		require.NoError(t, err)
		require.Equal(t, model.TrimPermHistoryUnverified, lin.TrimHistory)
		require.False(t, lin.Clean, "修剪歷史不是 none：不能自動建立乾淨起點")
		require.Contains(t, lin.Reason, "修剪錨記載曾有驗不過的點")
		// 對照：同一形狀但錨記載 none → 起點成立（證明本子測試只差在修剪歷史）
		require.NoError(t, e.db.Exec(`DELETE FROM audit_checkpoint_trims`).Error)
		none := model.TrimPermHistoryNone
		tr.ID, tr.PermHistory = 0, &none
		payload, err = audit.CheckpointTrimSignBytes(tr)
		require.NoError(t, err)
		tr.SigningKeyVersion, tr.Signature = e.signer.Sign(payload)
		require.NoError(t, e.db.Create(tr).Error)
		lin, err = audit.ReadPermissionLineageForTest(e.db, e.signer)
		require.NoError(t, err)
		require.True(t, lin.Clean)
	})
}

// trimFailingSigner 對修剪錨載荷回簽章失敗（版本 0），其他照常。
type trimFailingSigner struct{ inner *permFakeSigner }

func (s trimFailingSigner) ActiveVersion() int { return s.inner.ActiveVersion() }
func (s trimFailingSigner) Sign(data []byte) (int, string) {
	if strings.Contains(string(data), `"kind":"checkpoint_trim`) {
		return 0, ""
	}
	return s.inner.Sign(data)
}
func (s trimFailingSigner) Verify(v int, data []byte, sig string) (bool, error) {
	return s.inner.Verify(v, data, sig)
}

var _ = gorm.ErrRecordNotFound
