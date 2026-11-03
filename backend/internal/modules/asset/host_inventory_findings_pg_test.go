package asset

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit/port"
)

// 盤點結果的讀取、處置與告警（PostgreSQL）。

const invPasswdDeploy = "root:x:0:0:root:/root:/bin/sh\ndeploy:x:0:1001:Linux User:/home/deploy:/bin/sh\nops:x:1000:1000:Linux User:/home/ops:/bin/sh\n"

func TestInventoryRead(t *testing.T) {
	e := newInvEnv(t)
	e.tg.setStandard("0\n", invPasswdDeploy, stdGroup, sudoFrames(false, nil, "absent"))
	assetID, _ := e.asset("rd1")
	require.Equal(t, model.HostAccountScanSucceeded, e.runScan(assetID).Status)

	t.Run("盤點後新增同名帳號不重盤即顯示已納管", func(t *testing.T) {
		view, err := e.svc.GetAssetInventory(assetID, InventoryFindingQuery{})
		require.NoError(t, err)
		managedOf := func(v *AssetInventoryView, user string) bool {
			for _, f := range v.Findings {
				if f.Username == user {
					return f.Managed
				}
			}
			t.Fatalf("找不到 %s", user)
			return false
		}
		assert.False(t, managedOf(view, "deploy"))
		assert.NotEmpty(t, view.FixedNotes)
		assert.NotEmpty(t, view.Coverage)
		require.NoError(t, e.db.Create(&model.AssetAccount{AssetID: assetID, CredentialID: 1, Username: "deploy"}).Error)
		view, err = e.svc.GetAssetInventory(assetID, InventoryFindingQuery{})
		require.NoError(t, err)
		assert.True(t, managedOf(view, "deploy"))
		var scans int64
		e.db.Model(&model.HostAccountScan{}).Where("asset_id = ?", assetID).Count(&scans)
		assert.EqualValues(t, 1, scans, "未重新盤點")
		require.NoError(t, e.db.Where("asset_id = ? AND username = ?", assetID, "deploy").Delete(&model.AssetAccount{}).Error)
	})
	t.Run("範圍外資產的結果不出現", func(t *testing.T) {
		other, _ := e.asset("rd2")
		require.Equal(t, model.HostAccountScanSucceeded, e.runScan(other).Status)
		g, err := e.svc.ListGlobalFindings(InventoryGlobalQuery{AllowedAssetIDs: []uint{assetID}})
		require.NoError(t, err)
		require.NotEmpty(t, g.Findings)
		for _, f := range g.Findings {
			assert.Equal(t, assetID, f.AssetID)
		}
		g, err = e.svc.ListGlobalFindings(InventoryGlobalQuery{AllowedAssetIDs: []uint{}})
		require.NoError(t, err)
		assert.Empty(t, g.Findings, "無可檢視資產時為空")
	})
	t.Run("EXPLAIN全域預設篩選用到部分索引", func(t *testing.T) {
		var lines []string
		err := e.db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec("SET LOCAL enable_seqscan = off").Error; err != nil {
				return err
			}
			stmt := globalFindingsQuery(tx.Session(&gorm.Session{DryRun: true}), InventoryGlobalQuery{}).Find(&[]findingRow{}).Statement
			sql := tx.Dialector.Explain(stmt.SQL.String(), stmt.Vars...)
			return tx.Raw("EXPLAIN " + sql).Scan(&lines).Error
		})
		require.NoError(t, err)
		plan := strings.Join(lines, "\n")
		fmt.Println("EVIDENCE explain_global_default:\n" + plan)
		assert.Contains(t, plan, "idx_host_account_findings_open_privileged")
	})
	t.Run("刪除資產後全域清單不含其結果", func(t *testing.T) {
		require.NoError(t, e.db.Delete(&model.Asset{}, assetID).Error)
		g, err := e.svc.ListGlobalFindings(InventoryGlobalQuery{})
		require.NoError(t, err)
		for _, f := range g.Findings {
			assert.NotEqual(t, assetID, f.AssetID)
		}
	})
}

const invGroupWheel = "root:x:0:root\nwheel:x:10:svc1\nsudo:x:27:\nops:x:1000:\n"
const invGroupWheelSudo = "root:x:0:root\nwheel:x:10:svc1\nsudo:x:27:svc1\nops:x:1000:\n"
const invGroupSudoOnly = "root:x:0:root\nwheel:x:10:\nsudo:x:27:svc1\nops:x:1000:\n"
const invPasswdSvc1 = "root:x:0:0:root:/root:/bin/sh\nsvc1:x:1500:1500:Linux User:/home/svc1:/bin/sh\n"

func TestInventoryIgnoreReopen(t *testing.T) {
	setup := func(t *testing.T, group string) (*invEnv, uint, model.HostAccountFinding) {
		e := newInvEnv(t)
		e.tg.setStandard("0\n", invPasswdSvc1, group, sudoFrames(false, nil, "absent"))
		assetID, _ := e.asset("ig")
		require.Equal(t, model.HostAccountScanSucceeded, e.runScan(assetID).Status)
		return e, assetID, e.finding(assetID, "svc1")
	}
	t.Run("忽略需要理由", func(t *testing.T) {
		e, assetID, f := setup(t, invGroupWheel)
		for _, r := range []string{"", "   ", "a\x07b", strings.Repeat("字", 501)} {
			_, err := e.svc.IgnoreFinding(assetID, f.ID, r, invAdmin)
			assert.ErrorIs(t, err, ErrInventoryIgnoreReason)
		}
		assert.Equal(t, model.HostAccountFindingOpen, e.finding(assetID, "svc1").Status)
	})
	t.Run("被加入新群組時重新開啟", func(t *testing.T) {
		e, assetID, f := setup(t, invGroupWheel)
		_, err := e.svc.IgnoreFinding(assetID, f.ID, "  服務帳號  ", invAdmin)
		require.NoError(t, err)
		got := e.finding(assetID, "svc1")
		require.Equal(t, model.HostAccountFindingIgnored, got.Status)
		assert.Equal(t, "服務帳號", got.IgnoreReason)
		assert.Equal(t, got.PrivilegedReasons, got.IgnoredReasons, "忽略當下的理由快照")
		e.tg.setStandard("0\n", invPasswdSvc1, invGroupWheelSudo, sudoFrames(false, nil, "absent"))
		s := e.runScan(assetID)
		assert.Equal(t, model.HostAccountFindingOpen, e.finding(assetID, "svc1").Status)
		assert.Equal(t, 1, s.ReopenedTotal)
		var ig []model.AuditLog
		require.NoError(t, e.db.Where("action = ? AND resource_id = ?", model.ActionInventoryIgnore, f.ID).Find(&ig).Error)
		require.Len(t, ig, 1, "忽略紀錄保留在審計中")
		raw, err := json.Marshal(ig[0])
		require.NoError(t, err)
		assert.Contains(t, string(raw), "服務帳號", "忽略的審計含理由")
	})
	t.Run("理由減少不重開", func(t *testing.T) {
		e, assetID, f := setup(t, invGroupWheelSudo)
		_, err := e.svc.IgnoreFinding(assetID, f.ID, "服務帳號", invAdmin)
		require.NoError(t, err)
		e.tg.setStandard("0\n", invPasswdSvc1, invGroupSudoOnly, sudoFrames(false, nil, "absent"))
		s := e.runScan(assetID)
		assert.Equal(t, model.HostAccountFindingIgnored, e.finding(assetID, "svc1").Status)
		assert.Equal(t, 0, s.ReopenedTotal)
	})
	t.Run("消失後又出現時重新開啟", func(t *testing.T) {
		e, assetID, f := setup(t, invGroupWheel)
		_, err := e.svc.IgnoreFinding(assetID, f.ID, "服務帳號", invAdmin)
		require.NoError(t, err)
		e.tg.setStandard("0\n", stdAccountList, invGroupWheel, sudoFrames(false, nil, "absent"))
		e.runScan(assetID)
		gone := e.finding(assetID, "svc1")
		assert.False(t, gone.Present)
		assert.Equal(t, f.LastSeenScanID, gone.LastSeenScanID, "最近出現仍為上一次")
		e.tg.setStandard("0\n", invPasswdSvc1, invGroupWheel, sudoFrames(false, nil, "absent"))
		e.runScan(assetID)
		back := e.finding(assetID, "svc1")
		assert.True(t, back.Present)
		assert.Equal(t, model.HostAccountFindingOpen, back.Status)
	})
	t.Run("手動重新開啟", func(t *testing.T) {
		e, assetID, f := setup(t, invGroupWheel)
		_, err := e.svc.IgnoreFinding(assetID, f.ID, "服務帳號", invAdmin)
		require.NoError(t, err)
		_, err = e.svc.ReopenFinding(assetID, f.ID, invAdmin)
		require.NoError(t, err)
		assert.Equal(t, model.HostAccountFindingOpen, e.finding(assetID, "svc1").Status)
	})
	t.Run("他資產的結果視為不存在", func(t *testing.T) {
		e, _, f := setup(t, invGroupWheel)
		otherID, _ := e.asset("ig-other")
		_, err := e.svc.IgnoreFinding(otherID, f.ID, "服務帳號", invAdmin)
		assert.ErrorIs(t, err, ErrInventoryFindingNotFound)
		_, err = e.svc.IgnoreFinding(otherID, 999999, "服務帳號", invAdmin)
		assert.ErrorIs(t, err, ErrInventoryFindingNotFound)
		_, err = e.svc.ReopenFinding(otherID, f.ID, invAdmin)
		assert.ErrorIs(t, err, ErrInventoryFindingNotFound)
	})
	t.Run("審計寫入失敗時忽略不生效", func(t *testing.T) {
		e, assetID, f := setup(t, invGroupWheel)
		e.audits.fail = string(model.ActionInventoryIgnore)
		_, err := e.svc.IgnoreFinding(assetID, f.ID, "服務帳號", invAdmin)
		require.Error(t, err)
		assert.Equal(t, model.HostAccountFindingOpen, e.finding(assetID, "svc1").Status)
	})
}

const invPasswdAliceBob = "root:x:0:0:root:/root:/bin/sh\nalice:x:0:1001:Linux User:/home/alice:/bin/sh\nbob:x:0:1002:Linux User:/home/bob:/bin/bash\nsync:x:5:0:sync:/bin:/bin/sync\n"

func TestInventoryAlert(t *testing.T) {
	newCount := func(ev port.SystemAlertEvent) string { return ev.Params["new_count"] }
	t.Run("首次盤點發現兩個未納管特權帳號且sync不告警", func(t *testing.T) {
		e := newInvEnv(t)
		e.tg.setStandard("0\n", invPasswdAliceBob, stdGroup, sudoFrames(false, nil, "absent"))
		assetID, _ := e.asset("al1")
		s := e.runScan(assetID)
		require.Equal(t, model.HostAccountScanSucceeded, s.Status)
		require.Equal(t, 1, e.alerts.count())
		ev := e.alerts.events[0]
		assert.Equal(t, port.SystemAlertUnmanagedPrivilegedAccount, ev.Type)
		assert.Equal(t, "2", newCount(ev))
		assert.Equal(t, "default_account", ev.Params["identity_mode"])
		assert.Equal(t, uint(1), ev.Actor.UserID, "操作者為發起者")
		sync := e.finding(assetID, "sync")
		assert.True(t, sync.Privileged)
		assert.False(t, sync.LoginCapable)
		assert.False(t, sync.Alerted)

		t.Run("重複盤點不重複告警", func(t *testing.T) {
			e.runScan(assetID)
			assert.Equal(t, 1, e.alerts.count())
		})
	})
	t.Run("上一次結束時已納管這一次未納管則告警", func(t *testing.T) {
		e := newInvEnv(t)
		e.tg.setStandard("0\n", invPasswdAliceBob, stdGroup, sudoFrames(false, nil, "absent"))
		assetID, _ := e.asset("al2")
		for _, u := range []string{"alice", "bob"} {
			require.NoError(t, e.db.Create(&model.AssetAccount{AssetID: assetID, CredentialID: 1, Username: u}).Error)
		}
		e.runScan(assetID)
		assert.Equal(t, 0, e.alerts.count(), "全部已納管不告警")
		require.NoError(t, e.db.Where("asset_id = ? AND username = ?", assetID, "alice").Delete(&model.AssetAccount{}).Error)
		e.runScan(assetID)
		require.Equal(t, 1, e.alerts.count())
		assert.Equal(t, "1", newCount(e.alerts.events[0]))
	})
	t.Run("告警寫入失敗時結果與審計都未寫入", func(t *testing.T) {
		e := newInvEnv(t)
		e.tg.setStandard("0\n", invPasswdAliceBob, stdGroup, sudoFrames(false, nil, "absent"))
		assetID, _ := e.asset("al3")
		e.alerts.fail = true
		s := e.runScan(assetID)
		assert.Equal(t, model.HostAccountScanFailed, s.Status)
		assert.Equal(t, model.InventoryPersistFailed, s.FailureReason)
		assert.Empty(t, e.findings(assetID), "結果未寫入")
		var done []model.AuditLog
		require.NoError(t, e.db.Where("action = ? AND resource_id = ?", model.ActionInventoryScanDone, s.ID).Find(&done).Error)
		require.Len(t, done, 1, "只有失敗結束的審計")
		assert.Contains(t, done[0].Details, `"status":"failed"`)
		assert.Contains(t, done[0].Details, model.InventoryPersistFailed)
	})
}

func TestInventoryHostKeyMismatchRefused(t *testing.T) {
	e := newInvEnv(t)
	require.NoError(t, e.db.AutoMigrate(&model.AssetHostKey{}, &model.AssetHostKeyMismatch{}, &model.User{}))
	hk := NewHostKeyService(e.db)
	hk.SetAuditTxSink(e.audits)
	hk.SetSystemAlertSink(e.alerts)
	e.svc.hostKeys = hk
	e.svc.hostKeyFor = func(dc HostKeyDialContext) ssh.HostKeyCallback {
		cb, _ := hk.CallbackFor(dc)
		return cb
	}
	assetID, _ := e.asset("hk1")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	other, err := ssh.NewSignerFromKey(priv)
	require.NoError(t, err)
	host, port := splitHostPortT(t, e.tg.addr())
	pub := other.PublicKey()
	require.NoError(t, e.db.Create(&model.AssetHostKey{AssetID: assetID, Algorithm: pub.Type(),
		Fingerprint: ssh.FingerprintSHA256(pub), PublicKey: base64.StdEncoding.EncodeToString(pub.Marshal()),
		Host: host, Port: port, TrustGeneration: 1}).Error)

	s := e.runScan(assetID)
	assert.Equal(t, model.HostAccountScanFailed, s.Status)
	assert.Equal(t, model.InventoryHostKeyMismatch, s.FailureReason)
	assert.Empty(t, e.findings(assetID), "無結果寫入")
	e.tg.mu.Lock()
	pw, pk := e.tg.pwCalls, e.tg.pkCalls
	e.tg.mu.Unlock()
	assert.Zero(t, pw, "靶機未收到密碼認證嘗試")
	assert.Zero(t, pk, "靶機未收到公鑰認證嘗試")
	var logs []model.AuditLog
	require.NoError(t, e.db.Where("action = ? AND asset_id = ?", model.ActionHostKeyMismatch, assetID).Find(&logs).Error)
	require.Len(t, logs, 1)
	assert.Contains(t, logs[0].Details, `"outcome":"refused"`)
	assert.Contains(t, logs[0].Details, `"path":"account_inventory"`)
	assert.False(t, HostKeyPathAccountInventory.Interactive())
}

// 結束審計只記計數與檢查範圍，不列帳號名；盤點過程的日誌不含登入密碼與帳號說明欄。
func TestInventoryScanDoneAuditOmitsNames(t *testing.T) {
	const secret = "Inv-Probe-Secret-7c41e9"
	names := []string{"zed-ops-admin", "quill-deployer", "marlow-backup"}
	passwd := "root:x:0:0:root:/root:/bin/sh\n"
	for i, n := range names {
		passwd += fmt.Sprintf("%s:x:0:%d:Gecos Probe %d:/home/%s:/bin/sh\n", n, 2001+i, i, n)
	}
	e := newInvEnv(t)
	e.tg.password = secret
	main := "zed-ops-admin ALL=(ALL) ALL\n%wheel ALL=(ALL) ALL\n"
	e.tg.setStandard("0\n", passwd, stdGroup, sudoFrames(true, &main, "absent"))
	assetID, accID := e.asset("names")
	e.secrets.set(accID, secret)

	var accountsBefore int64
	require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("asset_id = ?", assetID).Count(&accountsBefore).Error)

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	s := e.runScan(assetID)
	log.SetOutput(prev)

	require.Equal(t, model.HostAccountScanSucceeded, s.Status)
	assert.Equal(t, "root,sudo,wheel,admin", e.scan(s.ID).PrivilegedGroups, "盤點紀錄存特權群組政策快照")
	var accountsAfter int64
	require.NoError(t, e.db.Model(&model.AssetAccount{}).Where("asset_id = ?", assetID).Count(&accountsAfter).Error)
	assert.Equal(t, accountsBefore, accountsAfter, "盤點不建立資產帳號")
	for _, n := range names {
		require.NotEmpty(t, e.finding(assetID, n).Username, "結果列有 %s，確認審計比對有對象", n)
	}
	var rows []model.AuditLog
	require.NoError(t, e.db.Where("action IN ?", []model.AuditAction{model.ActionInventoryScan, model.ActionInventoryScanDone}).Find(&rows).Error)
	var done int
	for _, r := range rows {
		if r.Action == model.ActionInventoryScanDone {
			done++
		}
		raw, err := json.Marshal(r)
		require.NoError(t, err)
		for _, n := range append(names, "root", "Gecos Probe", secret) {
			assert.NotContains(t, string(raw), n, "審計 %s 不得含 %q", r.Action, n)
		}
	}
	require.Equal(t, 1, done, "有一筆結束審計")
	assert.NotContains(t, logs.String(), secret, "日誌不含登入密碼")
	assert.NotContains(t, logs.String(), "Gecos Probe", "日誌不含帳號說明欄")

	// 成功路徑不寫日誌；另走一次登入失敗（送出的仍是同一組密碼），讓日誌真的有內容再檢查。
	e.tg.password = "Inv-Other-Password"
	var failLogs bytes.Buffer
	log.SetOutput(&failLogs)
	fs := e.runScan(assetID)
	log.SetOutput(prev)
	require.Equal(t, model.HostAccountScanFailed, fs.Status)
	require.Contains(t, failLogs.String(), "[HostAccountInventory]", "失敗路徑有日誌可檢查")
	assert.NotContains(t, failLogs.String(), secret, "日誌不含送出的密碼")
	assert.NotContains(t, failLogs.String(), "Gecos Probe", "日誌不含帳號說明欄")
	t.Logf("EVIDENCE audit_rows=%d log_bytes=%d fail_log_bytes=%d", len(rows), logs.Len(), failLogs.Len())
}

// 系統預設帳號 halt、sync（主要群組 root、不可登入）與在 sudo 群組的不能登入帳號 svcsudo。
const invPasswdRoutine = "root:x:0:0:root:/root:/bin/sh\nalice:x:1001:1001:Linux User:/home/alice:/bin/sh\n" +
	"halt:x:7:0:halt:/sbin:/sbin/halt\nsync:x:5:0:sync:/bin:/bin/sync\nsvcsudo:x:1600:1600:svc:/home/svcsudo:/usr/sbin/nologin\n"
const invGroupRoutine = "root:x:0:root\nsudo:x:27:alice,svcsudo\nalice:x:1001:\nsvcsudo:x:1600:\n"

func TestInventoryRoutineSystemAccountsNotActionable(t *testing.T) {
	e := newInvEnv(t)
	e.tg.setStandard("0\n", invPasswdRoutine, invGroupRoutine, sudoFrames(false, nil, "absent"))
	assetID, _ := e.asset("rt1") // 預設帳號 root 已納管
	s := e.runScan(assetID)
	require.Equal(t, model.HostAccountScanSucceeded, s.Status)
	names := func(fs []InventoryFindingView) []string {
		out := make([]string, 0, len(fs))
		for _, f := range fs {
			out = append(out, f.Username)
		}
		return out
	}
	yes, no := true, false

	t.Run("特權數照算、未納管特權數不計系統預設帳號", func(t *testing.T) {
		assert.Equal(t, 5, s.PrivilegedTotal, "root、alice、halt、sync、svcsudo")
		assert.Equal(t, 2, s.UnmanagedPrivilegedTotal, "alice、svcsudo")
	})
	t.Run("需要處理不含系統預設帳號、含在sudo群組的不能登入帳號", func(t *testing.T) {
		v, err := e.svc.GetAssetInventory(assetID, InventoryFindingQuery{Privileged: &yes, Managed: &no, Present: &yes, Status: model.HostAccountFindingOpen, Actionable: true})
		require.NoError(t, err)
		assert.Equal(t, []string{"alice", "svcsudo"}, names(v.Findings))
		assert.EqualValues(t, 2, v.Total)
	})
	t.Run("全部特權帳號仍列出系統預設帳號", func(t *testing.T) {
		v, err := e.svc.GetAssetInventory(assetID, InventoryFindingQuery{Privileged: &yes, Present: &yes})
		require.NoError(t, err)
		assert.Equal(t, []string{"alice", "halt", "root", "svcsudo", "sync"}, names(v.Findings))
	})
	t.Run("全域待處理清單不含系統預設帳號", func(t *testing.T) {
		g, err := e.svc.ListGlobalFindings(InventoryGlobalQuery{AllowedAssetIDs: []uint{assetID}})
		require.NoError(t, err)
		assert.Equal(t, []string{"alice", "svcsudo"}, names(g.Findings))
	})
	t.Run("告警新增數不計系統預設帳號與不能登入帳號", func(t *testing.T) {
		require.Equal(t, 1, e.alerts.count())
		assert.Equal(t, "1", e.alerts.events[0].Params["new_count"], "只有 alice")
		assert.False(t, e.finding(assetID, "halt").Alerted)
		assert.False(t, e.finding(assetID, "svcsudo").Alerted)
	})
}
