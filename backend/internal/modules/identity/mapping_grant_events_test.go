package identity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/audit/port"
	"github.com/custodexa/backend/internal/modules/authz"
)

// 映射授權變更事件夾具：映射守衛夾具加上授權變更分級（真實審計落地面＋記錄用告警落地面）。

type mappingEventEnv struct {
	*mappingGuardEnv
	alerts  *recordingAlertSink
	preview *fakeImpactPreview
}

type fakeImpactPreview struct {
	got  []MappingImpact
	fail bool
}

func (f *fakeImpactPreview) ObserveMappingImpact(_ *gorm.DB, in MappingImpact) error {
	if f.fail {
		return errors.New("注入的預覽輸入失敗")
	}
	f.got = append(f.got, in)
	return nil
}

func newMappingEventEnv(t *testing.T) *mappingEventEnv {
	t.Helper()
	g := newMappingGuardEnv(t, true)
	require.NoError(t, g.db.AutoMigrate(&model.UserGroupMember{}, &model.UserRoleMappingRuleSupport{}))
	env := &mappingEventEnv{mappingGuardEnv: g, alerts: &recordingAlertSink{}, preview: &fakeImpactPreview{}}
	grader := NewGrantGrader(audit.NewTxSink(), env.alerts)
	grader.SetMappingImpactPreview(env.preview)
	g.src.SetGrantGrader(grader)
	g.users.SetGrantGrader(grader)
	return env
}

func (e *mappingEventEnv) snapshotOf(t *testing.T, uid uint, groups ...string) {
	t.Helper()
	raw, err := json.Marshal(groups)
	require.NoError(t, err)
	require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", uid).Updates(map[string]any{
		"group_snapshot_channel": model.RoleMappingChannel(model.RoleMappingChannelKindProvider, e.provider),
		"group_snapshot_groups":  string(raw),
	}).Error)
}

// types 目前收到的事件類型（依序）。
func (e *mappingEventEnv) types() []string {
	var out []string
	for _, ev := range e.alerts.events {
		out = append(out, string(ev.Type))
	}
	return out
}

func (e *mappingEventEnv) reset() { e.alerts.events = nil }

// markedAudits 帶授權變更標記的審計列數。
func (e *mappingEventEnv) markedAudits(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, e.db.Model(&model.AuditLog{}).Where("details LIKE ?", "%grant_change_graded%").Count(&n).Error)
	return n
}

// supportedRole 讓 uid 目前由這條角色規則支持持有該角色（僅映射來源）。
func (e *mappingEventEnv) supportedRole(t *testing.T, uid uint, role string, ruleID uint) {
	t.Helper()
	require.NoError(t, e.db.Create(&model.UserRole{UserID: uid, RoleID: e.roles[role], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
	require.NoError(t, e.db.Create(&model.UserRoleMapping{UserID: uid, RoleID: e.roles[role],
		Channel: model.RoleMappingChannel(model.RoleMappingChannelKindProvider, e.provider)}).Error)
	require.NoError(t, e.db.Create(&model.UserRoleMappingRuleSupport{UserID: uid, RoleID: e.roles[role],
		Channel: model.RoleMappingChannel(model.RoleMappingChannelKindProvider, e.provider), RuleID: ruleID}).Error)
}

// supportedGroup 讓 uid 目前由這條群組規則支持成為該使用者群組成員（僅映射來源）。
func (e *mappingEventEnv) supportedGroup(t *testing.T, uid, groupID, ruleID uint) {
	t.Helper()
	// Manual 欄帶 default:true，零值 false 要用原生語句寫入才不會被預設值蓋掉
	require.NoError(t, e.db.Exec("INSERT INTO user_group_members (user_group_id,user_id,manual) VALUES (?,?,false)", groupID, uid).Error)
	require.NoError(t, e.db.Create(&model.UserGroupMappingRuleSupport{UserID: uid, UserGroupID: groupID,
		Channel: model.RoleMappingChannel(model.RoleMappingChannelKindProvider, e.provider), RuleID: ruleID}).Error)
}

func hasType(types []string, want string) int {
	n := 0
	for _, t := range types {
		if t == want {
			n++
		}
	}
	return n
}

// TestMappingGrantEvents 規則寫入與釘住的授權變更事件：對自己的增加（高）與減少（低）、
// 對他人的管理類發放（中）、兩者同時成立各一筆；快照不存在即未命中；任一步寫入失敗整筆回滾；
// 預覽輸入收到的受影響主體等於快照命中者。
func TestMappingGrantEvents(t *testing.T) {
	const (
		incr = "self_privilege_increased"
		decr = "self_privilege_decreased"
		mgmt = "management_role_granted"
	)
	kind := model.RoleMappingChannelKindProvider

	t.Run("角色規則：會命中自己的建立為高，並帶標記審計", func(t *testing.T) {
		e := newMappingEventEnv(t)
		actor := e.actor(e.admin, "root")
		e.snapshotOf(t, e.admin, "grp-aud")
		_ = e.roleRule(t, actor, "grp-aud", "auditor")
		assert.Equal(t, []string{incr}, e.types())
		ev := e.alerts.last(t)
		assert.Equal(t, "mapping", ev.Params["path"])
		assert.Equal(t, port.SystemAlertTargetUser, ev.Target.Kind)
		assert.EqualValues(t, 1, e.markedAudits(t))
		var l model.AuditLog
		require.NoError(t, e.db.Where("details LIKE ?", "%grant_change_graded%").First(&l).Error)
		assert.Contains(t, l.Details, "self_authorization")
		assert.Contains(t, l.Details, ev.CorrelationID)
	})

	t.Run("角色規則：停用與刪除支持自己的規則為低", func(t *testing.T) {
		e := newMappingEventEnv(t)
		actor := e.actor(e.admin, "root")
		r1 := e.roleRule(t, actor, "grp-1", "auditor")
		e.supportedRole(t, e.admin, "auditor", r1.ID)
		e.reset()
		_, err := e.src.UpdateMapping(kind, e.provider, r1.ID, GroupRoleMappingInput{MatchValue: "grp-1", Role: "auditor", Enabled: boolp(false), RiskAcknowledged: true, Actor: actor})
		require.NoError(t, err)
		assert.Equal(t, []string{decr}, e.types())

		r2 := e.roleRule(t, actor, "grp-2", "approver")
		e.supportedRole(t, e.admin, "approver", r2.ID)
		e.reset()
		require.NoError(t, e.src.DeleteMapping(kind, e.provider, r2.ID, actor))
		assert.Equal(t, []string{decr}, e.types())

		// 沒有支持自己的規則被停用：零事件
		r3 := e.roleRule(t, actor, "grp-3", "auditor")
		e.reset()
		_, err = e.src.UpdateMapping(kind, e.provider, r3.ID, GroupRoleMappingInput{MatchValue: "grp-3", Role: "auditor", Enabled: boolp(false), RiskAcknowledged: true, Actor: actor})
		require.NoError(t, err)
		assert.Empty(t, e.types())
	})

	t.Run("角色規則：修改使自己命中的目標改變為高", func(t *testing.T) {
		e := newMappingEventEnv(t)
		actor := e.actor(e.admin, "root")
		r := e.roleRule(t, actor, "grp-x", "auditor")
		e.supportedRole(t, e.admin, "auditor", r.ID)
		e.snapshotOf(t, e.admin, "grp-x")
		e.reset()
		_, err := e.src.UpdateMapping(kind, e.provider, r.ID, GroupRoleMappingInput{MatchValue: "grp-x", Role: "approver", RiskAcknowledged: true, Actor: actor})
		require.NoError(t, err)
		assert.Equal(t, []string{incr}, e.types())
	})

	t.Run("角色規則：他人管理類為中且不產生自我事件，快照不存在判定未命中", func(t *testing.T) {
		e := newMappingEventEnv(t)
		actor := e.actor(e.admin, "root")
		// 操作者沒有快照：即使目標是自己沒有的管理類角色也只有管理類發放
		_ = e.roleRule(t, actor, "grp-ida", "identity_admin")
		assert.Equal(t, []string{mgmt}, e.types())
		ev := e.alerts.last(t)
		assert.Equal(t, port.SystemAlertTargetRoleMapping, ev.Target.Kind)
		assert.Equal(t, "identity_admin", ev.Params["role_name"])
		assert.Equal(t, "mapping", ev.Params["path"])
	})

	t.Run("角色規則：一般角色或已持有的角色為零事件", func(t *testing.T) {
		e := newMappingEventEnv(t)
		actor := e.actor(e.admin, "root")
		e.snapshotOf(t, e.admin, "grp-u", "grp-adm")
		// 基礎使用者範本是一般角色，零事件
		_ = e.roleRule(t, actor, "grp-u", "user")
		assert.Empty(t, e.types())
		// 操作者本人已持有 admin，目標 admin 不構成自我新增；超管屬管理類，只有發放事件
		_ = e.roleRule(t, actor, "grp-adm", "admin")
		assert.Equal(t, []string{mgmt}, e.types())
		e.reset()
		e.reset()
		// 停用的建立不授出任何目標
		_, err := e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "grp-off", Role: "identity_admin", Enabled: boolp(false), RiskAcknowledged: true, Actor: actor})
		require.NoError(t, err)
		assert.Empty(t, e.types())
	})

	t.Run("角色規則：其他內建範本命中自己為增加", func(t *testing.T) {
		e := newMappingEventEnv(t)
		e.snapshotOf(t, e.admin, "grp-ap")
		_ = e.roleRule(t, e.actor(e.admin, "root"), "grp-ap", "approver")
		assert.Equal(t, []string{incr}, e.types())
	})

	t.Run("角色規則：同時符合自我增加與管理類發放各產生一筆", func(t *testing.T) {
		e := newMappingEventEnv(t)
		actor := e.actor(e.admin, "root")
		e.snapshotOf(t, e.admin, "grp-both")
		_ = e.roleRule(t, actor, "grp-both", "identity_admin")
		assert.Equal(t, 1, hasType(e.types(), incr))
		assert.Equal(t, 1, hasType(e.types(), mgmt))
		assert.Len(t, e.types(), 2)
		assert.EqualValues(t, 2, e.markedAudits(t))
	})

	t.Run("使用者群組規則：建立為高、停用與刪除為低、他人管理類為中、不帶授權的群組零事件", func(t *testing.T) {
		e := newMappingEventEnv(t)
		actor := e.actor(e.admin, "root")
		e.snapshotOf(t, e.admin, "grp-g")
		gAud := e.group(t, "g-aud", "auditor")
		r := e.groupRule(t, actor, "grp-g", gAud)
		assert.Equal(t, []string{incr}, e.types())
		assert.Equal(t, "mapping_user_group", e.alerts.last(t).Params["path"])

		e.supportedGroup(t, e.admin, gAud, r.ID)
		e.reset()
		_, err := e.src.UpdateUserGroupMapping(kind, e.provider, r.ID, UserGroupMappingInput{MatchValue: "grp-g", UserGroupID: gAud, Enabled: boolp(false), RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: actor})
		require.NoError(t, err)
		assert.Equal(t, []string{decr}, e.types())

		r2 := e.groupRule(t, actor, "grp-g2", gAud)
		e.reset()
		e.supportedGroup(t, e.admin, gAud, r2.ID)
		require.NoError(t, e.src.DeleteUserGroupMapping(kind, e.provider, r2.ID, actor))
		assert.Equal(t, []string{decr}, e.types())

		e.reset()
		gMgmt := e.group(t, "g-ida", "identity_admin")
		_ = e.groupRule(t, actor, "grp-other", gMgmt)
		assert.Equal(t, []string{mgmt}, e.types(), "快照不含此群組值：只有管理類發放")
		assert.Equal(t, port.SystemAlertTargetRoleMapping, e.alerts.last(t).Target.Kind)

		e.reset()
		gPlain := e.group(t, "g-plain")
		e.snapshotOf(t, e.admin, "grp-plain")
		_ = e.groupRule(t, actor, "grp-plain", gPlain)
		assert.Empty(t, e.types(), "不帶角色與授權的群組零事件")
	})

	t.Run("釘住：自己為高、他人管理類為中、他人一般角色零事件", func(t *testing.T) {
		e := newMappingEventEnv(t)
		root := Operator{UserID: e.admin, Username: "root"}
		other := e.mkUser(t, "other")
		for _, c := range []struct {
			uid  uint
			role string
			want []string
		}{
			{e.admin, "auditor", []string{incr}},
			{other, "identity_admin", []string{mgmt}},
			{other, "auditor", nil},
		} {
			require.NoError(t, e.db.Create(&model.UserRole{UserID: c.uid, RoleID: e.roles[c.role], Source: model.RoleSourceMapped, ScopeKind: model.ScopeKindGlobal}).Error)
			e.reset()
			_, err := e.users.PinMappedRoleBy(root, c.uid, c.role)
			require.NoError(t, err)
			assert.Equal(t, c.want, e.types(), "uid=%d role=%s", c.uid, c.role)
			if len(c.want) > 0 {
				assert.Equal(t, "pin", e.alerts.events[0].Params["path"])
			}
		}
	})

	t.Run("事件、審計或預覽輸入寫入失敗時規則、支持與世代全回滾", func(t *testing.T) {
		e := newMappingEventEnv(t)
		actor := e.actor(e.admin, "root")
		e.snapshotOf(t, e.admin, "grp-f")
		rr0, gr0, g0 := e.ruleCounts(t)
		v0 := e.version(t)
		e.alerts.fail = true
		_, err := e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "grp-f", Role: "identity_admin", RiskAcknowledged: true, Actor: actor})
		require.Error(t, err)
		rr, gr, g := e.ruleCounts(t)
		assert.Equal(t, []int64{rr0, gr0, g0}, []int64{rr, gr, g})
		assert.Equal(t, v0, e.version(t))
		e.alerts.fail = false

		// 既有規則被停用時事件失敗：規則維持啟用、支持保留
		r := e.roleRule(t, actor, "grp-s", "auditor")
		e.supportedRole(t, e.admin, "auditor", r.ID)
		v1 := e.version(t)
		e.alerts.fail = true
		_, err = e.src.UpdateMapping(kind, e.provider, r.ID, GroupRoleMappingInput{MatchValue: "grp-s", Role: "auditor", Enabled: boolp(false), RiskAcknowledged: true, Actor: actor})
		require.Error(t, err)
		assert.True(t, e.roleRuleState(t, r.ID).Enabled)
		var support int64
		require.NoError(t, e.db.Model(&model.UserRoleMappingRuleSupport{}).Where("rule_id = ?", r.ID).Count(&support).Error)
		assert.EqualValues(t, 1, support)
		assert.Equal(t, v1, e.version(t))
		e.alerts.fail = false

		// 預覽輸入失敗同樣整筆回滾
		e.preview.fail = true
		_, err = e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "grp-p", Role: "identity_admin", RiskAcknowledged: true, Actor: actor})
		require.Error(t, err)
		e.preview.fail = false

		// 標記審計寫入失敗：換成失敗的審計落地面
		grader := NewGrantGrader(failingPinSink{}, e.alerts)
		e.src.SetGrantGrader(grader)
		_, err = e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "grp-a", Role: "identity_admin", RiskAcknowledged: true, Actor: actor})
		require.Error(t, err)
		rr2, _, _ := e.ruleCounts(t)
		assert.Equal(t, rr+1, rr2, "只有前面成功建立的那一條規則在")
	})

	t.Run("預覽輸入收到的受影響主體等於快照命中者", func(t *testing.T) {
		e := newMappingEventEnv(t)
		actor := e.actor(e.admin, "root")
		hit1 := e.mkUser(t, "hit1")
		hit2 := e.mkUser(t, "hit2")
		miss := e.mkUser(t, "miss")
		noSnap := e.mkUser(t, "nosnap")
		_ = noSnap
		e.snapshotOf(t, hit1, "grp-team", "other")
		e.snapshotOf(t, hit2, "grp-team")
		e.snapshotOf(t, miss, "elsewhere")
		require.NoError(t, e.db.Model(&model.User{}).Where("id = ?", e.mkUser(t, "otherchan")).Updates(map[string]any{
			"group_snapshot_channel": "directory:99", "group_snapshot_groups": `["grp-team"]`}).Error)
		_ = e.roleRule(t, actor, "grp-team", "identity_admin")
		require.Len(t, e.preview.got, 1)
		got := e.preview.got[0]
		assert.Equal(t, []uint{hit1, hit2}, got.Subjects)
		assert.Equal(t, "identity_admin", got.TargetName)
		assert.Equal(t, "role", got.RuleType)
		// 停用的建立不餵預覽
		_, err := e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "grp-team-off", Role: "identity_admin", Enabled: boolp(false), RiskAcknowledged: true, Actor: actor})
		require.NoError(t, err)
		assert.Len(t, e.preview.got, 1)
	})

	t.Run("真實預覽：角色規則與群組規則各求出命中帳號新命中的危險組合，唯讀且不阻擋寫入", func(t *testing.T) {
		e := newMappingEventEnv(t)
		var seen []authz.PreviewResult
		var impacts []MappingImpact
		grader := NewGrantGrader(audit.NewTxSink(), e.alerts)
		grader.SetMappingImpactPreview(NewAuthzMappingImpactPreview(func(in MappingImpact, res authz.PreviewResult) {
			impacts, seen = append(impacts, in), append(seen, res)
		}))
		e.src.SetGrantGrader(grader)
		actor := e.actor(e.admin, "root")
		hit := e.mkUser(t, "hit")
		bystander := e.mkUser(t, "bystander")
		e.snapshotOf(t, hit, "grp-team")
		e.snapshotOf(t, bystander, "elsewhere")
		// hit 已持有安全管理類角色；規則再授出身分管理類角色，兩者合起來命中一個危險組合
		require.NoError(t, e.db.Create(&model.UserRole{UserID: hit, RoleID: e.roles["security_admin"], Source: model.RoleSourceManual, ScopeKind: model.ScopeKindGlobal}).Error)
		beforeRows := int64(0)
		require.NoError(t, e.db.Model(&model.UserRole{}).Count(&beforeRows).Error)
		_ = e.roleRule(t, actor, "grp-team", "identity_admin")
		require.Len(t, seen, 1)
		assert.Equal(t, 1, seen[0].Total, "只算快照命中者")
		require.Len(t, seen[0].Subjects, 1)
		subj := seen[0].Subjects[0]
		assert.Equal(t, hit, subj.UserID)
		assert.Contains(t, subj.NewCombos, authz.ComboIdentityWithSecurity)
		assert.True(t, subj.AssignCapable)
		assert.Equal(t, "role", impacts[0].RuleType)
		var afterRows int64
		require.NoError(t, e.db.Model(&model.UserRole{}).Count(&afterRows).Error)
		assert.Equal(t, beforeRows, afterRows, "預覽不寫入任何角色指派")

		// 使用者群組規則：群組帶身分管理類角色，成員身分一樣被假設加上
		gid := e.group(t, "ops-team", "identity_admin")
		_ = e.groupRule(t, actor, "grp-team", gid)
		require.Len(t, seen, 2)
		require.Len(t, seen[1].Subjects, 1)
		assert.Equal(t, hit, seen[1].Subjects[0].UserID)
		assert.Equal(t, "user_group", impacts[1].RuleType)
		assert.Equal(t, gid, impacts[1].TargetID)

		// 預覽求值失敗（目標不存在）不吞掉：由寫入交易回滾
		err := NewAuthzMappingImpactPreview(nil).ObserveMappingImpact(e.db,
			MappingImpact{RuleType: "role", TargetID: 999999, Subjects: []uint{hit}})
		assert.ErrorIs(t, err, authz.ErrPreviewInvalid)
	})

	t.Run("啟動自檢：規則寫入缺危險組合預覽即不就緒", func(t *testing.T) {
		e := newMappingEventEnv(t)
		require.NoError(t, e.src.GrantGraderReady())
		bare := NewGrantGrader(audit.NewTxSink(), e.alerts)
		e.src.SetGrantGrader(bare)
		assert.ErrorIs(t, e.src.GrantGraderReady(), ErrGrantGraderMissing)
		bare.SetMappingImpactPreview(NewAuthzMappingImpactPreview(nil))
		assert.NoError(t, e.src.GrantGraderReady())
	})

	t.Run("事件參數與審計不含外部群組原始值之外的秘密", func(t *testing.T) {
		e := newMappingEventEnv(t)
		e.snapshotOf(t, e.admin, "grp-z")
		_ = e.roleRule(t, e.actor(e.admin, "root"), "grp-z", "identity_admin")
		for _, ev := range e.alerts.events {
			for k, v := range ev.Params {
				assert.False(t, strings.Contains(v, "grp-z"), "參數 %s 不應帶外部群組值", k)
			}
		}
	})

	t.Run("模擬收回與寫入後摘要一致", func(t *testing.T) {
		// run 以與寫入相同的 mappingWrite 在唯讀交易呼叫模擬，取每位帳號的假設摘要；
		// 再經同一服務方法寫入，提交後逐帳號比對實際摘要。受影響帳號＝寫入會收回其支持者，
		// 其餘帳號的摘要寫入前後必須不變。
		run := func(t *testing.T, e *mappingEventEnv, change authz.MappingRuleChange, wantAffected []uint, write func() error) (authz.GrantSummary, map[uint]authz.SubjectState) {
			t.Helper()
			var users []uint
			require.NoError(t, e.db.Model(&model.User{}).Order("id").Pluck("id", &users).Error)
			tx := e.db.Begin()
			w, ruleID, err := mappingWriteFromChange(tx, e.admin, change)
			require.NoError(t, err)
			var affected []uint
			if w.revokesOldSupports() {
				affected, err = mappingSupporters(tx, w.Kind, w.SourceID, w.RuleType, ruleID)
				require.NoError(t, err)
			}
			sims, err := simulateMappingRevocation(tx, w, ruleID, users)
			require.NoError(t, err)
			simSum := map[uint]authz.GrantSummary{}
			before := map[uint]authz.GrantSummary{}
			for _, uid := range users {
				simSum[uid], err = authz.SummarizeState(tx, sims[uid])
				require.NoError(t, err)
				before[uid], err = authz.SummarizeGrants(tx, uid)
				require.NoError(t, err)
			}
			require.NoError(t, tx.Rollback().Error)
			assert.ElementsMatch(t, wantAffected, affected, "受影響帳號集合")
			require.NoError(t, write())
			inSet := map[uint]bool{}
			for _, id := range affected {
				inSet[id] = true
			}
			for _, uid := range users {
				actual, err := authz.SummarizeGrants(e.db, uid)
				require.NoError(t, err)
				want := before[uid]
				if inSet[uid] {
					want = simSum[uid]
				}
				assert.ElementsMatch(t, want.Entries, actual.Entries, "uid=%d 授權項", uid)
				assert.ElementsMatch(t, want.RuleIDs, actual.RuleIDs, "uid=%d 授權規則", uid)
			}
			return simSum[e.admin], sims
		}
		hasGroup := func(sum authz.GrantSummary, gid uint) bool {
			for _, en := range sum.Entries {
				if en.Via == authz.ViaGroup && en.GroupID == gid {
					return true
				}
			}
			return false
		}
		hasRole := func(sum authz.GrantSummary, roleName string) bool {
			for _, en := range sum.Entries {
				if en.RoleName == roleName {
					return true
				}
			}
			return false
		}
		roleChange := func(e *mappingEventEnv, ruleID uint, match string, role string, enabled *bool) authz.MappingRuleChange {
			return authz.MappingRuleChange{RuleType: mappingRuleRole, SourceType: "oidc", SourceID: e.provider, RuleID: ruleID,
				MatchValue: &match, RoleID: e.roles[role], Enabled: enabled}
		}
		groupChange := func(e *mappingEventEnv, ruleID uint, match string, gid uint, enabled *bool) authz.MappingRuleChange {
			return authz.MappingRuleChange{RuleType: mappingRuleUserGroup, SourceType: "oidc", SourceID: e.provider, RuleID: ruleID,
				MatchValue: &match, GroupID: gid, Enabled: enabled}
		}
		disableGroup := func(e *mappingEventEnv, actor GroupRoleMappingActor, r *model.GroupUserGroupMapping, match string, gid uint) func() error {
			return func() error {
				_, err := e.src.UpdateUserGroupMapping(kind, e.provider, r.ID, UserGroupMappingInput{MatchValue: match, UserGroupID: gid,
					Enabled: boolp(false), RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: actor})
				return err
			}
		}

		t.Run("新增零命中規則", func(t *testing.T) {
			e := newMappingEventEnv(t)
			actor := e.actor(e.admin, "root")
			bystander := e.mkUser(t, "bystander")
			e.supportedRole(t, bystander, "auditor", 9999)
			change := authz.MappingRuleChange{RuleType: mappingRuleRole, SourceType: "oidc", SourceID: e.provider,
				MatchValue: strp("grp-new"), RoleID: e.roles["identity_admin"]}
			run(t, e, change, nil, func() error {
				_, err := e.src.CreateMapping(kind, e.provider, GroupRoleMappingInput{MatchValue: "grp-new", Role: "identity_admin", RiskAcknowledged: true, Actor: actor})
				return err
			})
		})

		t.Run("相同新值", func(t *testing.T) {
			e := newMappingEventEnv(t)
			actor := e.actor(e.admin, "root")
			r := e.roleRule(t, actor, "grp-same", "auditor")
			u := e.mkUser(t, "u1")
			e.supportedRole(t, u, "auditor", r.ID)
			run(t, e, roleChange(e, r.ID, "grp-same", "auditor", nil), nil, func() error {
				_, err := e.src.UpdateMapping(kind, e.provider, r.ID, GroupRoleMappingInput{MatchValue: "grp-same", Role: "auditor", RiskAcknowledged: true, Actor: actor})
				return err
			})
		})

		t.Run("停用唯一支持", func(t *testing.T) {
			e := newMappingEventEnv(t)
			actor := e.actor(e.admin, "root")
			gid := e.group(t, "g-only", "identity_admin")
			r := e.groupRule(t, actor, "grp-only", gid)
			u := e.mkUser(t, "u1")
			e.supportedGroup(t, e.admin, gid, r.ID)
			e.supportedGroup(t, u, gid, r.ID)
			op, _ := run(t, e, groupChange(e, r.ID, "grp-only", gid, boolp(false)), []uint{e.admin, u}, disableGroup(e, actor, r, "grp-only", gid))
			assert.False(t, hasGroup(op, gid), "操作者只經這條規則取得，收回後不再是成員")
		})

		t.Run("停用同源雙規則", func(t *testing.T) {
			e := newMappingEventEnv(t)
			actor := e.actor(e.admin, "root")
			gid := e.group(t, "g-two", "identity_admin")
			r1 := e.groupRule(t, actor, "grp-1", gid)
			r2 := e.groupRule(t, actor, "grp-2", gid)
			e.supportedGroup(t, e.admin, gid, r1.ID)
			require.NoError(t, e.db.Create(&model.UserGroupMappingRuleSupport{UserID: e.admin, UserGroupID: gid,
				Channel: model.RoleMappingChannel(kind, e.provider), RuleID: r2.ID}).Error)
			op, _ := run(t, e, groupChange(e, r1.ID, "grp-1", gid, boolp(false)), []uint{e.admin}, disableGroup(e, actor, r1, "grp-1", gid))
			assert.True(t, hasGroup(op, gid), "另一條規則仍支持：保留成員身分")
		})

		t.Run("停用另有手動成員", func(t *testing.T) {
			e := newMappingEventEnv(t)
			actor := e.actor(e.admin, "root")
			gid := e.group(t, "g-manual", "identity_admin")
			r := e.groupRule(t, actor, "grp-m", gid)
			require.NoError(t, e.db.Exec("INSERT INTO user_group_members (user_group_id,user_id,manual) VALUES (?,?,true)", gid, e.admin).Error)
			require.NoError(t, e.db.Create(&model.UserGroupMappingRuleSupport{UserID: e.admin, UserGroupID: gid,
				Channel: model.RoleMappingChannel(kind, e.provider), RuleID: r.ID}).Error)
			op, _ := run(t, e, groupChange(e, r.ID, "grp-m", gid, boolp(false)), []uint{e.admin}, disableGroup(e, actor, r, "grp-m", gid))
			assert.True(t, hasGroup(op, gid), "本身是手動成員：保留")
		})

		t.Run("停用另有手動角色", func(t *testing.T) {
			e := newMappingEventEnv(t)
			actor := e.actor(e.admin, "root")
			r := e.roleRule(t, actor, "grp-role", "approver")
			e.supportedRole(t, e.admin, "approver", r.ID)
			require.NoError(t, model.SetUserRoleSource(e.db, e.admin, e.roles["approver"], model.RoleSourceBoth))
			op, _ := run(t, e, roleChange(e, r.ID, "grp-role", "approver", boolp(false)), []uint{e.admin}, func() error {
				_, err := e.src.UpdateMapping(kind, e.provider, r.ID, GroupRoleMappingInput{MatchValue: "grp-role", Role: "approver", Enabled: boolp(false), RiskAcknowledged: true, Actor: actor})
				return err
			})
			assert.True(t, hasRole(op, "approver"), "手動成分仍在：角色保留")
		})

		t.Run("改目標群組", func(t *testing.T) {
			e := newMappingEventEnv(t)
			actor := e.actor(e.admin, "root")
			ga := e.group(t, "g-a", "auditor")
			gb := e.group(t, "g-b", "approver")
			r := e.groupRule(t, actor, "grp-move", ga)
			u := e.mkUser(t, "u1")
			e.supportedGroup(t, u, ga, r.ID)
			e.supportedGroup(t, e.admin, ga, r.ID)
			_, sims := run(t, e, groupChange(e, r.ID, "grp-move", gb, nil), []uint{e.admin, u}, func() error {
				_, err := e.src.UpdateUserGroupMapping(kind, e.provider, r.ID, UserGroupMappingInput{MatchValue: "grp-move", UserGroupID: gb,
					RiskAcknowledged: true, SourceConfigAcknowledged: true, Actor: actor})
				return err
			})
			assert.NotContains(t, sims[u].GroupIDs, ga)
		})
	})
}

func strp(v string) *string { return &v }
