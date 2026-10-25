package parentrowlocks

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// expectFixedTree 決定樹掃描的期望：
//
//   - false（目前）：產品碼還沒把父表列鎖改成 NO KEY UPDATE，樹掃描必須恰好命中
//     baselineParentLocks 這 11 處，一處不多、一處不少。
//   - true：產品碼已改完，樹掃描必須 0 命中（扣除 permittedParentExceptions 的登記項）。
//
// 切換步驟：產品碼把 11 處改完後，把本常數改成 true，並清空 baselineParentLocks
// （或保留作歷史對照但不再被引用）。環境變數 PARENT_ROW_LOCK_EXPECT=baseline|fixed
// 可臨時覆蓋；PARENT_ROW_LOCK_SCAN_ROOT 可指向另一棵（例如由 git show 取出的舊版
// 檔案）目錄以重放掃描，此時不檢查例外表是否過期。
const expectFixedTree = true

// parentLockSite 是一處已知的父表明示列鎖。
type parentLockSite struct {
	File    string
	Func    string
	Table   string
	Purpose string
	Fate    string // 預期去向
}

const fateToNoKeyUpdate = "將改 FOR NO KEY UPDATE"

// baselineParentLocks 是修正前樹上全部的父表明示列鎖（11 處）。
// 本期沒有任何硬刪父表的路徑，所以沒有「保留 FOR UPDATE」的項目。
var baselineParentLocks = []parentLockSite{
	{"internal/modules/authz/self_grant_guard.go", "lockUserRows", "users", "主體帳號列鎖（自我授權判定）", fateToNoKeyUpdate},
	{"internal/modules/authz/access_request_service.go", "AccessRequestService.BreakGlass", "users", "破窗申請鎖申請人", fateToNoKeyUpdate},
	{"internal/modules/authz/access_request_submit_items.go", "AccessRequestService.submitItems", "users", "逐項申請鎖申請人", fateToNoKeyUpdate},
	{"internal/modules/identity/agent_token_service.go", "AgentTokenService.Create", "users", "簽發 agent 憑證鎖 agent 帳號（改為排序鎖計畫後以 NKU 取得）", fateToNoKeyUpdate},
	{"internal/modules/identity/user_service.go", "UserService.guardOwnerTransfer", "users", "擁有者轉移鎖 agent 帳號", fateToNoKeyUpdate},
	{"internal/modules/identity/agent_self_service.go", "agentSelfCreation.check", "users", "agent 自建鎖擁有者帳號", fateToNoKeyUpdate},
	{"internal/modules/identity/agent_breaker.go", "LockProbePrincipal", "users", "熔斷探測鎖 agent 帳號", fateToNoKeyUpdate},
	{"internal/modules/identity/agent_breaker.go", "AgentTokenService.ReleaseProbeBreaker", "users", "熔斷解除鎖 agent 帳號", fateToNoKeyUpdate},
	{"internal/modules/identity/user_group_role_bindings.go", "UserGroupService.ReplaceRoleBindings", "user_groups", "群組角色替換鎖群組", fateToNoKeyUpdate},
	{"internal/modules/identity/user_group_service.go", "UserGroupService.deleteGroup", "user_groups", "群組刪除鎖群組", fateToNoKeyUpdate},
	{"internal/modules/identity/user_group_service.go", "UserGroupService.replaceMembers", "user_groups", "成員替換鎖群組", fateToNoKeyUpdate},
}

// nonParentLock 登記一處「目標不是 users／user_groups」的 FOR UPDATE／FOR SHARE。
// Observed 是掃描器解析出的標籤（必須吻合），Actual 是人工確認的實際鎖定對象，
// 不得是父表。表外出現任何新的非 NKU 列鎖都會讓守衛失敗，要求先分類。
type nonParentLock struct {
	File     string
	Func     string
	Observed string
	Actual   string
	Reason   string
}

var nonParentLocks = []nonParentLock{
	{"internal/modules/identity/agent_breaker.go", "AgentTokenService.TripProbeBreakerInTx", "model:AgentToken", "agent_tokens", "憑證列鎖"},
	{"internal/modules/identity/agent_token_service.go", "AgentTokenService.changeState", "model:AgentToken", "agent_tokens", "憑證列鎖"},
	{"internal/modules/identity/agent_session_actor.go", "BindAgentSessionPrincipal", "model:AgentToken", "agent_tokens", "憑證列鎖"},
	{"internal/modules/identity/role_definition_service.go", "lockCustomRole", "model:Role", "roles", "角色定義列鎖"},
	{"internal/modules/identity/oidc_provider_lock.go", "var oidcProviderRowLockSQL", "oidc_providers", "oidc_providers", "身分提供者列鎖"},
	{"internal/modules/authz/agent_session_task.go", "BindAgentSessionTask", "model:AccessRequest", "access_requests", "任務（申請單）列鎖"},
	{"internal/modules/authz/agent_task_source.go", "ReadAgentTaskForReport", "model:AccessRequest", "access_requests", "任務（申請單）列鎖"},
	{"internal/modules/authz/authz_state.go", "LockStateForPermissionActivation", "authz_state", "authz_state", "權限版本單列鎖"},
	{"internal/modules/asset/credential_resolver.go", "lockCredentialRow", "credentials", "credentials", "憑證列鎖"},
	{"internal/modules/asset/asset_account_service.go", "lockAssetForAccountMutation", "assets", "assets", "資產列鎖"},
	{"internal/modules/asset/asset_service.go", "lockAssetForUpdateTx", "model:Asset", "assets", "資產列鎖"},
	{"internal/modules/asset/hostkey_binding.go", "HostKeyService.bindWorkRow", "model:AssetHostKey", "asset_host_keys", "主機金鑰列鎖"},
	{"internal/modules/asset/hostkey_identity_takeover_create.go", "lockTakeoverJob", "model:ChangeSecretCandidate+model:CredentialRotationMember", "change_secret_candidates／credential_rotation_members", "改密工作列鎖（依工作種類擇一）"},
	{"internal/modules/asset/hostkey_identity_takeover_create.go", "checkConfirmedIdentity", "model:AssetHostKey", "asset_host_keys", "主機金鑰列鎖"},
	{"internal/modules/audit/notification_channel_service.go", "NotificationChannelService.Update", "model:NotificationChannel", "notification_channels", "通知通道列鎖"},
	{"internal/modules/audit/principal_failure.go", "AuditFailureService.ReportStateMismatch", "model:AuditFailureEvent", "audit_failure_events", "失敗計數列鎖"},
	{"internal/modules/session/recording_delete.go", "RecordingService.DeleteRecording", "model:Session", "sessions", "連線紀錄列鎖"},
}

// permittedParentExceptions 登記允許存在的父表違規（目前只可能是硬刪父列，
// 須先完成外鍵閉包與入口序列化分析）。目前為空：本期沒有硬刪父表的路徑。
type permittedParentException struct {
	File   string
	Func   string
	Kind   hitKind
	Table  string
	Reason string
}

var permittedParentExceptions = []permittedParentException{}

func (p permittedParentException) matches(h hit) bool {
	return p.File == h.File && p.Func == h.Func && p.Kind == h.Kind && p.Table == h.Table
}

func (n nonParentLock) matches(h hit) bool {
	return n.File == h.File && n.Func == h.Func && n.Observed == h.Table
}

func TestParentRowLockModeGuard(t *testing.T) {
	t.Run("positives", testPositives)
	t.Run("negatives", testNegatives)
	t.Run("tree", testTree)
}

const posPrelude = "package x\nimport (\"gorm.io/gorm\"\n\"gorm.io/gorm/clause\")\n"

// 七個必須被命中的寫法（再加上同型變體）。
var positiveCases = []struct {
	name string
	src  string
	kind hitKind
	mode string // 鎖類才檢查
}{
	{"user_locking_update", `func f(tx *gorm.DB, id uint) error {
	var u model.User
	return tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&u, id).Error
}`, kindGormLock, "UPDATE"},
	{"user_group_locking_update", `func f(tx *gorm.DB, id uint) error {
	var g model.UserGroup
	return tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&g, id).Error
}`, kindGormLock, "UPDATE"},
	{"locking_strength_constant", `func f(tx *gorm.DB, ids []uint) error {
	q := tx.Model(&model.User{})
	q = q.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate})
	var out []uint
	return q.Where("id IN ?", ids).Pluck("id", &out).Error
}`, kindGormLock, "UPDATE"},
	{"raw_select_users_for_update", `func f(tx *gorm.DB, id uint) error {
	return tx.Raw("SELECT id FROM users WHERE id = ? FOR UPDATE", id).Scan(&id).Error
}`, kindSQLLock, "UPDATE"},
	{"users_non_partial_unique_index", "var ddl = `CREATE UNIQUE INDEX idx_users_display ON users USING btree (display_name)`", kindDDL, ""},
	{"unscoped_delete_user", `func f(tx *gorm.DB, id uint) error {
	return tx.Unscoped().Delete(&model.User{}, id).Error
}`, kindHardDelete, ""},
	{"unscoped_delete_user_group", `func f(tx *gorm.DB, id uint) error {
	return tx.Unscoped().Delete(&model.UserGroup{}, id).Error
}`, kindHardDelete, ""},
	// 同型變體
	{"raw_for_share_users", `func f(tx *gorm.DB) { tx.Raw("SELECT id FROM users WHERE id = 1 FOR SHARE") }`, kindSQLLock, "SHARE"},
	{"raw_concatenated_user_groups", `func f(tx *gorm.DB) { tx.Raw("SELECT id FROM user_groups " + "WHERE id = 1 " + "FOR UPDATE") }`, kindSQLLock, "UPDATE"},
	{"locking_strength_file_constant", "const lockMode = \"UPDATE\"\nfunc f(tx *gorm.DB, id uint) error {\n\tvar u model.User\n\treturn tx.Clauses(clause.Locking{Strength: lockMode}).Take(&u, id).Error\n}", kindGormLock, "UPDATE"},
	{"locking_strength_unresolvable", `func f(tx *gorm.DB, id uint, m string) error {
	var u model.User
	return tx.Clauses(clause.Locking{Strength: m}).First(&u, id).Error
}`, kindGormLock, "?"},
	{"unscoped_delete_via_variable", `func f(tx *gorm.DB, id uint) error {
	q := tx.Unscoped()
	var u model.User
	return q.Delete(&u, id).Error
}`, kindHardDelete, ""},
	{"raw_delete_from_users", `func f(tx *gorm.DB) { tx.Exec("DELETE FROM users WHERE id = 1") }`, kindHardDelete, ""},
	{"add_unique_constraint_users", "var ddl = `ALTER TABLE users ADD CONSTRAINT uq_x UNIQUE (display_name)`", kindDDL, ""},
}

func testPositives(t *testing.T) {
	for _, c := range positiveCases {
		t.Run(c.name, func(t *testing.T) {
			hs, err := scanSource("x.go", []byte(posPrelude+c.src))
			if err != nil {
				t.Fatalf("解析失敗: %v", err)
			}
			var viol []hit
			for _, h := range hs {
				if violatesParentRule(h) {
					viol = append(viol, h)
				}
			}
			if len(viol) != 1 {
				t.Fatalf("應恰好命中 1 處父表違規，實得 %d（全部命中: %v）", len(viol), hs)
			}
			if viol[0].Kind != c.kind {
				t.Fatalf("命中種類 = %s，期望 %s", viol[0].Kind, c.kind)
			}
			if c.mode != "" && viol[0].Mode != c.mode {
				t.Fatalf("命中模式 = %q，期望 %q", viol[0].Mode, c.mode)
			}
			t.Logf("EVIDENCE positive %s caught: %s", c.name, viol[0])
		})
	}
}

// 不得誤判為父表違規的寫法；以及必須落入「要求登記」的寫法。
var negativeCases = []struct {
	name         string
	src          string
	wantViolates bool
	wantClassify bool
}{
	{"user_no_key_update", `func f(tx *gorm.DB, id uint) error {
	var u model.User
	return tx.Clauses(clause.Locking{Strength: "NO KEY UPDATE"}).First(&u, id).Error
}`, false, false},
	{"raw_users_no_key_update", `func f(tx *gorm.DB) { tx.Raw("SELECT id FROM users WHERE id = 1 FOR NO KEY UPDATE") }`, false, false},
	{"raw_users_key_share", `func f(tx *gorm.DB) { tx.Raw("SELECT id FROM users WHERE id = 1 FOR KEY SHARE") }`, false, false},
	{"partial_unique_index", "var ddl = `CREATE UNIQUE INDEX idx_users_name ON users USING btree (name) WHERE (deleted_at IS NULL)`", false, false},
	{"soft_delete_user", `func f(tx *gorm.DB, id uint) error { return tx.Delete(&model.User{}, id).Error }`, false, false},
	{"unscoped_delete_other_table", `func f(tx *gorm.DB, id uint) error { return tx.Unscoped().Delete(&model.GroupRoleMapping{}, id).Error }`, false, false},
	{"prose_mentioning_for_update", `var msg = "retry later for update of the record"`, false, false},
	{"non_parent_for_update_needs_classification", `func f(tx *gorm.DB, id uint) error {
	var t model.AgentToken
	return tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&t, id).Error
}`, false, true},
	{"unresolvable_target_needs_classification", `func f(tx *gorm.DB, lk clause.Locking, id uint, dst any) error {
	lock := clause.Locking{Strength: "UPDATE"}
	return tx.Clauses(lock).First(dst, id).Error
}`, false, true},
}

func testNegatives(t *testing.T) {
	for _, c := range negativeCases {
		t.Run(c.name, func(t *testing.T) {
			hs, err := scanSource("x.go", []byte(posPrelude+c.src))
			if err != nil {
				t.Fatalf("解析失敗: %v", err)
			}
			viol, classify := 0, 0
			for _, h := range hs {
				if violatesParentRule(h) {
					viol++
				}
				if needsClassification(h) {
					classify++
				}
			}
			if (viol > 0) != c.wantViolates {
				t.Fatalf("父表違規 = %d 處，wantViolates=%v（命中: %v）", viol, c.wantViolates, hs)
			}
			if (classify > 0) != c.wantClassify {
				t.Fatalf("需登記 = %d 處，wantClassify=%v（命中: %v）", classify, c.wantClassify, hs)
			}
		})
	}
}

func testTree(t *testing.T) {
	root := os.Getenv("PARENT_ROW_LOCK_SCAN_ROOT")
	replay := root != ""
	if !replay {
		root = moduleRoot(t)
	}
	fixed := expectFixedTree
	switch os.Getenv("PARENT_ROW_LOCK_EXPECT") {
	case "baseline":
		fixed = false
	case "fixed":
		fixed = true
	}
	hits, nFiles, err := scanTree(root)
	if err != nil {
		t.Fatalf("掃描失敗（不得靜默略過檔案）: %v", err)
	}
	if nFiles == 0 || (!replay && nFiles < 500) {
		t.Fatalf("掃描檔數 = %d，掃描根疑似錯誤: %s", nFiles, root)
	}
	t.Logf("EVIDENCE scanned files=%d root=%s expect=%s", nFiles, filepath.Base(root), map[bool]string{false: "baseline", true: "fixed"}[fixed])

	var parentViol, unregistered []hit
	usedNonParent := map[int]bool{}
	usedPermitted := map[int]bool{}
	for _, h := range hits {
		if violatesParentRule(h) {
			permitted := false
			for i, p := range permittedParentExceptions {
				if p.matches(h) {
					usedPermitted[i] = true
					permitted = true
				}
			}
			if !permitted {
				parentViol = append(parentViol, h)
			}
			continue
		}
		if !needsClassification(h) {
			continue
		}
		found := false
		for i, n := range nonParentLocks {
			if n.matches(h) {
				usedNonParent[i] = true
				found = true
			}
		}
		if !found {
			unregistered = append(unregistered, h)
		}
	}

	for _, h := range unregistered {
		t.Errorf("未分類的列鎖（目標 %s，模式 %s）：%s\n  對 users／user_groups 一律用 FOR NO KEY UPDATE；若目標確實是其他表，登記到 nonParentLocks 並寫明理由", h.Table, h.Mode, h)
	}
	if !replay {
		for i, n := range nonParentLocks {
			if !usedNonParent[i] {
				t.Errorf("nonParentLocks 登記過期（樹上已無此命中）：%+v", n)
			}
		}
		for i, p := range permittedParentExceptions {
			if !usedPermitted[i] {
				t.Errorf("permittedParentExceptions 登記過期：%+v", p)
			}
		}
	}
	for _, n := range nonParentLocks {
		if tableIsParent(n.Actual) || tableIsParent(n.Observed) {
			t.Errorf("nonParentLocks 不得登記父表: %+v", n)
		}
	}

	sort.SliceStable(parentViol, func(i, j int) bool {
		if parentViol[i].File != parentViol[j].File {
			return parentViol[i].File < parentViol[j].File
		}
		return parentViol[i].Line < parentViol[j].Line
	})
	for _, h := range parentViol {
		t.Logf("EVIDENCE parent-violation %s | %s", h, h.Detail)
	}
	t.Logf("EVIDENCE parent-violations=%d registered-non-parent-locks=%d", len(parentViol), len(usedNonParent))

	if fixed {
		for _, h := range parentViol {
			t.Errorf("修正後的樹不應有父表列鎖違規：%s", h)
		}
		return
	}

	// 基底模式：命中集合必須恰等於清冊。
	want := map[string]parentLockSite{}
	for _, s := range baselineParentLocks {
		want[s.File+"|"+s.Func+"|"+s.Table] = s
	}
	got := map[string]hit{}
	for _, h := range parentViol {
		if h.Kind != kindGormLock && h.Kind != kindSQLLock {
			t.Errorf("基底模式下出現清冊外的非列鎖違規：%s", h)
			continue
		}
		if h.Mode != "UPDATE" {
			t.Errorf("基底命中的模式應為 UPDATE，實得 %q：%s", h.Mode, h)
		}
		if _, dup := got[h.key()]; dup {
			t.Errorf("同一個函式內出現多處同表命中：%s", h)
		}
		got[h.key()] = h
	}
	for k, s := range want {
		h, ok := got[k]
		if !ok {
			if !replay {
				t.Errorf("清冊項目未命中（已被改掉？切換 expectFixedTree）：%s %s %s", s.File, s.Func, s.Table)
			}
			continue
		}
		t.Logf("EVIDENCE baseline-site %s:%d %s table=%s fate=%q (%s)", h.File, h.Line, h.Func, h.Table, s.Fate, s.Purpose)
	}
	for k, h := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("清冊外的父表列鎖：%s", h)
		}
	}
	if !replay && len(got) != len(baselineParentLocks) {
		t.Errorf("基底命中 %d 處，清冊 %d 處", len(got), len(baselineParentLocks))
	}
}
