package authz

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 鎖點母體：backend 全部非測試檔的明示鎖語句（clause.Locking 字面值、含 FOR UPDATE／FOR NO KEY UPDATE／
// FOR SHARE／FOR KEY SHARE 或 advisory 鎖函式的字串字面值），以「檔案:所在函式」為鍵、連同命中數。
// 每一個鍵必須恰好登記在下列兩張表之一：指向 users、user_groups 的鎖點（與拓撲鎖登記點）要求守衛探針，
// 其餘鎖點逐列寫明為什麼不屬使用者層。程式碼新增任何未登記的鎖語句、或某鍵命中數改變，本測試即失敗，
// 逼新鎖點先分類。母體與明示列鎖的清冊及父表鎖點的清冊（含 lockUserRowTx）一一對應，另含使用者憑證互斥鎖與拓撲鎖兩個 advisory 點。

type probeRequirement int

const (
	probeBeforeLock probeRequirement = iota // 同一函式內、鎖語句之前要有探針
	probeRegisters                          // 同一函式內要有探針（拓撲鎖：取鎖之後登記）
)

type requiredLockSite struct {
	count int
	need  probeRequirement
	what  string
}

// lockSitesRequiringProbe 指向 users、user_groups 的明示鎖點、使用者憑證互斥鎖與拓撲鎖。
var lockSitesRequiringProbe = map[string]requiredLockSite{
	"internal/modules/authz/self_grant_guard.go:lockUserRows":                                    {1, probeBeforeLock, "R01 users 列（規則主體、核決申請人）"},
	"internal/modules/authz/access_request_service.go:AccessRequestService.BreakGlass":           {1, probeBeforeLock, "R04 users 列（破窗申請人）"},
	"internal/modules/authz/access_request_submit_items.go:AccessRequestService.submitItems":     {1, probeBeforeLock, "R05 users 列（逐項申請人）"},
	"internal/modules/identity/user_service.go:UserService.guardOwnerTransfer":                   {1, probeBeforeLock, "R07 users 列（擁有者轉移的 agent）"},
	"internal/modules/identity/agent_self_service.go:agentSelfCreation.check":                    {1, probeBeforeLock, "R08 users 列（agent 自建的擁有者）"},
	"internal/modules/identity/agent_breaker.go:LockProbePrincipal":                              {1, probeBeforeLock, "R09 users 列（熔斷探測）"},
	"internal/modules/identity/agent_breaker.go:AgentTokenService.ReleaseProbeBreaker":           {1, probeBeforeLock, "R10 users 列（熔斷解除）"},
	"internal/modules/identity/user_group_role_bindings.go:UserGroupService.ReplaceRoleBindings": {1, probeBeforeLock, "G01 user_groups 列（群組角色替換）"},
	"internal/modules/identity/user_group_service.go:UserGroupService.deleteGroup":               {1, probeBeforeLock, "G02 user_groups 列（群組刪除）"},
	"internal/modules/identity/user_group_service.go:UserGroupService.replaceMembers":            {1, probeBeforeLock, "G03 user_groups 列（成員替換）"},
	"internal/modules/identity/user_credential_lock.go:lockUserRowTx":                            {1, probeBeforeLock, "users 列 primitive（R06 經 lockUserPlanTx 併入）"},
	"internal/modules/identity/user_credential_lock.go:lockUserPairTx":                           {1, probeBeforeLock, "使用者憑證互斥鎖（advisory）"},
	"internal/modules/authz/topology_lock.go:LockScopeTopologyTx":                                {1, probeRegisters, "拓撲序列化鎖（登記點）"},
}

// lockSitesOtherLayers 不屬使用者層的鎖點與理由。
var lockSitesOtherLayers = map[string]struct {
	count  int
	reason string
}{
	"internal/database/instance_guard_backend_pg.go:var pgGuardTryLockSQL":                     {1, "單實例守衛的 session 級 advisory 鎖，非交易內鎖序"},
	"internal/database/instance_guard_backend_pg.go:var pgGuardUnlockSQL":                      {1, "同上（釋放）"},
	"internal/api/syslog_setting_handler.go:lockSyslogSettingTx":                               {1, "syslog 設定的系統層 advisory 鎖"},
	"internal/modules/identity/local_admin_invariant.go:WithLocalAdminInvariant":               {1, "本地管理員不變式的系統層鎖（先於使用者層）"},
	"internal/modules/identity/agent_breaker.go:AgentTokenService.TripProbeBreakerInTx":        {1, "agent_tokens 列"},
	"internal/modules/identity/agent_session_actor.go:BindAgentSessionPrincipal":               {1, "agent_tokens 列"},
	"internal/modules/identity/role_definition_service.go:lockCustomRole":                      {1, "roles 列（角色定義）"},
	"internal/modules/identity/oidc_provider_lock.go:var oidcProviderRowLockSQL":               {1, "oidc_providers 列（provider 層）"},
	"internal/modules/identity/agent_token_service.go:AgentTokenService.changeState":           {1, "agent_tokens 列"},
	"internal/modules/identity/ldap_directory_lock.go:WithLDAPDirectoryLock":                   {1, "LDAP 目錄 advisory 鎖（provider 層）"},
	"internal/modules/asset/asset_account_service.go:lockAssetForAccountMutation":              {1, "assets 列（業務列）"},
	"internal/modules/asset/credential_resolver.go:lockCredentialRow":                          {1, "credentials 列（業務列）"},
	"internal/modules/asset/hostkey_service.go:lockAssetHostKey":                               {1, "主機金鑰的資產級 advisory 鎖（業務層）"},
	"internal/modules/asset/asset_service.go:lockAssetForUpdateTx":                             {1, "assets 列（業務列）"},
	"internal/modules/asset/hostkey_binding.go:HostKeyService.bindWorkRow":                     {1, "asset_host_keys 列（主機身分綁定的自身列，資產級 advisory 鎖之後；業務層）"},
	"internal/modules/asset/hostkey_identity_takeover_create.go:checkConfirmedIdentity":        {1, "asset_host_keys 列（主機身分承接確認的自身列，資產級 advisory 鎖之後；業務層）"},
	"internal/modules/asset/hostkey_identity_takeover_create.go:lockTakeoverJob":               {1, "改密候選或輪替成員工作列（主機身分承接確認，自身列之後；業務層）"},
	"internal/modules/keyvault/key_manager_lock.go:KeyManagerService.withDataKeysLock":         {1, "KEK 資料金鑰的系統層 advisory 鎖"},
	"internal/modules/keyvault/key_manager_lock.go:var pgSessionLockAcquireSQL":                {1, "KEK session 級 advisory 鎖"},
	"internal/modules/keyvault/key_manager_lock.go:releasePGSessionLock":                       {1, "同上（釋放）"},
	"internal/modules/keyvault/kek_topology_lock.go:LockKEKTopologyTx":                         {1, "KEK 拓撲的系統層 advisory 鎖（與資產拓撲鎖無關）"},
	"internal/modules/audit/principal_failure.go:principalFailureLock":                         {1, "審計主體失敗彙總的 advisory 鎖"},
	"internal/modules/audit/principal_failure.go:AuditFailureService.ReportStateMismatch":      {1, "審計主體失敗彙總列"},
	"internal/modules/audit/agent_tool_call_ledger.go:AgentToolCallLedger.Begin":               {1, "agent 工具呼叫序號的 advisory 鎖（以使用者編號雜湊，非使用者憑證互斥鎖）"},
	"internal/modules/audit/notification_channel_service.go:NotificationChannelService.Update": {1, "通知管道設定列"},
	"internal/modules/authz/authz_state.go:LockStateForPermissionActivation":                   {1, "authz_state 單列（附證啟用交界）"},
	"internal/modules/authz/agent_task_source.go:ReadAgentTaskForReport":                       {1, "agent 任務列"},
	"internal/modules/authz/agent_session_task.go:BindAgentSessionTask":                        {1, "agent 任務列"},
	"internal/modules/policy/policy_history.go:lockPolicyHistory":                              {1, "政策歷史的 advisory 鎖"},
	"internal/modules/session/recording_delete.go:RecordingService.DeleteRecording":            {1, "sessions 列（錄影刪除）"},
	"internal/offsite/profile_lock.go:WithOffsiteProfileLock":                                  {1, "異地備份設定檔的 advisory 鎖"},
	"cmd/server/restore_oneshot.go:permissionRestoreOnce":                                      {1, "還原流程的本地管理員系統層鎖"},
}

// 這些函式是使用者層鎖函式，各自都要有探針（SQLite 分支不取實體鎖，仍要登記邏輯持有）。
var userLockFunctionsRequiringProbe = []string{
	"internal/modules/identity/user_credential_lock.go:withUserCredentialLockTx",
	"internal/modules/identity/user_credential_lock.go:lockUsersCredentialUpfrontTx",
	"internal/modules/identity/user_credential_lock.go:lockUserRowTx",
	"internal/modules/identity/user_credential_lock.go:lockUserPlanTx",
	"internal/modules/authz/self_grant_guard.go:lockUserRows",
}

// sourceMayHoldLocks 粗篩：檔案內容不含任何鎖或掛點字樣就不必解析（比對範圍寬於 isLockLiteral）。
var sourceMayHoldLocks = regexp.MustCompile(`Locking|FOR (NO KEY )?UPDATE|FOR (KEY )?SHARE|advisory|LockOrder`)

var lockStringPattern = regexp.MustCompile(`FOR (NO KEY )?UPDATE|FOR (KEY )?SHARE|pg_(try_)?advisory`)

type lockSiteHit struct {
	key      string
	pos      token.Pos
	position string
	fn       ast.Node // 最內層函式（FuncDecl 或 FuncLit）；套件層為 nil
}

type parsedFile struct {
	rel  string
	fset *token.FileSet
	file *ast.File
}

func backendRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, err, "找不到 backend 根目錄")
	return root
}

func parseBackendSources(t *testing.T) []parsedFile {
	t.Helper()
	root := backendRoot(t)
	var out []parsedFile
	for _, top := range []string{"internal", "cmd", "pkg"} {
		dir := filepath.Join(root, top)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		require.NoError(t, filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				if info.Name() == "testdata" || info.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			if !sourceMayHoldLocks.Match(src) {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, src, 0)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, path)
			out = append(out, parsedFile{rel: filepath.ToSlash(rel), fset: fset, file: f})
			return nil
		}))
	}
	require.NotEmpty(t, out)
	return out
}

func funcDeclName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

func isLockLiteral(n ast.Node) bool {
	switch x := n.(type) {
	case *ast.CompositeLit:
		sel, ok := x.Type.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "clause" && sel.Sel.Name == "Locking"
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return false
		}
		v, err := strconv.Unquote(x.Value)
		if err != nil {
			v = x.Value
		}
		return lockStringPattern.MatchString(v)
	}
	return false
}

// collectLockSites 列出全部鎖語句與所在函式。
func collectLockSites(files []parsedFile) []lockSiteHit {
	var hits []lockSiteHit
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			var owner string
			switch d := decl.(type) {
			case *ast.FuncDecl:
				owner = funcDeclName(d)
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							ast.Inspect(vs.Values[i], func(n ast.Node) bool {
								if n != nil && isLockLiteral(n) {
									hits = append(hits, lockSiteHit{key: pf.rel + ":var " + name.Name, pos: n.Pos(), position: pf.fset.Position(n.Pos()).String()})
								}
								return true
							})
						}
					}
				}
				continue
			}
			var stack []ast.Node
			ast.Inspect(decl, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				stack = append(stack, n)
				if isLockLiteral(n) {
					var fn ast.Node
					for i := len(stack) - 1; i >= 0; i-- {
						if _, ok := stack[i].(*ast.FuncLit); ok {
							fn = stack[i]
							break
						}
						if _, ok := stack[i].(*ast.FuncDecl); ok {
							fn = stack[i]
							break
						}
					}
					hits = append(hits, lockSiteHit{key: pf.rel + ":" + owner, pos: n.Pos(), position: pf.fset.Position(n.Pos()).String(), fn: fn})
				}
				return true
			})
		}
	}
	return hits
}

// callsNamed 回傳 n 之內呼叫名為 name 的函式（識別字或選擇子）的位置。
func callsNamed(n ast.Node, name string) []token.Pos {
	var out []token.Pos
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			if f.Name == name {
				out = append(out, call.Pos())
			}
		case *ast.SelectorExpr:
			if f.Sel.Name == name {
				out = append(out, call.Pos())
			}
		}
		return true
	})
	return out
}

const probeLoaderName = "LockOrderProbeHook"

func runLockSiteCoverage(t *testing.T) {
	files := parseBackendSources(t)
	hits := collectLockSites(files)

	byKey := map[string][]lockSiteHit{}
	for _, h := range hits {
		byKey[h.key] = append(byKey[h.key], h)
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var unclassified, missingProbe []string
	required := 0
	for _, k := range keys {
		hs := byKey[k]
		if req, ok := lockSitesRequiringProbe[k]; ok {
			assert.Equal(t, req.count, len(hs), "%s 命中數改變（%s）", k, req.what)
			for _, h := range hs {
				required++
				if h.fn == nil {
					missingProbe = append(missingProbe, h.position+" "+k+"（不在函式內）")
					continue
				}
				ok := false
				for _, p := range callsNamed(h.fn, probeLoaderName) {
					if req.need == probeRegisters || p < h.pos {
						ok = true
					}
				}
				if !ok {
					missingProbe = append(missingProbe, h.position+" "+k+"（"+req.what+"）")
				}
			}
			continue
		}
		if other, ok := lockSitesOtherLayers[k]; ok {
			assert.Equal(t, other.count, len(hs), "%s 命中數改變（%s）", k, other.reason)
			continue
		}
		for _, h := range hs {
			unclassified = append(unclassified, h.position+" "+k)
		}
	}
	for k := range lockSitesRequiringProbe {
		if _, ok := byKey[k]; !ok {
			t.Errorf("登記的使用者層鎖點不存在（已移動或改名，請重新登記）：%s", k)
		}
	}
	for k := range lockSitesOtherLayers {
		if _, ok := byKey[k]; !ok {
			t.Errorf("登記的其他層鎖點不存在（已移動或改名，請重新登記）：%s", k)
		}
	}
	assert.Empty(t, unclassified, "未分類的明示鎖語句：須登記到 lockSitesRequiringProbe 或 lockSitesOtherLayers")
	assert.Empty(t, missingProbe, "指向 users、user_groups 的明示鎖點缺守衛探針")
	t.Logf("EVIDENCE lockorder-sites total=%d user_layer=%d missing=%d unclassified=%d", len(hits), required, len(missingProbe), len(unclassified))

	// 使用者層鎖函式各自有探針
	funcs := map[string]*ast.FuncDecl{}
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok {
				funcs[pf.rel+":"+funcDeclName(fd)] = fd
			}
		}
	}
	for _, k := range userLockFunctionsRequiringProbe {
		fd, ok := funcs[k]
		if !assert.True(t, ok, "函式不存在：%s", k) {
			continue
		}
		assert.NotEmpty(t, callsNamed(fd, probeLoaderName), "%s 缺守衛探針", k)
	}

	// 豁免掛點：late joiner 恰兩處、各緊接在警告行之後的同一分支內；映射撤銷恰一處
	var lateJoiner, mapping []string
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			key := pf.rel + ":" + funcDeclName(fd)
			for range callsNamed(fd, "LockOrderExemptMappingRevocationHook") {
				mapping = append(mapping, key)
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				block, ok := n.(*ast.BlockStmt)
				if !ok {
					return true
				}
				for i, stmt := range block.List {
					ifs, ok := stmt.(*ast.IfStmt)
					if !ok || ifs.Init == nil || len(callsNamed(ifs.Init, "LockOrderExemptLateJoinerHook")) == 0 {
						continue
					}
					afterWarning := i > 0 && isWarningLog(block.List[i-1])
					lateJoiner = append(lateJoiner, key+" after_warning="+strconv.FormatBool(afterWarning))
				}
				return true
			})
		}
	}
	lateJoinerCalls := 0
	for _, pf := range files {
		lateJoinerCalls += len(callsNamed(pf.file, "LockOrderExemptLateJoinerHook"))
	}
	assert.Equal(t, 2, lateJoinerCalls, "late joiner 豁免掛點的呼叫總數")
	sort.Strings(lateJoiner)
	assert.Equal(t, []string{
		"internal/modules/identity/user_group_role_bindings.go:UserGroupService.ReplaceRoleBindings after_warning=true",
		"internal/modules/identity/user_group_service.go:UserGroupService.deleteGroup after_warning=true",
	}, lateJoiner, "late joiner 豁免掛點")
	assert.Equal(t, []string{"internal/modules/identity/mapping_revocation.go:revokeMappingSupportsLocked"}, mapping, "映射撤銷豁免掛點")

	// 守衛不讀設定或環境變數
	src, err := os.ReadFile(filepath.Join(backendRoot(t), "internal/modules/authz/lock_order_guard.go"))
	require.NoError(t, err)
	for _, banned := range []string{`"os"`, "Getenv", "LookupEnv", "internal/config", "policy."} {
		assert.NotContains(t, string(src), banned, "守衛不得讀設定或環境變數")
	}
}

// isWarningLog 判斷敘述是否為含「警告」字樣的 log.Printf。
func isWarningLog(stmt ast.Stmt) bool {
	es, ok := stmt.(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Printf" {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "log" {
		return false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	return ok && strings.Contains(lit.Value, "警告")
}
