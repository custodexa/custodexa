package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/modules/authz"
)

// updateEntryRules 重生共用 golden。golden 是快照而非不可竄改基準：重生後的 diff 必須在提交中逐條審視。
var updateEntryRules = flag.Bool("update", false, "重生 testdata/route-entry-rules.json（頁面入口規則的共用 golden）")

const entryRulesGoldenFile = "testdata/route-entry-rules.json"

// entryRulesBasePaths 入口規則鏡像建立時凍結的入口路徑。golden 必須全數包含它們；
// 之後新增入口只會讓列數增加，不會讓這份清單失效。
var entryRulesBasePaths = []string{
	"/access-control", "/access-reviews", "/alerts", "/approvals", "/approver-scopes", "/assets",
	"/audit-logs", "/audit/agent-tasks", "/audit/exports", "/audit/workbench", "/authorizations",
	"/change-secret-batches", "/change-secret-plans", "/checkpoint-verification", "/commands",
	"/compliance-map", "/credentials", "/dashboard", "/identity-sources", "/key-management",
	"/my-agents", "/my-connections", "/my-requests", "/offsite-storage", "/policy-groups",
	"/profile", "/roles", "/rotation-evidence", "/security-policies", "/sessions",
	"/transmission-inventory", "/user-groups", "/users", "/workspace",
}

type entryRuleRow struct {
	Path        string   `json:"path"`
	Kind        string   `json:"kind"`
	Permissions []string `json:"permissions"`
}

func entryRuleRowsFromTable() []entryRuleRow {
	rules := authz.RouteEntryRules()
	rows := make([]entryRuleRow, 0, len(rules))
	for _, r := range rules {
		perms := append([]string{}, r.Permissions...)
		rows = append(rows, entryRuleRow{Path: r.Path, Kind: r.Kind, Permissions: perms})
	}
	return rows
}

func marshalEntryRules(rows []entryRuleRow) []byte {
	b, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// compareEntryRules 雙向比對兩份規則，回傳每一處差異（空＝相等）。權限清單當集合比較。
func compareEntryRules(table, golden []entryRuleRow) []string {
	index := func(rows []entryRuleRow) map[string]entryRuleRow {
		m := make(map[string]entryRuleRow, len(rows))
		for _, r := range rows {
			m[r.Path] = r
		}
		return m
	}
	norm := func(p []string) string {
		c := append([]string{}, p...)
		sort.Strings(c)
		return strings.Join(c, ",")
	}
	t, g := index(table), index(golden)
	var diffs []string
	for path, tr := range t {
		gr, ok := g[path]
		switch {
		case !ok:
			diffs = append(diffs, fmt.Sprintf("%s：Go 表有、golden 沒有", path))
		case tr.Kind != gr.Kind:
			diffs = append(diffs, fmt.Sprintf("%s：規則種類 Go=%s golden=%s", path, tr.Kind, gr.Kind))
		case norm(tr.Permissions) != norm(gr.Permissions):
			diffs = append(diffs, fmt.Sprintf("%s：權限鍵 Go=[%s] golden=[%s]", path, norm(tr.Permissions), norm(gr.Permissions)))
		}
	}
	for path := range g {
		if _, ok := t[path]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s：golden 有、Go 表沒有", path))
		}
	}
	sort.Strings(diffs)
	return diffs
}

// TestRouteEntryRulesMirror 擋：Go 的入口規則鏡像表與共用 golden 分岔（前端另有 entry-rules-mirror.spec.js
// 以同一份 golden 比對 ENTRY_RULES，任一邊改了規則而另一邊沒改，兩支測試之一必紅）。
// 帶 -update 時以 Go 表重生 golden；不帶時只比對。
func TestRouteEntryRulesMirror(t *testing.T) {
	table := entryRuleRowsFromTable()
	if *updateEntryRules {
		require.NoError(t, os.MkdirAll(filepath.Dir(entryRulesGoldenFile), 0o755))
		require.NoError(t, os.WriteFile(entryRulesGoldenFile, marshalEntryRules(table), 0o644))
		t.Logf("EVIDENCE update=true rows=%d 已重生 %s", len(table), entryRulesGoldenFile)
		return
	}

	t.Run("Go 表與 golden 雙向相等（路徑集合、規則種類、權限鍵逐列）", func(t *testing.T) {
		raw, err := os.ReadFile(entryRulesGoldenFile)
		require.NoError(t, err, "golden 不存在即失敗，不略過；以 -update 重生")
		var golden []entryRuleRow
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		require.NoError(t, dec.Decode(&golden))
		assert.Empty(t, compareEntryRules(table, golden))
		assert.True(t, sort.SliceIsSorted(golden, func(i, j int) bool { return golden[i].Path < golden[j].Path }), "golden 依路徑升冪")
		assert.Equal(t, string(marshalEntryRules(table)), string(raw), "golden 位元組與 Go 表的規範序列化相同（排除手改格式）")
	})

	t.Run("golden 包含鏡像建立時凍結的全部入口，列數不少於凍結數", func(t *testing.T) {
		assert.Len(t, entryRulesBasePaths, 34)
		have := map[string]bool{}
		for _, r := range table {
			have[r.Path] = true
		}
		for _, p := range entryRulesBasePaths {
			assert.True(t, have[p], "凍結入口 %s 不在鏡像表", p)
		}
		assert.GreaterOrEqual(t, len(table), len(entryRulesBasePaths))
	})

	t.Run("比對器抓得到刪列、改種類與改權限鍵", func(t *testing.T) {
		cp := func() []entryRuleRow {
			out := make([]entryRuleRow, len(table))
			for i, r := range table {
				out[i] = entryRuleRow{Path: r.Path, Kind: r.Kind, Permissions: append([]string{}, r.Permissions...)}
			}
			return out
		}
		assert.Empty(t, compareEntryRules(table, cp()))
		g := cp()
		assert.NotEmpty(t, compareEntryRules(table, g[1:]), "golden 少一列")
		assert.NotEmpty(t, compareEntryRules(g[1:], table), "Go 表少一列")
		g = cp()
		for i := range g {
			if g[i].Path == "/credentials" {
				g[i].Kind = authz.RouteEntryAll
			}
		}
		assert.NotEmpty(t, compareEntryRules(table, g), "種類不同")
		g = cp()
		for i := range g {
			if g[i].Path == "/credentials" {
				g[i].Permissions = g[i].Permissions[1:]
			}
		}
		assert.NotEmpty(t, compareEntryRules(table, g), "權限鍵不同")
	})

	t.Run("規則形狀自洽：登入即可無權限鍵，其餘至少一個，路徑不重複", func(t *testing.T) {
		seen := map[string]bool{}
		for _, r := range table {
			assert.False(t, seen[r.Path], "路徑重複 %s", r.Path)
			seen[r.Path] = true
			switch r.Kind {
			case authz.RouteEntrySignedIn:
				assert.Empty(t, r.Permissions, r.Path)
			case authz.RouteEntryAll, authz.RouteEntryAny:
				assert.NotEmpty(t, r.Permissions, r.Path)
			default:
				t.Errorf("%s 種類不明 %q", r.Path, r.Kind)
			}
		}
	})
}
