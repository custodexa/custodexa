package agentmcp

import (
	"context"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
	"sort"
	"testing"
)

func listedTools(t *testing.T) []*mcp.Tool {
	t.Helper()
	ctx := context.Background()
	server := NewServer(nil)
	a, b := mcp.NewInMemoryTransports()
	ss, err := server.Connect(ctx, a, nil)
	require.NoError(t, err)
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, b, nil)
	require.NoError(t, err)
	t.Cleanup(func() { cs.Close() })
	result, err := cs.ListTools(ctx, nil)
	require.NoError(t, err)
	return result.Tools
}
func TestToolSurfaceIsClosedSet(t *testing.T) {
	var names []string
	for _, tool := range listedTools(t) {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	require.Equal(t, []string{"check_request", "close_session", "close_task", "list_assets", "open_session", "query", "read_screen", "request_access", "run_command", "send_keys"}, names)
}
func TestToolDescriptionsExplainBoundaries(t *testing.T) {
	required := map[string][]string{"list_assets": {"可連狀態＝此刻能不能連"}, "request_access": {"accounts", "request_id", "open"}, "check_request": {"繼續等", "改做別的事", "判定不會過", "cancelled", "closed_at"}, "open_session": {"request_id", "必填"}, "run_command": {"completed", "timed_out", "needs_input", "blocked", "unknown", "running", "不得盲目重送", "偽造", "交錯", "啟發式", "未帶鍵不去重"}, "send_keys": {"ctrl-c", "ctrl-d", "enter", "不自動"}, "query": {"60", "上限"}, "read_screen": {"非虛擬螢幕", "全螢幕", "不一致"}, "close_session": {"結算"}, "close_task": {"不是關閉的唯一途徑", "24 小時"}}
	for _, tool := range listedTools(t) {
		require.NotEmpty(t, tool.Description)
		for _, phrase := range required[tool.Name] {
			require.Contains(t, tool.Description, phrase, tool.Name)
		}
	}
}
