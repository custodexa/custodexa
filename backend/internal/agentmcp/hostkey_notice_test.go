package agentmcp

import (
	"encoding/json"
	"testing"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/sshproxy"
	"github.com/stretchr/testify/require"
)

// TestAgentHostKeyMismatchNotice 建線時送達的主機金鑰不符通知（connected 之後、第一個工具呼叫之前）
// 出現在開啟會話後第一個工具結果的 notices，不被呼叫開頭的清空吃掉；第二個工具結果不重複帶出。
func TestAgentHostKeyMismatchNotice(t *testing.T) {
	e, _, server := terminalFixture(t, func(data string, n int) string {
		return "ok\n$ "
	})
	// 建線序：connected 之後緊接通知幀（bridge.Run 的順序）
	connected, _ := sshproxy.EncodeMessage(sshproxy.MsgConnected, `{"session_id":1}`)
	require.NoError(t, server.WriteMessage(1, connected))
	notice, err := sshproxy.EncodeNoticeMessage(apierror.CodeSSHHostKeyChanged, nil)
	require.NoError(t, err)
	require.NoError(t, server.WriteMessage(1, notice))
	// 等 read 迴圈收下通知
	require.Eventually(t, func() bool {
		e.mu.Lock()
		defer e.mu.Unlock()
		return len(e.carried) == 1
	}, 2e9, 1e7)

	first := op(t, e, "run_command", map[string]any{"command": "echo test"})
	var v map[string]any
	require.NoError(t, json.Unmarshal([]byte(resultText(first)), &v))
	notices, _ := v["notices"].([]any)
	require.Len(t, notices, 1, "第一個工具結果應帶出建線通知: %v", v)
	require.Equal(t, map[string]any{"code": string(apierror.CodeSSHHostKeyChanged)}, notices[0])

	second := op(t, e, "run_command", map[string]any{"command": "echo again"})
	require.NoError(t, json.Unmarshal([]byte(resultText(second)), &v))
	notices, _ = v["notices"].([]any)
	require.Empty(t, notices, "第二個工具結果不得重複帶出建線通知: %v", v)
}
