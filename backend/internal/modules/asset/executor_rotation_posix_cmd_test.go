package asset

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 改密指令字串與每段 stdin 位元組的字面值釘住（登入者與被改者分開後的五種形狀）。
// 期望值寫字面值而非引用常數：常數被改（例如第二段拿掉 -k、退回經殼層的指令）即轉紅。
func TestElevatedCommandsAndStdinShapes(t *testing.T) {
	const newPW = "N3w-pw"
	type tc struct {
		name      string
		run       func(t *testing.T, srv *execSSHServer) error
		wantCmds  []string
		wantStdin []string
	}
	cases := []tc{
		{
			name: "自改 root",
			run: func(t *testing.T, srv *execSSHServer) error {
				srv.addAccount("root", "r-old", fakeSudoNone)
				return posixSSHExecutor{}.Rotate(context.Background(), directRotationTarget(t, srv, "root", false), []byte("r-old"), []byte(newPW))
			},
			wantCmds:  []string{"chpasswd"},
			wantStdin: []string{"root:" + newPW + "\n"},
		},
		{
			name: "自改 非 root",
			run: func(t *testing.T, srv *execSSHServer) error {
				srv.addAccount("app", "app-old", fakeSudoNone)
				return posixSSHExecutor{}.Rotate(context.Background(), directRotationTarget(t, srv, "app", false), []byte("app-old"), []byte(newPW))
			},
			wantCmds:  []string{"sudo -S -p '' sh -c 'chpasswd'"},
			wantStdin: []string{"app-old\napp:" + newPW + "\n"},
		},
		{
			name: "代改 root",
			run: func(t *testing.T, srv *execSSHServer) error {
				srv.addAccount("root", "r-pw", fakeSudoNone)
				srv.addAccount("app", "app-old", fakeSudoNone)
				_, err := posixSSHExecutor{}.RotateDelegated(context.Background(), directRotationTarget(t, srv, "app", false),
					rotationLogin{username: "root", password: []byte("r-pw")}, []byte(newPW))
				return err
			},
			wantCmds:  []string{"chpasswd"},
			wantStdin: []string{"app:" + newPW + "\n"},
		},
		{
			name: "代改 第一段",
			run: func(t *testing.T, srv *execSSHServer) error {
				srv.addAccount("cx-exec", "x-pw", fakeSudoNopasswd)
				srv.addAccount("app", "app-old", fakeSudoNone)
				_, err := posixSSHExecutor{}.RotateDelegated(context.Background(), directRotationTarget(t, srv, "app", false),
					rotationLogin{username: "cx-exec", password: []byte("x-pw")}, []byte(newPW))
				return err
			},
			wantCmds:  []string{"env LC_ALL=C sudo -n chpasswd"},
			wantStdin: []string{"app:" + newPW + "\n"},
		},
		{
			name: "代改 第二段",
			run: func(t *testing.T, srv *execSSHServer) error {
				srv.addAccount("cx-exec", "x-pw", fakeSudoPassword)
				srv.addAccount("app", "app-old", fakeSudoNone)
				_, err := posixSSHExecutor{}.RotateDelegated(context.Background(), directRotationTarget(t, srv, "app", false),
					rotationLogin{username: "cx-exec", password: []byte("x-pw")}, []byte(newPW))
				return err
			},
			wantCmds:  []string{"env LC_ALL=C sudo -n chpasswd", "sudo -k -S -p '' chpasswd"},
			wantStdin: []string{"app:" + newPW + "\n", "x-pw\napp:" + newPW + "\n"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newExecSSHServer(t)
			require.NoError(t, c.run(t, srv))
			sessions := srv.execSessions()
			require.Len(t, sessions, len(c.wantCmds))
			for i, s := range sessions {
				assert.Equal(t, c.wantCmds[i], s.cmd, "第 %d 段指令", i+1)
				assert.Equal(t, c.wantStdin[i], s.stdin, "第 %d 段 stdin", i+1)
				colons := 0
				for _, line := range strings.Split(strings.TrimRight(s.stdin, "\n"), "\n") {
					if strings.Contains(line, ":") {
						colons++
					}
				}
				assert.Equal(t, 1, colons, "第 %d 段 stdin 恰有一列帳號:新密碼", i+1)
			}
		})
	}
}

// 常數本身也釘字面值：不經殼層，且第二段先 sudo -k 清掉憑證快取。
func TestElevatedCommandConstantsAreLiteral(t *testing.T) {
	assert.Equal(t, "chpasswd", elevatedCmdRoot)
	assert.Equal(t, "env LC_ALL=C sudo -n chpasswd", elevatedCmdSudoNoPass)
	assert.Equal(t, "sudo -k -S -p '' chpasswd", elevatedCmdSudoPass)
}
