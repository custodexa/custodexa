//go:build linux || darwin

package sshproxy

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/localpty"
	"github.com/custodexa/backend/internal/material"
)

// 資料庫 CLI 會話：密碼由 localpty 在 client 索取時直接寫進 PTY，不經 bridge 的輸入泵，
// 因此不在鍵盤紀錄內；使用者鍵入的內容原樣在內。以假 CLI（sh）走真的 localpty 路徑。
func TestKeystrokeDBCLIPasswordNotRecordedTypedInputRecorded(t *testing.T) {
	const secret = "dbcli-pw-sentinel-7f3a"
	const typed = "select 'ks-typed-marker';\r"
	script := `printf 'Password: '; stty -echo; IFS= read -r pw; stty echo; echo; ` +
		`if [ "$pw" = "` + secret + `" ]; then echo AUTH_OK; else echo AUTH_BAD; fi; ` +
		`while IFS= read -r line; do echo "LINE_LEN:${#line}"; done`
	conn, err := localpty.StartWithOptions("/bin/sh", []string{"-c", script}, nil, 80, 24, localpty.Options{
		Auth: &localpty.PasswordAuth{
			Password: material.Adopt([]byte(secret)), Prompt: "Password: ",
		},
	})
	require.NoError(t, err)
	t.Cleanup(conn.Close)

	// 輸出端：驅動 Conn.Read（提示注入在其中發生），累積可見輸出
	var mu sync.Mutex
	var out bytes.Buffer
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				mu.Lock()
				out.Write(buf[:n])
				mu.Unlock()
			}
			if rerr != nil || rerr == io.EOF {
				return
			}
		}
	}()
	seen := func() string { mu.Lock(); defer mu.Unlock(); return out.String() }

	serverWS, clientWS := newWSPair(t)
	b := newBridge(serverWS, conn, nil, nil, "", 0, 0)
	cap := &ksCapture{}
	b.attachKeystroke(newKeystrokeTap(cap))
	go b.pumpInput()
	t.Cleanup(b.stop)

	require.Eventually(t, func() bool { return strings.Contains(seen(), "AUTH_OK") },
		5*time.Second, 10*time.Millisecond, "fake CLI must have accepted the injected password")
	sendInput(t, clientWS, typed)
	require.Eventually(t, func() bool { return cap.count() >= 1 }, 3*time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return strings.Contains(seen(), "LINE_LEN:") }, 3*time.Second, 10*time.Millisecond)

	var rec []byte
	for _, e := range cap.snapshot() {
		rec = append(rec, e.payload...)
	}
	require.Equal(t, typed, string(rec), "typed input recorded verbatim")
	require.NotContains(t, string(rec), secret, "injected password must not be in the keystroke record")
	require.NotContains(t, seen(), secret, "injected password must not be in the visible output")
}
