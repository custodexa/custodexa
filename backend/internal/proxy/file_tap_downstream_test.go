package proxy

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/pkg/guacamole"
)

// 未送結束指令即斷線的留痕，前提是 blob 真的送達下游。
// TestFileTapIncompleteStream 以 Verdict.Forward 代表轉送；這裡經真正的 Tunnel 轉發迴圈，
// 在假 guacd 端斷言兩個 blob 的內容確實到達，才算走到「已轉送大小」那條路徑。
func TestFileTapIncompleteStreamBlobsReachDownstream(t *testing.T) {
	for _, kind := range []string{"put", "file"} {
		t.Run(kind, func(t *testing.T) {
			db := setupFileTapDB(t)
			aid := uint(7)
			tap := NewFileTap(db, audit.NewDirectSink(db), 320, 1, &aid, "rdp")
			tap.SetDecider(func(string) bool { return true })

			guacd := newFakeGuacd(t)
			conn := guacd.dial(t)
			guacdSide := guacd.accepted(t)
			var mu sync.Mutex
			var got bytes.Buffer
			go func() {
				buf := make([]byte, 4096)
				for {
					n, err := guacdSide.Read(buf)
					if n > 0 {
						mu.Lock()
						got.Write(buf[:n])
						mu.Unlock()
					}
					if err != nil {
						return
					}
				}
			}()
			received := func() string {
				mu.Lock()
				defer mu.Unlock()
				return got.String()
			}

			srvWS, cliWS := wsPair(t)
			tunnel := NewTunnel(srvWS, conn, nil, nil, tap)
			done, _ := startTunnel(t, tunnel)

			for _, in := range []*guacamole.Instruction{
				openStream(kind, "5", "big.iso"),
				gi("blob", "5", b64("AAAA")),
				gi("blob", "5", b64("BBBBBB")),
			} {
				require.NoError(t, cliWS.WriteMessage(websocket.TextMessage, []byte(in.Encode())))
			}

			// 下游實際收到兩個 blob（內容為 base64 編碼後的原樣）
			require.Eventually(t, func() bool {
				r := received()
				return strings.Contains(r, b64("AAAA")) && strings.Contains(r, b64("BBBBBB"))
			}, 3*time.Second, 5*time.Millisecond, "兩個 blob 應送達下游")

			// 未送 end 即斷線
			require.NoError(t, cliWS.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(2*time.Second)))
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("tunnel did not stop")
			}

			rows := waitUploadRows(t, db, 2)
			require.Len(t, rows, 2, "started 與 incomplete 兩列")
			last, ok := byPhase(rows, "incomplete")
			require.True(t, ok, "應有 incomplete 列: %+v", rows)
			require.Equal(t, model.StatusFailure, last.Status)
			require.Contains(t, last.Details, `"size":10`)
			require.Equal(t, "big.iso", last.Path)
		})
	}
}
