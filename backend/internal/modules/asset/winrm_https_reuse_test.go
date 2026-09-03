package asset

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WinRM 傳輸不變式（真機發現的回歸）：NTLM 交握在每則 WS-Man 訊息前重跑，其第一段是匿名、
// 無 Authorization、Content-Length: 0 的 POST。若這一段落在工作階段連線池中「上一則訊息用過、
// 已完成認證」的 keep-alive 連線上，HTTPS 端的 HTTP.sys 會回 411 Length Required（純 HTTP 容忍
// 同一形狀）。修正是在交握前關閉閒置連線，使匿名首段永遠走全新連線。
//
// 真機無法在單元測試重現（無 NTLM 伺服端），故此處以 httptest.NewTLSServer 模擬 HTTP.sys 的
// 該行為：對「已完成交握之連線上再度到來的匿名段」回 411，其餘以罐頭挑戰把正式的
// winrmNTLMSecurity 交握帶到 200。

// httpsReuse411Server 模擬 HTTP.sys：以連線為單位記狀態，重用的已認證連線上的匿名段回 411。
type httpsReuse411Server struct {
	srv *httptest.Server

	mu              sync.Mutex
	reusedAnonymous int // 命中「重用連線上的匿名段 → 411」的次數
}

type reuseConnState struct {
	authLegs  int  // 這條連線上已收到的帶 Authorization 的段數
	completed bool // 這條連線是否已完成一次交握（收過 Type3）
}

type reuseConnKey struct{}

func newHTTPSReuse411Server(t *testing.T) *httpsReuse411Server {
	t.Helper()
	s := &httpsReuse411Server{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	srv.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, reuseConnKey{}, &reuseConnState{})
	}
	srv.StartTLS()
	s.srv = srv
	t.Cleanup(srv.Close)
	return s
}

func (s *httpsReuse411Server) handle(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	cs, _ := r.Context().Value(reuseConnKey{}).(*reuseConnState)
	if cs == nil { // 沒有連線狀態就無從模擬，直接 500
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if r.Header.Get("Authorization") == "" {
		// 匿名首段。落在「已完成交握」的重用連線上即為 HTTP.sys 的 411 觸發點。
		if cs.completed {
			s.mu.Lock()
			s.reusedAnonymous++
			s.mu.Unlock()
			w.WriteHeader(http.StatusLengthRequired) // 411
			return
		}
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	cs.authLegs++
	if cs.authLegs == 1 {
		// Type1 negotiate → 回 Type2 挑戰
		w.Header().Set("WWW-Authenticate", "Negotiate "+base64.StdEncoding.EncodeToString(reuseNTLMChallenge()))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Type3 authenticate → 交握完成
	cs.completed = true
	w.WriteHeader(http.StatusOK)
}

// reuseNTLMChallenge 一則最小但合法的 NTLM Type2 挑戰，帶 Seal/Sign/KeyExch/128-bit 旗標，
// 使 winrmNTLMSecurity 交握後建立安全工作階段並回報 Complete。
func reuseNTLMChallenge() []byte {
	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	_ = binary.Write(&b, binary.LittleEndian, uint32(2)) // MessageType = CHALLENGE
	_ = binary.Write(&b, binary.LittleEndian, [3]uint16{0, 0, 48})
	_ = binary.Write(&b, binary.LittleEndian, uint16(0))
	flags := uint32(0x1 | 0x200 | 0x10 | 0x20 | 0x8000 | 0x80000 | 0x40000000 | 0x20000000 | 0x80000000)
	_ = binary.Write(&b, binary.LittleEndian, flags)
	b.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8}) // ServerChallenge
	b.Write(make([]byte, 8))                 // Reserved
	_ = binary.Write(&b, binary.LittleEndian, [3]uint16{0, 0, 48})
	_ = binary.Write(&b, binary.LittleEndian, uint16(0))
	return b.Bytes()
}

// TestWinRMHandshakeUsesFreshConnectionOverHTTPS 交握前關閉閒置連線，使每次交握的匿名首段
// 都走全新連線；否則第二次交握會重用已認證的 keep-alive 連線，被 HTTP.sys 回 411。
func TestWinRMHandshakeUsesFreshConnectionOverHTTPS(t *testing.T) {
	s := newHTTPSReuse411Server(t)
	hc := newWinRMHTTPClient(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, 5*time.Second) //nolint:gosec // 測試自簽端點
	url := s.srv.URL + "/wsman"
	ctx := context.Background()

	// 第一次交握走全新連線，完成後連線回到池中（模擬每則 WS-Man 訊息一次交握）。
	require.NoError(t, newWinRMNTLMSecurity("Administrator", "pw").handshake(ctx, hc, url),
		"第一次交握（全新連線）應完成")

	// 第二次交握：修正後匿名首段走全新連線 → 成功；修正前重用已認證連線 → 411。
	err := newWinRMNTLMSecurity("Administrator", "pw").handshake(ctx, hc, url)
	require.NoError(t, err, "第二次交握不得因重用已認證連線而拿到 411：%v", err)

	assert.Zero(t, s.reusedAnonymous, "任何交握都不該把匿名首段送到已完成認證的重用連線上")
}
