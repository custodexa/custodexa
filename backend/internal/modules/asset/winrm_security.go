package asset

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"

	"github.com/bodgit/ntlmssp"
)

// winrmNTLMSecurity NTLM 認證與訊息層加密（NTLMv2 session security，seal＋sign）。
//
// 交握以**空載荷**請求完成（三段：401 挑戰、Negotiate、Authenticate），安全工作階段
// 建立後才封裝真正的 SOAP。沒有任何一條路徑會把 SOAP 以明文送出；連 Basic 認證的
// 選項都不存在——目標關掉 Negotiate 就是連不上，不是退而求其次。
type winrmNTLMSecurity struct {
	username string
	password string
	client   *ntlmssp.Client
}

// newWinRMNTLMSecurity 正式路徑的 winrmSecurityFactory。
func newWinRMNTLMSecurity(username, password string) winrmSecurity {
	return &winrmNTLMSecurity{username: username, password: password}
}

// handshake 完成 NTLM 交握並確認安全工作階段存在。
//
// 三種結局分開回：目標未經認證即接受、或不提供 Negotiate → errWinRMEncryptionUnavailable
// （沒有工作階段就沒有加密可言）；交握完成但被拒 → errWinRMAuthFailed（憑證錯）；
// 其餘 → 原錯誤（網路、TLS）。
func (s *winrmNTLMSecurity) handshake(ctx context.Context, hc *http.Client, url string) error {
	client, err := ntlmssp.NewClient(
		ntlmssp.SetUserInfo(s.username, s.password),
		ntlmssp.SetDomain(""),
		ntlmssp.SetVersion(ntlmssp.DefaultVersion()),
	)
	if err != nil {
		return fmt.Errorf("winrm: ntlm client: %w", err)
	}
	s.client = client

	// 每個 WS-Man 訊息前都會重新交握（NTLM 工作階段綁單一連線與序號）。工作階段的連線池
	// 會保留上一則訊息用過、且已完成認證的 keep-alive 連線；若讓交握的第一段（匿名、無
	// Authorization、Content-Length: 0 的 POST）落在那條被重用的連線上，HTTPS 端的 HTTP.sys
	// 會回 411 Length Required（純 HTTP 容忍同一形狀，故只有 https 受影響）。交握前先關閉閒置
	// 連線，保證第一段永遠走全新連線——與只做單次交握、不重用連線的傳輸探針同形。
	hc.CloseIdleConnections()

	var legs []winrmHsLeg
	resp, leg, err := winrmHandshakeRequest(ctx, hc, url, "")
	if err != nil {
		return err
	}
	legs = append(legs, leg)
	if resp.StatusCode == http.StatusOK {
		// 未認證就 200：目標不要求認證，也就不會有安全工作階段可封裝
		return errWinRMEncryptionUnavailable
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("winrm: handshake http %d %s", resp.StatusCode, winrmLegsString(legs))
	}
	for i := 0; i < 2; i++ {
		challenge, ok := negotiateChallenge(resp.Header)
		if !ok {
			return errWinRMEncryptionUnavailable
		}
		msg, err := s.client.Authenticate(challenge, nil)
		if err != nil {
			return fmt.Errorf("winrm: ntlm: %w", err)
		}
		resp, leg, err = winrmHandshakeRequest(ctx, hc, url, "Negotiate "+base64.StdEncoding.EncodeToString(msg))
		if err != nil {
			return err
		}
		legs = append(legs, leg)
		if resp.StatusCode != http.StatusUnauthorized {
			break
		}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return errWinRMAuthFailed
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("winrm: handshake http %d %s", resp.StatusCode, winrmLegsString(legs))
	}
	if !s.client.Complete() || s.client.SecuritySession() == nil {
		return errWinRMEncryptionUnavailable
	}
	return nil
}

// seal 封裝：4 位元組簽章長度（little-endian）＋簽章＋密文。
func (s *winrmNTLMSecurity) seal(plain []byte) ([]byte, error) {
	session := s.client.SecuritySession()
	if session == nil {
		return nil, errWinRMEncryptionUnavailable
	}
	sealed, signature, err := session.Wrap(plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4, 4+len(signature)+len(sealed))
	binary.LittleEndian.PutUint32(out, uint32(len(signature)))
	out = append(out, signature...)
	out = append(out, sealed...)
	return out, nil
}

// unseal 解封並驗章；簽章不符即錯（回應被竄改或工作階段錯位）。
func (s *winrmNTLMSecurity) unseal(data []byte) ([]byte, error) {
	session := s.client.SecuritySession()
	if session == nil {
		return nil, errWinRMEncryptionUnavailable
	}
	if len(data) < 4 {
		return nil, errors.New("winrm: sealed payload too short")
	}
	sigLen := int(binary.LittleEndian.Uint32(data[:4]))
	if sigLen < 0 || 4+sigLen > len(data) {
		return nil, errors.New("winrm: sealed payload signature length out of range")
	}
	return session.Unwrap(data[4+sigLen:], data[4:4+sigLen])
}

// winrmHsLeg 一段交握的診斷：實際寫出的長度標頭、連線是否重用、回應狀態與伺服端形態。
// 只在交握以非預期 HTTP 狀態失敗時併入錯誤字串（其內容無憑證，body 取前段供定位）。
type winrmHsLeg struct {
	wroteCL string
	wroteTE string
	reused  bool
	status  int
	server  string
	respCL  string
	body    string
}

func winrmLegsString(legs []winrmHsLeg) string {
	var b strings.Builder
	for i, l := range legs {
		fmt.Fprintf(&b, "[leg%d status=%d wroteCL=%q wroteTE=%q reused=%v server=%q respCL=%q body=%q]",
			i+1, l.status, l.wroteCL, l.wroteTE, l.reused, l.server, l.respCL, l.body)
	}
	return b.String()
}

// winrmHandshakeRequest 空載荷的 POST；本文讀完即丟，只留狀態碼與標頭。
//
// 空載荷不是省事：交握階段還沒有安全工作階段，任何載荷都只能以明文送出。
func winrmHandshakeRequest(ctx context.Context, hc *http.Client, url, authorization string) (*http.Response, winrmHsLeg, error) {
	var leg winrmHsLeg
	trace := &httptrace.ClientTrace{
		WroteHeaderField: func(key string, vals []string) {
			switch strings.ToLower(key) {
			case "content-length":
				leg.wroteCL = strings.Join(vals, ",")
			case "transfer-encoding":
				leg.wroteTE = strings.Join(vals, ",")
			}
		},
		GotConn: func(info httptrace.GotConnInfo) { leg.reused = info.Reused },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, url, nil)
	if err != nil {
		return nil, leg, err
	}
	req.ContentLength = 0
	req.Header.Set("User-Agent", winrmUserAgent)
	req.Header.Set("Content-Type", winrmSOAPContentType)
	req.Header.Set("Connection", "Keep-Alive")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, leg, err
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, winrmMaxResponseBytes))
	_ = resp.Body.Close()
	leg.status = resp.StatusCode
	leg.server = resp.Header.Get("Server")
	leg.respCL = resp.Header.Get("Content-Length")
	leg.body = strings.TrimSpace(string(snippet))
	return resp, leg, nil
}

// negotiateChallenge 自 WWW-Authenticate 取 Negotiate 挑戰；裸 `Negotiate` 回 (nil, true)，
// 沒有 Negotiate 回 (nil, false)。
func negotiateChallenge(h http.Header) ([]byte, bool) {
	for _, v := range h.Values("Www-Authenticate") {
		if v == "Negotiate" {
			return nil, true
		}
		if strings.HasPrefix(v, "Negotiate ") {
			b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len("Negotiate "):]))
			if err != nil {
				return nil, false
			}
			return b, true
		}
	}
	return nil, false
}
