//go:build loopback

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/bodgit/ntlmssp"
)

// handshake 探針：逐段重演 NTLM 三段交握，記錄每段實際寫出的長度相關標頭與回應狀態碼。
//
// 只在某個 scheme 的交握回了非 401／200 的狀態碼（例如 411）時用來定位是哪一段、
// 哪個標頭出問題。不印挑戰內容，只印狀態碼、Content-Length／Transfer-Encoding 與
// WWW-Authenticate 的形態；憑證只用於第三段，且不進輸出。
type probeLeg struct {
	Leg           int      `json:"leg"`
	WroteHeaders  []string `json:"wrote_headers"`
	Status        int      `json:"status"`
	Proto         string   `json:"proto"`
	RespHeaders   []string `json:"resp_headers"`
	WWWAuthShapes []string `json:"www_authenticate_shapes"`
	ConnReused    bool     `json:"conn_reused"`
	Err           string   `json:"error,omitempty"`
}

func runHandshakeProbe(ctx context.Context, url, username, password string, insecure bool) ([]probeLeg, error) {
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure}, //nolint:gosec // 探針
		MaxIdleConnsPerHost: 1,
		TLSNextProto:        map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	hc := &http.Client{Transport: transport}
	client, err := ntlmssp.NewClient(ntlmssp.SetUserInfo(username, password), ntlmssp.SetDomain(""), ntlmssp.SetVersion(ntlmssp.DefaultVersion()))
	if err != nil {
		return nil, err
	}
	var legs []probeLeg
	send := func(n int, authorization string) (*http.Response, probeLeg) {
		leg := probeLeg{Leg: n}
		trace := &httptrace.ClientTrace{
			WroteHeaderField: func(key string, value []string) {
				k := strings.ToLower(key)
				if k == "content-length" || k == "transfer-encoding" || k == "connection" || k == "content-type" || k == "authorization" {
					v := strings.Join(value, ",")
					if k == "authorization" {
						v = fmt.Sprintf("<%d bytes>", len(v))
					}
					leg.WroteHeaders = append(leg.WroteHeaders, key+": "+v)
				}
			},
			GotConn: func(info httptrace.GotConnInfo) { leg.ConnReused = info.Reused },
		}
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, url, nil)
		req.ContentLength = 0
		req.Header.Set("User-Agent", "WinRM client")
		req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
		req.Header.Set("Connection", "Keep-Alive")
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := hc.Do(req)
		if err != nil {
			leg.Err = err.Error()
			return nil, leg
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		leg.Status = resp.StatusCode
		leg.Proto = resp.Proto
		for _, k := range []string{"Content-Length", "Content-Type", "Connection", "Server"} {
			if v := resp.Header.Get(k); v != "" {
				leg.RespHeaders = append(leg.RespHeaders, k+": "+v)
			}
		}
		for _, v := range resp.Header.Values("Www-Authenticate") {
			if i := strings.IndexByte(v, ' '); i > 0 {
				leg.WWWAuthShapes = append(leg.WWWAuthShapes, v[:i]+" <"+fmt.Sprint(len(v)-i-1)+" chars>")
			} else {
				leg.WWWAuthShapes = append(leg.WWWAuthShapes, v)
			}
		}
		return resp, leg
	}

	resp, leg := send(1, "")
	legs = append(legs, leg)
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return legs, nil
	}
	negotiate, err := client.Authenticate(nil, nil)
	if err != nil {
		return legs, err
	}
	resp, leg = send(2, "Negotiate "+base64.StdEncoding.EncodeToString(negotiate))
	legs = append(legs, leg)
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		return legs, nil
	}
	var challenge []byte
	for _, v := range resp.Header.Values("Www-Authenticate") {
		if strings.HasPrefix(v, "Negotiate ") {
			challenge, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(v[len("Negotiate "):]))
		}
	}
	if challenge == nil {
		return legs, nil
	}
	authenticate, err := client.Authenticate(challenge, nil)
	if err != nil {
		return legs, err
	}
	_, leg = send(3, "Negotiate "+base64.StdEncoding.EncodeToString(authenticate))
	legs = append(legs, leg)
	return legs, nil
}

func printProbe(legs []probeLeg) {
	for _, l := range legs {
		b, _ := json.Marshal(l)
		fmt.Println("PROBE " + string(b))
	}
}
