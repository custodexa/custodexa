//go:build ignore

// mssql_cred_probe 憑證面實測用的一次性探針。
// 開一條 mssql web CLI 會話，依序送入指令並把**原始輸出全部印出**，供人工判讀
// 「真憑證是否可從子程序側讀到」。與 dbws_smoke 的差別：不做斷言、只做取樣。
// 用法: go run scripts/mssql_cred_probe.go -token <jwt> -asset <id> -cmds 'a;;b;;c'
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type message struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
}

func main() {
	token := flag.String("token", "", "JWT token")
	asset := flag.String("asset", "", "database asset id")
	base := flag.String("url", "ws://localhost:8080", "backend base ws url")
	cmds := flag.String("cmds", "", "以 ;; 分隔的指令序列")
	wait := flag.Duration("wait", 4*time.Second, "每條指令後的收集時間")
	flag.Parse()

	if *token == "" || *asset == "" {
		log.Fatal("缺少 -token 或 -asset")
	}
	ct := issueConnectToken(*base, *token, *asset)

	q := url.Values{}
	q.Set("connect_token", ct)
	q.Set("cols", "120")
	q.Set("rows", "30")
	ws, resp, err := websocket.DefaultDialer.Dial(*base+"/api/v1/ssh?"+q.Encode(), nil)
	if err != nil {
		if resp != nil {
			log.Fatalf("連線失敗: %v (HTTP %d)", err, resp.StatusCode)
		}
		log.Fatalf("連線失敗: %v", err)
	}
	defer ws.Close()

	out := make(chan string, 1024)
	go func() {
		for {
			_, raw, err := ws.ReadMessage()
			if err != nil {
				close(out)
				return
			}
			var msg message
			if json.Unmarshal(raw, &msg) != nil {
				continue
			}
			if msg.Data != "" {
				out <- "[" + msg.Type + "] " + msg.Data
			}
		}
	}()

	drain := func(label string, d time.Duration) {
		fmt.Printf("\n===== %s =====\n", label)
		deadline := time.After(d)
		var sb strings.Builder
		for {
			select {
			case s, ok := <-out:
				if !ok {
					fmt.Print(sb.String())
					fmt.Println("\n<<< 連線已關閉 >>>")
					return
				}
				sb.WriteString(s)
			case <-deadline:
				fmt.Print(sb.String())
				return
			}
		}
	}

	drain("開場（連線／提示符）", 8*time.Second)

	send := func(data string) {
		raw, _ := json.Marshal(message{Type: "data", Data: data})
		if err := ws.WriteMessage(websocket.TextMessage, raw); err != nil {
			log.Fatalf("送出失敗: %v", err)
		}
	}

	for _, c := range strings.Split(*cmds, ";;") {
		if strings.TrimSpace(c) == "" {
			continue
		}
		send(c + "\r")
		drain("送出: "+c, *wait)
	}
	fmt.Println("\n===== 探針結束 =====")
}

func issueConnectToken(wsBase, jwt, assetID string) string {
	httpBase := strings.Replace(strings.Replace(wsBase, "wss://", "https://", 1), "ws://", "http://", 1)
	aid, err := strconv.Atoi(assetID)
	if err != nil {
		log.Fatalf("無效的 -asset: %q", assetID)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	post := func(path string, body any) (int, []byte) {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, httpBase+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("POST %s 失敗: %v", path, err)
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, respBody
	}
	status, respBody := post("/api/v1/connect-tokens", map[string]int{"asset_id": aid})
	if status == http.StatusPreconditionRequired {
		var gate struct {
			Risks []struct {
				Key string `json:"key"`
			} `json:"risks"`
		}
		if err := json.Unmarshal(respBody, &gate); err != nil || len(gate.Risks) == 0 {
			log.Fatalf("傳輸閘 428 回應解析失敗: %s", respBody)
		}
		keys := make([]string, 0, len(gate.Risks))
		for _, r := range gate.Risks {
			keys = append(keys, r.Key)
		}
		if s, b := post("/api/v1/transmission-consents", map[string]any{"asset_id": aid, "risk_keys": keys}); s != http.StatusOK {
			log.Fatalf("傳輸風險同意立據失敗 (HTTP %d): %s", s, b)
		}
		status, respBody = post("/api/v1/connect-tokens", map[string]int{"asset_id": aid})
	}
	if status != http.StatusOK {
		log.Fatalf("簽發 connect token 失敗 (HTTP %d): %s", status, respBody)
	}
	var out struct {
		ConnectToken string `json:"connect_token"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil || out.ConnectToken == "" {
		log.Fatalf("connect token 回應解析失敗: %s", respBody)
	}
	return out.ConnectToken
}
