//go:build ignore

// dbws_smoke 對 /api/v1/ssh 的資料庫協議路徑做端到端 WebSocket 煙霧測試
// （database-protocol）：以 JWT 簽發一次性 connect token（連線收口）→
// 連線 psql → SELECT 算術驗證往返 → resize 不斷線。
// 用法: go run scripts/dbws_smoke.go -token <jwt> -asset <db資產id> [-url ws://localhost:8080]
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
	extra := flag.String("extra", "", "額外執行的指令（驗證審計/阻斷用）")
	prompt := flag.String("prompt", "=#", "CLI 提示符特徵（psql：=#；redis：6379>；mysql：mysql>）")
	probe := flag.String("probe", "select 40+2 as smoke;", "往返驗證指令")
	want := flag.String("want", "42", "往返驗證期望輸出")
	flag.Parse()

	if *token == "" || *asset == "" {
		log.Fatal("缺少 -token 或 -asset")
	}

	ct := issueConnectToken(*base, *token, *asset)

	q := url.Values{}
	q.Set("connect_token", ct)
	q.Set("cols", "120")
	q.Set("rows", "30")
	wsURL := *base + "/api/v1/ssh?" + q.Encode()

	ws, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil {
			log.Fatalf("連線失敗: %v (HTTP %d)", err, resp.StatusCode)
		}
		log.Fatalf("連線失敗: %v", err)
	}
	defer ws.Close()

	writeMsg := func(msgType, data string) {
		raw, _ := json.Marshal(message{Type: msgType, Data: data})
		if err := ws.WriteMessage(websocket.TextMessage, raw); err != nil {
			log.Fatalf("送出 %s 失敗: %v", msgType, err)
		}
	}

	// send 逐行送出：含多行的 data（如 mssql 的「SQL ↵ GO」）**必須**拆成多則訊息。
	// 指令審計的 CommandParser 以「一次 WriteInput 含 \r」判定一次 Enter，兩行擠在同一
	// 則訊息時只會結算第一行、第二行被當成輸出流吞掉——實測即因此讓 GO 沒進審計，
	// 誤判成 tsql 切分失效。逐行送出才與真人逐次按 Enter 的輸入流同形。
	send := func(msgType, data string) {
		if msgType != "data" || !strings.Contains(strings.TrimSuffix(data, "\r"), "\r") {
			writeMsg(msgType, data)
			return
		}
		for _, line := range strings.Split(strings.TrimSuffix(data, "\r"), "\r") {
			writeMsg(msgType, line+"\r")
			time.Sleep(150 * time.Millisecond)
		}
	}

	// 一次性設總 deadline 阻塞讀：gorilla 的 read deadline 逾時後連線永久失效，
	// 「逾時 continue 再讀」會直接 panic（repeated read on failed connection）——
	// 短 deadline 輪詢不可行。keyword 未到而逾時即返回累積輸出，交呼叫端斷言。
	readUntil := func(keyword string, timeout time.Duration) string {
		var sb strings.Builder
		ws.SetReadDeadline(time.Now().Add(timeout))
		for {
			_, raw, err := ws.ReadMessage()
			if err != nil {
				return sb.String()
			}
			var msg message
			if json.Unmarshal(raw, &msg) != nil {
				continue
			}
			if msg.Type == "data" {
				sb.WriteString(msg.Data)
				if strings.Contains(sb.String(), keyword) {
					return sb.String()
				}
			}
		}
	}

	out := readUntil(*prompt, 8*time.Second)
	if !strings.Contains(out, *prompt) {
		log.Fatalf("FAIL prompt: 未見 CLI 提示符 %q: %q", *prompt, out)
	}
	fmt.Println("PASS prompt")

	send("data", *probe+"\r")
	out = readUntil(*want, 8*time.Second)
	if !strings.Contains(out, *want) {
		log.Fatalf("FAIL probe: 輸出未含 %q: %q", *want, out)
	}
	fmt.Println("PASS probe")

	send("resize", `{"cols":200,"rows":50}`)
	time.Sleep(200 * time.Millisecond)
	send("data", *probe+"\r")
	out = readUntil(*want, 8*time.Second)
	if !strings.Contains(out, *want) {
		log.Fatalf("FAIL resize 後往返: %q", out)
	}
	fmt.Println("PASS resize")

	if *extra != "" {
		send("data", *extra+"\r")
		readUntil(*prompt, 5*time.Second)
		fmt.Println("PASS extra")
	}

	send("data", "exit\r")
	time.Sleep(300 * time.Millisecond)
	fmt.Println("PASS all")
}

// issueConnectToken 以 JWT 簽發一次性 connect token（連線收口後 WS 端點
// 只吃 connect_token，不收 JWT）。DB 資產走預設帳號，不帶 account_id。
// 簽發被傳輸風險閘擋（428，dev 靶機無 TLS 的 warn 檔）時，忠實走產品流程：
// 以回應的風險項立同意據（POST /transmission-consents）後重簽一次。
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
