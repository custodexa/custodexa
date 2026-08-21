//go:build ignore

// sshws_smoke 對 /api/v1/ssh 做端到端 WebSocket 煙霧測試：
// 以 JWT 簽發一次性 connect token（連線收口）→ 撥線 → echo 指令 → resize →
// stty size 驗證 PTY 尺寸。
// 用法: go run scripts/sshws_smoke.go -token <jwt> -asset 1 [-account <id>] [-url ws://localhost:8080]
//
//	-account 指定資產帳號簽發（0=省略欄位，走預設帳號）
//	-extra-expect 斷言 -extra 指令的輸出須含該字串（空=不斷言）
//
// 閒置斷線驗證（session-timeout，需後端 SSH_IDLE_TIMEOUT_MINUTES=1）：
//
//	加 -idle-wait 120 → 完成基本測試後不再輸入，期間僅送 ping（不算活躍），
//	等待伺服器注入「[已斷線] 閒置逾時」並關閉連線。
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
	asset := flag.String("asset", "1", "asset id")
	account := flag.Int("account", 0, "資產帳號 id（0=省略，走預設帳號）")
	base := flag.String("url", "ws://localhost:8080", "backend base ws url")
	extra := flag.String("extra", "", "額外執行的指令（驗證審計/告警用）")
	extraExpect := flag.String("extra-expect", "", "extra 輸出須含的字串（空=不斷言）")
	idleWait := flag.Int("idle-wait", 0, "閒置斷線驗證：靜默等待秒數上限（0=不驗證）")
	flag.Parse()

	if *token == "" {
		log.Fatal("缺少 -token")
	}

	ct := issueConnectToken(*base, *token, *asset, *account)

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

	send := func(msgType, data string) {
		raw, _ := json.Marshal(message{Type: msgType, Data: data})
		if err := ws.WriteMessage(websocket.TextMessage, raw); err != nil {
			log.Fatalf("送出 %s 失敗: %v", msgType, err)
		}
	}

	// 一次性設總 deadline 阻塞讀：gorilla 的 read deadline 逾時後連線永久失效，
	// 不可用短 deadline 輪詢（再 ReadMessage 直接 panic）。keyword 未到而逾時
	// 即返回累積輸出，交由呼叫端斷言失敗。
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

	// 初始同步不等提示符（root 是 #、一般帳號是 $），送 marker 等回顯與輸出，
	// 對任何帳號/shell 都成立。
	send("data", "echo sync-$((40+2))\r")
	if out := readUntil("sync-42", 8*time.Second); !strings.Contains(out, "sync-42") {
		log.Fatalf("FAIL sync: shell 未就緒: %q", out)
	}

	send("data", "echo smoke-$((20+22))\r")
	out := readUntil("smoke-42", 8*time.Second)
	if !strings.Contains(out, "smoke-42") {
		log.Fatalf("FAIL echo: 輸出未含 smoke-42: %q", out)
	}
	fmt.Println("PASS echo")

	send("resize", `{"cols":200,"rows":50}`)
	time.Sleep(200 * time.Millisecond)
	send("data", "stty size\r")
	out = readUntil("50 200", 8*time.Second)
	if !strings.Contains(out, "50 200") {
		log.Fatalf("FAIL resize: stty size 未回報 50 200: %q", out)
	}
	fmt.Println("PASS resize")

	if *extra != "" {
		send("data", *extra+"\r")
		if *extraExpect != "" {
			out = readUntil(*extraExpect, 8*time.Second)
			if !strings.Contains(out, *extraExpect) {
				log.Fatalf("FAIL extra: 輸出未含 %q: %q", *extraExpect, out)
			}
		} else {
			// 等指令回顯（非提示符——root 是 #、一般帳號是 $，回顯對任何帳號都成立）
			readUntil(*extra, 5*time.Second)
		}
		fmt.Println("PASS extra")
	}

	send("ping", "")

	if *idleWait > 0 {
		waitIdleDisconnect(ws, time.Duration(*idleWait)*time.Second)
	}

	fmt.Println("PASS all")
}

// issueConnectToken 以 JWT 簽發一次性 connect token（連線收口後 WS 端點
// 只吃 connect_token，不收 JWT）。accountID=0 時省略欄位，走資產預設帳號。
func issueConnectToken(wsBase, jwt, assetID string, accountID int) string {
	httpBase := strings.Replace(strings.Replace(wsBase, "wss://", "https://", 1), "ws://", "http://", 1)
	aid, err := strconv.Atoi(assetID)
	if err != nil {
		log.Fatalf("無效的 -asset: %q", assetID)
	}
	body := map[string]int{"asset_id": aid}
	if accountID > 0 {
		body["account_id"] = accountID
	}
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, httpBase+"/api/v1/connect-tokens", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("簽發 connect token 失敗: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("簽發 connect token 失敗 (HTTP %d): %s", resp.StatusCode, respBody)
	}
	var out struct {
		ConnectToken string `json:"connect_token"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil || out.ConnectToken == "" {
		log.Fatalf("connect token 回應解析失敗: %s", respBody)
	}
	return out.ConnectToken
}

// waitIdleDisconnect 靜默等待伺服器閒置斷線：不再送任何輸入，
// 背景每 20 秒送 ping 證明控制訊號不重置閒置計時，直到收到斷線通知。
// 注意 gorilla/websocket 的 read deadline 逾時即永久失效，不能用短 deadline
// 輪詢——一次性設 maxWait 為限，阻塞讀直到通知或連線關閉。
func waitIdleDisconnect(ws *websocket.Conn, maxWait time.Duration) {
	const notice = "閒置逾時"

	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				raw, _ := json.Marshal(message{Type: "ping"})
				// 伺服器收線後寫入必然失敗，忽略即可
				_ = ws.WriteMessage(websocket.TextMessage, raw)
			}
		}
	}()

	ws.SetReadDeadline(time.Now().Add(maxWait))
	var sb strings.Builder
	for {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			if strings.Contains(sb.String(), notice) {
				fmt.Println("PASS idle-timeout（已收斷線通知且連線關閉）")
				return
			}
			log.Fatalf("FAIL idle: 連線結束但未見斷線通知 (err=%v): %q", err, sb.String())
		}
		var msg message
		if json.Unmarshal(raw, &msg) != nil {
			continue
		}
		if msg.Type == "data" {
			sb.WriteString(msg.Data)
			if strings.Contains(sb.String(), notice) {
				fmt.Println("PASS idle-timeout（已收斷線通知）")
				return
			}
		}
	}
}
