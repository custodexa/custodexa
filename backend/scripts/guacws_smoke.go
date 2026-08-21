//go:build ignore

// guacws_smoke 對 /api/v1/connect 做端到端 WebSocket 煙霧測試（RDP/VNC 圖形協議）。
//
// 與 sshws_smoke 的分工：SSH 已退出 guacd 路徑走 internal/sshproxy，圖形協議則是
// 「後端先與 guacd 完成握手 → 成功才升級 WebSocket → Tunnel 純轉發」，故本腳本
// 撥線成功本身即代表 guacd 握手（含目標主機認證）通過——認證失敗時後端在升級前
// 就以 HTTP 500 INTERNAL_GUACD_HANDSHAKE 回絕，WebSocket 根本建不起來。
//
// 用法: go run scripts/guacws_smoke.go -token <jwt> -asset <id> [-hold 5] [-url ws://localhost:8080]
//
// 斷言：
//   - WS 升級成功且協商到 guacamole 子協議（＝通道真的建立，非只有 TCP 可達）
//   - 收到 guacd 的 sync 幀（畫面串流已開始；error 幀即失敗）
//   - -hold 秒內持續收指令，期間回 sync ack 並送一次 mouse 事件（走客戶端輸入路徑）
//
// 全數通過印 "PASS all"，供 scripts/e2e_smoke.sh 以 grep 判定。
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

	"github.com/custodexa/backend/pkg/guacamole"
	"github.com/gorilla/websocket"
)

func main() {
	token := flag.String("token", "", "JWT token")
	asset := flag.String("asset", "", "asset id")
	account := flag.Int("account", 0, "資產帳號 id（0=省略，走預設帳號）")
	base := flag.String("url", "ws://localhost:8080", "backend base ws url")
	width := flag.String("width", "1024", "初始畫面寬")
	height := flag.String("height", "768", "初始畫面高")
	hold := flag.Int("hold", 5, "建線後保持連線的秒數（讓 guacd 累積錄影內容）")
	flag.Parse()

	if *token == "" || *asset == "" {
		log.Fatal("缺少 -token 或 -asset")
	}

	ct := issueConnectToken(*base, *token, *asset, *account)

	q := url.Values{}
	q.Set("connect_token", ct)
	q.Set("width", *width)
	q.Set("height", *height)
	wsURL := *base + "/api/v1/connect?" + q.Encode()

	dialer := *websocket.DefaultDialer
	dialer.Subprotocols = []string{"guacamole"}
	dialer.HandshakeTimeout = 30 * time.Second
	ws, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			log.Fatalf("FAIL connect: WS 建立失敗: %v (HTTP %d) %s", err, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		log.Fatalf("FAIL connect: WS 建立失敗: %v", err)
	}
	defer ws.Close()

	if sub := ws.Subprotocol(); sub != "guacamole" {
		log.Fatalf("FAIL subprotocol: 協商到的子協議為 %q（應為 guacamole）", sub)
	}
	fmt.Println("PASS ws-upgrade")

	write := func(inst *guacamole.Instruction) error {
		return ws.WriteMessage(websocket.TextMessage, []byte(inst.Encode()))
	}

	// 讀到第一個 sync 幀為止：sync 是 guacd 每畫格結束時送的同步點，收到即代表
	// 畫面串流已經開始（不是只有握手回了 ready）。error 幀直接判失敗。
	deadline := time.Now().Add(30 * time.Second)
	ws.SetReadDeadline(deadline)
	var opcodes []string
	firstSync := ""
	for firstSync == "" {
		_, raw, err := ws.ReadMessage()
		if err != nil {
			log.Fatalf("FAIL sync: 等待 sync 幀時連線中斷: %v（已收 opcode: %s）", err, strings.Join(opcodes, ","))
		}
		for _, chunk := range splitInstructions(string(raw)) {
			inst, derr := guacamole.DecodeInstruction(chunk)
			if derr != nil {
				continue
			}
			opcodes = append(opcodes, inst.Opcode)
			if inst.Opcode == "error" {
				log.Fatalf("FAIL sync: guacd 回 error 幀: %v", inst.Args)
			}
			if inst.Opcode == "disconnect" {
				log.Fatalf("FAIL sync: guacd 於畫面串流前即斷線（已收 opcode: %s）", strings.Join(opcodes, ","))
			}
			if inst.Opcode == "sync" && firstSync == "" {
				firstSync = "ok"
				if len(inst.Args) > 0 {
					// 回 sync ack：不回的話 guacd 會停止推送後續畫格
					_ = write(guacamole.NewInstruction("sync", inst.Args[0]))
				}
			}
		}
	}
	fmt.Printf("PASS sync（畫面串流已開始，前 %d 個 opcode: %s）\n", len(opcodes), strings.Join(head(opcodes, 8), ","))

	// 送一次滑鼠事件：走 Tunnel 的客戶端輸入路徑（clientInputOpcodes 之一），
	// 同時讓畫面產生變化，確保錄影檔不是空殼
	_ = write(guacamole.NewInstruction("mouse", "400", "300", "0"))

	// 保持連線，持續回 sync ack 讓 guacd 續推畫格（錄影內容於此期間累積）
	holdUntil := time.Now().Add(time.Duration(*hold) * time.Second)
	frames := 0
	for time.Now().Before(holdUntil) {
		ws.SetReadDeadline(holdUntil.Add(2 * time.Second))
		_, raw, err := ws.ReadMessage()
		if err != nil {
			break
		}
		for _, chunk := range splitInstructions(string(raw)) {
			inst, derr := guacamole.DecodeInstruction(chunk)
			if derr != nil {
				continue
			}
			if inst.Opcode == "sync" && len(inst.Args) > 0 {
				frames++
				_ = write(guacamole.NewInstruction("sync", inst.Args[0]))
			}
		}
	}
	fmt.Printf("PASS hold（%d 秒內收到 %d 個 sync 幀）\n", *hold, frames)

	// 主動 disconnect：讓 guacd 正常收線並 flush 錄影檔，後端才走得到更名與
	// sessions.recording_path 更新那段（錄影落檔斷言的前提）
	_ = write(guacamole.NewInstruction("disconnect"))
	time.Sleep(500 * time.Millisecond)
	// 送 WS close frame（CloseNormalClosure）再斷 TCP：**這才是真實瀏覽器關分頁走的路徑**，
	// 煙測必須走它。瀏覽器關閉分頁時 WebSocket 送的是協議層正常關閉訊號，不是裸斷 TCP；
	// 若煙測只測裸斷 TCP，正常關閉這條主要路徑就等於零覆蓋——圖形隧道先前「正常關閉後
	// 滯留到下一次保活 ping」的缺陷正是這樣被繞過而長期未被發現的
	//（change graphics-teardown-sync）。修法（兩條 pump 各 defer t.Close()）落地後
	// 正常關閉與異常關閉走同一條收線路徑，本煙測不需為此多等任何一輪 ticker。
	_ = ws.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(2*time.Second))
	ws.Close()
	time.Sleep(300 * time.Millisecond)

	fmt.Println("PASS all")
}

// splitInstructions 將一則 WS 訊息拆成個別指令：後端逐指令寫一個 text frame，
// 但不保證恆為一對一，故仍以分號切分後逐段解碼。
func splitInstructions(msg string) []string {
	var out []string
	for _, part := range strings.SplitAfter(msg, ";") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func head(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// issueConnectToken 以 JWT 簽發一次性 connect token（連線收口後 WS 端點
// 只吃 connect_token，不收 JWT）。與 sshws_smoke 同語義。
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
