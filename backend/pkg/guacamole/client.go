package guacamole

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Client 表示與 guacd 的連線
type Client struct {
	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	mu        sync.Mutex
	connected bool
}

// NewClient 建立新的 Guacamole 客戶端並連線到 guacd
func NewClient(host string, port int) (*Client, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("連線到 guacd 失敗: %w", err)
	}

	client := &Client{
		conn:      conn,
		reader:    bufio.NewReader(conn),
		writer:    bufio.NewWriter(conn),
		connected: true,
	}

	return client, nil
}

// ReadInstruction 從 guacd 讀取一個指令
func (c *Client) ReadInstruction() (*Instruction, error) {
	if !c.connected {
		return nil, fmt.Errorf("連線已關閉")
	}

	// 移除讀取超時，讓連接可以長時間等待
	// guacd 需要時間來建立實際的 SSH/RDP/VNC 連接

	// 依協議規範逐 rune 讀取一個完整指令（guacamole-protocol-conformance）。
	// **不可再用 `ReadString(';')`**：協議的值可以合法含有 `;`（檔名、log、error 文字），
	// 以分號切分會在值中間截斷，殘渣留在 reader 裡使其後每一個指令都失步。
	// bufio.Reader 滿足 io.RuneReader，直接餵入套件級 ReadInstruction。
	instruction, err := ReadInstruction(c.reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			c.connected = false
			return nil, fmt.Errorf("連線已關閉")
		}
		return nil, fmt.Errorf("讀取指令失敗: %w", err)
	}

	return instruction, nil
}

// WriteInstruction 向 guacd 寫入一個指令
func (c *Client) WriteInstruction(instruction *Instruction) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return fmt.Errorf("連線已關閉")
	}

	// 編碼指令
	encoded := instruction.Encode()

	// 寫入
	_, err := c.writer.WriteString(encoded)
	if err != nil {
		return fmt.Errorf("寫入指令失敗: %w", err)
	}

	// 刷新緩衝區
	if err := c.writer.Flush(); err != nil {
		return fmt.Errorf("刷新緩衝區失敗: %w", err)
	}

	return nil
}

// Close 關閉與 guacd 的連線
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	c.connected = false
	return c.conn.Close()
}

// IsConnected 檢查連線狀態
func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Handshake 執行 Guacamole 握手協議
func (c *Client) Handshake(protocol string, params map[string]string) error {
	// 1. 發送 select 指令選擇協議
	if err := c.WriteInstruction(NewSelectInstruction(protocol)); err != nil {
		return fmt.Errorf("發送 select 指令失敗: %w", err)
	}

	// 2. 讀取 args 指令（guacd 回傳需要的參數列表）
	argsInst, err := c.ReadInstruction()
	if err != nil {
		return fmt.Errorf("讀取 args 指令失敗: %w", err)
	}

	if argsInst.Opcode != "args" {
		return fmt.Errorf("預期 args 指令，收到: %s", argsInst.Opcode)
	}

	// DEBUG: 打印 args 指令的內容
	fmt.Printf("[DEBUG] args 指令參數: %v\n", argsInst.Args)

	// 3. 在 connect 之前，必須先發送客戶端能力聲明
	// 這是 Guacamole 協議的要求：size, audio, video, image 必須在 connect 之前發送

	// 3.1 發送 size 指令（螢幕尺寸）
	width := 1024
	height := 768
	if w, ok := params["width"]; ok {
		fmt.Sscanf(w, "%d", &width)
	}
	if h, ok := params["height"]; ok {
		fmt.Sscanf(h, "%d", &height)
	}
	sizeInst := NewSizeInstruction(width, height)
	if err := c.WriteInstruction(sizeInst); err != nil {
		return fmt.Errorf("發送 size 指令失敗: %w", err)
	}
	fmt.Printf("[DEBUG] 已發送 size 指令: %dx%d\n", width, height)

	// 3.2 發送 audio 指令（支援的音頻格式）
	audioInst := NewAudioInstruction() // 空參數表示不支援音頻
	if err := c.WriteInstruction(audioInst); err != nil {
		return fmt.Errorf("發送 audio 指令失敗: %w", err)
	}
	fmt.Printf("[DEBUG] 已發送 audio 指令\n")

	// 3.3 發送 video 指令（支援的視頻格式）
	videoInst := NewVideoInstruction() // 空參數表示不支援視頻
	if err := c.WriteInstruction(videoInst); err != nil {
		return fmt.Errorf("發送 video 指令失敗: %w", err)
	}
	fmt.Printf("[DEBUG] 已發送 video 指令\n")

	// 3.4 發送 image 指令（支援的圖像格式）
	imageInst := NewImageInstruction("image/png", "image/jpeg")
	if err := c.WriteInstruction(imageInst); err != nil {
		return fmt.Errorf("發送 image 指令失敗: %w", err)
	}
	fmt.Printf("[DEBUG] 已發送 image 指令\n")

	// 4. 最後發送 connect 指令和參數
	// args 指令格式：[VERSION_1_5_0, param_name1, param_name2, ...]
	// connect 指令格式：[VERSION_1_5_0, param_value1, param_value2, ...]
	connectArgs := make([]string, 0, len(argsInst.Args))

	if len(argsInst.Args) == 0 {
		return fmt.Errorf("args 指令沒有參數")
	}

	// 第一個參數：協議版本（從 args 的第一個參數獲取）
	protocolVersion := argsInst.Args[0]
	connectArgs = append(connectArgs, protocolVersion)
	fmt.Printf("[DEBUG] 使用協議版本: %s\n", protocolVersion)

	// 根據 guacd 要求的參數順序填入值（從 args[1:] 開始是參數名稱列表）
	for _, argName := range argsInst.Args[1:] {
		if value, ok := params[argName]; ok {
			connectArgs = append(connectArgs, value)
		} else {
			// 空參數也要填入，保持參數數量一致
			connectArgs = append(connectArgs, "")
		}
	}

	fmt.Printf("[DEBUG] connect 指令參數數量: %d\n", len(connectArgs))

	connectInst := &Instruction{
		Opcode: "connect",
		Args:   connectArgs,
	}

	if err := c.WriteInstruction(connectInst); err != nil {
		return fmt.Errorf("發送 connect 指令失敗: %w", err)
	}

	// 4. 讀取 ready 指令（表示連線成功）
	readyInst, err := c.ReadInstruction()
	if err != nil {
		return fmt.Errorf("讀取 ready 指令失敗: %w", err)
	}

	if readyInst.Opcode == "error" {
		errorMsg := "未知錯誤"
		if len(readyInst.Args) > 0 {
			errorMsg = readyInst.Args[0]
		}
		return fmt.Errorf("guacd 回傳錯誤: %s", errorMsg)
	}

	if readyInst.Opcode != "ready" {
		return fmt.Errorf("預期 ready 指令，收到: %s", readyInst.Opcode)
	}

	return nil
}
