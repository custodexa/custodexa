package proxy

import (
	"fmt"
	"log"
	"sync"

	"github.com/custodexa/backend/pkg/guacamole"
)

// Connection 表示一個到 guacd 的連線，包含握手狀態管理
type Connection struct {
	ID         string
	GuacClient *guacamole.Client
	Protocol   string
	Params     map[string]string
	Ready      bool
	mu         sync.Mutex
}

// NewConnection 創建新的連線（尚未連線）
func NewConnection(protocol string, params map[string]string) *Connection {
	return &Connection{
		Protocol: protocol,
		Params:   params,
		Ready:    false,
	}
}

// Connect 連線到 guacd 並執行握手流程
func (c *Connection) Connect(guacdHost string, guacdPort int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	log.Printf("[Connection] 開始連線到 guacd %s:%d...", guacdHost, guacdPort)

	// 1. 建立 TCP 連線到 guacd
	client, err := guacamole.NewClient(guacdHost, guacdPort)
	if err != nil {
		return fmt.Errorf("連線 guacd 失敗: %w", err)
	}
	c.GuacClient = client

	log.Printf("[Connection] 已連線到 guacd，開始握手流程...")

	// 2. 執行完整握手流程
	if err := c.handshake(); err != nil {
		c.GuacClient.Close()
		c.GuacClient = nil
		return fmt.Errorf("握手失敗: %w", err)
	}

	c.Ready = true
	log.Printf("[Connection] 握手完成，連線已就緒")

	return nil
}

// handshake 執行完整的 Guacamole 握手流程
// 參考 test-backend-handshake-v2.go 的成功實作
func (c *Connection) handshake() error {
	// 1. 發送 select 指令
	log.Printf("[Handshake] 發送 select: %s", c.Protocol)
	selectInst := guacamole.NewSelectInstruction(c.Protocol)
	if err := c.GuacClient.WriteInstruction(selectInst); err != nil {
		return fmt.Errorf("發送 select 失敗: %w", err)
	}

	// 2. 接收 args 指令
	log.Printf("[Handshake] 等待 args...")
	argsInst, err := c.GuacClient.ReadInstruction()
	if err != nil {
		return fmt.Errorf("讀取 args 失敗: %w", err)
	}

	if argsInst.Opcode != "args" {
		return fmt.Errorf("預期 args，收到: %s", argsInst.Opcode)
	}

	log.Printf("[Handshake] 收到 args: %d 個參數", len(argsInst.Args))
	if len(argsInst.Args) >= 3 {
		log.Printf("[Handshake] VERSION: %s, 參數: %s, %s, ...",
			argsInst.Args[0], argsInst.Args[1], argsInst.Args[2])
	}

	// 3. 發送客戶端能力聲明
	// 3.1 size 指令
	width := 1024
	height := 768
	if w, ok := c.Params["width"]; ok {
		fmt.Sscanf(w, "%d", &width)
	}
	if h, ok := c.Params["height"]; ok {
		fmt.Sscanf(h, "%d", &height)
	}

	log.Printf("[Handshake] 發送 size: %dx%d", width, height)
	sizeInst := guacamole.NewSizeInstruction(width, height)
	if err := c.GuacClient.WriteInstruction(sizeInst); err != nil {
		return fmt.Errorf("發送 size 失敗: %w", err)
	}

	// 3.2 audio 指令
	log.Printf("[Handshake] 發送 audio")
	audioInst := guacamole.NewAudioInstruction()
	if err := c.GuacClient.WriteInstruction(audioInst); err != nil {
		return fmt.Errorf("發送 audio 失敗: %w", err)
	}

	// 3.3 video 指令
	log.Printf("[Handshake] 發送 video")
	videoInst := guacamole.NewVideoInstruction()
	if err := c.GuacClient.WriteInstruction(videoInst); err != nil {
		return fmt.Errorf("發送 video 失敗: %w", err)
	}

	// 3.4 image 指令
	log.Printf("[Handshake] 發送 image")
	imageInst := guacamole.NewImageInstruction("image/png", "image/jpeg")
	if err := c.GuacClient.WriteInstruction(imageInst); err != nil {
		return fmt.Errorf("發送 image 失敗: %w", err)
	}

	// 4. 構建並發送 connect 指令
	// 根據 args 動態構建 connect 參數
	log.Printf("[Handshake] 構建 connect 指令...")
	connectArgs := make([]string, len(argsInst.Args))

	// 第一個參數：VERSION
	connectArgs[0] = argsInst.Args[0]

	// 後續參數：根據參數名稱從 Params 中取值
	for i := 1; i < len(argsInst.Args); i++ {
		paramName := argsInst.Args[i]
		if value, ok := c.Params[paramName]; ok {
			connectArgs[i] = value
		} else {
			connectArgs[i] = "" // 空參數也要填入
		}
	}

	log.Printf("[Handshake] 發送 connect (%d 參數): hostname=%s, port=%s, username=%s",
		len(connectArgs), c.Params["hostname"], c.Params["port"], c.Params["username"])

	connectInst := guacamole.NewInstruction("connect", connectArgs...)
	if err := c.GuacClient.WriteInstruction(connectInst); err != nil {
		return fmt.Errorf("發送 connect 失敗: %w", err)
	}

	// 5. 等待 ready 指令
	log.Printf("[Handshake] 等待 ready...")
	readyInst, err := c.GuacClient.ReadInstruction()
	if err != nil {
		return fmt.Errorf("讀取 ready 失敗: %w", err)
	}

	if readyInst.Opcode == "error" {
		// 內部 error 值（僅落 log 與 apierror.RespondInternal 的 cause，永不直達
		// 使用者：handler 以 INTERNAL_GUACD_HANDSHAKE 泛化回應）。原中文預設值
		// 改英文，讓中文字面量守衛的清單歸零而不必為它開豁免
		errorMsg := "unknown error"
		if len(readyInst.Args) > 0 {
			errorMsg = readyInst.Args[0]
		}
		return fmt.Errorf("guacd 回傳錯誤: %s", errorMsg)
	}

	if readyInst.Opcode != "ready" {
		return fmt.Errorf("預期 ready，收到: %s", readyInst.Opcode)
	}

	log.Printf("[Handshake] 收到 ready，握手成功！")

	return nil
}

// ReadInstruction 從 guacd 讀取指令
func (c *Connection) ReadInstruction() (*guacamole.Instruction, error) {
	if c.GuacClient == nil {
		return nil, fmt.Errorf("連線未建立")
	}
	return c.GuacClient.ReadInstruction()
}

// WriteInstruction 向 guacd 寫入指令
func (c *Connection) WriteInstruction(inst *guacamole.Instruction) error {
	if c.GuacClient == nil {
		return fmt.Errorf("連線未建立")
	}
	return c.GuacClient.WriteInstruction(inst)
}

// Close 關閉連線
func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.GuacClient != nil {
		log.Printf("[Connection] 關閉連線")
		err := c.GuacClient.Close()
		c.GuacClient = nil
		c.Ready = false
		return err
	}

	return nil
}

// IsReady 檢查連線是否已就緒
func (c *Connection) IsReady() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Ready
}
