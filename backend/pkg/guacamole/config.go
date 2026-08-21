package guacamole

import "strconv"

// SSHConfig SSH 連線配置
type SSHConfig struct {
	Hostname     string
	Port         int
	Username     string
	Password     string
	TerminalType string // 終端類型，如 xterm-256color
	Width        int    // 終端寬度（字元數）
	Height       int    // 終端高度（行數）
}

// ToParams 轉換為 Guacamole 參數
func (c *SSHConfig) ToParams() map[string]string {
	params := map[string]string{
		"hostname": c.Hostname,
		"port":     "22",
		"username": c.Username,
	}

	if c.Port > 0 {
		params["port"] = strconv.Itoa(c.Port)
	}

	if c.Password != "" {
		params["password"] = c.Password
	}

	// 終端機類型（重要！）
	if c.TerminalType != "" {
		params["terminal-type"] = c.TerminalType
	} else {
		params["terminal-type"] = "xterm-256color"
	}

	// 終端機大小（重要！）
	if c.Width > 0 {
		params["width"] = strconv.Itoa(c.Width)
	}
	if c.Height > 0 {
		params["height"] = strconv.Itoa(c.Height)
	}

	// 終端機設定
	params["enable-sftp"] = "false"
	params["color-scheme"] = "green-black"
	params["font-size"] = "12"
	params["font-name"] = "monospace"

	return params
}

// RDPConfig RDP 連線配置
type RDPConfig struct {
	Hostname        string
	Port            int
	Username        string
	Password        string
	Domain          string
	Security        string // any, nla, tls, rdp
	IgnoreCert      bool
	EnableDrive     bool
	EnablePrinting  bool
	EnableAudio     bool
	EnableClipboard bool
	Width           int
	Height          int
	DPI             int
}

// ToParams 轉換為 Guacamole 參數
func (c *RDPConfig) ToParams() map[string]string {
	params := map[string]string{
		"hostname": c.Hostname,
		"port":     "3389",
		"username": c.Username,
	}

	if c.Port > 0 {
		params["port"] = strconv.Itoa(c.Port)
	}

	if c.Password != "" {
		params["password"] = c.Password
	}

	if c.Domain != "" {
		params["domain"] = c.Domain
	}

	// 安全性設定
	if c.Security != "" {
		params["security"] = c.Security
	} else {
		params["security"] = "any"
	}

	if c.IgnoreCert {
		params["ignore-cert"] = "true"
	}

	// 畫面設定
	if c.Width > 0 && c.Height > 0 {
		params["width"] = strconv.Itoa(c.Width)
		params["height"] = strconv.Itoa(c.Height)
	}

	if c.DPI > 0 {
		params["dpi"] = strconv.Itoa(c.DPI)
	}

	// 功能啟用
	if c.EnableDrive {
		params["enable-drive"] = "true"
		params["drive-name"] = "Shared"
		params["drive-path"] = "/tmp"
	}

	if c.EnablePrinting {
		params["enable-printing"] = "true"
	}

	if c.EnableAudio {
		params["enable-audio"] = "true"
	}

	if c.EnableClipboard {
		params["enable-clipboard"] = "true"
	}

	return params
}

// VNCConfig VNC 連線配置
type VNCConfig struct {
	Hostname        string
	Port            int
	Password        string
	ColorDepth      int // 8, 16, 24, 32
	SwapRedBlue     bool
	Cursor          string // local, remote
	ReadOnly        bool
	EnableAudio     bool
	EnableClipboard bool
}

// ToParams 轉換為 Guacamole 參數
func (c *VNCConfig) ToParams() map[string]string {
	params := map[string]string{
		"hostname": c.Hostname,
		"port":     "5900",
	}

	if c.Port > 0 {
		params["port"] = strconv.Itoa(c.Port)
	}

	if c.Password != "" {
		params["password"] = c.Password
	}

	// 顯示設定
	if c.ColorDepth > 0 {
		params["color-depth"] = strconv.Itoa(c.ColorDepth)
	}

	if c.SwapRedBlue {
		params["swap-red-blue"] = "true"
	}

	if c.Cursor != "" {
		params["cursor"] = c.Cursor
	}

	if c.ReadOnly {
		params["read-only"] = "true"
	}

	// 功能啟用
	if c.EnableAudio {
		params["enable-audio"] = "true"
	}

	if c.EnableClipboard {
		params["enable-clipboard"] = "true"
	}

	return params
}
