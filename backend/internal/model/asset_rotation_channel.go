package model

// 改密通道的值域與推導。
//
// 通道回答的是「改密要怎麼連上這台機器」，與會話協定是兩件事：Windows 主機以
// rdp 登記（會話走 RDP），改密卻要走 WinRM 或 PowerShell over SSH，兩者的目標埠、
// 傳輸保證與指令集都不同。把它設在資產而非帳號，是因為一台機器只有一種進得去的
// 遠端管理方式，帳號層只需要區分認證來源。
const (
	// RotationChannelPosixSSH SSH 到 POSIX shell（chpasswd／authorized_keys）
	RotationChannelPosixSSH = "posix_ssh"
	// RotationChannelWindowsWinRM WinRM（NTLM，訊息層加密強制）
	RotationChannelWindowsWinRM = "windows_winrm"
	// RotationChannelWindowsSSH SSH 到 Windows OpenSSH，指令走 PowerShell
	RotationChannelWindowsSSH = "windows_ssh"
	// RotationChannelNone 不改密。顯式設定的「不做」，與「未設定」不同：
	// 前者是管理者的決定，後者交給推導
	RotationChannelNone = "none"
)

// WinRM 連線方式與 TLS 驗證模式的值域。
const (
	WinrmSchemeHTTP  = "http"
	WinrmSchemeHTTPS = "https"

	// WinrmTLSModeSystem 以作業系統的信任錨驗證伺服器憑證
	WinrmTLSModeSystem = "system"
	// WinrmTLSModeCA 只信任本資產上傳的 CA
	WinrmTLSModeCA = "ca"
	// WinrmTLSModeInsecure 不驗證憑證（傳輸階梯標風險）
	WinrmTLSModeInsecure = "insecure"
)

// WinRM 的預設埠（scheme 決定；資產的 winrm_port 為 0 時採用）。
const (
	WinrmDefaultPortHTTP  = 5985
	WinrmDefaultPortHTTPS = 5986
)

// RotationDefaultSSHPort windows_ssh 通道在非 ssh 協定資產上的預設埠。
const RotationDefaultSSHPort = 22

// RotationChannels 全部合法通道值（不含「未設定」的空字串）。
func RotationChannels() []string {
	return []string{
		RotationChannelPosixSSH,
		RotationChannelWindowsWinRM,
		RotationChannelWindowsSSH,
		RotationChannelNone,
	}
}

// IsRotationChannel 回報字串是否為合法通道值（空字串＝未設定，視為合法）。
func IsRotationChannel(s string) bool {
	if s == "" {
		return true
	}
	for _, c := range RotationChannels() {
		if c == s {
			return true
		}
	}
	return false
}

// EffectiveRotationChannel 推導後的有效通道。
//
// **空字串一律推導、不回填**：migration 之後既有列全部是空字串，推導使 ssh 資產
// 維持 posix_ssh、其餘協定維持不改密——升級前後行為逐項相同。若改成在 migration
// 裡回填實值，日後改推導規則就再也分不出哪些列是管理者設的、哪些是當初回填的。
func (a *Asset) EffectiveRotationChannel() string {
	if a.RotationChannel != "" {
		return a.RotationChannel
	}
	if a.Protocol == ProtocolSSH {
		return RotationChannelPosixSSH
	}
	return RotationChannelNone
}

// IsWindowsRotationChannel 兩條 Windows 通道的共同判定（指令集為 PowerShell）。
func IsWindowsRotationChannel(channel string) bool {
	return channel == RotationChannelWindowsWinRM || channel == RotationChannelWindowsSSH
}

// RotationChannelCompatibleWith 通道與協定的相容性。
//
// windows_* 限 rdp 與 ssh：Windows 主機在本系統以 rdp 登記，而已經以 ssh 登記的
// Windows 主機（OpenSSH）只是指令集不同。posix_ssh 限 ssh。none 與未設定恆相容。
func RotationChannelCompatibleWith(protocol ProtocolType, channel string) bool {
	switch channel {
	case "", RotationChannelNone:
		return true
	case RotationChannelPosixSSH:
		return protocol == ProtocolSSH
	case RotationChannelWindowsWinRM, RotationChannelWindowsSSH:
		return protocol == ProtocolRDP || protocol == ProtocolSSH
	default:
		return false
	}
}

// EffectiveWinrmPort winrm_port 為 0 時依 scheme 取預設。
func (a *Asset) EffectiveWinrmPort() int {
	if a.WinrmPort > 0 {
		return a.WinrmPort
	}
	if a.WinrmScheme == WinrmSchemeHTTPS {
		return WinrmDefaultPortHTTPS
	}
	return WinrmDefaultPortHTTP
}

// EffectiveRotationSSHPort windows_ssh 通道的目標埠。
//
// 協定為 ssh 的資產沿用 Port——那就是同一條 SSH 服務，另設一個埠只會製造兩個
// 可能不一致的事實。其餘協定（rdp）用 rotation_ssh_port，0 取 22。
func (a *Asset) EffectiveRotationSSHPort() int {
	if a.Protocol == ProtocolSSH {
		return a.Port
	}
	if a.RotationSSHPort > 0 {
		return a.RotationSSHPort
	}
	return RotationDefaultSSHPort
}
