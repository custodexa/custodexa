package asset

import (
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/custodexa/backend/internal/model"
)

var (
	// ErrInvalidRotationChannel 通道值不在值域內，或與資產協定不相容。
	// 值域外的通道會讓執行期選路落到「未接線」分支，而管理員在畫面上看到的是
	// 一個設好了的通道——症狀是每次執行都失敗卻查不出設定哪裡不對
	ErrInvalidRotationChannel = errors.New("rotation_channel 僅允許空值（依協定推導）、posix_ssh、windows_winrm、windows_ssh 或 none；posix_ssh 限 ssh 協定，windows_winrm 與 windows_ssh 限 rdp 或 ssh 協定")
	// ErrInvalidRotationChannelParams 通道附屬欄位不合（連線方式、TLS 模式、CA 憑證、埠）。
	// 五種違規共用一碼：它們都是「這組通道設定不完整或不合格式」，
	// 逐項分碼會讓前端多五個鍵而使用者拿到的指引沒有更精確
	ErrInvalidRotationChannelParams = errors.New("改密通道設定不完整或不合格式：windows_winrm 須指定連線方式（http／https），https 須指定憑證驗證模式（system／ca／insecure），ca 模式須提供可解析的 CA 憑證（PEM），埠須為 0（取預設）或 1 至 65535")
)

// validateRotationChannel 改密通道側車的完整驗證。
//
// **以套用後的最終資產呼叫**（協定與通道可能在同一次更新中一起變動，各自在自己的
// 分支內驗會放行「協定改成 mysql、通道照樣送 windows_winrm」這種組合）。
func validateRotationChannel(asset *model.Asset) error {
	if !model.IsRotationChannel(asset.RotationChannel) {
		return ErrInvalidRotationChannel
	}
	if !model.RotationChannelCompatibleWith(asset.Protocol, asset.RotationChannel) {
		return ErrInvalidRotationChannel
	}
	if !validRotationPort(asset.WinrmPort) || !validRotationPort(asset.RotationSSHPort) {
		return ErrInvalidRotationChannelParams
	}
	if asset.RotationChannel != model.RotationChannelWindowsWinRM {
		return nil
	}

	switch asset.WinrmScheme {
	case model.WinrmSchemeHTTP:
		// http 之下沒有 TLS 可驗證。留著一個 TLS 模式值會讓設定畫面與清冊看起來
		// 有一層並不存在的保護——不接受，而不是靜默忽略
		if asset.WinrmTLSMode != "" {
			return ErrInvalidRotationChannelParams
		}
	case model.WinrmSchemeHTTPS:
		switch asset.WinrmTLSMode {
		case model.WinrmTLSModeSystem, model.WinrmTLSModeInsecure:
		case model.WinrmTLSModeCA:
			if !parsesAsCertificate(asset.WinrmCACert) {
				return ErrInvalidRotationChannelParams
			}
		default:
			// 空值不視為預設：憑證驗證要不要做是一個必須有人負責的決定，
			// 靜默取「系統信任」會讓「還沒想過」與「想過並選了」無法分辨
			return ErrInvalidRotationChannelParams
		}
	default:
		return ErrInvalidRotationChannelParams
	}
	return nil
}

// validRotationPort 0＝取通道預設；其餘須為合法 TCP 埠。
func validRotationPort(port int) bool {
	return port == 0 || (port >= 1 && port <= 65535)
}

// parsesAsCertificate PEM 是否至少含一張可解析的憑證。
//
// **儲存時就驗**：憑證只在改密執行期才用得到，而那是排程觸發的背景動作——
// 把「PEM 貼錯了」留到那時才發現，管理員拿到的是一筆失敗記錄而不是表單錯誤。
func parsesAsCertificate(pemText string) bool {
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err == nil {
			return true
		}
		return false
	}
}

// clearRotationChannel 清空通道與全部附屬欄位。
//
// 協定改為與通道不相容時由伺服端呼叫。留著休眠的殘值等於把缺口制度化：
// 協定改回時會靜默恢復一份沒人記得設過的連線設定，而那份設定指向的是憑證與埠。
func clearRotationChannel(asset *model.Asset) {
	asset.RotationChannel = ""
	asset.WinrmScheme = ""
	asset.WinrmPort = 0
	asset.WinrmTLSMode = ""
	asset.WinrmCACert = ""
	asset.RotationSSHPort = 0
}

// fillRotationProjection 填入推導欄位。
//
// listView 為真時抹去 CA 憑證本體：PEM 動輒數 KB，讓資產列表的每一列都扛著它
// 會使傳輸量隨憑證大小起伏，而列表只需要知道「設了沒有」。編輯路徑（單筆讀取）
// 仍回本體，否則表單無法回填。
func fillRotationProjection(asset *model.Asset, listView bool) {
	asset.EffectiveChannel = asset.EffectiveRotationChannel()
	asset.HasWinrmCACert = asset.WinrmCACert != ""
	if listView {
		asset.WinrmCACert = ""
	}
}
