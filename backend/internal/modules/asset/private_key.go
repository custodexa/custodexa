package asset

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ErrPrivateKeyInvalid 私鑰無法解析為可用的簽章金鑰（格式錯誤、內容不完整、
// 貼成公鑰、受 passphrase 保護等）。
//
// 寫入時驗證、終端撥號、SFTP 撥號與連線測試共用這一個 sentinel 與判準：
// 驗證與連線用同一個解析函式，才不會出現「建立時擋下、實際連得上」或反過來的情形。
var ErrPrivateKeyInvalid = errors.New("私鑰無法解析")

// ParsePrivateKey 將私鑰解析為 SSH signer；失敗時回包裝 ErrPrivateKeyInvalid 的錯誤。
//
// 系統不支援受 passphrase 保護的私鑰，故一律以不帶 passphrase 的方式解析。
// 庫的原始錯誤只包進 error 供伺服端日誌，呼叫端不得把它放進對外回應。
func ParsePrivateKey(raw []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPrivateKeyInvalid, err)
	}
	return signer, nil
}

// ValidatePrivateKey 供人工輸入私鑰的寫入路徑在加密落庫前檢查。
// 空字串回 nil：是否必填、空值是否代表沿用現行私鑰，由呼叫端判斷。
func ValidatePrivateKey(pem string) error {
	if pem == "" {
		return nil
	}
	_, err := ParsePrivateKey([]byte(pem))
	return err
}
