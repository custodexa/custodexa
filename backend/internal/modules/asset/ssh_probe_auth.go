package asset

import (
	"errors"
	"fmt"

	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/sshmaterial"
	"golang.org/x/crypto/ssh"
)

// ErrorCodePrivateKeyInvalid 撥測粗分類：帳號的私鑰存在但無法解析
// （格式錯誤或受 passphrase 保護）。與「無可用帳號」分開，管理者才知道要換的是私鑰本身。
const ErrorCodePrivateKeyInvalid = "private_key_invalid"

var (
	// errProbeNoSecret 就位版本既無私鑰也無密碼：無從認證，不撥號
	errProbeNoSecret = errors.New("帳號無可用的私鑰或密碼")
	// errProbePrivateKeyInvalid 私鑰無法解析：正式連線同樣會失敗，不撥號
	errProbePrivateKeyInvalid = errors.New("私鑰無法解析")
)

// sshProbeAuthMethods 依帳號秘密組裝 SSH 撥測的認證方式。
//
// 規則與正式終端連線（sshproxy 的 authMethods）逐條相同，撥測才能如實預測
// 「按下連線會不會成功」：
//   - 有私鑰即提供公鑰認證，有密碼即提供密碼認證；兩者皆有時放進同一份清單，
//     私鑰在前、密碼在後，由同一次交握依序出示。不拆成多次連線，也不改試其他
//     秘密版本——目標端看到的認證事件與一次正式連線相同。
//   - 私鑰存在但解析失敗時直接回錯，不退回密碼：正式連線在此情形下同樣無法
//     建立，若撥測改用密碼而回報成功，就是在說一件實際上不成立的事。
//   - 空密碼不包成密碼認證：對允許空密碼的伺服器，空密碼可能「登入成功」，
//     讓畫面顯示資產可連，但那不是可用的憑證。
//
// 私鑰明文只在 material.Use 借用期間存在；回傳的 signer 由呼叫端在撥號結束後
// 丟棄。password 的所有權仍屬呼叫端（撥號函式負責銷毀）。
func sshProbeAuthMethods(password *sshmaterial.Password, privateKey *material.Secret) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if !privateKey.IsEmpty() {
		signer, err := material.Use(privateKey, ssh.ParsePrivateKey)
		if err != nil {
			// 原始解析錯誤可能帶金鑰格式細節，只包進 error 供伺服端日誌，不進回應
			return nil, fmt.Errorf("%w: %v", errProbePrivateKeyInvalid, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if !password.Empty() {
		methods = append(methods, ssh.PasswordCallback(password.Callback))
	}

	if len(methods) == 0 {
		return nil, errProbeNoSecret
	}
	return methods, nil
}
