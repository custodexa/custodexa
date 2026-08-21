package localpty

import (
	"fmt"
	"strings"
)

// SafeArg 驗證將進入 CLI argv 的資產欄位值（防 flag 注入與控制字元）。
// 本地 CLI 子程序雖經 exec.Command 繞過 shell（無 shell 注入），
// 但 CLI 工具本身仍解析以 "-" 開頭的 argv 為旗標
// （psql --command、kubectl --kubeconfig 等），故位置/值參數須拒絕：
//   - 以 "-" 開頭（會被當旗標）
//   - 含換行/歸位（破壞 kubeconfig YAML 等多行結構）
//   - 含 NUL（截斷）
//
// 空字串視為合法（呼叫端自行決定欄位是否必填）。
func SafeArg(field, value string) error {
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "-") {
		return fmt.Errorf("%s 不可以 - 開頭（避免被解讀為命令旗標）", field)
	}
	if strings.ContainsAny(value, "\n\r\x00") {
		return fmt.Errorf("%s 含非法控制字元", field)
	}
	return nil
}

// SafeSecret 驗證憑證類值（不入 argv，但會進 kubeconfig YAML 等多行檔）：
// 僅拒絕換行/歸位/NUL，不限制 "-" 開頭（token 可能合法地以 - 開頭）。
func SafeSecret(field, value string) error {
	if strings.ContainsAny(value, "\n\r\x00") {
		return fmt.Errorf("%s 含非法控制字元", field)
	}
	return nil
}
