//go:build !pkcs11

package config

// HSMBuildEnabled 本執行檔是否含 HSM（PKCS#11）能力（D2.2 列 11）。
// 預設映像不含 cgo 依賴故為 false；HSM 變體以 `-tags pkcs11` 建置。
// 置於 config 而非 cmd/server：後者的路由收斂守衛禁止 build constraint 檔。
const HSMBuildEnabled = false
