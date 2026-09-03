//go:build loopback

// overlaygen：為 rotation-loopback 的 Windows 建置產生 `go build -overlay` 檔。
//
// 後端 module 只在 Linux 建置：internal/localpty 以 syscall.Credential 降權，
// 該型別在 windows 目標上不存在，而 asset 模組經 k8sproxy 間接依賴 localpty。
// 真機回歸要在 Windows runner 上跑，故以 overlay 在**建置時**換掉那一處
// （loopback 二進位從不呼叫 localpty），工作樹本身一行不動。
//
// 替換逐行精確比對；任一片段找不到即失敗——conn.go 改了就在這裡紅，不會靜默建出不同的東西。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const targetRel = "internal/localpty/conn.go"

var (
	removeBlock = "\t\tcmd.SysProcAttr = &syscall.SysProcAttr{\n" +
		"\t\t\tCredential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},\n" +
		"\t\t}\n"
	replaceBlock = "\t\t_, _ = uid, gid\n"
	removeImport = "\t\"syscall\"\n"
)

func main() {
	moduleRoot := flag.String("module-root", ".", "backend module root (directory containing go.mod)")
	out := flag.String("out", "", "output directory for the patched file and overlay.json")
	flag.Parse()
	if *out == "" {
		die("-out is required")
	}
	root, err := filepath.Abs(*moduleRoot)
	if err != nil {
		die(err.Error())
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		die("go.mod not found under " + root)
	}
	src := filepath.Join(root, filepath.FromSlash(targetRel))
	raw, err := os.ReadFile(src)
	if err != nil {
		die(err.Error())
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	patched, err := patch(text)
	if err != nil {
		die(err.Error())
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		die(err.Error())
	}
	dst := filepath.Join(*out, "localpty_conn.go")
	if err := os.WriteFile(dst, []byte(patched), 0o644); err != nil {
		die(err.Error())
	}
	overlay := map[string]map[string]string{"Replace": {src: dst}}
	b, _ := json.MarshalIndent(overlay, "", "  ")
	overlayPath := filepath.Join(*out, "overlay.json")
	if err := os.WriteFile(overlayPath, b, 0o644); err != nil {
		die(err.Error())
	}
	fmt.Println(overlayPath)
}

func patch(text string) (string, error) {
	if strings.Count(text, removeBlock) != 1 {
		return "", fmt.Errorf("%s: expected exactly one SysProcAttr block, found %d", targetRel, strings.Count(text, removeBlock))
	}
	if strings.Count(text, removeImport) != 1 {
		return "", fmt.Errorf("%s: expected exactly one syscall import line, found %d", targetRel, strings.Count(text, removeImport))
	}
	text = strings.Replace(text, removeBlock, replaceBlock, 1)
	text = strings.Replace(text, removeImport, "", 1)
	return text, nil
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "overlaygen: "+msg)
	os.Exit(1)
}
