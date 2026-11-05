//go:build keystroke_devcheck

// devcheck：dev 環境鍵盤紀錄驗證工具（build tag keystroke_devcheck，不進出貨映像）。
//
// 在 backend 容器內以 `go run -tags keystroke_devcheck ./internal/keystroke/devcheck` 執行，
// 讀取 keystroke_records 列、以組態的 KEK 解封檔案金鑰、用正式讀取器驗證並解密，
// 只輸出計數與判定，絕不印出任何按鍵內容。
//
// 斷言字串（可不是秘密的標記、或是不該出現的資產密碼）由環境變數傳入，避免進命令列：
//
//	DEVCHECK_EXPECT  以換行分隔的字串，每個都必須出現在解密後的輸入中
//	DEVCHECK_ABSENT  以換行分隔的字串，每個都必須不出現在解密後的輸入中，
//	                 也不得出現在磁碟上的原始檔案位元組中
//
// 用法：devcheck -session <id> [-min-events N] [-expect-status S] [-expect-integrity I]
// 結束碼：全部斷言成立為 0，否則為 1。
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/custodexa/backend/config"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/keystroke"
	"github.com/custodexa/backend/internal/keystroke/format"
	"github.com/custodexa/backend/internal/keystroke/reader"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/keyvault"
	"github.com/custodexa/backend/pkg/crypto"
)

func lines(env string) []string {
	var out []string
	for _, s := range strings.Split(os.Getenv(env), "\n") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func main() {
	sid := flag.Uint("session", 0, "會話 id")
	minEvents := flag.Int("min-events", 1, "事件數下限")
	expStatus := flag.String("expect-status", "", "期望的 keystroke_records.status（空＝不檢查）")
	expInteg := flag.String("expect-integrity", "", "期望的讀取器判定（空＝不檢查）")
	dumpKS := flag.Bool("dump-keysyms", false, "印出每筆事件的 kind、keysym 數值與按放（不印字元內容）")
	flag.Parse()
	if *sid == 0 {
		fmt.Println("FAIL usage: -session required")
		os.Exit(2)
	}

	cfg := config.Load()
	if err := database.InitDatabase(cfg); err != nil {
		fmt.Println("FAIL db:", err)
		os.Exit(1)
	}
	dec, err := config.DecideKEK(config.OSEnvLookup, config.HSMBuildEnabled)
	if err != nil || dec.Mode != config.KEKModeEnv {
		fmt.Println("FAIL kek: devcheck 只支援 env 模式")
		os.Exit(1)
	}
	key, reason := config.DecodeKEKMaterialKey(dec.Material)
	if reason != "" {
		fmt.Println("FAIL kek material:", reason)
		os.Exit(1)
	}
	kek, err := crypto.NewLocalAESKEKProvider(key, crypto.KEKModeEnv)
	if err != nil {
		fmt.Println("FAIL kek provider:", err)
		os.Exit(1)
	}
	km, err := keyvault.InitKeyManagerWithBootstrap(database.DB, kek, nil)
	if err != nil {
		fmt.Println("FAIL keymanager:", err)
		os.Exit(1)
	}
	defer km.ZeroizeForRelease()

	var row model.KeystrokeRecord
	if err := database.DB.Where("session_id = ?", *sid).First(&row).Error; err != nil {
		fmt.Println("FAIL no keystroke_records row for session")
		os.Exit(1)
	}
	ok := true
	check := func(name string, pass bool, detail string) {
		v := "PASS"
		if !pass {
			v = "FAIL"
			ok = false
		}
		fmt.Printf("%s %s %s\n", v, name, detail)
	}
	fmt.Printf("INFO status=%s protocol=%s event_count_col=%d segment_count_col=%d byte_size_col=%d coverage=%q failure=%q\n",
		row.Status, row.Protocol, row.EventCount, row.SegmentCount, row.ByteSize, row.CoverageReason, row.FailureCause)
	if *expStatus != "" {
		check("status", row.Status == *expStatus, "want="+*expStatus)
	}

	secret, err := km.DecryptBytesFor(context.Background(), keyvault.RefKeystrokeFileKey, row.FileKeyEnc)
	if err != nil {
		fmt.Println("FAIL unwrap file key")
		os.Exit(1)
	}
	defer secret.Destroy()
	root := keystroke.RootFromAuditDir(os.Getenv("AUDIT_LOG_PATH"))
	var res reader.Result
	_ = secret.Borrow(func(b []byte) error {
		res = reader.Read(root, reader.Record{UUID: row.RecordUUID, SessionID: uint64(row.SessionID),
			Protocol: row.Protocol, FilePath: row.FilePath}, b, reader.Options{})
		return nil
	})
	fmt.Printf("INFO integrity=%s total_events=%d segments_read=%d\n", res.Status, res.TotalEvents, res.SegmentsRead)
	check("min_events", res.TotalEvents >= *minEvents, fmt.Sprintf("events=%d min=%d", res.TotalEvents, *minEvents))
	if *expInteg != "" {
		check("integrity", string(res.Status) == *expInteg, "want="+*expInteg)
	}

	var plain []byte
	markers, blocked := 0, 0
	for _, e := range res.Events {
		switch e.Kind {
		case format.KindBytes:
			plain = append(plain, e.Payload...)
			if e.Flags&format.FlagBlocked != 0 {
				blocked++
			}
		case format.KindMarker:
			markers++
		}
	}
	kinds := map[byte]int{}
	for i, e := range res.Events {
		kinds[e.Kind]++
		if *dumpKS {
			switch e.Kind {
			case format.KindKeysym:
				if ks, pressed, derr := format.DecodeKeysym(e.Payload); derr == nil {
					fmt.Printf("EVENT %d kind=0x%02x keysym=0x%X pressed=%v flags=%d\n", i, e.Kind, ks, pressed, e.Flags)
				} else {
					fmt.Printf("EVENT %d kind=0x%02x decode_error\n", i, e.Kind)
				}
			default:
				fmt.Printf("EVENT %d kind=0x%02x payload_len=%d flags=%d\n", i, e.Kind, len(e.Payload), e.Flags)
			}
		}
	}
	fmt.Printf("INFO kind_counts=%v\n", kinds)
	fmt.Printf("INFO plaintext_len=%d marker_events=%d blocked_events=%d\n", len(plain), markers, blocked)
	for i, s := range lines("DEVCHECK_EXPECT") {
		check(fmt.Sprintf("expect[%d]", i), bytes.Contains(plain, []byte(s)), fmt.Sprintf("len=%d", len(s)))
	}
	if strings.Contains(os.Getenv("DEVCHECK_EXPECT_CR"), "1") {
		check("contains_enter", bytes.Contains(plain, []byte("\r")), "")
	}
	// 磁碟位元組：不得含任何 EXPECT／ABSENT 字串（密文）
	if full, err := reader.ResolveInRoot(root, row.FilePath); err == nil {
		raw, rerr := os.ReadFile(full)
		check("file_readable", rerr == nil, "bytes="+fmt.Sprint(len(raw)))
		st, _ := os.Stat(full)
		fdir, _ := os.Stat(filepath.Dir(full))
		if st != nil && fdir != nil {
			fmt.Printf("INFO file_mode=%o dir_mode=%o\n", st.Mode().Perm(), fdir.Mode().Perm())
		}
		leak := 0
		for _, s := range append(lines("DEVCHECK_EXPECT"), lines("DEVCHECK_ABSENT")...) {
			if bytes.Contains(raw, []byte(s)) {
				leak++
			}
		}
		check("disk_ciphertext_no_plaintext", leak == 0, fmt.Sprintf("leaks=%d", leak))
	} else {
		check("file_path", false, "rejected")
	}
	for i, s := range lines("DEVCHECK_ABSENT") {
		check(fmt.Sprintf("absent[%d]", i), !bytes.Contains(plain, []byte(s)), fmt.Sprintf("len=%d", len(s)))
	}
	if !ok {
		os.Exit(1)
	}
}
