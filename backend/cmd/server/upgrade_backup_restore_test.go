package main

// 固定升級前備份（上一個正式版以正式程式建庫後的 PostgreSQL plain dump）的讀取與還原。
// 讀取時先比對 sha256，不符即停；還原到每個子案例自己的獨立資料庫，不共用其他庫。
// 備份檔放在 openspec 某個 change 目錄的 research/upgrade-backup/ 下，以檔名掃描解析（未歸檔與已歸檔兩種佈局、
// docker 唯讀掛載與 host 全 repo checkout 兩種根），恰一份才用；多於一份即 t.Fatal。
// 備份檔不一定隨原始碼提供：找不到時 t.Skip 並寫明原因；掛載本身缺漏由同套件讀取 openspec 清冊的守衛擋下。

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/testgate"
)

const (
	upgradeBackupRel    = "research/upgrade-backup/custodexa-1.17.9-pre-upgrade-2026-10-25.sql.gz"
	upgradeBackupSHA256 = "8bf05812c9e027cb2f0492ccb76559abb1272e6fde653f525dd91213bf8a80b8"
)

// upgradeBackupPath 在 openspec 的 change 目錄（含已歸檔）中找備份檔，恰一份才回傳。
func upgradeBackupPath(t *testing.T) string {
	t.Helper()
	moduleRoot := guardModuleRoot(t)
	var found, tried []string
	for _, root := range []string{
		filepath.Join(moduleRoot, "testdata", "openspec"),   // docker 唯讀掛載
		filepath.Join(filepath.Dir(moduleRoot), "openspec"), // host 全 repo checkout
	} {
		for _, pattern := range []string{
			filepath.Join(root, "changes", "*", upgradeBackupRel),
			filepath.Join(root, "changes", "archive", "*", upgradeBackupRel),
		} {
			tried = append(tried, pattern)
			matches, err := filepath.Glob(pattern)
			require.NoError(t, err)
			found = append(found, matches...)
		}
	}
	if len(found) == 0 {
		t.Skipf("本樹未收錄升級前備份，跳過升級路徑重入驗證。已試：\n  %s", joinLines(tried))
	}
	if len(found) != 1 {
		t.Fatalf("升級前備份應恰有一份，找到 %d 份：%v\n已試：\n  %s\n"+
			"docker 內須有 `./openspec:/app/testdata/openspec:ro` 掛載；host 直跑須在 repo 完整 checkout 下執行",
			len(found), found, joinLines(tried))
	}
	return found[0]
}

// readUpgradeBackup 讀備份本體、驗 sha256、解壓後回傳 SQL 文字。
func readUpgradeBackup(t *testing.T) []byte {
	t.Helper()
	path := upgradeBackupPath(t)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != upgradeBackupSHA256 {
		t.Fatalf("升級前備份 sha256 不符：%s（應為 %s，檔案 %s）", got, upgradeBackupSHA256, path)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	require.NoError(t, err)
	body, err := io.ReadAll(zr)
	require.NoError(t, err)
	fmt.Printf("EVIDENCE upgrade_backup=%s sha256=%s gz_bytes=%d sql_bytes=%d\n",
		filepath.Base(path), upgradeBackupSHA256, len(raw), len(body))
	return body
}

// newRestoredPG 建一個獨立資料庫、把 plain dump 還原進去，回傳連到該庫的連線（預設 search_path，與正式環境同）。
// TEST_PG_DSN 須為 key=value 形式：以附加 dbname 指向新庫。
func newRestoredPG(t *testing.T, name string, dump []byte) *gorm.DB {
	t.Helper()
	dsn := testgate.Value(t, testgate.EnvPGDSN)
	require.NotContains(t, dsn, "://", "TEST_PG_DSN 須為 key=value 形式，才能附加 dbname 指向獨立資料庫")
	admin := pwloOpen(t, dsn)
	drop := "DROP DATABASE IF EXISTS " + name + " WITH (FORCE)"
	require.NoError(t, admin.Exec(drop).Error)
	require.NoError(t, admin.Exec("CREATE DATABASE "+name).Error)
	t.Cleanup(func() {
		if err := admin.Exec(drop).Error; err != nil {
			t.Errorf("測試資料庫清理失敗（請手動 DROP DATABASE %s）: %v", name, err)
		}
	})
	target := dsn + " dbname=" + name
	copies := restorePlainDump(t, target, dump)
	fmt.Printf("EVIDENCE upgrade_backup_restored database=%s copy_blocks=%d\n", name, copies)
	return pwloOpen(t, target)
}

// restorePlainDump 以單一連線依序執行 dump：一般 SQL 段走簡單查詢協定（可含多個語句），
// COPY ... FROM stdin 區塊改走 CopyFrom。psql 的 \restrict／\unrestrict 中繼指令略過（本還原器不執行任何中繼指令），
// 其他中繼指令一律停下。回傳 COPY 區塊數。
func restorePlainDump(t *testing.T, dsn string, dump []byte) int {
	t.Helper()
	ctx := context.Background()
	conn, err := pgconn.Connect(ctx, dsn)
	require.NoError(t, err, "還原用連線失敗")
	defer func() { _ = conn.Close(ctx) }()

	var pending strings.Builder
	flush := func() {
		if strings.TrimSpace(pending.String()) != "" {
			_, err := conn.Exec(ctx, pending.String()).ReadAll()
			require.NoError(t, err, "還原 SQL 段失敗")
		}
		pending.Reset()
	}
	lines := strings.SplitAfter(string(dump), "\n")
	copies := 0
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], "\n")
		switch {
		case strings.HasPrefix(line, `\restrict `), strings.HasPrefix(line, `\unrestrict `):
			continue
		case strings.HasPrefix(line, `\`):
			t.Fatalf("dump 第 %d 行是未預期的 psql 中繼指令：%q", i+1, line)
		case strings.HasPrefix(line, "COPY ") && strings.HasSuffix(line, " FROM stdin;"):
			flush()
			var data strings.Builder
			j := i + 1
			for ; j < len(lines) && strings.TrimRight(lines[j], "\n") != `\.`; j++ {
				data.WriteString(lines[j])
			}
			require.Less(t, j, len(lines), "COPY 區塊缺結尾：%s", line)
			_, err := conn.CopyFrom(ctx, strings.NewReader(data.String()), strings.TrimSuffix(line, ";"))
			require.NoError(t, err, "COPY 失敗：%s", line)
			copies++
			i = j
		default:
			pending.WriteString(lines[i])
		}
	}
	flush()
	return copies
}

// sqlRowsText 把查詢結果逐列逐欄轉成文字（欄以 | 分隔、列以 ; 分隔），供前後逐欄比對。
func sqlRowsText(t *testing.T, db *gorm.DB, q string) string {
	t.Helper()
	rows, err := db.Raw(q).Rows()
	require.NoError(t, err, q)
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	require.NoError(t, err)
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		require.NoError(t, rows.Scan(ptrs...))
		parts := make([]string, len(vals))
		for i, v := range vals {
			if b, ok := v.([]byte); ok {
				parts[i] = string(b)
			} else {
				parts[i] = fmt.Sprint(v)
			}
		}
		out = append(out, strings.Join(parts, "|"))
	}
	require.NoError(t, rows.Err())
	return strings.Join(out, ";")
}
