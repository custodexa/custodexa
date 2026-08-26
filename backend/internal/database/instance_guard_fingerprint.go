package database

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// 純函式：持鎖者指紋、ack 判定、攔下訊息、重取錯誤分類。
// 全部無 I/O，離線表格測試逐格釘住。

// fingerprintNull 正規化字串中 NULL 欄的占位符。
const fingerprintNull = "-"

// fingerprintCode 正規化字串 sha256 十六進位前 12 碼。
func fingerprintCode(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])[:12]
}

// fingerprintOf 由 pg_stat_activity 三欄組指紋；nil 代表 NULL（以 "-" 代入）。
//
// backend_start 以 RFC3339Nano UTC 正規化——同一工作階段在任何時區、任何客戶端
// 算出的碼都相同，操作者手打的 ack 才對得上。
func fingerprintOf(applicationName *string, pid *int64, backendStart *time.Time) HolderFingerprint {
	fp := HolderFingerprint{
		ApplicationName: fingerprintNull,
		BackendStart:    fingerprintNull,
		Source:          FingerprintSourcePGStatActivity,
	}
	pidStr := fingerprintNull
	if applicationName != nil {
		fp.ApplicationName = *applicationName
	}
	if pid != nil {
		fp.PID = *pid
		pidStr = strconv.FormatInt(*pid, 10)
	}
	if backendStart != nil {
		fp.BackendStart = backendStart.UTC().Format(time.RFC3339Nano)
	}
	fp.Code = fingerprintCode(fp.ApplicationName + "|" + pidStr + "|" + fp.BackendStart)
	return fp
}

// degradedFingerprint 指紋查詢本身失敗時的降級指紋：正規化字串
// `unavailable|<錯誤類別>`。它不綁定持鎖者，只綁「查不到」這個事實——揭露於 spec，
// 審計事件以 Source=unavailable 標示。
func degradedFingerprint(class string) HolderFingerprint {
	return HolderFingerprint{
		ApplicationName: fingerprintNull,
		BackendStart:    fingerprintNull,
		Source:          FingerprintSourceUnavailable,
		Code:            fingerprintCode("unavailable|" + class),
	}
}

// sqliteFingerprint sqlite 分支的固定形式指紋 `sqlite|<pid>|<行程 Acquire 時間>`。
func sqliteFingerprint(pid int, start time.Time) HolderFingerprint {
	startStr := fingerprintNull
	if !start.IsZero() {
		startStr = start.UTC().Format(time.RFC3339Nano)
	}
	return HolderFingerprint{
		ApplicationName: "sqlite",
		PID:             int64(pid),
		BackendStart:    startStr,
		Source:          FingerprintSourceSQLite,
		Code:            fingerprintCode("sqlite|" + strconv.Itoa(pid) + "|" + startStr),
	}
}

// readable 可讀形式：印在攔下訊息、日誌與橫幅。
func (f HolderFingerprint) readable() string {
	if f.Source == FingerprintSourceUnavailable {
		return fmt.Sprintf("持鎖者細節不可得（降級確認碼） code=%s", f.Code)
	}
	return fmt.Sprintf("application_name=%s pid=%d backend_start=%s code=%s",
		f.ApplicationName, f.PID, f.BackendStart, f.Code)
}

// ackVerdict INSTANCE_GUARD_ACK 的四態判定結果。
type ackVerdict int

const (
	// ackNotSet 有衝突、未設定 → 攔下
	ackNotSet ackVerdict = iota
	// ackMatch 有衝突、等於本次指紋碼 → 允許啟動（overridden）
	ackMatch
	// ackMismatch 有衝突、設定但不等 → 視同未設（攔下＋加註持鎖者已變更）
	ackMismatch
	// ackUnused 無衝突且有設定 → 正常啟動、不使用、建議移除
	ackUnused
)

// evaluateAck 純函式：精確比對，不做前綴或大小寫寬鬆比對。
func evaluateAck(ack, code string, conflict bool) ackVerdict {
	if !conflict {
		if ack == "" {
			return ackNotSet
		}
		return ackUnused
	}
	if ack == "" {
		return ackNotSet
	}
	if code != "" && ack == code {
		return ackMatch
	}
	return ackMismatch
}

// blockedMessage 攔下訊息（五要素：現況、持鎖者指紋、風險、兩條救援指令、澄清）。形式沿 legacySchemaError：陳述現況 → 為何攔 →
// 具體怎麼做 → 澄清常見誤解。
//
// SHALL NOT 含連線字串、密碼、主機位址、資料庫名、持鎖者 client_addr；
// 指紋（application_name／pid／backend_start）是救援指令的成分，必須印。
func blockedMessage(fp HolderFingerprint, verdict ackVerdict) string {
	var b strings.Builder
	b.WriteString("CRITICAL：單實例鎖由另一個資料庫工作階段持有。本版不支援多實例部署，本實例未啟動服務。\n")
	if fp.Source == FingerprintSourceUnavailable {
		b.WriteString("  持鎖者：無法取得持鎖者細節（pg_stat_activity 查詢失敗或無權限），降級確認碼為 code=" + fp.Code + "\n")
	} else {
		b.WriteString("  持鎖者：" + fp.readable() + "\n")
	}
	if verdict == ackMismatch {
		b.WriteString("  提供的 INSTANCE_GUARD_ACK 與當前持鎖者指紋不符（持鎖者已變更），請以上列 code 重新確認。\n")
	}
	b.WriteString("  風險：兩個實例同時執行會造成金鑰快取、匯出工作、錄影落地與封印期留痕的資料問題（見 docs/ops/deployment-topology-limits.md）。\n")
	b.WriteString("  處置 (a)：若確認另一實例仍在執行：先停止它，再重啟本實例（無需任何設定）。\n")
	b.WriteString("  處置 (b)：若確認無其他實例在執行（例如持鎖者是主機當機後殘留的工作階段）：設定環境變數 INSTANCE_GUARD_ACK=" + fp.Code +
		" 後重啟。本次啟動會寫入審計事件並在管理介面顯示橫幅，直到鎖由本實例取得。\n")
	b.WriteString("  澄清：這不是資料庫損毀；本次啟動未由本實例執行 migration 或任何資料寫入；" +
		"INSTANCE_GUARD_ACK 綁定上列指紋，持鎖者變更後失效；" +
		"確認後兩實例並存造成的資料問題由確認者承擔，守衛只保證此事被記錄。")
	return b.String()
}

// guardErrorClass 重取／驗證錯誤的類別。分類只決定告知方式，不決定退出。
type guardErrorClass string

const (
	guardErrRetryable guardErrorClass = "retryable"
	guardErrPermanent guardErrorClass = "permanent"
	guardErrUnknown   guardErrorClass = "unknown"
)

// reason 類別對應的 GuardReason。
func (c guardErrorClass) reason() GuardReason {
	switch c {
	case guardErrRetryable:
		return GuardReasonDBUnreachable
	case guardErrPermanent:
		return GuardReasonPermanent
	default:
		return GuardReasonUnknown
	}
}

// errGuardNotConnected 釘選連線不存在（lost 期間重釘失敗後）；歸可重試類。
var errGuardNotConnected = errors.New("單實例守衛：釘選連線不存在")

// sqlstateOf 取 SQLSTATE：優先 errors.As 取 *pgconn.PgError，取不到退回字串比對
// （沿 kernel/dberr 的方言無關作法；pgx 的錯誤訊息固定帶 `(SQLSTATE xxxxx)`）。
// 無 SQLSTATE 回空字串。
func sqlstateOf(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	const marker = "SQLSTATE "
	msg := err.Error()
	if i := strings.Index(msg, marker); i >= 0 && len(msg) >= i+len(marker)+5 {
		code := msg[i+len(marker) : i+len(marker)+5]
		for _, r := range code {
			if (r < '0' || r > '9') && (r < 'A' || r > 'Z') {
				return ""
			}
		}
		return code
	}
	return ""
}

// classifyGuardError 純函式：可重試（資料庫不可達）／永久（權限與物件）／未知。
// **未知歸永久**的處置（不節流的 CRITICAL 日誌），差別只在 reason 字串。
func classifyGuardError(err error) guardErrorClass {
	if err == nil {
		return guardErrUnknown
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled),
		errors.Is(err, driver.ErrBadConn),
		errors.Is(err, io.EOF),
		errors.Is(err, io.ErrUnexpectedEOF),
		errors.Is(err, errGuardNotConnected):
		return guardErrRetryable
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return guardErrRetryable
	}
	code := sqlstateOf(err)
	if code == "" {
		return guardErrUnknown
	}
	class := code[:2]
	switch {
	case class == "08", code == "57P01", code == "57P02", code == "57P03", code == "53300":
		return guardErrRetryable
	case code == "42501", class == "28", class == "42", class == "3D":
		return guardErrPermanent
	}
	return guardErrUnknown
}
