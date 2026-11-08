package dbproxy

import "strings"

// 受管憑證只用於本次會話所指向的資產。
//
// 本檔是輸入側的判定：送出的整行含改連其他主機的指令時，該行不轉送。
//
// 判定採 token 制、任一位置命中即算，寧可誤擋：字面恰為指令名的字串常值或鍵名同樣命中，
// 使用者改寫輸入即可；子字串（如 connected_clients、disconnect）不算。
// 是固定行為，不受指令規則設定影響。postgres 另有既有的再提示守衛，不在此判定。

// ReconnectVerdict 一行輸入的判定結果。
type ReconnectVerdict int

const (
	// ReconnectAllow 未命中改連指令，可轉送。
	ReconnectAllow ReconnectVerdict = iota
	// ReconnectHit 整行含改連目標的指令，不得轉送。
	ReconnectHit
	// ReconnectUncertain 無法確定整行內容（引號或跳脫無法正規化），不得轉送。
	ReconnectUncertain
)

// String 供測試訊息與日誌（只含判定名，不含輸入內容）。
func (v ReconnectVerdict) String() string {
	switch v {
	case ReconnectAllow:
		return "Allow"
	case ReconnectHit:
		return "Hit"
	case ReconnectUncertain:
		return "Uncertain"
	default:
		return "Unknown"
	}
}

// ReconnectGuardedProtocol 該協議的命令列工具是否適用本判定。
func ReconnectGuardedProtocol(protocol string) bool {
	switch protocol {
	case "mysql", "redis", "mssql":
		return true
	default:
		return false
	}
}

// ReconnectDirective 判定一行輸入（不含行尾換行）是否含改連目標的指令。
//
//   - mysql／mariadb：任一 token 不分大小寫等於 connect，或整行任一位置出現 `\r` 短指令
//     （小寫；大寫 `\R` 是另一個指令，不算）。
//   - redis：依 redis-cli 的引號規則解碼後，任一 token 不分大小寫等於 connect；
//     引號未閉合或跳脫不完整時回 ReconnectUncertain。
//   - mssql：任一 token 不分大小寫等於 :connect、:r、:out 或 !!（後三者可間接執行含改連的內容）。
//   - 其他協議（含 postgres）：一律 ReconnectAllow。
func ReconnectDirective(protocol, line string) ReconnectVerdict {
	switch protocol {
	case "mysql":
		if strings.Contains(line, `\r`) {
			return ReconnectHit
		}
		if hasToken(sqlTokens(line), "connect") {
			return ReconnectHit
		}
		return ReconnectAllow
	case "mssql":
		// :connect 直接改連；:r（讀入腳本檔）、:out（輸出導向檔）、!!（執行外部命令）
		// 可間接讓客戶端執行含改連的內容，一併視為命中
		for _, want := range []string{":connect", ":r", ":out", "!!"} {
			if hasToken(sqlTokens(line), want) {
				return ReconnectHit
			}
		}
		return ReconnectAllow
	case "redis":
		tokens, ok := redisTokens(line)
		if !ok {
			return ReconnectUncertain
		}
		if hasToken(tokens, "connect") {
			return ReconnectHit
		}
		return ReconnectAllow
	default:
		return ReconnectAllow
	}
}

func hasToken(tokens []string, want string) bool {
	for _, t := range tokens {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// sqlTokens 去除引號字元後，以空白與語句分隔符切 token。
// 分隔符：`;`，以及 mysql 的 `\g`、`\G`（送出語句的短指令）；逗號與括號不拆
// （它們不會讓指令名變成另一個字）。
func sqlTokens(line string) []string {
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch c {
		case '\'', '"', '`':
			continue
		case '\\':
			if i+1 < len(line) && (line[i+1] == 'g' || line[i+1] == 'G') {
				b.WriteByte(' ')
				i++
				continue
			}
			b.WriteByte(c)
		case ';':
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return strings.FieldsFunc(b.String(), isTokenSpace)
}

func isTokenSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	default:
		return false
	}
}

// redisTokens 依 redis-cli（sdssplitargs）的規則把一行切成引數：
//
//   - 以空白分隔；引號段必須緊接空白或行尾。
//   - 雙引號內：`\xHH` 為十六進位位元組，`\n \r \t \b \a` 為對應控制字元，
//     其他 `\c` 取字元 c 本身；
//   - 單引號內：只有 `\'` 是跳脫。
//   - `\x` 後不足兩位十六進位時依 redis-cli 當一般跳脫（取 x 本身）。
//   - 引號未閉合、閉合後緊接非空白字元，視為無法正規化。
//
// 第二個回傳值 false 表示無法正規化。
func redisTokens(line string) ([]string, bool) {
	var tokens []string
	i, n := 0, len(line)
	for {
		for i < n && isTokenSpace(rune(line[i])) {
			i++
		}
		if i >= n {
			return tokens, true
		}
		var cur []byte
		inDouble, inSingle := false, false
		for done := false; !done; {
			switch {
			case inDouble:
				if i >= n {
					return nil, false // 未閉合
				}
				c := line[i]
				switch {
				case c == '\\' && i+3 < n && line[i+1] == 'x' && isHexByte(line[i+2]) && isHexByte(line[i+3]):
					cur = append(cur, hexVal(line[i+2])<<4|hexVal(line[i+3]))
					i += 3
				case c == '\\' && i+1 < n:
					i++
					switch line[i] {
					case 'n':
						cur = append(cur, '\n')
					case 'r':
						cur = append(cur, '\r')
					case 't':
						cur = append(cur, '\t')
					case 'b':
						cur = append(cur, '\b')
					case 'a':
						cur = append(cur, '\a')
					default:
						cur = append(cur, line[i])
					}
				case c == '\\':
					return nil, false // 行尾孤立的反斜線
				case c == '"':
					if i+1 < n && !isTokenSpace(rune(line[i+1])) {
						return nil, false // 閉合引號後須為空白或行尾
					}
					done = true
				default:
					cur = append(cur, c)
				}
			case inSingle:
				if i >= n {
					return nil, false
				}
				c := line[i]
				switch {
				case c == '\\' && i+1 < n && line[i+1] == '\'':
					i++
					cur = append(cur, '\'')
				case c == '\'':
					if i+1 < n && !isTokenSpace(rune(line[i+1])) {
						return nil, false
					}
					done = true
				default:
					cur = append(cur, c)
				}
			default:
				if i >= n {
					done = true
					break
				}
				c := line[i]
				switch {
				case isTokenSpace(rune(c)):
					done = true
				case c == '"':
					inDouble = true
				case c == '\'':
					inSingle = true
				default:
					cur = append(cur, c)
				}
			}
			if i < n {
				i++
			}
		}
		tokens = append(tokens, string(cur))
	}
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
