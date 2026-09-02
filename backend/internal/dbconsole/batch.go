package dbconsole

import (
	"errors"
	"strings"
)

// ErrGoCountUnsupported `GO <n>`（重複執行 n 次）不支援。
//
// 支援它等於替使用者執行一條他只寫了一次的語句 n 次，而每一次都是一個獨立的
// 執行單位、要各有一個事件 ID 與一筆審計列。與其做一個半套的實作，
// 不如明確拒絕——使用者自己複製貼上 n 次，審計看到的就是 n 個單位。
var ErrGoCountUnsupported = errors.New("dbconsole: 不支援 GO <n>（批次重複次數）")

// SplitUnits 把一次送出的文字切成執行單位。
//
// **只有 MSSQL 會切**：T-SQL 的執行單位是批次，以獨立一行的 `GO` 送出，
// 而 `;` 只是語句分隔符。MySQL 與 PostgreSQL 的一次送出就是一個執行單位——
// 切它們需要方言感知的 SQL 解析，切錯就是送出一段被改寫過的 SQL，
// 而「不代為改寫送出內容」是既有的產品紀律。
//
// 空批次（連續兩個 GO、或結尾的 GO）不產生單位：它沒有任何東西可送，
// 產生一個空的執行單位只會在審計上多一筆沒有內容的列。
func SplitUnits(p Protocol, text string) ([]string, error) {
	if p != ProtocolMSSQL {
		if strings.TrimSpace(text) == "" {
			return nil, nil
		}
		return []string{text}, nil
	}

	var units []string
	var cur []string
	flush := func() {
		body := strings.Join(cur, "\n")
		cur = nil
		if strings.TrimSpace(body) == "" {
			return
		}
		units = append(units, body)
	}

	// 逐行掃描並保留原始換行語義：批次內容逐位元組送出，不做任何正規化。
	// **不剝除 \r**：Windows 客戶端送 CRLF 是常態，剝掉它會讓送出的文字
	// 與使用者編輯器裡的文字不同，而審計列記的是「使用者送了什麼」
	for _, line := range strings.Split(text, "\n") {
		kind, err := classifyGoLine(line)
		if err != nil {
			return nil, err
		}
		if kind {
			flush()
			continue
		}
		cur = append(cur, line)
	}
	flush()
	return units, nil
}

// classifyGoLine 這一行是不是批次終止符。
//
// 規則與命令列路徑的判定同一份語義：整行 trim 後不分大小寫等於 `GO`。
// **必須是整行**——`SELECT 'GO'` 裡的 GO 不是終止符，把它當成終止符會把一句
// 合法的 SQL 攔腰切成兩個都不合法的批次。
//
// `GO <正整數>` 回 ErrGoCountUnsupported 而不是「當成普通一行」：
// 靜默把它當內容送出去，目標端會回一個語法錯誤，而使用者拿到的訊息不會告訴他
// 真正的原因是這裡不支援重複次數。
func classifyGoLine(line string) (bool, error) {
	t := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), "\r"))
	if len(t) < 2 || !strings.EqualFold(t[:2], "GO") {
		return false, nil
	}
	rest := strings.TrimSpace(t[2:])
	if rest == "" {
		return true, nil
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			// `GOTO`／`GO_SOMETHING` 之類：不是終止符，是內容
			return false, nil
		}
	}
	if strings.Trim(rest, "0") == "" {
		// `GO 0`：重複零次，語義上是「不執行」。同樣不支援，
		// 而不是靜默當成一次
		return false, ErrGoCountUnsupported
	}
	return false, ErrGoCountUnsupported
}

// QuoteIdentifier 以方言的引用形式包住一個識別字。
//
// **只用於系統自發的 `USE`，且傳入的名稱必須是目標端目錄剛回傳的**。
// 這不是一個通用的跳脫函式：它對付的是名稱裡合法出現的引用字元
// （反引號、方括號、雙引號），而不是使用者輸入的惡意內容——後者根本到不了這裡，
// 因為切庫的目標一律先與目錄清單比對過。
func QuoteIdentifier(p Protocol, name string) string {
	switch p {
	case ProtocolMySQL:
		return "`" + strings.ReplaceAll(name, "`", "``") + "`"
	case ProtocolMSSQL:
		return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
	default:
		return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	}
}
