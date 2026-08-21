package audit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrInvalidCursor 游標無法解析（格式錯、被截斷、非本端點產出的字串）
var ErrInvalidCursor = errors.New("invalid timeline cursor")

// TimelineCursor 複合游標 `(ts, type, id)`（auditor-workbench D7）。
//
// **為什麼不是 offset**：時間軸由六個來源各自查詢後合併。offset 是「跳過前 N 筆
// 合併結果」，但每個來源只知道自己的 N，服務層無從把一個全域 offset 拆給六個
// 來源；硬拆的任何做法在來源間筆數分布改變時都會錯位——實務上表現為**整段漏列**
// （某來源被跳過的比它實際貢獻的多），而漏列在稽核時間軸上是靜默的，
// 使用者看到的是一段「什麼都沒發生」的空白。
//
// keyset 游標則是「所有排序鍵大於此值的列」，每個來源都能獨立回答，
// 且不受其他來源筆數影響。
//
// **三個欄位缺一不可**：
//   - 只用 ts：同一毫秒的多筆會被整批跳過或整批重取。dev 庫實測單一會話建立
//     瞬間即有多筆同秒事件，這不是罕見情形。
//   - ts+id：不同來源的 id 各自從 1 起算，跨來源比較 id 沒有意義——
//     兩個來源的 id=5 會互相「吃掉」對方。
//   - 故排序鍵是 (ts, type, id)：type 提供跨來源的確定序，id 在來源內唯一，
//     三者合起來對全體事件構成**全序**（無並列），這是分頁不重不漏的前提。
type TimelineCursor struct {
	TS   time.Time
	Type TimelineEventType
	ID   uint
}

// Encode 序列化為不透明字串。用 base64 是為了讓它在 URL 與 query string 內
// 安全傳遞，並讓「客戶端自己拼游標」明顯是不受支援的用法
func (c TimelineCursor) Encode() string {
	raw := fmt.Sprintf("%d|%s|%d", c.TS.UTC().UnixMicro(), c.Type, c.ID)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeTimelineCursor 還原游標；任何不合法輸入回 ErrInvalidCursor
// （由呼叫端轉為 400 錯誤碼——靜默當成「從頭開始」會讓分頁悄悄重跑第一頁）
func DecodeTimelineCursor(s string) (TimelineCursor, error) {
	var c TimelineCursor
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return c, ErrInvalidCursor
	}
	parts := strings.Split(string(b), "|")
	if len(parts) != 3 {
		return c, ErrInvalidCursor
	}
	us, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return c, ErrInvalidCursor
	}
	id, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return c, ErrInvalidCursor
	}
	if !IsTimelineEventType(parts[1]) {
		return c, ErrInvalidCursor
	}
	// UTC：游標跨時區傳遞時的顯示時區不影響排序鍵，微秒整數是唯一事實
	c.TS = time.UnixMicro(us).UTC()
	c.Type = TimelineEventType(parts[1])
	c.ID = uint(id)
	return c, nil
}

// keysetWhere 產生某個來源在此游標之後的 keyset 條件。
//
// 全序是 (ts, type, id) 的字典序，而**單一來源內 type 是常數**，故條件依
// 該來源的 type 與游標 type 的大小關係退化成三種形態：
//
//	src.Type >  cur.Type  →  ts >= cur.TS
//	                         （同一 ts 上，排序在游標之後的整段都要，含 ts 相等者）
//	src.Type == cur.Type  →  ts > cur.TS OR (ts = cur.TS AND id > cur.ID)
//	src.Type <  cur.Type  →  ts > cur.TS
//	                         （同一 ts 上本來源全部排在游標之前，必須整段排除）
//
// 第一與第三種形態的差別（`>=` vs `>`）正是「同 ts 跨來源」的漏列/重複所在：
// 兩邊都寫 `>` 會漏掉與游標同 ts 但 type 較大的來源那一整批；
// 兩邊都寫 `>=` 會把 type 較小的來源同 ts 那批重複發一次。
func keysetWhere(timeCol, idCol string, src TimelineEventType, cur *TimelineCursor) (string, []any) {
	if cur == nil {
		return "", nil
	}
	switch {
	case src > cur.Type:
		return fmt.Sprintf("%s >= ?", timeCol), []any{cur.TS}
	case src == cur.Type:
		return fmt.Sprintf("(%s > ? OR (%s = ? AND %s > ?))", timeCol, timeCol, idCol),
			[]any{cur.TS, cur.TS, cur.ID}
	default:
		return fmt.Sprintf("%s > ?", timeCol), []any{cur.TS}
	}
}

// lessEvent 事件的全序比較（合併時的唯一判準，與 keysetWhere 必須同一把尺）
func lessEvent(a, b TimelineEvent) bool {
	if !a.TS.Equal(b.TS) {
		return a.TS.Before(b.TS)
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	return a.SourceID < b.SourceID
}
