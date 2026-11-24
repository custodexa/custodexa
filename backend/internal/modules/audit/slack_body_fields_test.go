package audit

import (
	"encoding/json"
	"fmt"
)

// slackBodyFields 把 Slack 本文的頂層欄位解成字串對照（文字原樣、布林寫成 "true"／"false"），
// 讓既有斷言照舊以 payload["text"] 讀取，並可斷言關閉自動抓取的兩個旗標。
type slackBodyFields map[string]string

func (f *slackBodyFields) UnmarshalJSON(raw []byte) error {
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return err
	}
	out := slackBodyFields{}
	for k, v := range generic {
		switch x := v.(type) {
		case string:
			out[k] = x
		default:
			out[k] = fmt.Sprint(x)
		}
	}
	*f = out
	return nil
}
