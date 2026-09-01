package offsite

import (
	"fmt"
	"strings"
	"time"
)

// object key 組法。key 一律由系統組出，不接受使用者輸入
// （design §5 輸入驗證）；prefix 為部署設定的 key 前綴，空＝無前綴。

// RecordingObjectKey 錄影物件的 key：
// {prefix}/recordings/{YYYY}/{MM}/session-{id}.{ext}
// endedAt＝會話結束時刻（年月分桶依它）；ext 不含點（cast／guac）。
func RecordingObjectKey(prefix string, sessionID uint, endedAt time.Time, ext string) string {
	return joinPrefix(prefix, fmt.Sprintf("recordings/%04d/%02d/session-%d.%s",
		endedAt.UTC().Year(), int(endedAt.UTC().Month()), sessionID, ext))
}

// ExportObjectKey 證據包物件的 key：{prefix}/exports/job-{id}.zip
func ExportObjectKey(prefix string, jobID uint) string {
	return joinPrefix(prefix, fmt.Sprintf("exports/job-%d.zip", jobID))
}

// ConnectionTestObjectKey 測試連線探測物的 key（第 1 段）。
// nanos＝呼叫當下的 UnixNano，使重複測試不互撞、遺留物可辨識。
func ConnectionTestObjectKey(prefix string, nanos int64) string {
	return joinPrefix(prefix, fmt.Sprintf(".custodexa-connection-test-%d", nanos))
}

// joinPrefix prefix 空＝無前綴；尾端多餘的 "/" 一律修掉再接，
// 防部署者填 "a/" 產出 "a//recordings/..."。
func joinPrefix(prefix, rest string) string {
	p := strings.Trim(prefix, "/")
	if p == "" {
		return rest
	}
	return p + "/" + rest
}
