package main

import (
	"log"
	"time"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/observability"
)

// 單實例守衛的組裝根 adapter。
//
// database 是 infra，api／observability 不 import 它；守衛快照到 API 視圖、到指標資料源
// 的轉換全部落在這裡（單一轉換點）。審計事件的轉換在 stage2.go（instanceGuardAuditSink），
// 因為那是審計產生點，manifest 依 file:line 登記。

// instanceGuardView 把守衛快照轉成 API 視圖。時間一律 RFC3339 UTC；零值時間為空字串。
func instanceGuardView(snap database.GuardSnapshot) api.InstanceGuardView {
	v := api.InstanceGuardView{
		State:        string(snap.State),
		Since:        rfc3339OrEmpty(snap.Since),
		Reason:       string(snap.Reason),
		DBSessionPID: snap.DBSessionPID,
		Ack:          snap.Ack,
		LostTotal:    snap.LostTotal,
		Peers:        snap.Peers,
		Instance: api.InstanceGuardInstance{
			Hostname:  snap.Instance.Hostname,
			PID:       snap.Instance.PID,
			StartedAt: rfc3339OrEmpty(snap.Instance.StartedAt),
		},
	}
	if snap.Holder != nil {
		v.Holder = &api.InstanceGuardHolder{
			ApplicationName:   snap.Holder.ApplicationName,
			PID:               snap.Holder.PID,
			BackendStart:      snap.Holder.BackendStart,
			Code:              snap.Holder.Code,
			FingerprintSource: snap.Holder.Source,
		}
	}
	return v
}

func rfc3339OrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// instanceGuardProbe 管理者限定端點的全貌來源（包級單例快照）。
func instanceGuardProbe() api.InstanceGuardView {
	return instanceGuardView(database.InstanceGuardSnapshot())
}

// instanceGuardStatusProbe seal status 的粗狀態來源：不含識別資訊。
func instanceGuardStatusProbe() api.InstanceGuardStatus {
	return instanceGuardProbe().Coarse()
}

// instanceGuardMetricsSource 指標 collector 的現讀來源。
func instanceGuardMetricsSource() observability.InstanceGuardStatus {
	snap := database.InstanceGuardSnapshot()
	return observability.InstanceGuardStatus{
		State:     string(snap.State),
		LostTotal: snap.LostTotal,
		Peers:     snap.Peers,
	}
}

// instanceGuardEventDetails 審計事件的 details：全部明文、無憑證、無 DSN、
// 無任何工作階段的 client_addr。純函式，供 stage2 的 sink 與測試共用。
func instanceGuardEventDetails(ev database.GuardEvent) map[string]any {
	details := map[string]any{
		"event":  ev.Event,
		"reason": string(ev.Reason),
		"at":     rfc3339OrEmpty(ev.At),
		"instance": map[string]any{
			"hostname":   ev.Instance.Hostname,
			"pid":        ev.Instance.PID,
			"started_at": rfc3339OrEmpty(ev.Instance.StartedAt),
		},
		"db_session_pid": ev.DBSessionPID,
		"lost_total":     ev.LostTotal,
	}
	if ev.Holder != nil {
		details["holder"] = map[string]any{
			"application_name":   ev.Holder.ApplicationName,
			"pid":                ev.Holder.PID,
			"backend_start":      ev.Holder.BackendStart,
			"code":               ev.Holder.Code,
			"fingerprint_source": ev.Holder.Source,
		}
	}
	switch ev.Event {
	case database.GuardEventOverridden:
		details["ack"] = ev.Ack
		// 環境變數無法識別自然人：不假造身分，由部署方的變更管理承擔
		details["actor"] = "operator via env"
	case database.GuardEventRegained:
		details["unheld_for_ms"] = ev.UnheldForMS
	}
	return details
}

// logInstanceGuardAcquired 段 1 取鎖成功的一行啟動日誌（含本實例識別與工作階段）。
func logInstanceGuardAcquired() {
	snap := database.InstanceGuardSnapshot()
	log.Printf("[InstanceGuard] 單實例鎖狀態=%s hostname=%s pid=%d started_at=%s db_session_pid=%d",
		snap.State, snap.Instance.Hostname, snap.Instance.PID, rfc3339OrEmpty(snap.Instance.StartedAt), snap.DBSessionPID)
}
