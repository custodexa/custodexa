package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/database"
)

// instanceGuardView 是守衛快照到 API 視圖的**唯一轉換點**，此前整支零測試覆蓋：
// 既有測試都以手寫的 api.InstanceGuardView 直接餵 handler，繞過了轉換本身
//（形態見 docs/dev/testing.md §5 第 9 條「測試繞過生產裝配路徑」）。
// 其後果是 `actor`／`actor_source` 兩欄（橫幅次行「由誰確認啟動」的資料來源）
// 從快照掉到地上也沒有任何訊號。本檔逐欄釘住整個映射。

func fullGuardSnapshot() database.GuardSnapshot {
	return database.GuardSnapshot{
		State:  database.GuardStateHeld,
		Since:  time.Date(2026, 9, 7, 1, 2, 3, 0, time.FixedZone("UTC+8", 8*3600)),
		Reason: database.GuardReasonAckPage,
		Instance: database.GuardInstance{
			Hostname:  "node-a",
			PID:       4242,
			StartedAt: time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC),
		},
		DBSessionPID: 909,
		Holder: &database.HolderFingerprint{
			ApplicationName: "custodexa-instance-guard",
			PID:             777,
			BackendStart:    "2026-09-07T00:00:00Z",
			Code:            "abc123abc123",
			Source:          database.FingerprintSourcePGStatActivity,
		},
		Ack:         "abc123abc123",
		LostTotal:   3,
		Peers:       2,
		Actor:       "halt-admin",
		ActorSource: database.GuardActorSourcePage,
	}
}

// TestInstanceGuardViewMapsEveryField 快照的每一欄都要落到視圖對應欄。
func TestInstanceGuardViewMapsEveryField(t *testing.T) {
	v := instanceGuardView(fullGuardSnapshot())

	if v.State != string(database.GuardStateHeld) {
		t.Fatalf("state = %q", v.State)
	}
	if v.Reason != string(database.GuardReasonAckPage) {
		t.Fatalf("reason = %q", v.Reason)
	}
	// 時間一律 RFC3339 UTC（來源刻意給 UTC+8，避免「原樣搬過去」也能通過）。
	if v.Since != "2026-09-06T17:02:03Z" {
		t.Fatalf("since = %q，want RFC3339 UTC", v.Since)
	}
	if v.Instance.Hostname != "node-a" || v.Instance.PID != 4242 ||
		v.Instance.StartedAt != "2026-09-07T00:00:00Z" {
		t.Fatalf("instance = %+v", v.Instance)
	}
	if v.DBSessionPID != 909 || v.Ack != "abc123abc123" || v.LostTotal != 3 || v.Peers != 2 {
		t.Fatalf("db_session_pid／ack／lost_total／peers 映射有誤：%+v", v)
	}
	if v.Holder == nil {
		t.Fatal("holder 未映射")
	}
	if v.Holder.ApplicationName != "custodexa-instance-guard" || v.Holder.PID != 777 ||
		v.Holder.BackendStart != "2026-09-07T00:00:00Z" || v.Holder.Code != "abc123abc123" ||
		v.Holder.FingerprintSource != database.FingerprintSourcePGStatActivity {
		t.Fatalf("holder = %+v", v.Holder)
	}

	// 橫幅次行的兩欄：頁面路徑的確認者帳號與來源。
	if v.Actor != "halt-admin" {
		t.Fatalf("actor = %q，want halt-admin（橫幅次行要能說出由誰確認啟動）", v.Actor)
	}
	if v.ActorSource != database.GuardActorSourcePage {
		t.Fatalf("actor_source = %q，want %q", v.ActorSource, database.GuardActorSourcePage)
	}
}

// TestInstanceGuardViewCarriesEnvActor 環境變數路徑的兩欄同樣要出得去。
//
// 兩條路徑各一格：只驗一條時另一條寫錯沒有訊號（與 database 側同名測試的理由一致）。
func TestInstanceGuardViewCarriesEnvActor(t *testing.T) {
	snap := fullGuardSnapshot()
	snap.Actor = database.GuardActorEnv
	snap.ActorSource = database.GuardActorSourceEnv

	v := instanceGuardView(snap)
	if v.Actor != database.GuardActorEnv || v.ActorSource != database.GuardActorSourceEnv {
		t.Fatalf("環境變數路徑的 actor／actor_source = %q／%q，want %q／%q",
			v.Actor, v.ActorSource, database.GuardActorEnv, database.GuardActorSourceEnv)
	}

	// JSON 鍵名也釘住：前端橫幅讀的是 actor／actor_source。
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["actor"] != database.GuardActorEnv || body["actor_source"] != database.GuardActorSourceEnv {
		t.Fatalf("JSON 兩欄 = %v／%v", body["actor"], body["actor_source"])
	}
}

// TestInstanceGuardViewZeroValues 未經確認啟動（held、無持鎖者、零值時間）的形態。
func TestInstanceGuardViewZeroValues(t *testing.T) {
	v := instanceGuardView(database.GuardSnapshot{State: database.GuardStateHeld})
	if v.Since != "" || v.Instance.StartedAt != "" {
		t.Fatalf("零值時間應映射為空字串，實得 since=%q started_at=%q", v.Since, v.Instance.StartedAt)
	}
	if v.Holder != nil {
		t.Fatalf("無持鎖者時 holder 應為 nil，實得 %+v", v.Holder)
	}
	if v.Actor != "" || v.ActorSource != "" {
		t.Fatalf("未經確認啟動時兩欄應為空，實得 %q／%q", v.Actor, v.ActorSource)
	}
}
