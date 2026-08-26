package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// 位址樞紐與位址篩選：六來源同一組 WHERE（fetch／count／spans 三處一致）、
// 雙對造、未知來源三原因、保留字 unknown、正規化、候選查詢。

const (
	ipvA = "203.0.113.5"
	ipvB = "198.51.100.7"
	ipv6 = "2001:db8::1"
)

// seedIPPivot 佈一組帶位址的六來源資料。回傳「所屬會話已刪」的告警 id。
func seedIPPivot(t *testing.T, db *gorm.DB) {
	t.Helper()
	t0 := time.Date(2026, 8, 10, 8, 0, 0, 0, time.UTC)
	aid := tlAssetID
	mustCreate := func(v interface{}) {
		t.Helper()
		if err := db.Create(v).Error; err != nil {
			t.Fatalf("seed %T: %v", v, err)
		}
	}
	mustCreate(&model.User{Username: "alice", FullName: "Alice", Active: true})   // id 1 = tlUserID? 不依賴
	mustCreate(&model.Asset{Name: "srv-1", Host: "h", Protocol: "ssh", Port: 22, Active: true})

	newSession := func(sid string, userID uint, ip string, at time.Time) *model.Session {
		s := &model.Session{SessionID: sid, Status: "closed", Protocol: "ssh",
			UserID: userID, AssetID: &aid, ClientIP: ip, StartTime: at}
		mustCreate(s)
		return s
	}
	s1 := newSession("s1", tlUserID, ipvA, t0.Add(10*time.Minute))
	newSession("s2", 8, ipvA, t0.Add(12*time.Minute))  // NAT：另一帳號同位址
	newSession("s3", tlUserID, ipvB, t0.Add(14*time.Minute))
	newSession("s4", tlUserID, "", t0.Add(16*time.Minute)) // 未知（unresolvable）
	newSession("s6", 8, ipv6, t0.Add(17*time.Minute))

	auditRow := func(userID uint, uname, ip string, action model.AuditAction, res model.AuditResource, at time.Time) {
		mustCreate(&model.AuditLog{CreatedAt: at, Action: action, Resource: res,
			Status: model.StatusSuccess, UserID: userID, Username: uname, AssetID: &aid, ClientIP: ip})
	}
	auditRow(tlUserID, "alice", ipvA, model.ActionUpdate, model.ResourceAsset, t0.Add(20*time.Minute))
	auditRow(0, "", "", model.ActionExecute, model.ResourceAuditLog, t0.Add(21*time.Minute))  // system
	auditRow(tlUserID, "alice", "", model.ActionUpdate, model.ResourceAsset, t0.Add(22*time.Minute)) // unresolvable
	auditRow(0, "", ipvA, model.ActionLogin, model.ResourceAuth, t0.Add(23*time.Minute)) // 未認證列（有位址）
	auditRow(tlUserID, "alice", ipvA, model.ActionFileUpload, model.ResourceFile, t0.Add(24*time.Minute))
	auditRow(tlUserID, "alice", ipvB, model.ActionNewSourceIP, model.ResourceAuth, t0.Add(25*time.Minute))

	if err := db.Exec(`INSERT INTO session_commands (session_id, user_id, asset_id, command, seq, executed_at)
		VALUES (?, ?, ?, 'ls', 1, ?)`, s1.ID, tlUserID, aid, t0.Add(30*time.Minute)).Error; err != nil {
		t.Fatalf("seed command: %v", err)
	}
	if err := db.Exec(`INSERT INTO command_alerts (rule_id, rule_name, session_id, user_id, asset_id,
		command, severity, triggered_at, kind, reason_code)
		VALUES (1, 'rm-guard', ?, ?, ?, 'rm -rf /', 'high', ?, 'rule', '')`,
		s1.ID, tlUserID, aid, t0.Add(31*time.Minute)).Error; err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	// 所屬會話缺失的告警（session_id 指向不存在的列）→ session_missing
	if err := db.Exec(`INSERT INTO command_alerts (rule_id, rule_name, session_id, user_id, asset_id,
		command, severity, triggered_at, kind, reason_code)
		VALUES (NULL, 'new_source_ip', 99999, ?, ?, '', 'medium', ?, 'new_source_ip', 'new_source_ip_session')`,
		tlUserID, aid, t0.Add(32*time.Minute)).Error; err != nil {
		t.Fatalf("seed orphan alert: %v", err)
	}
	mustCreate(&model.ClipboardEvent{SessionID: s1.ID, Direction: "send",
		ContentStatus: model.ClipboardContentAvailable, CreatedAt: t0.Add(33*time.Minute)})
}

func ipQuery(ip string) TimelineQuery {
	q := baseQuery(SubjectUser, 0)
	q.Subject = SubjectIP
	q.SubjectID = 0
	q.SubjectIP = ip
	return q
}

func typeCount(events []TimelineEvent) map[TimelineEventType]int64 {
	got := map[TimelineEventType]int64{}
	for _, e := range events {
		got[e.Type]++
	}
	return got
}

func TestTimelineIPPivotCoversSixSourcesAndCountsAgree(t *testing.T) {
	db := setupTimelineDB(t)
	seedIPPivot(t, db)
	svc := NewTimelineService(db)

	q := ipQuery(ipvA)
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	got := typeCount(res.Events)
	want := map[TimelineEventType]int64{
		TimelineTypeSession: 2, TimelineTypeAuditLog: 2, TimelineTypeFileTransfer: 1,
		TimelineTypeCommand: 1, TimelineTypeAlert: 1, TimelineTypeClipboard: 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("位址樞紐 %s 類事件 = %d, want %d", k, got[k], v)
		}
		if res.Counts[k] != v {
			t.Errorf("位址樞紐 %s 類 counts = %d, want %d（與 events 漂移＝三處 WHERE 不同步）", k, res.Counts[k], v)
		}
	}

	// 雙對造：每列 actor（誰）＋counterpart（哪台）；未認證列 actor 為 nil
	var unauth, authed int
	for _, e := range res.Events {
		if *mustIP(t, e) != ipvA {
			t.Fatalf("位址樞紐出現他址事件: %+v", e)
		}
		if e.Actor == nil {
			unauth++
		} else {
			authed++
			if e.Actor.Kind != "user" {
				t.Errorf("actor.kind 應恆為 user，實得 %q", e.Actor.Kind)
			}
		}
	}
	if unauth != 1 {
		t.Errorf("未認證列（user_id=0 帶位址）應恰 1 筆且 actor 為 nil，實得 %d", unauth)
	}
	if authed != 7 {
		t.Errorf("已認證列應 7 筆帶 actor，實得 %d", authed)
	}

	// spans 同一組 WHERE：ipvA 恰兩場會話，皆帶位址
	if len(res.Spans) != 2 {
		t.Fatalf("位址樞紐 spans = %d, want 2", len(res.Spans))
	}
	for _, sp := range res.Spans {
		if sp.ClientIP == nil || *sp.ClientIP != ipvA {
			t.Errorf("span 位址欄 = %v, want %s", sp.ClientIP, ipvA)
		}
	}

	// alert 事件 params 帶 kind／reason_code（前端據此對非規則類對映文案）
	for _, e := range res.Events {
		if e.Type == TimelineTypeAlert {
			if e.Params["kind"] != "rule" {
				t.Errorf("alert params.kind = %q, want rule", e.Params["kind"])
			}
			if _, ok := e.Params["reason_code"]; !ok {
				t.Error("alert params 缺 reason_code 鍵")
			}
		}
	}

	// 游標分頁不漏列：逐頁（每頁 3）取完 ＝ 一次取完
	all := drainAll(t, svc, ipQuery(ipvA), 3)
	if len(all) != len(res.Events) {
		t.Fatalf("分頁取完 %d 筆 ≠ 一次取完 %d 筆", len(all), len(res.Events))
	}
}

func mustIP(t *testing.T, e TimelineEvent) *string {
	t.Helper()
	if e.ClientIP == nil {
		t.Fatalf("位址樞紐事件的 client_ip 不得為 null: %+v", e)
	}
	return e.ClientIP
}

func TestTimelineIPPivotNormalizesIPv6Input(t *testing.T) {
	db := setupTimelineDB(t)
	seedIPPivot(t, db)
	svc := NewTimelineService(db)

	// 縮寫前的 IPv6 輸入須正規化後比對（儲存值為 Go 正規形式）
	res, err := svc.Query(ipQuery("2001:0db8:0000::0001"))
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if n := res.Counts[TimelineTypeSession]; n != 1 {
		t.Errorf("IPv6 正規化後應命中 1 場會話，實得 %d", n)
	}
}

func TestTimelineUserPivotClientIPFilter(t *testing.T) {
	db := setupTimelineDB(t)
	seedIPPivot(t, db)
	svc := NewTimelineService(db)

	// 人樞紐＋位址篩選：六類各自生效
	q := baseQuery(SubjectUser, tlUserID)
	q.ClientIP = ipvA
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	want := map[TimelineEventType]int64{
		TimelineTypeSession: 1, TimelineTypeAuditLog: 1, TimelineTypeFileTransfer: 1,
		TimelineTypeCommand: 1, TimelineTypeAlert: 1, TimelineTypeClipboard: 1,
	}
	got := typeCount(res.Events)
	for k, v := range want {
		if got[k] != v || res.Counts[k] != v {
			t.Errorf("人樞紐位址篩選 %s：events=%d counts=%d, want %d", k, got[k], res.Counts[k], v)
		}
	}
	// 未認證列（user_id=0）不出現在人樞紐
	for _, e := range res.Events {
		if e.Type == TimelineTypeAuditLog && e.SummaryCode == "timeline.audit_log.login" {
			t.Errorf("未認證列漏進人樞紐: %+v", e)
		}
	}

	// 未篩選：未知來源列計入筆數（session 4 場含未知 1、audit_log 含空位址列）
	q2 := baseQuery(SubjectUser, tlUserID)
	res2, err := svc.Query(q2)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if res2.Counts[TimelineTypeSession] != 3 {
		t.Errorf("人樞紐未篩選 session counts = %d, want 3（含未知來源那場）", res2.Counts[TimelineTypeSession])
	}
	if res2.Counts[TimelineTypeAlert] != 2 {
		t.Errorf("人樞紐未篩選 alert counts = %d, want 2（含會話缺失那筆）", res2.Counts[TimelineTypeAlert])
	}

	// unknown 保留字：只看未知來源列（session 空位址、audit_log 空位址、告警會話缺失）
	q3 := baseQuery(SubjectUser, tlUserID)
	q3.ClientIP = ClientIPUnknown
	res3, err := svc.Query(q3)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	got3 := typeCount(res3.Events)
	want3 := map[TimelineEventType]int64{
		TimelineTypeSession: 1, TimelineTypeAuditLog: 1, TimelineTypeAlert: 1,
	}
	for k, v := range want3 {
		if got3[k] != v || res3.Counts[k] != v {
			t.Errorf("unknown 篩選 %s：events=%d counts=%d, want %d", k, got3[k], res3.Counts[k], v)
		}
	}
	if got3[TimelineTypeCommand] != 0 || got3[TimelineTypeClipboard] != 0 || got3[TimelineTypeFileTransfer] != 0 {
		t.Errorf("unknown 篩選不應含已知位址的列: %v", got3)
	}
	// spans 同步生效：只剩未知來源那場
	if len(res3.Spans) != 1 || res3.Spans[0].ClientIP != nil {
		t.Errorf("unknown 篩選 spans 應恰 1 場且位址 null，實得 %+v", res3.Spans)
	}
}

func TestTimelineUnknownReasonsAndExplicitNull(t *testing.T) {
	db := setupTimelineDB(t)
	seedIPPivot(t, db)
	svc := NewTimelineService(db)

	q := baseQuery(SubjectUser, tlUserID)
	q.ClientIP = ClientIPUnknown
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	reasons := map[TimelineEventType]string{}
	for _, e := range res.Events {
		if e.ClientIP != nil {
			t.Fatalf("unknown 篩選下 client_ip 應為 null: %+v", e)
		}
		reasons[e.Type] = e.ClientIPReason
		// JSON 形狀：顯式 null，不是缺欄
		raw, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if !strings.Contains(string(raw), `"client_ip":null`) {
			t.Errorf("事件 JSON 應含顯式 \"client_ip\":null，實得 %s", raw)
		}
	}
	if reasons[TimelineTypeSession] != ClientIPReasonUnresolvable {
		t.Errorf("會話空位址原因 = %q, want unresolvable", reasons[TimelineTypeSession])
	}
	if reasons[TimelineTypeAuditLog] != ClientIPReasonUnresolvable {
		t.Errorf("有使用者的空位址日誌原因 = %q, want unresolvable", reasons[TimelineTypeAuditLog])
	}
	if reasons[TimelineTypeAlert] != ClientIPReasonSessionMissing {
		t.Errorf("會話缺失告警原因 = %q, want session_missing", reasons[TimelineTypeAlert])
	}

	// 系統列（user_id=0 空位址）：原因 system——它不可歸屬任何使用者，
	// 由位址樞紐亦不可達，這裡直接驗 fetch 層的原因判定
	events, err := svc.fetchAuditLogs(TimelineTypeAuditLog, TimelineQuery{
		Subject: SubjectUser, SubjectID: 0, From: baseQuery(SubjectUser, 1).From,
		To: baseQuery(SubjectUser, 1).To, Types: allTimelineTypes, Limit: 50}, 50)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	var sawSystem bool
	for _, e := range events {
		if e.ClientIPReason == ClientIPReasonSystem {
			sawSystem = true
		}
	}
	if !sawSystem {
		t.Error("系統列（user_id=0 空位址）應標 reason=system")
	}

	// audit_log 類的摘要碼由 action 自動組出：新標記 action 直接可用
	q2 := ipQuery(ipvB)
	res2, err := svc.Query(q2)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var sawMark bool
	for _, e := range res2.Events {
		if e.SummaryCode == "timeline.audit_log.new_source_ip" {
			sawMark = true
		}
	}
	if !sawMark {
		t.Error("ipvB 位址軸上應見 timeline.audit_log.new_source_ip 摘要碼")
	}
}

func TestTimelineNormalizeRejectsBadAddressInputs(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*TimelineQuery)
		want error
	}{
		{"subject_ip 非位址", func(q *TimelineQuery) { q.SubjectIP = "not-an-ip" }, ErrInvalidSourceAddress},
		{"subject_ip 保留字", func(q *TimelineQuery) { q.SubjectIP = ClientIPUnknown }, ErrInvalidSourceAddress},
		{"位址樞紐帶 client_ip 篩選", func(q *TimelineQuery) { q.ClientIP = ipvB }, ErrInvalidSourceAddress},
		{"位址樞紐帶 subject_id", func(q *TimelineQuery) { q.SubjectID = 9 }, ErrInvalidSubject},
	}
	for _, tc := range cases {
		q := ipQuery(ipvA)
		tc.mut(&q)
		if err := q.Normalize(); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	// 人樞紐的位址篩選打錯字：大聲拒絕，不靜默回空
	q := baseQuery(SubjectUser, tlUserID)
	q.ClientIP = "zz.zz"
	if err := q.Normalize(); !errors.Is(err, ErrInvalidSourceAddress) {
		t.Errorf("人樞紐非法位址篩選: err = %v, want ErrInvalidSourceAddress", err)
	}
	// 保留字與正規化：unknown 放行、IPv6 縮寫正規化
	q2 := baseQuery(SubjectUser, tlUserID)
	q2.ClientIP = ClientIPUnknown
	if err := q2.Normalize(); err != nil {
		t.Errorf("unknown 保留字應放行: %v", err)
	}
	q3 := ipQuery("2001:0DB8::1")
	if err := q3.Normalize(); err != nil || q3.SubjectIP != ipv6 {
		t.Errorf("subject_ip 應正規化為 %s，實得 %q（err=%v）", ipv6, q3.SubjectIP, err)
	}
}

func TestTimelineIPSubjectsPrefixOrderLimit(t *testing.T) {
	db := setupTimelineDB(t)
	if err := db.AutoMigrate(&model.UserSourceIP{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc := NewTimelineService(db)
	t0 := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	seed := func(user uint, ip string, last time.Time) {
		if err := db.Create(&model.UserSourceIP{UserID: user, ClientIP: ip,
			FirstSeenAt: t0, LastSeenAt: last}).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// 同位址兩使用者：DISTINCT 合併、取 MAX(last_seen_at)
	seed(1, "203.0.113.5", t0.Add(1*time.Hour))
	seed(2, "203.0.113.5", t0.Add(5*time.Hour))
	seed(1, "203.0.113.9", t0.Add(3*time.Hour))
	seed(1, "198.51.100.7", t0.Add(9*time.Hour))

	subs, err := svc.ListIPSubjects("", 10)
	if err != nil {
		t.Fatalf("subjects: %v", err)
	}
	if len(subs) != 3 {
		t.Fatalf("DISTINCT 候選應 3 筆，實得 %+v", subs)
	}
	if subs[0].IP != "198.51.100.7" || subs[1].IP != "203.0.113.5" || subs[2].IP != "203.0.113.9" {
		t.Errorf("應依最近見到降序: %+v", subs)
	}
	if !subs[1].LastSeenAt.Equal(t0.Add(5 * time.Hour)) {
		t.Errorf("同位址多使用者應取 MAX(last_seen_at)，實得 %v", subs[1].LastSeenAt)
	}

	// 前綴匹配＋上限
	subs, err = svc.ListIPSubjects("203.0", 10)
	if err != nil {
		t.Fatalf("subjects(prefix): %v", err)
	}
	if len(subs) != 2 {
		t.Errorf("前綴 203.0 應 2 筆，實得 %+v", subs)
	}
	subs, err = svc.ListIPSubjects("", 2)
	if err != nil {
		t.Fatalf("subjects(limit): %v", err)
	}
	if len(subs) != 2 {
		t.Errorf("limit=2 應 2 筆，實得 %d", len(subs))
	}
	// LIKE 萬用字元不作 pattern 解讀
	subs, err = svc.ListIPSubjects("%", 10)
	if err != nil {
		t.Fatalf("subjects(escape): %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("字面 %% 前綴不應命中任何位址，實得 %+v", subs)
	}
	// 欄位集合：只有 ip 與 last_seen_at
	raw, err := json.Marshal(TimelineIPSubject{IP: "1.2.3.4", LastSeenAt: t0})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(m) != 2 {
		t.Errorf("候選條目欄位集合應恰 {ip, last_seen_at}，實得 %v", m)
	}
}
