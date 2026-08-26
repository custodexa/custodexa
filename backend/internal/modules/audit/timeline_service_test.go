package audit

import (
	"reflect"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setupTimelineDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	// session_commands／command_alerts 生產上由原生 SQL migration 建（timestamptz），
	// sqlite 掃描不了該型別，故此處以 datetime 原生建表（沿 audit_export_service_test 慣例）
	if err := db.Exec(`CREATE TABLE session_commands (
		id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
		asset_id INTEGER, command TEXT NOT NULL, seq INTEGER NOT NULL, executed_at DATETIME NOT NULL,
		k8s_pod TEXT, k8s_container TEXT,
		degraded BOOLEAN NOT NULL DEFAULT 0, degrade_reason TEXT NOT NULL DEFAULT '')`).Error; err != nil {
		t.Fatalf("create session_commands: %v", err)
	}
	if err := db.Exec(`CREATE TABLE command_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id INTEGER, rule_name TEXT NOT NULL,
		session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, asset_id INTEGER,
		command TEXT NOT NULL, severity TEXT NOT NULL, triggered_at DATETIME NOT NULL,
		reviewed_by INTEGER, reviewed_at DATETIME, disposition TEXT NOT NULL DEFAULT 'pending',
		note TEXT NOT NULL DEFAULT '', blocked BOOLEAN NOT NULL DEFAULT 0,
		kind TEXT NOT NULL DEFAULT 'rule', reason_code TEXT NOT NULL DEFAULT '')`).Error; err != nil {
		t.Fatalf("create command_alerts: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.Asset{}, &model.Session{},
		&model.AuditLog{}, &model.ClipboardEvent{}, &model.AuditRetentionWatermark{},
		&model.AuditCheckpoint{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

const (
	tlUserID  uint = 7
	tlAssetID uint = 42
)

// seedAllSources 在**同一個 ts** 上為六個來源各造 n 筆。
//
// 同 ts 是本組測試的全部重點：跨來源的排序若沒有確定序，分頁就會漏列或重複，
// 而在真實資料上這不是邊界情形——一次連線建立會在同一瞬間同時產生
// sessions 列與 audit_logs 列
func seedAllSources(t *testing.T, db *gorm.DB, ts time.Time, n int) {
	t.Helper()
	aid := tlAssetID
	for i := 0; i < n; i++ {
		if err := db.Create(&model.AuditLog{
			CreatedAt: ts, Action: model.ActionUpdate, Resource: model.ResourceAsset,
			Status: model.StatusSuccess, UserID: tlUserID, Username: "alice", AssetID: &aid,
		}).Error; err != nil {
			t.Fatalf("audit_log: %v", err)
		}
		if err := db.Create(&model.AuditLog{
			CreatedAt: ts, Action: model.ActionFileUpload, Resource: model.ResourceFile,
			Status: model.StatusSuccess, UserID: tlUserID, Username: "alice", AssetID: &aid,
		}).Error; err != nil {
			t.Fatalf("file audit_log: %v", err)
		}
		sess := &model.Session{
			SessionID: time.Now().Format("150405.000000000") + string(rune('a'+i)),
			Status:    model.SessionStatus("closed"), Protocol: model.ProtocolType("ssh"),
			UserID: tlUserID, AssetID: &aid, StartTime: ts,
		}
		if err := db.Create(sess).Error; err != nil {
			t.Fatalf("session: %v", err)
		}
		if err := db.Exec(`INSERT INTO session_commands (session_id, user_id, asset_id, command, seq, executed_at)
			VALUES (?, ?, ?, ?, ?, ?)`, sess.ID, tlUserID, aid, "ls", i+1, ts).Error; err != nil {
			t.Fatalf("command: %v", err)
		}
		if err := db.Exec(`INSERT INTO command_alerts (rule_id, rule_name, session_id, user_id, asset_id,
			command, severity, triggered_at, disposition, note) VALUES (1,'rm-rf',?,?,?,'rm -rf /','high',?,'pending','')`,
			sess.ID, tlUserID, aid, ts).Error; err != nil {
			t.Fatalf("alert: %v", err)
		}
		if err := db.Create(&model.ClipboardEvent{
			SessionID: sess.ID, Direction: "send",
			ContentEnc: "enc:a1:v1:x", ContentLength: 1, ContentStatus: model.ClipboardContentAvailable,
			CreatedAt: ts,
		}).Error; err != nil {
			t.Fatalf("clipboard: %v", err)
		}
	}
}

func baseQuery(subject TimelineSubject, id uint) TimelineQuery {
	return TimelineQuery{
		Subject:   subject,
		SubjectID: id,
		From:      time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		To:        time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC),
	}
}

// drainAll 逐頁取完，回全部事件（呼叫端據此比對「一次取完」的結果）
func drainAll(t *testing.T, svc *TimelineService, q TimelineQuery, pageSize int) []TimelineEvent {
	t.Helper()
	var all []TimelineEvent
	q.Limit = pageSize
	for page := 0; ; page++ {
		if page > 200 {
			t.Fatal("分頁未收斂：游標可能未前進（重複回同一頁）")
		}
		res, err := svc.Query(q)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		all = append(all, res.Events...)
		if !res.Truncated {
			return all
		}
		if res.NextCursor == "" {
			t.Fatal("truncated=true 卻無 next_cursor：使用者無從取得剩餘資料")
		}
		cur, err := DecodeTimelineCursor(res.NextCursor)
		if err != nil {
			t.Fatalf("decode cursor: %v", err)
		}
		q.Cursor = &cur
	}
}

// TestTimelineCursorNoDuplicateNoLoss 本 change 唯一有正確性風險的演算法的主測試。
//
// 六個來源在**完全相同的 ts** 上各有多筆。逐頁取完（小 limit，逼出多輪游標）
// 的集合，必須與一次取完（大 limit）的集合逐筆相等。
//
// 這條測試同時是 keysetWhere 三分支的突變偵測器：
//   - 把 `src > cur.Type` 分支的 `>=` 寫成 `>` → 與游標同 ts 但 type 較大的
//     來源整批被跳過 → 漏列 → 集合不等。
//   - 把 `src < cur.Type` 分支的 `>` 寫成 `>=` → 同 ts 且 type 較小者重複發 → 重複。
//   - 拿掉 type 這一維（只用 ts+id）→ 不同來源的 id 互相吃掉 → 兩種錯誤同時出現。
func TestTimelineCursorNoDuplicateNoLoss(t *testing.T) {
	db := setupTimelineDB(t)
	ts := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	seedAllSources(t, db, ts, 5)
	// 第二個時刻，確保游標也要跨 ts 前進
	seedAllSources(t, db, ts.Add(time.Second), 4)
	svc := NewTimelineService(db)

	for _, subject := range []TimelineSubject{SubjectUser, SubjectAsset} {
		id := tlUserID
		if subject == SubjectAsset {
			id = tlAssetID
		}
		q := baseQuery(subject, id)

		q.Limit = timelineMaxLimit
		full, err := svc.Query(q)
		if err != nil {
			t.Fatalf("%s 一次取完: %v", subject, err)
		}
		if full.Truncated {
			t.Fatalf("%s 測資超過單次上限，本測試前提不成立", subject)
		}

		for _, pageSize := range []int{1, 2, 3, 7, 13} {
			paged := drainAll(t, svc, q, pageSize)
			if len(paged) != len(full.Events) {
				t.Fatalf("%s pageSize=%d：逐頁取得 %d 筆，一次取得 %d 筆",
					subject, pageSize, len(paged), len(full.Events))
			}
			seen := map[string]int{}
			for _, e := range paged {
				seen[e.ID]++
			}
			for id, n := range seen {
				if n > 1 {
					t.Errorf("%s pageSize=%d：事件 %s 重複 %d 次", subject, pageSize, id, n)
				}
			}
			for i, e := range full.Events {
				if paged[i].ID != e.ID {
					t.Fatalf("%s pageSize=%d：第 %d 筆 %s ≠ %s（序不一致或漏列）",
						subject, pageSize, i, paged[i].ID, e.ID)
				}
			}
		}
	}
}

// TestTimelineTotalOrderIsStrict 全序無並列：任兩筆事件的排序鍵不得相等。
// 並列即代表游標無法把它們分開，分頁必然重複或漏列
func TestTimelineTotalOrderIsStrict(t *testing.T) {
	db := setupTimelineDB(t)
	ts := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	seedAllSources(t, db, ts, 3)
	svc := NewTimelineService(db)
	q := baseQuery(SubjectUser, tlUserID)
	q.Limit = timelineMaxLimit
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Events) < 18 {
		t.Fatalf("測資不足（%d 筆），無法驗證全序", len(res.Events))
	}
	for i := 1; i < len(res.Events); i++ {
		a, b := res.Events[i-1], res.Events[i]
		if !lessEvent(a, b) {
			t.Fatalf("第 %d 與 %d 筆非嚴格遞增：%v/%s/%d vs %v/%s/%d",
				i-1, i, a.TS, a.Type, a.SourceID, b.TS, b.Type, b.SourceID)
		}
	}
}

// TestTimelineAdapterSourcesAndEmpty 每個 adapter 一個正例一個空集合案例
func TestTimelineAdapterSourcesAndEmpty(t *testing.T) {
	db := setupTimelineDB(t)
	ts := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	seedAllSources(t, db, ts, 2)
	svc := NewTimelineService(db)

	for _, tp := range allTimelineTypes {
		q := baseQuery(SubjectUser, tlUserID)
		q.Types = []TimelineEventType{tp}
		q.Limit = timelineMaxLimit
		res, err := svc.Query(q)
		if err != nil {
			t.Fatalf("%s: %v", tp, err)
		}
		if len(res.Events) == 0 {
			t.Errorf("%s 正例應有事件", tp)
		}
		for _, e := range res.Events {
			if e.Type != tp {
				t.Errorf("%s 的查詢回傳了 %s 事件（類別篩選失效）", tp, e.Type)
			}
			if e.SummaryCode == "" {
				t.Errorf("%s 事件缺 summary_code（前端無法渲染）", tp)
			}
		}
		// 空集合：換一個不存在的主體
		empty := baseQuery(SubjectUser, 9999)
		empty.Types = []TimelineEventType{tp}
		res2, err := svc.Query(empty)
		if err != nil {
			t.Fatalf("%s 空集合: %v", tp, err)
		}
		if len(res2.Events) != 0 || res2.Counts[tp] != 0 {
			t.Errorf("%s 空集合竟有 %d 筆事件／counts=%d", tp, len(res2.Events), res2.Counts[tp])
		}
	}
}

// TestTimelineFileTransferNotDoubleCounted 檔案傳輸與操作日誌同住 audit_logs，
// 兩類的 WHERE 必須互斥；否則同一列會在時間軸上出現兩次
func TestTimelineFileTransferNotDoubleCounted(t *testing.T) {
	db := setupTimelineDB(t)
	ts := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	seedAllSources(t, db, ts, 3)
	svc := NewTimelineService(db)
	q := baseQuery(SubjectUser, tlUserID)
	q.Types = []TimelineEventType{TimelineTypeAuditLog, TimelineTypeFileTransfer}
	q.Limit = timelineMaxLimit
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	bySource := map[uint]int{}
	for _, e := range res.Events {
		bySource[e.SourceID]++
	}
	for id, n := range bySource {
		if n > 1 {
			t.Errorf("audit_logs 列 %d 同時以兩個類別出現 %d 次", id, n)
		}
	}
	if res.Counts[TimelineTypeAuditLog] != 3 || res.Counts[TimelineTypeFileTransfer] != 3 {
		t.Errorf("counts 不互斥：audit_log=%d file_transfer=%d（各應為 3）",
			res.Counts[TimelineTypeAuditLog], res.Counts[TimelineTypeFileTransfer])
	}
}

// TestTimelineAssetPivotRejectsResourceIDImpersonation 資產樞紐只認 asset_id 欄。
//
// 造一筆 resource_id 與資產 id 相同、但 asset_id 為空的改密計畫審計列
//（正是訂正前 extractResource 會產出的形態），資產樞紐**不得**撈到它
func TestTimelineAssetPivotRejectsResourceIDImpersonation(t *testing.T) {
	db := setupTimelineDB(t)
	ts := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	impostor := tlAssetID
	if err := db.Create(&model.AuditLog{
		CreatedAt: ts, Action: model.ActionExecute, Resource: model.ResourceChangeSecretPlan,
		ResourceID: &impostor, // 計畫 id 恰好等於資產 id
		Status:     model.StatusSuccess, UserID: tlUserID, Username: "alice",
		Path: "/api/v1/change-secret-plans/42/run",
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := NewTimelineService(db)
	q := baseQuery(SubjectAsset, tlAssetID)
	q.Limit = timelineMaxLimit
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Events) != 0 {
		t.Fatalf("資產樞紐撈到 %d 筆假事件（resource_id 冒充 asset_id）", len(res.Events))
	}
}

// TestTimelineTruncationHonesty 達上限時 truncated=true，且 counts 仍是真實總數
func TestTimelineTruncationHonesty(t *testing.T) {
	db := setupTimelineDB(t)
	ts := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	seedAllSources(t, db, ts, 4) // 六類 × 4 = 24 筆
	svc := NewTimelineService(db)
	q := baseQuery(SubjectUser, tlUserID)
	q.Limit = 5
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Events) != 5 || !res.Truncated {
		t.Fatalf("limit=5 應回 5 筆且 truncated=true，實得 %d 筆 truncated=%v",
			len(res.Events), res.Truncated)
	}
	for _, tp := range allTimelineTypes {
		if res.Counts[tp] != 4 {
			t.Errorf("%s 的 counts=%d，應為不受 limit 影響的 4", tp, res.Counts[tp])
		}
	}
}

// TestTimelineRejectsUnknownType 未知型別回錯誤而非靜默忽略
func TestTimelineRejectsUnknownType(t *testing.T) {
	db := setupTimelineDB(t)
	svc := NewTimelineService(db)
	q := baseQuery(SubjectUser, tlUserID)
	q.Types = []TimelineEventType{"nonexistent"}
	if _, err := svc.Query(q); err != ErrUnknownEventType {
		t.Fatalf("未知型別應回 ErrUnknownEventType，實得 %v", err)
	}
	bad := baseQuery("account", 1)
	if _, err := svc.Query(bad); err != ErrInvalidSubject {
		t.Fatalf("未知樞紐應回 ErrInvalidSubject，實得 %v", err)
	}
	rev := baseQuery(SubjectUser, tlUserID)
	rev.From, rev.To = rev.To, rev.From
	if _, err := svc.Query(rev); err != ErrInvalidRange {
		t.Fatalf("to <= from 應回 ErrInvalidRange，實得 %v", err)
	}
}

// TestTimelineCoverageTriState 三態各一例
func TestTimelineCoverageTriState(t *testing.T) {
	db := setupTimelineDB(t)
	ts := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	seedAllSources(t, db, ts, 1)
	svc := NewTimelineService(db)
	q := baseQuery(SubjectUser, tlUserID)
	q.Limit = timelineMaxLimit

	// (1) 冷啟動：無水位列＝present（不是 unknown）
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	byType := map[TimelineEventType]TimelineCoverage{}
	for _, c := range res.Coverage {
		byType[c.Type] = c
	}
	for _, tp := range []TimelineEventType{TimelineTypeAuditLog, TimelineTypeCommand, TimelineTypeAlert} {
		if byType[tp].State != CoveragePresent {
			t.Errorf("冷啟動時 %s 應為 present，實得 %s", tp, byType[tp].State)
		}
	}
	// (2) not_retained：剪貼簿與會話不在任何 retention 目標內
	for _, tp := range []TimelineEventType{TimelineTypeClipboard, TimelineTypeSession} {
		if byType[tp].State != CoverageNotRetained {
			t.Errorf("%s 應為 not_retained，實得 %s", tp, byType[tp].State)
		}
	}

	// (3) purged：水位落在窗內
	wm := NewRetentionWatermarkService(db)
	if err := wm.Advance(model.RetentionClassSessionCommand, q.From.Add(48*time.Hour), 90, true); err != nil {
		t.Fatalf("advance: %v", err)
	}
	res2, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query2: %v", err)
	}
	var cov TimelineCoverage
	for _, c := range res2.Coverage {
		if c.Type == TimelineTypeCommand {
			cov = c
		}
	}
	if cov.State != CoveragePurged {
		t.Fatalf("水位落在窗內時應為 purged，實得 %s", cov.State)
	}
	if cov.PolicyDays == nil || *cov.PolicyDays != 90 || !cov.Partial || cov.LastPurgeAt == nil {
		t.Errorf("purged 未帶齊 policy_days／partial／last_purge_at：%+v", cov)
	}

	// (4) 水位早於窗起點＝該窗未被清除，回 present
	if err := wm.Advance(model.RetentionClassCommandAlert, q.From.Add(-72*time.Hour), 90, false); err != nil {
		t.Fatalf("advance2: %v", err)
	}
	res3, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query3: %v", err)
	}
	for _, c := range res3.Coverage {
		if c.Type == TimelineTypeAlert && c.State != CoveragePresent {
			t.Errorf("水位早於窗起點時應為 present，實得 %s", c.State)
		}
	}
}

// TestRetentionWatermarkMonotonic 水位只可前進。
//
// 保留天數自 90 調為 365 時 cutoff 會變早；若照寫，已被清除的區間會被
// 重新宣稱為完整，工作台把「已依政策清除」呈現成「本來就沒發生」
func TestRetentionWatermarkMonotonic(t *testing.T) {
	db := setupTimelineDB(t)
	wm := NewRetentionWatermarkService(db)
	late := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	early := time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC)

	if err := wm.Advance(model.RetentionClassAuditLog, late, 90, false); err != nil {
		t.Fatalf("advance1: %v", err)
	}
	if err := wm.Advance(model.RetentionClassAuditLog, early, 365, false); err != nil {
		t.Fatalf("advance2: %v", err)
	}
	all, err := wm.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got := all[model.RetentionClassAuditLog]
	if !got.PurgedThroughAt.UTC().Equal(late) {
		t.Fatalf("水位倒退：期望 %v，實得 %v", late, got.PurgedThroughAt.UTC())
	}
	// 描述性欄位照實覆寫（它們講的是「最近一次執行」，不是不變式）
	if got.PolicyDays != 365 {
		t.Errorf("policy_days 應覆寫為 365，實得 %d", got.PolicyDays)
	}

	// 永久保留（0 天）不寫水位——沒有任何區間被清除
	if err := wm.Advance(model.RetentionClassRecording, late, 0, false); err != nil {
		t.Fatalf("advance3: %v", err)
	}
	all2, _ := wm.Load()
	if _, ok := all2[model.RetentionClassRecording]; ok {
		t.Error("保留天數為 0 時不應寫入水位")
	}
}

// TestRetentionWatermarkNeverDeleted 水位表永久保留：刪除一律被拒。
//
// 水位一旦消失，該類別會回退為冷啟動語義（present），已清除的區間立刻
// 被誤呈為「完整且無紀錄」——那正是本表要防的誤讀
func TestRetentionWatermarkNeverDeleted(t *testing.T) {
	db := setupTimelineDB(t)
	wm := NewRetentionWatermarkService(db)
	if err := wm.Advance(model.RetentionClassAuditLog, time.Now().Add(-24*time.Hour), 90, false); err != nil {
		t.Fatalf("advance: %v", err)
	}
	var row model.AuditRetentionWatermark
	if err := db.First(&row).Error; err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := db.Delete(&row).Error; err == nil {
		t.Fatal("刪除水位列竟成功——永久保留守衛失效")
	}
	var n int64
	db.Model(&model.AuditRetentionWatermark{}).Count(&n)
	if n != 1 {
		t.Fatalf("守衛被繞過，剩 %d 列", n)
	}
}

// TestTimelineSpansOverlapWindow 跨度取「與窗有交集」而非「起點落在窗內」。
// 只取起點會讓「昨天開、今天還在線」的長會話在今天的窗內整條消失
func TestTimelineSpansOverlapWindow(t *testing.T) {
	db := setupTimelineDB(t)
	aid := tlAssetID
	q := baseQuery(SubjectUser, tlUserID)
	if err := db.Create(&model.Session{
		SessionID: "long-running", Status: "active", Protocol: "ssh",
		UserID: tlUserID, AssetID: &aid,
		StartTime: q.From.Add(-48 * time.Hour), // 窗前開始，尚未結束
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := NewTimelineService(db)
	q.Limit = timelineMaxLimit
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(res.Spans) != 1 {
		t.Fatalf("跨窗會話應出現在 spans，實得 %d 條", len(res.Spans))
	}
	if res.Spans[0].End != nil {
		t.Error("進行中會話的 end 應為 null（畫成硬邊會被誤讀為已結束）")
	}
	// 該會話的 start_time 在窗外，故**不**應出現在事件軸上
	for _, e := range res.Events {
		if e.Type == TimelineTypeSession {
			t.Error("start_time 在窗外的會話不應成為窗內的點事件")
		}
	}
}

// TestTimelineRecordingTriState 錄影三態
func TestTimelineRecordingTriState(t *testing.T) {
	db := setupTimelineDB(t)
	q := baseQuery(SubjectUser, tlUserID)
	aid := tlAssetID
	end := q.From.Add(time.Hour)
	mk := func(sid string, hasRec bool, endAt *time.Time) {
		if err := db.Create(&model.Session{
			SessionID: sid, Status: "closed", Protocol: "ssh", UserID: tlUserID, AssetID: &aid,
			StartTime: q.From.Add(30 * time.Minute), EndTime: endAt, HasRecording: hasRec,
		}).Error; err != nil {
			t.Fatalf("seed %s: %v", sid, err)
		}
	}
	mk("no-rec", false, &end)
	mk("has-rec", true, &end)

	wm := NewRetentionWatermarkService(db)
	// 水位晚於 has-rec 的結束時刻 → 判 purged
	if err := wm.Advance(model.RetentionClassRecording, end.Add(time.Hour), 30, false); err != nil {
		t.Fatalf("advance: %v", err)
	}
	svc := NewTimelineService(db)
	q.Limit = timelineMaxLimit
	res, err := svc.Query(q)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	var none, purged int
	for _, s := range res.Spans {
		switch s.RecordingState {
		case RecordingStateNone:
			none++
		case RecordingStatePurged:
			purged++
		}
	}
	if none != 1 || purged != 1 {
		t.Fatalf("錄影三態判定錯誤：none=%d purged=%d（各應為 1）", none, purged)
	}

	// available：水位早於結束時刻
	db2 := setupTimelineDB(t)
	if err := db2.Create(&model.Session{
		SessionID: "avail", Status: "closed", Protocol: "ssh", UserID: tlUserID, AssetID: &aid,
		StartTime: q.From.Add(30 * time.Minute), EndTime: &end, HasRecording: true,
	}).Error; err != nil {
		t.Fatalf("seed avail: %v", err)
	}
	res2, err := NewTimelineService(db2).Query(q)
	if err != nil {
		t.Fatalf("query2: %v", err)
	}
	if len(res2.Spans) != 1 || res2.Spans[0].RecordingState != RecordingStateAvailable {
		t.Fatalf("無錄影水位時應為 available，實得 %+v", res2.Spans)
	}
}

// TestTimelineSubjectsMinimalFields 主體目錄只回最小欄位。
//
// 以**白名單斷言**而非肉眼看：本端點存在的理由是不放寬 /users，
// 若日後有人「順手」把 email／role 加進 struct，這條會轉紅
func TestTimelineSubjectsMinimalFields(t *testing.T) {
	db := setupTimelineDB(t)
	u := &model.User{Username: "bob", FullName: "Bob", Active: true}
	if err := db.Create(u).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// 停用改以 Update 落值：`Active` 帶 gorm `default:true`，Create 時傳 false
	// 會被當成零值而改用 DB 預設（GORM 既有行為），測資會靜默變成啟用中
	if err := db.Model(u).Update("active", false).Error; err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	svc := NewTimelineService(db)
	subs, err := svc.ListSubjects(SubjectUser, "bo", 10)
	if err != nil {
		t.Fatalf("subjects: %v", err)
	}
	if len(subs) != 1 || subs[0].Name != "bob" {
		t.Fatalf("應查得 bob，實得 %+v", subs)
	}
	if subs[0].Active {
		t.Error("已停用主體應標記 active=false 而非被濾掉")
	}
	// 欄位白名單（json 標籤）
	allowed := map[string]bool{"id": true, "name": true, "display_name": true, "active": true, "deleted": true}
	tp := reflect.TypeOf(subs[0])
	for i := 0; i < tp.NumField(); i++ {
		tag := tp.Field(i).Tag.Get("json")
		if !allowed[tag] {
			t.Errorf("主體目錄外洩欄位 %q——本端點存在的理由就是不交出這些", tag)
		}
	}
}

// TestTimelineSubjectsAssetKind 資產型主體目錄。
//
// 既有的 MinimalFields 只走 user 分支，asset 分支的 SELECT 欄位清單因此
// 從未被執行過——上線後在 Postgres 直接以 42703（column "status" does not
// exist）回 500，而資產樞紐的主體選擇器完全挑不了資產。
// 兩個分支各有自己的欄位清單，就要各有自己的測試
func TestTimelineSubjectsAssetKind(t *testing.T) {
	db := setupTimelineDB(t)
	a := &model.Asset{Name: "db-prod-01", Host: "10.1.2.3", Protocol: "ssh", Port: 22, Active: true}
	if err := db.Create(a).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	dis := &model.Asset{Name: "db-retired-02", Host: "10.1.2.4", Protocol: "ssh", Port: 22}
	if err := db.Create(dis).Error; err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	if err := db.Model(dis).Update("active", false).Error; err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	svc := NewTimelineService(db)
	subs, err := svc.ListSubjects(SubjectAsset, "", 10)
	if err != nil {
		t.Fatalf("subjects(asset): %v", err)
	}
	if len(subs) != 2 {
		t.Fatalf("應查得兩台資產（含已停用），實得 %+v", subs)
	}
	byName := map[string]TimelineSubjectRef{}
	for _, s := range subs {
		byName[s.Name] = s
	}
	if !byName["db-prod-01"].Active {
		t.Error("啟用中資產應 active=true")
	}
	if byName["db-retired-02"].Active {
		t.Error("已停用資產應標記 active=false 而非被濾掉——調查對象常已下架")
	}
	if byName["db-prod-01"].DisplayName != "10.1.2.3" {
		t.Errorf("資產的 display_name 應為 host，實得 %q", byName["db-prod-01"].DisplayName)
	}

	// 搜尋走 name 與 host 兩欄
	got, err := svc.ListSubjects(SubjectAsset, "10.1.2.4", 10)
	if err != nil {
		t.Fatalf("subjects(asset, host q): %v", err)
	}
	if len(got) != 1 || got[0].Name != "db-retired-02" {
		t.Fatalf("以 host 搜尋應命中 db-retired-02，實得 %+v", got)
	}

	// 軟刪主體仍查得到並標記
	if err := db.Delete(a).Error; err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	subs, err = svc.ListSubjects(SubjectAsset, "db-prod", 10)
	if err != nil {
		t.Fatalf("subjects(asset, deleted): %v", err)
	}
	if len(subs) != 1 || !subs[0].Deleted {
		t.Fatalf("已軟刪資產應查得到並標記 deleted=true，實得 %+v", subs)
	}
}
