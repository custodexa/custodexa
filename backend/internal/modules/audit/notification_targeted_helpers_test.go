package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"gorm.io/gorm"
)

// 定向通知（個人訊息）測試的共用替身：本機 Slack 替身（查詢與送訊息兩個方法）、可設定的收件人判定、
// 帶電子郵件欄的使用者表。替身經 NOTIFY_DM_EXTRA_HOSTS 放行（127.0.0.1），不對外送出任何請求。

const (
	tnlToken  = "xoxb-9999-8888-targetedTOKEN"
	tnlTarget = "C0CHANNEL"
)

// slackCall 替身收到的一個請求。
type slackCall struct {
	Method string // users.lookupByEmail 或 chat.postMessage
	Header http.Header
	Body   []byte
	Email  string // 查詢請求本文的 email（只供斷言，不輸出）
	At     time.Time
}

// dmSlackStub 本機 Slack 替身。lookup／post 為 nil 時用預設回應（查到帳號、送出成功）。
type dmSlackStub struct {
	mu     sync.Mutex
	srv    *httptest.Server
	clock  *fakeClock
	calls  []slackCall
	ids    map[string]string
	lookup func(n int, email string, w http.ResponseWriter)
	post   func(n int, w http.ResponseWriter)
}

func newDMSlackStub(t *testing.T, clock *fakeClock) *dmSlackStub {
	t.Helper()
	s := &dmSlackStub{clock: clock, ids: map[string]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		call := slackCall{Method: method, Header: r.Header.Clone(), Body: body}
		if method == slackLookupByEmailMethod {
			form, _ := url.ParseQuery(string(body))
			call.Email = form.Get("email")
		}
		s.mu.Lock()
		if s.clock != nil {
			call.At = s.clock.now()
		}
		s.calls = append(s.calls, call)
		n := 0
		for _, c := range s.calls {
			if c.Method == method {
				n++
			}
		}
		lookup, post := s.lookup, s.post
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch method {
		case slackLookupByEmailMethod:
			if lookup != nil {
				lookup(n-1, call.Email, w)
				return
			}
			_, _ = fmt.Fprintf(w, `{"ok":true,"user":{"id":%q,"deleted":false,"is_bot":false,"profile":{"display_name":"Disp %s"}}}`,
				s.idFor(call.Email), s.idFor(call.Email))
		case slackPostMessageMethod:
			if post != nil {
				post(n-1, w)
				return
			}
			_, _ = io.WriteString(w, `{"ok":true}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// idFor 替身為每個電子郵件配一個固定的 Slack 使用者識別碼。
func (s *dmSlackStub) idFor(email string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.ids[email]; ok {
		return id
	}
	id := fmt.Sprintf("U%04d", len(s.ids)+1)
	s.ids[email] = id
	return id
}

func (s *dmSlackStub) callsOf(method string) []slackCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []slackCall
	for _, c := range s.calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (s *dmSlackStub) total() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *dmSlackStub) set(lookup func(int, string, http.ResponseWriter), post func(int, http.ResponseWriter)) {
	s.mu.Lock()
	s.lookup, s.post = lookup, post
	s.mu.Unlock()
}

func jsonReply(code int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

// fakeJudge 可設定的收件人判定。
type fakeJudge struct {
	mu          sync.Mutex
	recipients  []uint
	err         error
	panicMsg    string
	verdict     map[uint]TargetedVerdict
	verdictErr  error
	panicVerdct bool
	awaiting    bool
	usedDB      bool
	recipCalls  int
}

func (f *fakeJudge) judge() TargetedJudge {
	return TargetedJudge{
		Recipients: func(db *gorm.DB, _ TargetedSubject) ([]uint, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.recipCalls++
			if f.usedDB {
				// 以呼叫端給的句柄查一次：交易佔住唯一連線時，以一般連線查詢會等待自己
				var n int64
				if err := db.Model(&model.NotificationChannel{}).Count(&n).Error; err != nil {
					return nil, err
				}
			}
			if f.panicMsg != "" {
				panic(f.panicMsg)
			}
			return append([]uint(nil), f.recipients...), f.err
		},
		Verdict: func(_ *gorm.DB, _ TargetedSubject, uid uint) (TargetedVerdict, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.panicVerdct {
				f.panicVerdct = false
				panic("verdict panic")
			}
			if f.verdictErr != nil {
				return TargetedIneligible, f.verdictErr
			}
			return f.verdict[uid], nil
		},
		Awaiting: func(*gorm.DB, TargetedSubject) (bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.awaiting, nil
		},
	}
}

func (f *fakeJudge) setVerdict(uid uint, v TargetedVerdict) {
	f.mu.Lock()
	if f.verdict == nil {
		f.verdict = map[uint]TargetedVerdict{}
	}
	f.verdict[uid] = v
	f.mu.Unlock()
}

// tnlEnv 定向通知測試環境。
type tnlEnv struct {
	*ndlEnv
	slack *dmSlackStub
	judge *fakeJudge
}

func resetDMCache() {
	dmAddressCache.mu.Lock()
	dmAddressCache.m = map[dmCacheKey]dmCacheEntry{}
	dmAddressCache.mu.Unlock()
}

func newTNLEnv(t *testing.T) *tnlEnv {
	t.Helper()
	e := newNDLEnv(t)
	if err := e.db.Exec(`ALTER TABLE users ADD COLUMN email TEXT`).Error; err != nil {
		t.Fatal(err)
	}
	t.Setenv(dmExtraHostsEnv, "127.0.0.1")
	resetDMCache()
	t.Cleanup(resetDMCache)
	t.Cleanup(func() {
		for ev := range targetedEventKind {
			RegisterDeliveryPrecheck(ev, nil)
		}
	})
	env := &tnlEnv{ndlEnv: e, slack: newDMSlackStub(t, e.clock), judge: &fakeJudge{awaiting: true}}
	for ev := range targetedEventKind {
		if err := e.w.UseTargetedJudge(ev, env.judge.judge()); err != nil {
			t.Fatal(err)
		}
	}
	return env
}

// user 建立使用者（email 為 nil＝未填）。
func (e *tnlEnv) user(name string, email *string) uint {
	e.t.Helper()
	res := e.db.Exec(`INSERT INTO users (username, email) VALUES (?, ?)`, name, email)
	if res.Error != nil {
		e.t.Fatal(res.Error)
	}
	var id uint
	e.db.Raw(`SELECT id FROM users WHERE username = ? ORDER BY id DESC LIMIT 1`, name).Scan(&id)
	return id
}

func emailOf(name string) *string { s := name + "@reviewers.example"; return &s }

// dmChannel 建立開啟對個人派送的 slack_app 通道（指向替身）。
func (e *tnlEnv) dmChannel(name string) model.NotificationChannel {
	e.t.Helper()
	ch := e.slackAppChannel(name, e.slack.srv.URL, tnlToken, tnlTarget)
	if err := e.db.Model(&model.NotificationChannel{}).Where("id = ?", ch.ID).Update("direct_message_enabled", true).Error; err != nil {
		e.t.Fatal(err)
	}
	ch.DirectMessageEnabled = true
	return ch
}

// created 排入一則連線申請建立事件。
func (e *tnlEnv) created(requestID uint) {
	e.t.Helper()
	e.enqueueEvent(notifycat.EventAccessRequestCreated, map[string]string{
		"request_id": fmt.Sprint(requestID), "requester_name": "alice", "asset_name": "db-prod", "asset_count": "1"})
}

// rounds 跑 n 輪，每輪之間推進 step（讓限速目的地有名額、退避到期）。
func (e *tnlEnv) rounds(n int, step time.Duration) {
	for i := 0; i < n; i++ {
		e.w.RunOnce()
		e.clock.advance(step)
	}
}

func (e *tnlEnv) userRows() []model.NotificationDelivery {
	e.t.Helper()
	var rows []model.NotificationDelivery
	if err := e.db.Where("audience = ?", deliveryAudienceUser).Order("id").Find(&rows).Error; err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func (e *tnlEnv) channelRows() []model.NotificationDelivery {
	e.t.Helper()
	var rows []model.NotificationDelivery
	if err := e.db.Where("audience = ?", deliveryAudienceChannel).Order("id").Find(&rows).Error; err != nil {
		e.t.Fatal(err)
	}
	return rows
}

// undeliveredMessages 未能送達事件的內容列。
func (e *tnlEnv) undeliveredMessages() []model.NotificationMessage {
	e.t.Helper()
	var rows []model.NotificationMessage
	if err := e.db.Where("event_key = ?", string(notifycat.EventTargetedNotificationUndelivered)).Order("id").Find(&rows).Error; err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func msgParams(t *testing.T, m model.NotificationMessage) map[string]string {
	t.Helper()
	p := map[string]string{}
	if m.Params != "" {
		if err := json.Unmarshal([]byte(m.Params), &p); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// postText 送訊息請求本文的 text 與 channel。
func postBody(t *testing.T, c slackCall) (channel, text string, unfurlLinks, unfurlMedia bool) {
	t.Helper()
	var b struct {
		Channel     string `json:"channel"`
		Text        string `json:"text"`
		UnfurlLinks *bool  `json:"unfurl_links"`
		UnfurlMedia *bool  `json:"unfurl_media"`
	}
	if err := json.Unmarshal(c.Body, &b); err != nil {
		t.Fatalf("送訊息本文不是 JSON: %v", err)
	}
	if b.UnfurlLinks == nil || b.UnfurlMedia == nil {
		t.Fatal("送訊息本文缺少關閉自動抓取的旗標")
	}
	return b.Channel, b.Text, *b.UnfurlLinks, *b.UnfurlMedia
}

var errJudge = errors.New("判定失敗（測試）")
