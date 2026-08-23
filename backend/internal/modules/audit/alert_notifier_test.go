package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/branding"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/notifycat"
	"github.com/stretchr/testify/assert"
)

// newTestNotifier 建立測試用 notifier：極短退避——重試次數的驗證不需要真實等待
func newTestNotifier() *AlertNotifier {
	n := NewAlertNotifier(nil, nil)
	n.backoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	return n
}

func sampleAlert() model.CommandAlert {
	assetID := uint(3)
	ruleID := uint(1)
	return model.CommandAlert{
		ID:          42,
		RuleID:      &ruleID,
		RuleName:    "遞迴強制刪除",
		SessionID:   7,
		UserID:      9,
		AssetID:     &assetID,
		Command:     "rm -rf /data",
		Severity:    model.AlertSeverityHigh,
		TriggeredAt: time.Date(2026, 6, 12, 8, 0, 0, 0, time.UTC),
	}
}

func TestAlertNotifier_Notify(t *testing.T) {
	t.Run("payload 欄位符合約定形狀", func(t *testing.T) {
		var gotBody []byte
		var gotContentType string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotBody, _ = io.ReadAll(r.Body)
			gotContentType = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "ops", Type: "webhook", URL: server.URL, Enabled: true},
		})

		n.notify(sampleAlert())

		assert.Equal(t, "application/json", gotContentType)
		var payload map[string]interface{}
		assert.NoError(t, json.Unmarshal(gotBody, &payload))
		assert.Equal(t, "command_alert", payload["event"])

		alertBody := payload["alert"].(map[string]interface{})
		assert.Equal(t, float64(42), alertBody["id"])
		assert.Equal(t, "rm -rf /data", alertBody["command"])
		assert.Equal(t, "high", alertBody["severity"])
		assert.Equal(t, "遞迴強制刪除", alertBody["rule_name"])
		assert.Contains(t, alertBody["triggered_at"], "2026-06-12T08:00:00")

		sessionBody := payload["session"].(map[string]interface{})
		assert.Equal(t, float64(7), sessionBody["id"])
		assert.Equal(t, float64(9), sessionBody["user_id"])
		assert.Equal(t, float64(3), sessionBody["asset_id"])
	})

	t.Run("secret 設定時附可驗 HMAC 簽名", func(t *testing.T) {
		const secret = "test-shared-secret"
		var gotBody []byte
		var gotSignature string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotBody, _ = io.ReadAll(r.Body)
			gotSignature = r.Header.Get("X-OT-Signature")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "signed", URL: server.URL, Secret: secret, Enabled: true},
		})

		n.notify(sampleAlert())

		// 收端視角驗章：以共享 secret 對 body 原文重算 HMAC-SHA256 比對
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(gotBody)
		expected := hex.EncodeToString(mac.Sum(nil))
		assert.NotEmpty(t, gotSignature)
		assert.Equal(t, expected, gotSignature)
	})

	t.Run("secret 為空時不附簽名 header", func(t *testing.T) {
		var hasSignature bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, hasSignature = r.Header["X-Ot-Signature"]
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "unsigned", URL: server.URL, Enabled: true},
		})

		n.notify(sampleAlert())

		assert.False(t, hasSignature)
	})

	t.Run("收端 500 時重試 3 次（共 4 次嘗試）", func(t *testing.T) {
		var attempts int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "broken", URL: server.URL, Enabled: true},
		})

		n.notify(sampleAlert())

		assert.Equal(t, int32(4), atomic.LoadInt32(&attempts))
	})

	t.Run("成功後不再重試", func(t *testing.T) {
		var attempts int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "healthy", URL: server.URL, Enabled: true},
		})

		n.notify(sampleAlert())

		assert.Equal(t, int32(1), atomic.LoadInt32(&attempts))
	})

	t.Run("停用通道不發送", func(t *testing.T) {
		var attempts int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		n := newTestNotifier()
		count := n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "disabled", URL: server.URL, Enabled: false},
		})

		n.notify(sampleAlert())

		assert.Equal(t, 0, count)
		assert.Equal(t, int32(0), atomic.LoadInt32(&attempts))
	})

	t.Run("收端不可達時失敗不擴散", func(t *testing.T) {
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			// 169.254.0.1 link-local 不可路由，配合短退避快速走完重試
			{ID: 1, Name: "unreachable", URL: "http://169.254.0.1:1/hook", Enabled: true},
		})
		n.client.Timeout = 200 * time.Millisecond

		// 不 panic、不回傳錯誤即為「失敗僅 log」語意成立
		assert.NotPanics(t, func() { n.notify(sampleAlert()) })
	})

	t.Run("slack 通道送 {text} 且不附簽名", func(t *testing.T) {
		var gotBody []byte
		var hasSignature bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotBody, _ = io.ReadAll(r.Body)
			_, hasSignature = r.Header["X-Ot-Signature"]
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		n := newTestNotifier()
		// 即使殘留 secret，slack 類型也不得簽名
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "slack", Type: model.NotificationChannelTypeSlack, URL: server.URL, Secret: "leftover", Enabled: true},
		})

		n.notify(sampleAlert())

		assert.False(t, hasSignature, "slack 不應附 X-OT-Signature")
		var payload map[string]interface{}
		assert.NoError(t, json.Unmarshal(gotBody, &payload))
		text, ok := payload["text"].(string)
		assert.True(t, ok, "slack body 應為 {\"text\": ...}")
		assert.Contains(t, text, "遞迴強制刪除")
		assert.Contains(t, text, "rm -rf /data")
		assert.Contains(t, text, "🔴") // high severity emoji
		// 不應出現 webhook 的結構化欄位
		assert.NotContains(t, payload, "event")
	})

	t.Run("slack text 對含 shell metachar 的指令做跳脫", func(t *testing.T) {
		var gotBody []byte
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		alert := sampleAlert()
		alert.Command = "grep secret > /tmp/x && cat <in"

		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "slack", Type: model.NotificationChannelTypeSlack, URL: server.URL, Enabled: true},
		})

		n.notify(alert)

		var payload map[string]string
		assert.NoError(t, json.Unmarshal(gotBody, &payload))
		// & < > 應轉為 HTML 實體，不得殘留裸字元
		assert.Contains(t, payload["text"], "&gt;")
		assert.Contains(t, payload["text"], "&lt;")
		assert.Contains(t, payload["text"], "&amp;")
		assert.NotContains(t, payload["text"], "> /tmp")
		assert.NotContains(t, payload["text"], "<in")
	})
}

// TestAlertBlockedSurfacing 阻斷型告警的 payload 衛生：
// 阻斷事實走 blocked 布林欄與通道語系短語，不靠 RuleName 後綴散文
func TestAlertBlockedSurfacing(t *testing.T) {
	t.Run("webhook payload 帶 blocked 欄", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "ops", Type: model.NotificationChannelTypeWebhook, URL: url, Enabled: true},
		})

		alert := sampleAlert()
		alert.Blocked = true
		n.notify(alert)

		var payload map[string]any
		assert.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
		alertBody := payload["alert"].(map[string]any)
		assert.Equal(t, true, alertBody["blocked"])
		// 規則名保持純淨：阻斷標示不得混進使用者資料欄
		assert.Equal(t, "遞迴強制刪除", alertBody["rule_name"])
	})

	t.Run("非阻斷告警 blocked 為 false", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "ops", Type: model.NotificationChannelTypeWebhook, URL: url, Enabled: true},
		})

		n.notify(sampleAlert())

		var payload map[string]any
		assert.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
		assert.Equal(t, false, payload["alert"].(map[string]any)["blocked"])
	})

	t.Run("Slack 阻斷標示與等級走通道語系", func(t *testing.T) {
		alert := sampleAlert()
		alert.Blocked = true
		zh := buildSlackText(model.NotificationChannelLanguageZhTW, alertEventCommandAlert, alert, alertSubjectNames{})
		en := buildSlackText(model.NotificationChannelLanguageEnUS, alertEventCommandAlert, alert, alertSubjectNames{})

		assert.Contains(t, zh, "已阻斷")
		assert.Contains(t, zh, "高風險")
		assert.Contains(t, en, "Blocked")
		assert.Contains(t, en, "High")
		assert.NotContains(t, en, "已阻斷")
		// 使用者資料兩語系都原樣
		assert.Contains(t, zh, "遞迴強制刪除")
		assert.Contains(t, en, "遞迴強制刪除")
		// 非阻斷告警不得出現標示
		assert.NotContains(t,
			buildSlackText(model.NotificationChannelLanguageZhTW, alertEventCommandAlert, sampleAlert(), alertSubjectNames{}),
			"已阻斷")
	})
}

// captureOne 起一個只收一次 body 的 webhook 收端
func captureOne(t *testing.T) (url string, received chan []byte) {
	t.Helper()
	received = make(chan []byte, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return server.URL, received
}

func awaitBody(t *testing.T, received chan []byte) []byte {
	t.Helper()
	select {
	case body := <-received:
		return body
	case <-time.After(3 * time.Second):
		t.Fatal("3s 內未收到投遞")
		return nil
	}
}

// TestNotifyEvent 系統事件結構化投遞：webhook 機器形狀、
// Slack 走 per-channel 語系渲染、契約異常降級不拒發
func TestNotifyEvent(t *testing.T) {
	t.Run("webhook payload 為 {event,params,sent_at}", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "ops", Type: model.NotificationChannelTypeWebhook, URL: url, Enabled: true},
		})

		n.NotifyEvent(notifycat.EventDailyReviewOverdue, map[string]string{"date": "2026-07-31"})

		var got notifyEventPayload
		assert.NoError(t, json.Unmarshal(awaitBody(t, received), &got))
		assert.Equal(t, "daily_review_overdue", got.Event)
		assert.Equal(t, map[string]string{"date": "2026-07-31"}, got.Params)
		assert.False(t, got.Degraded)
		assert.NotEmpty(t, got.SentAt)
	})

	t.Run("Slack 依通道語系渲染（en-US）", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "slack-en", Type: model.NotificationChannelTypeSlack,
				URL: url, Enabled: true, Language: model.NotificationChannelLanguageEnUS},
		})

		n.NotifyEvent(notifycat.EventBreakGlassUsed, map[string]string{
			"request_id": "42", "asset_name": "db-prod",
			"username": "alice", "duration_minutes": "15",
		})

		var payload map[string]string
		assert.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
		text := payload["text"]
		// en-US 目錄命中：英文文案＋原樣使用者資料，且不得殘留 zh 文案
		assert.Contains(t, text, "Access request #42")
		assert.Contains(t, text, "db-prod")
		assert.Contains(t, text, "alice")
		assert.NotContains(t, text, "破窗")
	})

	t.Run("Slack 語系分歧：同事件不同通道各自渲染", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "zh", Type: model.NotificationChannelTypeSlack, URL: url,
				Enabled: true, Language: model.NotificationChannelLanguageZhTW},
			{ID: 2, Name: "ja", Type: model.NotificationChannelTypeSlack, URL: url,
				Enabled: true, Language: model.NotificationChannelLanguageJaJP},
		})

		n.NotifyEvent(notifycat.EventDailyReviewOverdue, map[string]string{"date": "2026-07-31"})

		texts := make([]string, 0, 2)
		for i := 0; i < 2; i++ {
			var payload map[string]string
			assert.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
			texts = append(texts, payload["text"])
		}
		assert.NotEqual(t, texts[0], texts[1], "per-channel 語系應產生不同文案")
	})

	t.Run("cause_code 於 Slack 渲染為該語系短語", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "slack-en", Type: model.NotificationChannelTypeSlack,
				URL: url, Enabled: true, Language: model.NotificationChannelLanguageEnUS},
		})

		n.NotifyEvent(notifycat.EventAuditFailure, map[string]string{
			"mechanism":  model.MechanismRecordingText,
			"started_at": "2026-07-31T00:00:00Z",
			"cause_code": model.CauseRecordingFileMissing,
		})

		var payload map[string]string
		assert.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
		assert.Contains(t, payload["text"],
			notifycat.Phrase(model.NotificationChannelLanguageEnUS,
				notifycat.LexiconCause, model.CauseRecordingFileMissing))
		assert.NotContains(t, payload["text"], model.CauseRecordingFileMissing,
			"應顯示短語而非裸機器碼")
	})

	t.Run("未註冊事件降級投遞而非拒發（webhook）", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "ops", Type: model.NotificationChannelTypeWebhook, URL: url, Enabled: true},
		})

		n.NotifyEvent(notifycat.Event("ghost.event"), map[string]string{"who": "alice\nbob"})

		body := awaitBody(t, received)
		var got notifyEventPayload
		assert.NoError(t, json.Unmarshal(body, &got))
		// event 身分永不丟——合規告警的識別靠它
		assert.Equal(t, "ghost.event", got.Event)
		assert.True(t, got.Degraded)
		assert.NotEmpty(t, got.SentAt)
		// 未註冊 event 無契約可依：params 值全數剝除
		assert.Empty(t, got.Params)
		assert.NotContains(t, string(body), "alice")
	})

	t.Run("未註冊事件降級投遞而非拒發（Slack）", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "slack", Type: model.NotificationChannelTypeSlack, URL: url,
				Enabled: true, Language: model.NotificationChannelLanguageEnUS},
		})

		n.NotifyEvent(notifycat.Event("ghost.event"), map[string]string{"who": "alice"})

		var payload map[string]string
		assert.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
		assert.Contains(t, payload["text"], ":warning:")
		assert.Contains(t, payload["text"], "ghost.event")
		assert.NotContains(t, payload["text"], "alice", "未註冊 event 的 params 值不得出站")
	})

	t.Run("參數不合契約亦降級不拒發", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "ops", Type: model.NotificationChannelTypeWebhook, URL: url, Enabled: true},
		})

		// date 為必要參數，刻意不給
		n.NotifyEvent(notifycat.EventDailyReviewOverdue, map[string]string{})

		var got notifyEventPayload
		assert.NoError(t, json.Unmarshal(awaitBody(t, received), &got))
		assert.True(t, got.Degraded, "缺必要參數時仍須投遞（合規告警不得消失）")
	})

	// 降級投遞的洩漏面：Validate 失敗時，未宣告的鍵
	// （呼叫端誤傳的 forensic detail、錯字鍵）值一律不得抵達收端。
	// 淨化只管形狀，管不了「該不該出站」——去識別紅線是靠 EventSpec 守的
	const leakyDetail = "dial tcp 10.0.0.5:514: connection refused"

	t.Run("降級不得挾帶未宣告鍵的值（webhook）", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "ops", Type: model.NotificationChannelTypeWebhook, URL: url, Enabled: true},
		})

		// cause_code 為必要參數，刻意不給 → 降級；同時多帶未宣告的 detail
		n.NotifyEvent(notifycat.EventAuditFailure, map[string]string{
			"mechanism":  model.MechanismSyslogForward,
			"started_at": "2026-08-01T00:00:00Z",
			"detail":     leakyDetail,
		})

		body := awaitBody(t, received)
		var got notifyEventPayload
		assert.NoError(t, json.Unmarshal(body, &got))
		assert.True(t, got.Degraded)
		assert.NotContains(t, string(body), "10.0.0.5", "forensic detail 不得出站")
		if _, leaked := got.Params["detail"]; leaked {
			t.Fatalf("未宣告鍵不得出站: %v", got.Params)
		}
		// 已宣告鍵仍保留：降級是收窄出站面，不是把事件內容全部清空
		assert.Equal(t, model.MechanismSyslogForward, got.Params["mechanism"])
	})

	t.Run("降級不得挾帶未宣告鍵的值（Slack）", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "slack-en", Type: model.NotificationChannelTypeSlack, URL: url,
				Enabled: true, Language: model.NotificationChannelLanguageEnUS},
		})

		n.NotifyEvent(notifycat.EventAuditFailure, map[string]string{
			"mechanism":  model.MechanismSyslogForward,
			"started_at": "2026-08-01T00:00:00Z",
			"detail":     leakyDetail,
		})

		var payload map[string]string
		assert.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
		text := payload["text"]
		assert.NotContains(t, text, "10.0.0.5", "forensic detail 不得出現在 Slack 文字")
		assert.NotContains(t, text, "detail")
		assert.Contains(t, text, "audit_failure", "event 身分仍須出站")
	})

	t.Run("降級文案走通道語系（en-US 為英文）", func(t *testing.T) {
		url, received := captureOne(t)
		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "slack-en", Type: model.NotificationChannelTypeSlack, URL: url,
				Enabled: true, Language: model.NotificationChannelLanguageEnUS},
			{ID: 2, Name: "slack-zh", Type: model.NotificationChannelTypeSlack, URL: url,
				Enabled: true, Language: model.NotificationChannelLanguageZhTW},
		})

		n.NotifyEvent(notifycat.Event("ghost.event"), map[string]string{"who": "alice"})

		texts := map[string]bool{}
		for i := 0; i < 2; i++ {
			var payload map[string]string
			assert.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
			texts[payload["text"]] = true
		}
		assert.Len(t, texts, 2, "降級文案應 per-channel 語系分歧")

		var enText, zhText string
		for text := range texts {
			if strings.Contains(text, "did not satisfy") {
				enText = text
			}
			if strings.Contains(text, "降級") {
				zhText = text
			}
		}
		assert.NotEmpty(t, enText, "en-US 通道降級文字應為英文，實得 %v", texts)
		assert.NotEmpty(t, zhText, "zh-TW 通道降級文字應為中文，實得 %v", texts)
		assert.NotContains(t, enText, "降級", "en-US 通道不得殘留中文降級文案")
	})
}

func TestSeverityEmoji(t *testing.T) {
	assert.Equal(t, "🔴", severityEmoji(model.AlertSeverityHigh))
	assert.Equal(t, "🟠", severityEmoji(model.AlertSeverityMedium))
	assert.Equal(t, "🟡", severityEmoji(model.AlertSeverityLow))
	assert.Equal(t, "⚪", severityEmoji("")) // default 分支不留空
	assert.Equal(t, "⚪", severityEmoji("unknown"))
}

func TestSlackEscape(t *testing.T) {
	// & 必須先轉，否則會二次轉義後續實體
	assert.Equal(t, "a &amp;&lt;&gt; b", slackEscape("a &<> b"))
	assert.Equal(t, "no metachar", slackEscape("no metachar"))
}

func TestAlertNotifier_Enqueue(t *testing.T) {
	t.Run("佇列滿載時不阻塞", func(t *testing.T) {
		// 不啟動 worker：佇列只進不出，灌超過容量驗證 Enqueue 的非阻塞語意
		n := newTestNotifier()

		done := make(chan struct{})
		go func() {
			for i := 0; i < notifyQueueSize*2; i++ {
				n.Enqueue(sampleAlert())
			}
			close(done)
		}()

		select {
		case <-done:
			// 滿載後多餘告警被丟棄，佇列維持在容量上限
			assert.Equal(t, notifyQueueSize, len(n.queue))
		case <-time.After(2 * time.Second):
			t.Fatal("Enqueue 在佇列滿載時阻塞")
		}
	})

	t.Run("worker 消費佇列並送達", func(t *testing.T) {
		var attempts int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&attempts, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		n := newTestNotifier()
		n.setChannels([]model.NotificationChannel{
			{ID: 1, Name: "async", URL: server.URL, Enabled: true},
		})
		n.Start()

		n.Enqueue(sampleAlert())

		// 異步投遞：輪詢等待 worker 完成（上限 2s 避免測試卡死）
		deadline := time.Now().Add(2 * time.Second)
		for atomic.LoadInt32(&attempts) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		assert.Equal(t, int32(1), atomic.LoadInt32(&attempts))
	})
}

func TestSendTestNotification(t *testing.T) {
	t.Run("回傳收端狀態碼且 payload 為測試事件", func(t *testing.T) {
		var gotBody []byte
		var gotSignature string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotBody, _ = io.ReadAll(r.Body)
			gotSignature = r.Header.Get("X-OT-Signature")
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		ch := &model.NotificationChannel{ID: 1, Name: "test", URL: server.URL, Secret: "s3cret"}
		status, err := SendTestNotification(ch)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, status)
		var payload map[string]interface{}
		assert.NoError(t, json.Unmarshal(gotBody, &payload))
		assert.Equal(t, "test", payload["event"])
		assert.NotEmpty(t, gotSignature)
		// rule_name 為機器識別字，不再是散文「測試發送」
		assert.Equal(t, testRuleName, payload["alert"].(map[string]any)["rule_name"])
	})

	t.Run("Slack 測試通知標題由通道語系渲染", func(t *testing.T) {
		url, received := captureOne(t)
		ch := &model.NotificationChannel{ID: 1, Name: "slack-en",
			Type: model.NotificationChannelTypeSlack, URL: url,
			Language: model.NotificationChannelLanguageEnUS}
		if _, err := SendTestNotification(ch); err != nil {
			t.Fatalf("send: %v", err)
		}

		var payload map[string]string
		assert.NoError(t, json.Unmarshal(awaitBody(t, received), &payload))
		enTitle, enText := notifycat.Render(model.NotificationChannelLanguageEnUS,
			notifycat.EventTest, map[string]string{"product": branding.Name})
		assert.Contains(t, payload["text"], enTitle)
		assert.Contains(t, payload["text"], enText)
		assert.NotContains(t, payload["text"], "測試通知")
	})

	t.Run("收端不可達時回傳錯誤", func(t *testing.T) {
		// 先起再關，拿到一個必然拒連的位址
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		url := server.URL
		server.Close()

		ch := &model.NotificationChannel{ID: 1, Name: "down", URL: url}
		_, err := SendTestNotification(ch)

		assert.Error(t, err)
	})
}

// TestSanitizeDeliveryError 投遞錯誤脫敏：
// url.Error.Error() 內嵌完整請求 URL（webhook 路徑＝持有型 secret），脫敏後
// 只保留 op 與 host，不得洩漏 path/query/userinfo；底層錯誤或非 url.Error
// 夾帶已知目標 URL 時亦須抹除（安全審查復現的情境）
func TestSanitizeDeliveryError(t *testing.T) {
	t.Run("真實投遞失敗不洩漏 URL 敏感段但保留 host", func(t *testing.T) {
		// 起再關取必然拒連位址，帶敏感 path/query/userinfo
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		base := server.URL // http://127.0.0.1:PORT
		server.Close()
		hostPort := base[len("http://"):]
		secretURL := "http://user:SUPERSECRETPW@" + hostPort + "/services/T0/B0/tokenSECRETvalue?token=QUERYSECRET"

		ch := &model.NotificationChannel{ID: 1, Name: "down", URL: secretURL}
		_, err := deliverOnce(&http.Client{Timeout: notifyHTTPTimeout}, ch, []byte(`{}`))
		if err == nil {
			t.Fatal("拒連位址應回錯誤")
		}

		out := SanitizeDeliveryError(err, secretURL)
		for _, leak := range []string{"SUPERSECRETPW", "tokenSECRETvalue", "QUERYSECRET", "/services/", "token=", "user:"} {
			assert.NotContains(t, out, leak, "脫敏輸出洩漏敏感段: %q", out)
		}
		// host 應保留供維運定位
		assert.Contains(t, out, hostPort)
	})

	t.Run("底層錯誤內嵌完整 URL 也被抹除", func(t *testing.T) {
		secretURL := "https://hooks.example/token/SECRETpath?key=QSECRET"
		err := &url.Error{
			Op:  "Post",
			URL: secretURL,
			Err: errors.New("proxy failed for " + secretURL),
		}
		out := SanitizeDeliveryError(err, secretURL)
		for _, leak := range []string{"SECRETpath", "QSECRET", "/token/"} {
			assert.NotContains(t, out, leak, "底層錯誤夾帶的 URL 未被抹除: %q", out)
		}
		assert.Contains(t, out, "hooks.example")
	})

	t.Run("非 url.Error 夾帶目標 URL 也被抹除", func(t *testing.T) {
		secretURL := "https://hooks.example/token/SECRETpath"
		wrapped := fmt.Errorf("custom transport: %s unreachable", secretURL)
		out := SanitizeDeliveryError(wrapped, secretURL)
		assert.NotContains(t, out, "SECRETpath")
		assert.Contains(t, out, "hooks.example")
	})

	t.Run("nil 與不含敏感段的一般錯誤原樣保留", func(t *testing.T) {
		assert.Equal(t, "", SanitizeDeliveryError(nil, "https://hooks.example/x"))
		plain := assert.AnError
		assert.Equal(t, plain.Error(), SanitizeDeliveryError(plain, ""))
		assert.Equal(t, plain.Error(), SanitizeDeliveryError(plain, "https://hooks.example/x"))
	})
}

// TestAlertContextReadability 脈絡行的主體可辨識性。
//
// 只測三種形態：有資產、無資產、名稱解析不到（降級）。**刻意不測**故障注入
// （與「查不到名稱」是同一條降級分支）、字元跳脫（slackEscape 有自己的測試）、
// 改名後重試（spec 明載的預期行為）——理由逐條見該 change 的 design。
func TestAlertContextReadability(t *testing.T) {
	zh := model.NotificationChannelLanguageZhTW

	t.Run("名稱與識別碼並列且順序為 誰→哪台→會話→時間", func(t *testing.T) {
		got := buildAlertContext(zh, sampleAlert(),
			alertSubjectNames{User: "alice", Asset: "web-prod-01"})

		// 名稱可辨識、識別碼保留供追查
		assert.Contains(t, got, "使用者 alice (#9)")
		assert.Contains(t, got, "資產 web-prod-01 (#3)")
		assert.Contains(t, got, "會話 #7")
		assert.Contains(t, got, "2026-06-12T08:00:00Z")

		// 順序：使用者在資產之前、資產在會話之前
		assert.Less(t, strings.Index(got, "使用者"), strings.Index(got, "資產"),
			"稽核的第一個問題是「誰做的」，主體須在最前")
		assert.Less(t, strings.Index(got, "資產"), strings.Index(got, "會話"),
			"會話識別碼是追查索引而非判讀資訊，須後置")
	})

	t.Run("無資產時省略資產欄", func(t *testing.T) {
		alert := sampleAlert()
		alert.AssetID = nil
		got := buildAlertContext(zh, alert, alertSubjectNames{User: "alice"})

		assert.Contains(t, got, "使用者 alice (#9)")
		assert.NotContains(t, got, "資產")
	})

	t.Run("名稱解析不到時降級為僅識別碼", func(t *testing.T) {
		got := buildAlertContext(zh, sampleAlert(), alertSubjectNames{})

		// 退化形態：標籤＋識別碼，不得出現空名稱造成的殘缺括號
		assert.Contains(t, got, "使用者 #9")
		assert.Contains(t, got, "資產 #3")
		assert.NotContains(t, got, "()", "空名稱不得留下殘缺的括號")
		// 時間與會話仍在——通知不因名稱缺失而少資訊
		assert.Contains(t, got, "會話 #7")
		assert.Contains(t, got, "2026-06-12T08:00:00Z")
	})

	t.Run("實體標籤隨通道語系", func(t *testing.T) {
		names := alertSubjectNames{User: "alice", Asset: "web-prod-01"}
		en := buildAlertContext(model.NotificationChannelLanguageEnUS, sampleAlert(), names)
		ja := buildAlertContext(model.NotificationChannelLanguageJaJP, sampleAlert(), names)

		assert.Contains(t, en, "user alice (#9)")
		assert.Contains(t, ja, "ユーザー alice (#9)")
		assert.NotContains(t, ja, "使用者")
		// 主體名稱是使用者資料，兩語系都原樣不譯
		assert.Contains(t, en, "web-prod-01")
		assert.Contains(t, ja, "web-prod-01")
	})
}
