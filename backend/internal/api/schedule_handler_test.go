package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// 下次執行時刻的預覽端點。
//
// 前端的頻率選擇器與兩個排程列表都問這一支，理由是時區、日曆邊界（每月 31 日、
// 閏年）與排程器實際採用的解析規則只有後端說得準；前端自己算會與真正的執行
// 時刻分岔，而分岔的症狀是畫面上寫著一個永遠不會發生的時間。

// TestScheduleNextRuns 五欄 cron 回 N 筆遞增時刻，時刻為排程器實際採用的時區。
func TestScheduleNextRuns(t *testing.T) {
	env := newPolicyTestEnv(t)

	w := env.do(t, http.MethodPost, "/api/v1/schedules/next-runs", "admin",
		map[string]any{"cron": "0 0 1 1,4,7,10 *", "count": 3})
	if w.Code != http.StatusOK {
		t.Fatalf("狀態 = %d，want 200（body %s）", w.Code, w.Body.String())
	}
	// 回應**不包 data 信封**：前端的攔截器直接讀頂層 runs／timezone
	var body struct {
		Runs     []string `json:"runs"`
		Timezone string   `json:"timezone"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析回應 %q: %v", w.Body.String(), err)
	}
	if len(body.Runs) != 3 {
		t.Fatalf("筆數 = %d，want 3（body %s）", len(body.Runs), w.Body.String())
	}
	if body.Timezone == "" {
		t.Errorf("未回時區")
	}
	var prev time.Time
	for i, raw := range body.Runs {
		ts, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			t.Fatalf("第 %d 筆 %q 不是 RFC3339: %v", i, raw, err)
		}
		if i > 0 && !ts.After(prev) {
			t.Errorf("時刻未遞增：%v 之後是 %v", prev, ts)
		}
		if ts.Day() != 1 {
			t.Errorf("每季 1 日的時刻落在 %d 日", ts.Day())
		}
		prev = ts
	}
}

// TestScheduleNextRunsDefaultsCount 未給筆數時回三筆（選擇器的預設呈現）。
func TestScheduleNextRunsDefaultsCount(t *testing.T) {
	env := newPolicyTestEnv(t)

	w := env.do(t, http.MethodPost, "/api/v1/schedules/next-runs", "admin",
		map[string]any{"cron": "30 2 * * *"})
	if w.Code != http.StatusOK {
		t.Fatalf("狀態 = %d（body %s）", w.Code, w.Body.String())
	}
	var body struct {
		Runs []string `json:"runs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("解析回應: %v", err)
	}
	if len(body.Runs) != 3 {
		t.Errorf("預設筆數 = %d，want 3", len(body.Runs))
	}
}

// TestScheduleNextRunsRejectsBadCron 格式錯誤回 400 與具名碼，
// 讓選擇器就近顯示原因而不是一片空白。
func TestScheduleNextRunsRejectsBadCron(t *testing.T) {
	env := newPolicyTestEnv(t)

	cases := []struct {
		name string
		body map[string]any
		code string
	}{
		{"四欄", map[string]any{"cron": "0 0 1 1"}, "VALIDATION_SCHEDULE_BAD_CRON"},
		{"空字串", map[string]any{"cron": ""}, "VALIDATION_SCHEDULE_BAD_CRON"},
		{"欄位值越界", map[string]any{"cron": "99 0 1 1 *"}, "VALIDATION_SCHEDULE_BAD_CRON"},
		{"帶秒的六欄", map[string]any{"cron": "0 0 0 1 1 *"}, "VALIDATION_SCHEDULE_BAD_CRON"},
		{"筆數越界", map[string]any{"cron": "0 0 * * *", "count": 99}, "VALIDATION_SCHEDULE_RUN_COUNT"},
		{"筆數為負", map[string]any{"cron": "0 0 * * *", "count": -1}, "VALIDATION_SCHEDULE_RUN_COUNT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := env.do(t, http.MethodPost, "/api/v1/schedules/next-runs", "admin", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("狀態 = %d，want 400（body %s）", w.Code, w.Body.String())
			}
			if got := decodePolicyBody(t, w)["code"]; got != tc.code {
				t.Errorf("錯誤碼 = %v，want %s", got, tc.code)
			}
		})
	}
}

// TestScheduleNextRunsRequiresAdmin 非 admin 不得使用（本端點會逼後端解析
// 使用者送來的字串並算出時刻，屬管理面）。
func TestScheduleNextRunsRequiresAdmin(t *testing.T) {
	env := newPolicyTestEnv(t)

	w := env.do(t, http.MethodPost, "/api/v1/schedules/next-runs", "auditor",
		map[string]any{"cron": "0 0 * * *", "count": 1})
	if w.Code != http.StatusForbidden {
		t.Errorf("auditor = %d，want 403（body %s）", w.Code, w.Body.String())
	}
}
