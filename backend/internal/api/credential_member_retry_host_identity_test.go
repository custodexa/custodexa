package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/middleware"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 成員補跑端點的主機身分契約：與候選重試同一套 body 解析與錯誤出口；
// 不帶 body 的既有形狀不變、被擋下時該成員多一個 host_identity、
// 帶明示確認時交給承接服務，授權目標已改變時以 reason 呈現而非身分衝突。

// countingRotations 包住真的輪替服務：計數補跑呼叫，並可回放固定的停止檢視。
type countingRotations struct {
	CredentialRotationServiceInterface
	resultCalls int
	view        *asset.HostIdentityView
}

func (c *countingRotations) RunMemberResult(ctx context.Context, rid, mid uint,
	origin asset.RotationRecordOrigin) (*asset.MemberRunResult, error) {
	c.resultCalls++
	res, err := c.CredentialRotationServiceInterface.RunMemberResult(ctx, rid, mid, origin)
	if err != nil {
		return nil, err
	}
	if c.view != nil {
		res.HostIdentity = c.view
	}
	return res, nil
}

type memberRetryEnv struct {
	router    *gin.Engine
	confirmer *fakeHostIdentityConfirmer
	rotations *countingRotations
	db        *gorm.DB
	memberID  uint // 被補跑的成員（已就位）
	otherID   uint // 同輪替的另一個成員
}

func newMemberRetryEnv(t *testing.T) *memberRetryEnv {
	t.Helper()
	_, ch, db, _ := setupCandidateLeakEnv(t)
	rot := &model.CredentialRotation{CredentialID: 1, Mode: model.CredentialRotationModeSplit,
		Status: model.CredentialRotationRunning, RequestedBy: 1, RequestedByName: "admin", StartedAt: time.Now()}
	if err := db.Create(rot).Error; err != nil {
		t.Fatalf("seed rotation: %v", err)
	}
	mk := func(acct uint, state, lastErr string) uint {
		m := &model.CredentialRotationMember{RotationID: rot.ID, AccountID: acct, CredentialID: 1, AssetID: 1,
			Username: "root", AssetName: "a1", State: state, LastError: lastErr, AttemptCount: 2}
		if err := db.Create(m).Error; err != nil {
			t.Fatalf("seed member: %v", err)
		}
		return m.ID
	}
	env := &memberRetryEnv{confirmer: &fakeHostIdentityConfirmer{}, db: db}
	env.memberID = mk(1, model.CredentialMemberApplied, "")
	env.otherID = mk(2, model.CredentialMemberApplied, "")
	env.rotations = &countingRotations{CredentialRotationServiceInterface: ch.rotations}
	ch.rotations = env.rotations
	ch.confirmer = env.confirmer

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uint(1))
		c.Set("username", "admin")
		middleware.SetPrincipal(c, legacyPrincipal("admin"))
	})
	r.POST("/credentials/:id/rotations/:rid/members/:mid/retry", ch.RetryMember)
	env.router = r
	return env
}

func (e *memberRetryEnv) post(t *testing.T, mid uint, body string) (int, map[string]any) {
	t.Helper()
	path := "/credentials/1/rotations/1/members/" + itoa(mid) + "/retry"
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(http.MethodPost, path, nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("回應非 JSON（%d）: %q", w.Code, w.Body.String())
	}
	return w.Code, out
}

func itoa(n uint) string { b, _ := json.Marshal(n); return string(b) }

// members 取出回應 data.members，鍵為成員 id。
func memberRetryMembers(t *testing.T, got map[string]any) map[uint]map[string]any {
	t.Helper()
	data, ok := got["data"].(map[string]any)
	if !ok {
		t.Fatalf("回應缺 data: %v", got)
	}
	list, _ := data["members"].([]any)
	out := map[uint]map[string]any{}
	for _, it := range list {
		m := it.(map[string]any)
		out[uint(m["id"].(float64))] = m
	}
	return out
}

func (e *memberRetryEnv) memberRow(t *testing.T, id uint) model.CredentialRotationMember {
	t.Helper()
	var m model.CredentialRotationMember
	if err := e.db.First(&m, id).Error; err != nil {
		t.Fatalf("read member: %v", err)
	}
	return m
}

// 基準版（P2M_BASE）成員 DTO 的鍵：applied 且無候選標記時回應中每個成員的全部鍵
var baseMemberKeys = []string{"account_id", "asset_id", "asset_name", "attempt_count", "id", "state", "username"}

func TestCredentialMemberRetryHostIdentityAPI(t *testing.T) {
	t.Run("不帶body對未停止的成員_成員鍵與基準版逐鍵相同", func(t *testing.T) {
		env := newMemberRetryEnv(t)
		for _, body := range []string{"", "{}", `{"confirm_host_identity":null}`} {
			code, got := env.post(t, env.memberID, body)
			if code != http.StatusOK {
				t.Fatalf("body=%q: status=%d %v", body, code, got)
			}
			if keys := retryBodySortedKeys(got); !reflect.DeepEqual(keys, []string{"data"}) {
				t.Fatalf("body=%q: 頂層鍵 %v，預期只有 data", body, keys)
			}
			members := memberRetryMembers(t, got)
			if len(members) != 2 {
				t.Fatalf("body=%q: 成員數 %d", body, len(members))
			}
			for id, m := range members {
				if keys := retryBodySortedKeys(m); !reflect.DeepEqual(keys, baseMemberKeys) {
					t.Fatalf("body=%q: 成員 %d 鍵 %v 與基準 %v 不同", body, id, keys, baseMemberKeys)
				}
			}
		}
		if env.confirmer.calls != 0 || env.rotations.resultCalls != 3 {
			t.Fatalf("承接服務 %d 次、補跑 %d 次", env.confirmer.calls, env.rotations.resultCalls)
		}
	})

	t.Run("不帶body對身分停止的成員_只有被補跑的那台多host_identity且無秘密", func(t *testing.T) {
		env := newMemberRetryEnv(t)
		env.rotations.view = &asset.HostIdentityView{Status: "changed", Detail: "host_key_changed", Phase: "handshake",
			VerificationSent: "false", Confirmable: true,
			Original: &asset.HostIdentityOriginalView{Transport: "ssh", RecordID: 7, Algorithm: "ssh-ed25519",
				Fingerprint: "SHA256:abc", Generation: 3, Binding: "bound"}}
		code, got := env.post(t, env.memberID, "")
		if code != http.StatusOK {
			t.Fatalf("status=%d %v", code, got)
		}
		members := memberRetryMembers(t, got)
		hi, ok := members[env.memberID]["host_identity"].(map[string]any)
		if !ok {
			t.Fatalf("被補跑的成員缺 host_identity: %v", members[env.memberID])
		}
		for _, k := range []string{"status", "detail", "phase", "verification_sent", "original", "current",
			"candidate_applied", "deadline", "expired", "confirmable"} {
			if _, has := hi[k]; !has {
				t.Fatalf("host_identity 缺 %q: %v", k, hi)
			}
		}
		if _, has := members[env.otherID]["host_identity"]; has {
			t.Fatalf("其他成員不得帶 host_identity")
		}
		if _, has := members[env.memberID]["reason"]; has {
			t.Fatalf("身分停止不帶 reason")
		}
		assertNoSecretKeys(t, got)
	})

	t.Run("帶確認成功_服務收到成員確認且不另跑一般補跑", func(t *testing.T) {
		env := newMemberRetryEnv(t)
		code, got := env.post(t, env.memberID, validSSHConfirm)
		if code != http.StatusOK {
			t.Fatalf("status=%d %v", code, got)
		}
		if env.confirmer.calls != 1 || env.confirmer.kind != "member" || env.confirmer.jobID != env.memberID {
			t.Fatalf("服務呼叫 %d 次 kind=%q job=%d", env.confirmer.calls, env.confirmer.kind, env.confirmer.jobID)
		}
		want := asset.HostIdentityConfirmRequest{Transport: "ssh", RecordID: 7, Algorithm: "ssh-ed25519",
			Fingerprint: "SHA256:abc", Generation: 3}
		if env.confirmer.req != want {
			t.Fatalf("確認內容 %+v，預期 %+v", env.confirmer.req, want)
		}
		if env.rotations.resultCalls != 0 {
			t.Fatalf("帶確認時不得另外跑一般補跑")
		}
		for id, m := range memberRetryMembers(t, got) {
			if _, has := m["reason"]; has {
				t.Fatalf("成員 %d 不應帶 reason", id)
			}
		}
	})

	t.Run("帶WinRM確認_不帶身分欄位也進服務", func(t *testing.T) {
		env := newMemberRetryEnv(t)
		code, _ := env.post(t, env.memberID, `{"confirm_host_identity":{"transport":"winrm"}}`)
		if code != http.StatusOK || env.confirmer.calls != 1 || env.confirmer.req.Transport != "winrm" {
			t.Fatalf("status=%d calls=%d req=%+v", code, env.confirmer.calls, env.confirmer.req)
		}
	})

	t.Run("驗證未通過_200且回輪替_成員不帶reason", func(t *testing.T) {
		env := newMemberRetryEnv(t)
		env.confirmer.result = asset.ErrHostIdentityVerifyFailed
		code, got := env.post(t, env.memberID, validSSHConfirm)
		if code != http.StatusOK {
			t.Fatalf("status=%d %v", code, got)
		}
		if _, has := memberRetryMembers(t, got)[env.memberID]["reason"]; has {
			t.Fatalf("驗證未通過不是目標變更，不得帶 reason")
		}
	})

	t.Run("身分已移動_409_CONFLICT_HOST_IDENTITY_MOVED且細節只含受控值", func(t *testing.T) {
		cases := []struct {
			name       string
			err        error
			wantDetail string
		}{
			{"身分已變動", &asset.HostIdentityConflictError{}, ""},
			{"不可確認", &asset.HostIdentityConflictError{Detail: "not_confirmable"}, "not_confirmable"},
			{"確認進行中", &asset.HostIdentityConflictError{Detail: "confirmation_pending"}, "confirmation_pending"},
			{"不同公鑰未同意", &asset.HostIdentityConflictError{Detail: "different_key_not_accepted"}, "different_key_not_accepted"},
			{"哨兵錯誤", asset.ErrHostIdentityMoved, ""},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				env := newMemberRetryEnv(t)
				env.confirmer.result = tc.err
				code, got := env.post(t, env.memberID, validSSHConfirm)
				if code != http.StatusConflict || got["code"] != string(apierror.CodeConflictHostIdentityMoved) {
					t.Fatalf("status=%d body=%v", code, got)
				}
				if d, has := got["detail"]; tc.wantDetail == "" && has {
					t.Fatalf("不應帶 detail：%v", d)
				} else if tc.wantDetail != "" && d != tc.wantDetail {
					t.Fatalf("detail=%v，預期 %q", d, tc.wantDetail)
				}
			})
		}
	})

	t.Run("目標已改變_200且該成員reason為既有原因碼_不是身分移動_成員列不被改寫", func(t *testing.T) {
		env := newMemberRetryEnv(t)
		env.confirmer.result = asset.ErrHostIdentityConfirmTargetChanged
		before := env.memberRow(t, env.memberID)
		code, got := env.post(t, env.memberID, validSSHConfirm)
		if code != http.StatusOK {
			t.Fatalf("status=%d %v", code, got)
		}
		raw, _ := json.Marshal(got)
		if strings.Contains(string(raw), string(apierror.CodeConflictHostIdentityMoved)) || strings.Contains(string(raw), "target_changed") {
			t.Fatalf("目標變更不得呈現為身分移動：%s", raw)
		}
		members := memberRetryMembers(t, got)
		if members[env.memberID]["reason"] != "CHANGE_SECRET_AUTHZ_TARGET_CHANGED" {
			t.Fatalf("reason=%v", members[env.memberID]["reason"])
		}
		if _, has := members[env.otherID]["reason"]; has {
			t.Fatalf("其他成員不得帶 reason")
		}
		after := env.memberRow(t, env.memberID)
		if after.LastError != before.LastError || after.AttemptCount != before.AttemptCount || after.State != before.State {
			t.Fatalf("成員列被改寫：%+v -> %+v", before, after)
		}
		if env.rotations.resultCalls != 0 {
			t.Fatalf("不得另跑一般補跑")
		}
	})

	t.Run("不合法body_400且承接服務與補跑都沒被呼叫", func(t *testing.T) {
		bad := map[string]string{
			"確認內容多餘欄位":    `{"confirm_host_identity":{"transport":"ssh","record_id":7,"algorithm":"ssh-ed25519","fingerprint":"SHA256:abc","generation":3,"actor":"someone"}}`,
			"頂層force鍵":    `{"force":true,"confirm_host_identity":{"transport":"winrm"}}`,
			"只有force鍵":    `{"force":true}`,
			"確認內容含force":  `{"confirm_host_identity":{"transport":"winrm","force":true}}`,
			"未知transport": `{"confirm_host_identity":{"transport":"telnet"}}`,
			"ssh缺身分欄位":    `{"confirm_host_identity":{"transport":"ssh"}}`,
			"winrm帶身分欄位":  `{"confirm_host_identity":{"transport":"winrm","record_id":7}}`,
			"非JSON":       `not json`,
			"尾端多餘內容":      `{"confirm_host_identity":null} {}`,
		}
		for name, body := range bad {
			t.Run(name, func(t *testing.T) {
				env := newMemberRetryEnv(t)
				code, got := env.post(t, env.memberID, body)
				if code != http.StatusBadRequest || got["code"] != string(apierror.CodeBadRequestFormat) {
					t.Fatalf("status=%d body=%v", code, got)
				}
				if env.confirmer.calls != 0 || env.rotations.resultCalls != 0 {
					t.Fatalf("不合法 body 不得進服務：承接 %d 補跑 %d", env.confirmer.calls, env.rotations.resultCalls)
				}
			})
		}
	})

	t.Run("嚴格解碼/尾隨內容_400且服務都沒被呼叫", func(t *testing.T) {
		bad := map[string]string{
			"尾隨右中括號":     `{"confirm_host_identity":{"transport":"winrm"}}]`,
			"尾隨右大括號":     `{"confirm_host_identity":{"transport":"winrm"}}}`,
			"ssh後尾隨右大括號": `{"confirm_host_identity":{"transport":"ssh","record_id":7,"algorithm":"ssh-ed25519","fingerprint":"SHA256:abc","generation":3}}}`,
			"第二個JSON值":   `{"confirm_host_identity":{"transport":"winrm"}} {"confirm_host_identity":{"transport":"winrm"}}`,
			"尾隨數字":       `{"confirm_host_identity":{"transport":"winrm"}} 1`,
		}
		for name, body := range bad {
			t.Run(name, func(t *testing.T) {
				env := newMemberRetryEnv(t)
				code, got := env.post(t, env.memberID, body)
				if code != http.StatusBadRequest || got["code"] != string(apierror.CodeBadRequestFormat) {
					t.Fatalf("status=%d body=%v", code, got)
				}
				if env.confirmer.calls != 0 {
					t.Fatalf("尾隨內容不得進服務，實際 %d 次", env.confirmer.calls)
				}
			})
		}
		env := newMemberRetryEnv(t)
		code, _ := env.post(t, env.memberID, `{"confirm_host_identity":{"transport":"winrm"}}`+"\n")
		if code == http.StatusBadRequest {
			t.Fatalf("合法 body（尾端空白）不應被拒")
		}
		if env.confirmer.calls != 1 {
			t.Fatalf("合法 body 應進服務一次，實際 %d", env.confirmer.calls)
		}
	})

	t.Run("成員不屬於該輪替_404且承接服務沒被呼叫", func(t *testing.T) {
		env := newMemberRetryEnv(t)
		code, got := env.post(t, 9999, validSSHConfirm)
		if code != http.StatusNotFound || got["code"] != string(apierror.CodeCredentialRotationMemberNotFound) {
			t.Fatalf("status=%d body=%v", code, got)
		}
		if env.confirmer.calls != 0 {
			t.Fatalf("不得呼叫承接服務")
		}
	})

	t.Run("無權_403形狀與一般權限不足相同", func(t *testing.T) {
		env := newMemberRetryEnv(t)
		env.confirmer.result = asset.ErrCredentialBindForbidden
		code, got := env.post(t, env.memberID, validSSHConfirm)
		if code != http.StatusForbidden || got["code"] != string(apierror.CodePermissionDenied) {
			t.Fatalf("status=%d body=%v", code, got)
		}
		for _, k := range retryBodySortedKeys(got) {
			if k != "code" && k != "error" {
				t.Fatalf("403 回應不得帶額外鍵 %q", k)
			}
		}
	})

	t.Run("合法body與無body都照常進各自的路徑", func(t *testing.T) {
		env := newMemberRetryEnv(t)
		env.post(t, env.memberID, "")
		if env.confirmer.calls != 0 || env.rotations.resultCalls != 1 {
			t.Fatalf("無 body：承接 %d 補跑 %d", env.confirmer.calls, env.rotations.resultCalls)
		}
		env.post(t, env.memberID, validSSHConfirm)
		if env.confirmer.calls != 1 || env.rotations.resultCalls != 1 {
			t.Fatalf("合法 body：承接 %d 補跑 %d", env.confirmer.calls, env.rotations.resultCalls)
		}
	})
}
