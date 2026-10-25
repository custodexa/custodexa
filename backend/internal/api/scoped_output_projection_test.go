package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// allMembersProjection 測試用輪替成員投影：回全部成員，等同全量。
type allMembersProjection struct {
	rot interface {
		Members(rotationID uint) ([]model.CredentialRotationMember, error)
	}
}

func (p allMembersProjection) MembersInView(_ context.Context, rotationID uint) ([]model.CredentialRotationMember, *int, error) {
	m, err := p.rot.Members(rotationID)
	return m, nil, err
}

func (allMembersProjection) OutputScopeWired() bool { return true }

// fixedProjection 依固定的可見資產集合投影；hidden 為 nil 代表全量。
type fixedProjection struct {
	members []model.CredentialRotationMember
	visible map[uint]bool // 空且 full 為假時全部省略
	full    bool
}

func (p fixedProjection) MembersInView(context.Context, uint) ([]model.CredentialRotationMember, *int, error) {
	if p.full {
		return p.members, nil, nil
	}
	kept := []model.CredentialRotationMember{}
	hidden := map[uint]bool{}
	for _, m := range p.members {
		if p.visible[m.AssetID] {
			kept = append(kept, m)
		} else {
			hidden[m.AssetID] = true
		}
	}
	n := len(hidden)
	return kept, &n, nil
}

func (fixedProjection) OutputScopeWired() bool { return true }

type stubCreds struct{ CredentialServiceInterface }

func (stubCreds) BindingAssetID(uint, uint) uint { return 0 }

// stubRotations 輪替服務替身：固定的一輪與成員。
type stubRotations struct {
	rot     *model.CredentialRotation
	members []model.CredentialRotationMember
}

func (s stubRotations) Start(context.Context, uint, asset.StartRotationRequest) (*model.CredentialRotation, error) {
	return s.rot, nil
}
func (s stubRotations) StartSplit(context.Context, uint, asset.StartRotationRequest) (*model.CredentialRotation, error) {
	return s.rot, nil
}
func (s stubRotations) Detach(context.Context, uint, uint, asset.DetachCredentialRequest) (*model.CredentialRotation, error) {
	return s.rot, nil
}
func (stubRotations) Run(context.Context, uint) error             { return nil }
func (stubRotations) RunMember(context.Context, uint, uint) error { return nil }
func (stubRotations) RunMemberResult(context.Context, uint, uint, asset.RotationRecordOrigin) (*asset.MemberRunResult, error) {
	return nil, nil
}
func (stubRotations) Abandon(context.Context, uint) error               { return nil }
func (stubRotations) RequireRotationTarget(context.Context, uint) error { return nil }
func (s stubRotations) Rotation(uint, uint) (*model.CredentialRotation, error) {
	return s.rot, nil
}
func (s stubRotations) Members(uint) ([]model.CredentialRotationMember, error) { return s.members, nil }
func (stubRotations) AggregateState(uint) (string, error)                      { return "settled", nil }
func (stubRotations) UnsettledRotationID(uint) (uint, error)                   { return 0, nil }
func (stubRotations) CandidateKeptMembers(uint) (map[uint]bool, error)         { return nil, nil }

type changedConfirmer struct{}

func (changedConfirmer) ConfirmHostIdentityAndVerify(context.Context, string, uint, asset.HostIdentityConfirmRequest) error {
	return asset.ErrHostIdentityConfirmTargetChanged
}

func projFixtureRotation() (*model.CredentialRotation, []model.CredentialRotationMember) {
	rot := &model.CredentialRotation{ID: 5, CredentialID: 3, Epoch: 1, Mode: model.CredentialRotationModeGroup,
		Status: model.CredentialRotationRunning, RequestedBy: 1, RequestedByName: "op", StartedAt: time.Unix(1700000000, 0)}
	members := []model.CredentialRotationMember{
		{ID: 21, RotationID: 5, AccountID: 31, AssetID: 41, AssetName: "zz-proj-visible", Username: "zz-proj-user-a", State: "pending", AttemptCount: 1},
		{ID: 22, RotationID: 5, AccountID: 32, AssetID: 42, AssetName: "zz-proj-hidden", Username: "zz-proj-user-b", State: "pending", AttemptCount: 1},
	}
	return rot, members
}

func projRouter(h *CredentialHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/credentials/:id/rotations/:rid/members/:mid/retry", h.RetryMember)
	r.POST("/credentials/:id/bindings/:accountId/detach", h.Detach)
	return r
}

func projServe(r *gin.Engine, path, body string) (int, string) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// TestRotationRetrySupplementFollowsProjection 補跑的補充資料只附在投影留下的成員上。
func TestRotationRetrySupplementFollowsProjection(t *testing.T) {
	rot, members := projFixtureRotation()
	svc := stubRotations{rot: rot, members: members}
	h := NewCredentialHandler(stubCreds{}, svc, nil)
	h.confirmer = changedConfirmer{}
	h.SetRotationMemberProjection(fixedProjection{members: members, visible: map[uint]bool{41: true}})
	r := projRouter(h)
	const confirm = `{"confirm_host_identity":{"transport":"winrm"}}`

	code, raw := projServe(r, "/credentials/3/rotations/5/members/21/retry", confirm)
	require.Equal(t, http.StatusOK, code, raw)
	assert.Contains(t, raw, `"reason"`, "可見成員帶原因碼")
	assert.Contains(t, raw, "zz-proj-visible")
	assert.NotContains(t, raw, "zz-proj-hidden")

	code, raw = projServe(r, "/credentials/3/rotations/5/members/22/retry", confirm)
	require.Equal(t, http.StatusOK, code, raw)
	assert.NotContains(t, raw, `"reason"`)
	assert.NotContains(t, raw, `"host_identity"`)
	for _, forbidden := range []string{"zz-proj-hidden", "zz-proj-user-b", `"id":22`, `"asset_id":42`, `"account_id":32`} {
		assert.NotContains(t, raw, forbidden)
	}
}

// 全域主體脫離成功回應的鍵集基準（與修補前逐鍵相同）。
var projDetachGlobalKeys = []string{
	".data", ".data.aggregate_state", ".data.credential_id", ".data.epoch", ".data.id", ".data.members",
	".data.members[].account_id", ".data.members[].asset_id", ".data.members[].asset_name",
	".data.members[].attempt_count", ".data.members[].id", ".data.members[].state", ".data.members[].username",
	".data.mode", ".data.requested_by", ".data.requested_by_name", ".data.started_at", ".data.status",
}

func projKeys(t *testing.T, raw string) []string {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(raw), &v))
	set := map[string]bool{}
	var walk func(prefix string, x any)
	walk = func(prefix string, x any) {
		switch tv := x.(type) {
		case map[string]any:
			for k, c := range tv {
				set[prefix+"."+k] = true
				walk(prefix+"."+k, c)
			}
		case []any:
			for _, c := range tv {
				walk(prefix+"[]", c)
			}
		}
	}
	walk("", v)
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestDetachSuccessResponseProjection 脫離成功回應：範圍化主體已投影，全域主體鍵集不變。
func TestDetachSuccessResponseProjection(t *testing.T) {
	rot, members := projFixtureRotation()
	svc := stubRotations{rot: rot, members: members}
	const path = "/credentials/3/bindings/31/detach"

	t.Run("scoped", func(t *testing.T) {
		h := NewCredentialHandler(stubCreds{}, svc, nil)
		h.SetRotationMemberProjection(fixedProjection{members: members, visible: map[uint]bool{41: true}})
		code, raw := projServe(projRouter(h), path, `{}`)
		require.Equal(t, http.StatusOK, code, raw)
		assert.Contains(t, raw, "zz-proj-visible")
		assert.Contains(t, raw, `"out_of_scope_asset_count"`)
		for _, forbidden := range []string{"zz-proj-hidden", "zz-proj-user-b", `"asset_id":42`} {
			assert.NotContains(t, raw, forbidden)
		}
	})
	t.Run("global_unchanged", func(t *testing.T) {
		h := NewCredentialHandler(stubCreds{}, svc, nil)
		h.SetRotationMemberProjection(fixedProjection{members: members, full: true})
		code, raw := projServe(projRouter(h), path, `{}`)
		require.Equal(t, http.StatusOK, code, raw)
		assert.Equal(t, projDetachGlobalKeys, projKeys(t, raw))
		assert.Contains(t, raw, "zz-proj-hidden")
	})
	t.Run("projection_missing_fails_closed", func(t *testing.T) {
		h := NewCredentialHandler(stubCreds{}, svc, nil)
		code, raw := projServe(projRouter(h), path, `{}`)
		assert.Equal(t, http.StatusInternalServerError, code, raw)
		assert.NotContains(t, raw, "members")
		assert.NotContains(t, raw, "zz-proj")
	})
}

// fullOutputScope 測試用改密輸出判定：全量。
type fullOutputScope struct{}

func (fullOutputScope) CredentialOutputScope(context.Context) (asset.CredentialOutputScope, error) {
	return fullOutputScopeView{}, nil
}

type fullOutputScopeView struct{}

func (fullOutputScopeView) Full() bool { return true }
func (fullOutputScopeView) AssetsInView(ids []uint) (map[uint]bool, error) {
	return allInView(ids), nil
}
func (fullOutputScopeView) CredentialsInView(ids []uint) (map[uint]bool, error) {
	return allInView(ids), nil
}

func allInView(ids []uint) map[uint]bool {
	out := make(map[uint]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// unlimitedChangeSecretScope 測試用候選計畫範圍：不限範圍。
type unlimitedChangeSecretScope struct{ noopTopologyPort }

func (unlimitedChangeSecretScope) CapabilityMissing(context.Context, *gorm.DB, uint, []string) (string, error) {
	return "", nil
}
func (unlimitedChangeSecretScope) AssetScope(context.Context, *gorm.DB, uint, string) (asset.ChangeSecretAssetScope, error) {
	return asset.ChangeSecretAssetScope{}, nil
}
func (unlimitedChangeSecretScope) ViewScope(context.Context, *gorm.DB, uint, string) (asset.ChangeSecretAssetScope, error) {
	return asset.ChangeSecretAssetScope{}, nil
}
func (unlimitedChangeSecretScope) CandidateDenial(context.Context, *gorm.DB, uint, uint) error {
	return nil
}
func (unlimitedChangeSecretScope) CredentialsVisible(context.Context, *gorm.DB, uint, string, []uint) (map[uint]bool, bool, error) {
	return nil, true, nil
}
