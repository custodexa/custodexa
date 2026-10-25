package asset_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/api"
	"github.com/custodexa/backend/internal/apierror"
	"github.com/custodexa/backend/internal/material"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
	"github.com/custodexa/backend/internal/modules/audit"
	"github.com/custodexa/backend/internal/modules/authz"
	"github.com/custodexa/backend/internal/testgate"
	"github.com/custodexa/backend/pkg/crypto"
)

// 背景工作與候選的範圍重驗。候選：候選 → 帳號 → 資產，以帳號改密的讀取範圍判定；
// 範圍化檢視者的列表只列範圍內候選，對範圍外候選重試與不存在同形。

// rwNoCodec 候選列表與單筆讀取不解封秘密；任何加解密呼叫都是測試錯誤
type rwNoCodec struct{}

var errRwNoCodec = errors.New("測試不應解封候選秘密")

func (rwNoCodec) EncryptFor(context.Context, crypto.CipherRef, string) (string, error) {
	return "", errRwNoCodec
}
func (rwNoCodec) DecryptFor(context.Context, crypto.CipherRef, string) (string, error) {
	return "", errRwNoCodec
}
func (rwNoCodec) EncryptBytesFor(context.Context, crypto.CipherRef, []byte) (string, error) {
	return "", errRwNoCodec
}
func (rwNoCodec) DecryptBytesFor(context.Context, crypto.CipherRef, string) (*material.Secret, error) {
	return nil, errRwNoCodec
}

func TestRotationWorkScopeRecheck(t *testing.T) {
	gin.SetMode(gin.TestMode)
	e := newBsEnv(t)
	if os.Getenv(testgate.EnvPGDSN) != "" {
		require.Equal(t, "postgres", e.db.Dialector.Name())
		fmt.Println("EVIDENCE dialect=postgres")
	}

	t.Run("candidate_projection_and_retry_same_shape", func(t *testing.T) {
		cands, err := asset.NewChangeSecretCandidateService(e.db, rwNoCodec{}, nil, nil)
		require.NoError(t, err)
		cands.WithScope(e.scope)
		h := api.NewChangeSecretHandler(nil, nil, cands, nil, e.svc, nil)
		legacyCands, err := asset.NewChangeSecretCandidateService(e.db, rwNoCodec{}, nil, nil)
		require.NoError(t, err)
		legacy := api.NewChangeSecretHandler(nil, nil, legacyCands, nil, e.svc, nil)

		mk := func(key string) model.ChangeSecretCandidate {
			c := model.ChangeSecretCandidate{AccountID: e.acc[key+"/postgres"], AssetID: e.assets[key],
				AccountUsername: "postgres", SecretType: model.ChangeSecretTypePassword, AttemptCount: 2,
				NextAttemptAt: time.Now().Add(time.Hour)}
			require.NoError(t, e.db.Create(&c).Error)
			return c
		}
		in, out := mk("bs-in-1"), mk("bs-out-1")

		// 列表：範圍化檢視者只見範圍內候選
		code, body := e.get(h.ListCandidates, "scoped", "/api/v1/change-secret-candidates", nil)
		require.Equal(t, http.StatusOK, code, string(body))
		var list struct {
			Data []struct {
				ID uint `json:"id"`
			} `json:"data"`
			Total int `json:"total"`
		}
		require.NoError(t, json.Unmarshal(body, &list))
		require.Equal(t, 1, list.Total)
		require.Equal(t, in.ID, list.Data[0].ID)
		e.noOutOfScopeNames(body)

		// 範圍外候選重試與不存在 ID：同為 404 候選不存在（不是 403），嘗試次數不變
		idp := func(id uint) gin.Params { return gin.Params{{Key: "id", Value: fmt.Sprint(id)}} }
		c1, b1 := e.post2(h.RetryCandidate, "scoped", fmt.Sprintf("/api/v1/change-secret-candidates/%d/retry", out.ID), idp(out.ID))
		c2, b2 := e.post2(h.RetryCandidate, "scoped", "/api/v1/change-secret-candidates/987659/retry", idp(987659))
		require.Equal(t, http.StatusNotFound, c1, string(b1))
		require.Equal(t, c1, c2)
		require.Equal(t, string(b1), string(b2), "範圍外與不存在逐位元相同")
		var resp map[string]any
		require.NoError(t, json.Unmarshal(b1, &resp))
		require.Equal(t, string(apierror.CodeCandidateNotFound), resp["code"])
		var after model.ChangeSecretCandidate
		require.NoError(t, e.db.First(&after, out.ID).Error)
		require.Equal(t, 2, after.AttemptCount)

		// 範圍內候選：單筆存取放行（經候選 → 帳號 → 資產解析，不是不限範圍）
		got, err := cands.GetFor(context.Background(), e.users["scoped"], in.ID)
		require.NoError(t, err)
		require.Equal(t, in.ID, got.ID)
		_, err = cands.GetFor(context.Background(), e.users["scoped"], out.ID)
		require.Error(t, err)
		require.False(t, errors.Is(err, asset.ErrCandidateNotFound), "範圍外回範圍拒絕值，由出口轉成候選不存在")

		// 沒有任何指派者：重試不存在 ID 與範圍外候選同形
		c3, b3 := e.post2(h.RetryCandidate, "nocap", fmt.Sprintf("/api/v1/change-secret-candidates/%d/retry", out.ID), idp(out.ID))
		require.Equal(t, http.StatusNotFound, c3, string(b3))
		require.Equal(t, string(b1), string(b3), "無指派者與範圍化主體逐位元相同")

		// 全域主體：列表與未注入範圍判定的現行服務逐位元相同，含範圍外候選
		_, now := e.get(h.ListCandidates, "global", "/api/v1/change-secret-candidates", nil)
		_, was := e.get(legacy.ListCandidates, "global", "/api/v1/change-secret-candidates", nil)
		require.Equal(t, string(was), string(now))
		require.Contains(t, string(now), fmt.Sprintf(`"id":%d`, out.ID))
		// 全域主體對不存在 ID：沿現行 404
		c4, b4 := e.post2(h.RetryCandidate, "global", "/api/v1/change-secret-candidates/987659/retry", idp(987659))
		c5, b5 := e.post2(legacy.RetryCandidate, "global", "/api/v1/change-secret-candidates/987659/retry", idp(987659))
		require.Equal(t, http.StatusNotFound, c4)
		require.Equal(t, c5, c4)
		require.Equal(t, string(b5), string(b4))
	})

	// 顯式清除候選：範圍外與不存在同為 404 候選不存在且列仍在；範圍內可刪；全域主體與現行相同
	t.Run("candidate_discard_scope_same_shape", func(t *testing.T) {
		cands, err := asset.NewChangeSecretCandidateService(e.db, rwNoCodec{}, nil, audit.NewTxSink())
		require.NoError(t, err)
		cands.WithScope(e.scope)
		h := api.NewChangeSecretHandler(nil, nil, cands, nil, e.svc, nil)
		legacyCands, err := asset.NewChangeSecretCandidateService(e.db, rwNoCodec{}, nil, audit.NewTxSink())
		require.NoError(t, err)
		legacy := api.NewChangeSecretHandler(nil, nil, legacyCands, nil, e.svc, nil)

		mk := func(key string) model.ChangeSecretCandidate {
			c := model.ChangeSecretCandidate{AccountID: e.acc[key+"/postgres"], AssetID: e.assets[key],
				AccountUsername: "postgres", SecretType: model.ChangeSecretTypePassword, AttemptCount: 1,
				NextAttemptAt: time.Now().Add(time.Hour)}
			require.NoError(t, e.db.Create(&c).Error)
			return c
		}
		exists := func(id uint) bool {
			var n int64
			require.NoError(t, e.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", id).Count(&n).Error)
			return n == 1
		}
		in, out, out2 := mk("bs-in-2"), mk("bs-out-2"), mk("bs-out-3")
		idp := func(id uint) gin.Params { return gin.Params{{Key: "id", Value: fmt.Sprint(id)}} }
		path := func(id uint) string { return fmt.Sprintf("/api/v1/change-secret-candidates/%d", id) }

		// 範圍化主體：範圍外候選與不存在 ID 同為 404 候選不存在，範圍外的列仍在
		c1, b1 := e.post2(h.DiscardCandidate, "scoped", path(out.ID), idp(out.ID))
		c2, b2 := e.post2(h.DiscardCandidate, "scoped", path(987661), idp(987661))
		require.Equal(t, http.StatusNotFound, c1, string(b1))
		require.Equal(t, c1, c2)
		require.Equal(t, string(b1), string(b2), "範圍外與不存在逐位元相同")
		var resp map[string]any
		require.NoError(t, json.Unmarshal(b1, &resp))
		require.Equal(t, string(apierror.CodeCandidateNotFound), resp["code"])
		require.True(t, exists(out.ID), "範圍外候選不被刪除")
		e.noOutOfScopeNames(b1)

		// 沒有任何指派者：範圍外候選同形
		c3, b3 := e.post2(h.DiscardCandidate, "nocap", path(out.ID), idp(out.ID))
		require.Equal(t, http.StatusNotFound, c3, string(b3))
		require.Equal(t, string(b1), string(b3), "無指派者與範圍化主體逐位元相同")
		require.True(t, exists(out.ID))

		// 範圍內候選可刪
		c4, b4 := e.post2(h.DiscardCandidate, "scoped", path(in.ID), idp(in.ID))
		require.Equal(t, http.StatusOK, c4, string(b4))
		require.False(t, exists(in.ID))
		var discarded int64
		require.NoError(t, e.db.Model(&model.AuditLog{}).Where("details LIKE ?", "%"+model.AccountOpDiscardCandidate+"%").
			Count(&discarded).Error)
		require.EqualValues(t, 1, discarded, "範圍內清除照常留痕")

		// 全域主體：不存在 ID 與現行逐位元相同；範圍外候選照常可刪
		c5, b5 := e.post2(h.DiscardCandidate, "global", path(987662), idp(987662))
		c6, b6 := e.post2(legacy.DiscardCandidate, "global", path(987662), idp(987662))
		require.Equal(t, http.StatusNotFound, c5)
		require.Equal(t, c6, c5)
		require.Equal(t, string(b6), string(b5))
		c7, b7 := e.post2(h.DiscardCandidate, "global", path(out.ID), idp(out.ID))
		c8, b8 := e.post2(legacy.DiscardCandidate, "global", path(out2.ID), idp(out2.ID))
		require.Equal(t, http.StatusOK, c7, string(b7))
		require.Equal(t, c8, c7)
		require.Equal(t, string(b8), string(b7))
		require.False(t, exists(out.ID))
		require.False(t, exists(out2.ID))
	})

	// 全系統改密管理＋節點範圍帳號改密、該節點刪除後：有效範圍為空，讀取為空集合、範圍外候選不可刪，
	// 不回到相容全量；完全沒有帳號改密指派者仍是相容全量
	t.Run("empty_node_assignment_not_legacy_full", func(t *testing.T) {
		gone := model.AssetGroup{Name: "bs-gone"}
		require.NoError(t, e.db.Create(&gone).Error)
		e.nodes["bs-gone"] = gone.ID
		manage := e.role("bs-manage-only", authz.PermChangeSecretManage)
		e.users["emptynode"] = e.user("bs-emptynode")
		e.bindGlobal(e.users["emptynode"], manage)
		e.bind(e.users["emptynode"], e.role("bs-rotate-gone", authz.PermAccountRotate), "bs-gone")
		e.users["legacyfull"] = e.user("bs-legacyfull")
		e.bindGlobal(e.users["legacyfull"], manage)
		require.NoError(t, e.db.Delete(&gone).Error, "節點軟刪除，指派列保留")

		cands, err := asset.NewChangeSecretCandidateService(e.db, rwNoCodec{}, nil, audit.NewTxSink())
		require.NoError(t, err)
		cands.WithScope(e.scope)
		h := api.NewChangeSecretHandler(nil, nil, cands, nil, e.svc, nil)
		probe := e.account(e.assets["bs-out-1"], "emptyprobe", 0)
		out := model.ChangeSecretCandidate{AccountID: probe, AssetID: e.assets["bs-out-1"], AccountUsername: "emptyprobe",
			SecretType: model.ChangeSecretTypePassword, AttemptCount: 1, NextAttemptAt: time.Now().Add(time.Hour)}
		require.NoError(t, e.db.Create(&out).Error)
		batch, _, err := e.svc.Create(&asset.ChangeSecretBatchRequest{Username: "postgres",
			AccountIDs: []uint{e.acc["bs-out-2/postgres"]}, PasswordMode: model.BatchPasswordPerTarget},
			e.users["global"], "bs-global")
		require.NoError(t, err)
		listed := func(userKey string, list func(*gin.Context), path string) map[uint]bool {
			code, body := e.get(list, userKey, path, nil)
			require.Equal(t, http.StatusOK, code, string(body))
			var resp struct {
				Data []struct {
					ID uint `json:"id"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(body, &resp))
			ids := map[uint]bool{}
			for _, d := range resp.Data {
				ids[d.ID] = true
			}
			return ids
		}

		sc, err := e.scope.ViewScope(context.Background(), e.db, e.users["emptynode"], asset.CredCapAccountRotate)
		require.NoError(t, err)
		require.True(t, sc.Limited, "有效節點已空：不是不限範圍")
		require.Empty(t, listed("emptynode", h.ListCandidates, "/api/v1/change-secret-candidates"), "候選列表為空")
		require.Empty(t, listed("emptynode", h.ListBatches, "/api/v1/change-secret-batches"), "批次列表為空")
		idp := gin.Params{{Key: "id", Value: fmt.Sprint(out.ID)}}
		code, body := e.post2(h.DiscardCandidate, "emptynode", fmt.Sprintf("/api/v1/change-secret-candidates/%d", out.ID), idp)
		require.Equal(t, http.StatusNotFound, code, string(body))
		var n int64
		require.NoError(t, e.db.Model(&model.ChangeSecretCandidate{}).Where("id = ?", out.ID).Count(&n).Error)
		require.EqualValues(t, 1, n, "範圍外候選不被刪除")

		// 對照：完全沒有帳號改密指派者，相容全量照舊
		require.True(t, listed("legacyfull", h.ListCandidates, "/api/v1/change-secret-candidates")[out.ID])
		require.True(t, listed("legacyfull", h.ListBatches, "/api/v1/change-secret-batches")[batch.ID])
	})
}
