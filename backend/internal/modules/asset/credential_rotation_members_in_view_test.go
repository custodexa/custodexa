package asset

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// fakeOutputScope 輸出判定替身。
type fakeOutputScope struct {
	full    bool
	inView  map[uint]bool
	viewErr error
}

func (f fakeOutputScope) Full() bool { return f.full }
func (f fakeOutputScope) AssetsInView(ids []uint) (map[uint]bool, error) {
	if f.viewErr != nil {
		return nil, f.viewErr
	}
	out := map[uint]bool{}
	for _, id := range ids {
		if f.inView[id] {
			out[id] = true
		}
	}
	return out, nil
}
func (f fakeOutputScope) CredentialsInView(ids []uint) (map[uint]bool, error) {
	return map[uint]bool{}, nil
}

type fakeOutputSource struct {
	scope CredentialOutputScope
	err   error
}

func (f fakeOutputSource) CredentialOutputScope(context.Context) (CredentialOutputScope, error) {
	return f.scope, f.err
}

func TestCredentialRotationMembersInView(t *testing.T) {
	db := setupAccountDB(t)
	require.NoError(t, db.AutoMigrate(&model.CredentialRotationMember{}))
	// 成員：資產 10（兩個帳號）、11、12
	rows := []model.CredentialRotationMember{
		{RotationID: 1, AccountID: 1, AssetID: 10}, {RotationID: 1, AccountID: 2, AssetID: 10},
		{RotationID: 1, AccountID: 3, AssetID: 11}, {RotationID: 1, AccountID: 4, AssetID: 12},
	}
	require.NoError(t, db.Create(&rows).Error)
	svc := &CredentialRotationService{db: db}

	boom := errors.New("boom")
	ptr := func(n int) *int { return &n }
	cases := []struct {
		name       string
		src        CredentialOutputScopeSource
		wired      bool
		wantErr    bool
		wantMember int
		wantHidden *int
	}{
		{name: "未注入", src: nil, wantErr: true},
		{name: "輸出判定回錯誤", src: fakeOutputSource{err: boom}, wired: true, wantErr: true},
		{name: "全量", src: fakeOutputSource{scope: fakeOutputScope{full: true}}, wired: true, wantMember: 4},
		{name: "受限全在內", src: fakeOutputSource{scope: fakeOutputScope{inView: map[uint]bool{10: true, 11: true, 12: true}}},
			wired: true, wantMember: 4, wantHidden: ptr(0)},
		{name: "部分在外", src: fakeOutputSource{scope: fakeOutputScope{inView: map[uint]bool{11: true}}},
			wired: true, wantMember: 1, wantHidden: ptr(2)},
		{name: "全在外", src: fakeOutputSource{scope: fakeOutputScope{inView: map[uint]bool{}}},
			wired: true, wantMember: 0, wantHidden: ptr(3)},
		{name: "同一資產兩個成員只計一台", src: fakeOutputSource{scope: fakeOutputScope{inView: map[uint]bool{11: true, 12: true}}},
			wired: true, wantMember: 2, wantHidden: ptr(1)},
		{name: "AssetsInView 回錯誤", src: fakeOutputSource{scope: fakeOutputScope{viewErr: boom}}, wired: true, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 以指標傳遞（服務含互斥鎖，不可複製）；案例結束還原輸出來源
			s := svc
			orig := s.output
			t.Cleanup(func() { s.output = orig })
			if c.src != nil {
				s.output = c.src
			}
			assert.Equal(t, c.wired, s.OutputScopeWired())
			members, hidden, err := s.MembersInView(context.Background(), 1)
			if c.wantErr {
				require.Error(t, err)
				assert.Nil(t, members)
				assert.Nil(t, hidden)
				return
			}
			require.NoError(t, err)
			assert.Len(t, members, c.wantMember)
			if c.wantHidden == nil {
				assert.Nil(t, hidden)
			} else {
				require.NotNil(t, hidden)
				assert.Equal(t, *c.wantHidden, *hidden)
			}
		})
	}
}
