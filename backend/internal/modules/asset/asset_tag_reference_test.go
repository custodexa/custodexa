package asset

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/custodexa/backend/internal/database"
)

// tagRefPortStub 歸一參照來源替身：回固定集合並記錄呼叫次數。
type tagRefPortStub struct {
	ids    []uint
	scoped bool
	err    error
	calls  int
}

func (p *tagRefPortStub) VisibleAssetIDsTx(context.Context, *gorm.DB) ([]uint, bool, error) {
	p.calls++
	return p.ids, p.scoped, p.err
}

func TestTagSpellingReference(t *testing.T) {
	ctx := context.Background()

	t.Run("scoped_reference_uses_union_only", func(t *testing.T) {
		db := setupTagsDB(t)
		svc := newTagsService(t)
		out := mkTagAsset(t, db, "out", "DBA,Prod")
		in := mkTagAsset(t, db, "in", "web")
		port := &tagRefPortStub{ids: []uint{in.ID}, scoped: true}
		svc.SetTagReferencePort(port)

		got, err := svc.NormalizeTagsForWriteTx(ctx, database.DB, "dba, Web, prod")
		require.NoError(t, err)
		assert.Equal(t, "dba,web,prod", got, "聯集外才有的寫法不得被歸一進來")
		assert.Equal(t, 1, port.calls)
		outSpellings := map[string]bool{"DBA": true, "Prod": true}
		for _, tag := range strings.Split(got, ",") {
			assert.False(t, outSpellings[tag], "結果出現聯集外資產 %d 才有的寫法 %q", out.ID, tag)
		}
	})

	t.Run("scoped_reference_in_union_spelling_applies", func(t *testing.T) {
		db := setupTagsDB(t)
		svc := newTagsService(t)
		in := mkTagAsset(t, db, "in", "DBA")
		svc.SetTagReferencePort(&tagRefPortStub{ids: []uint{in.ID}, scoped: true})
		got, err := svc.NormalizeTagsForWriteTx(ctx, database.DB, "Dba")
		require.NoError(t, err)
		assert.Equal(t, "DBA", got)
	})

	t.Run("scoped_empty_union_no_reference", func(t *testing.T) {
		db := setupTagsDB(t)
		svc := newTagsService(t)
		mkTagAsset(t, db, "out", "DBA")
		svc.SetTagReferencePort(&tagRefPortStub{scoped: true})
		got, err := svc.NormalizeTagsForWriteTx(ctx, database.DB, "dba")
		require.NoError(t, err)
		assert.Equal(t, "dba", got)
	})

	t.Run("non_scoped_full_table", func(t *testing.T) {
		db := setupTagsDB(t)
		svc := newTagsService(t)
		mkTagAsset(t, db, "seed", "DBA")
		svc.SetTagReferencePort(&tagRefPortStub{scoped: false})
		got, err := svc.NormalizeTagsForWriteTx(ctx, database.DB, "Dba")
		require.NoError(t, err)
		assert.Equal(t, "DBA", got)
	})

	t.Run("system_caller_full_table_without_port", func(t *testing.T) {
		db := setupTagsDB(t)
		svc := newTagsService(t)
		mkTagAsset(t, db, "seed", "DBA")
		port := &tagRefPortStub{err: errors.New("must not be called")}
		svc.SetTagReferencePort(port)
		got, err := svc.NormalizeTagsForWriteTx(WithSystemCaller(ctx), database.DB, "Dba")
		require.NoError(t, err)
		assert.Equal(t, "DBA", got)
		assert.Zero(t, port.calls)
	})

	t.Run("port_error_fails_closed", func(t *testing.T) {
		db := setupTagsDB(t)
		svc := newTagsService(t)
		mkTagAsset(t, db, "seed", "DBA")
		boom := errors.New("no principal")
		svc.SetTagReferencePort(&tagRefPortStub{err: boom})
		got, err := svc.NormalizeTagsForWriteTx(ctx, database.DB, "Dba")
		assert.ErrorIs(t, err, boom)
		assert.Empty(t, got, "來源失敗不得退回全表歸一")
	})
}
