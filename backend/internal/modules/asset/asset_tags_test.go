package asset

import (
	"context"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"

	"github.com/custodexa/backend/internal/modules/audit"
)

func setupTagsDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.Asset{}, &model.AuditLog{}, &model.AssetGroup{}, &model.AssetNode{},
	))
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB })
	return db
}

func newTagsService(t *testing.T) *AssetService {
	t.Helper()
	key := make([]byte, 32)
	svc, err := NewAssetService(aesColumnCodec(t, key), "localhost", 4822, audit.NewTxSink())
	require.NoError(t, err)
	return svc
}

func mkTagAsset(t *testing.T, db *gorm.DB, name, tags string) *model.Asset {
	t.Helper()
	asset := &model.Asset{
		Name: name, Protocol: model.ProtocolSSH, Host: "10.0.0.1", Port: 22,
		Username: "root", Tags: tags, Active: true,
	}
	require.NoError(t, db.Create(asset).Error)
	return asset
}

func TestNormalizeTagList_基本與冪等(t *testing.T) {
	got := normalizeTagList("生產, 資料庫,,生產, web ")
	assert.Equal(t, []string{"生產", "資料庫", "web"}, got)

	// canonical 去重保首見書寫形
	got = normalizeTagList("DBA,Dba,dba")
	assert.Equal(t, []string{"DBA"}, got)

	// 冪等：套兩次結果不變
	once := strings.Join(normalizeTagList("生產, 資料庫,,生產"), ",")
	twice := strings.Join(normalizeTagList(once), ",")
	assert.Equal(t, once, twice)

	assert.Empty(t, normalizeTagList("  ,, "))
}

func TestValidateTagList_上限(t *testing.T) {
	many := make([]string, maxTagsPerAsset+1)
	for i := range many {
		many[i] = "t"
	}
	assert.ErrorIs(t, validateTagList(many), ErrTooManyTags)

	assert.ErrorIs(t, validateTagList([]string{strings.Repeat("字", maxTagRunes+1)}), ErrTagTooLong)

	// 總長超 500：8 個 64 字元 ASCII 標籤＝512+7 > 500
	long := make([]string, 8)
	for i := range long {
		long[i] = strings.Repeat("a", 63) + string(rune('a'+i))
	}
	assert.ErrorIs(t, validateTagList(long), ErrTagsTotalTooLong)

	assert.NoError(t, validateTagList([]string{"生產", "db_prod"}))
}

func TestTagWholeWordPattern_跳脫(t *testing.T) {
	assert.Equal(t, `%,db\_prod,%`, tagWholeWordPattern("db_prod"))
	assert.Equal(t, `%,100\%,%`, tagWholeWordPattern("100%"))
	assert.Equal(t, `%,a\\b,%`, tagWholeWordPattern(`a\b`))
	// canonical：比對鍵小寫
	assert.Equal(t, `%,dba,%`, tagWholeWordPattern("DBA"))
}

func TestAssetService_List_TagsFilter(t *testing.T) {
	db := setupTagsDB(t)
	svc := newTagsService(t)

	a1 := mkTagAsset(t, db, "a1", "生產,資料庫")
	mkTagAsset(t, db, "a2", "非生產")
	a3 := mkTagAsset(t, db, "a3", "db_prod")
	mkTagAsset(t, db, "a4", "dbxprod")
	a5 := mkTagAsset(t, db, "a5", "100%,web")

	list := func(tags ...string) []string {
		resp, err := svc.List(&AssetFilter{Tags: tags, Page: 1, PageSize: 50})
		require.NoError(t, err)
		names := make([]string, 0, len(resp.Data))
		for _, a := range resp.Data {
			names = append(names, a.Name)
		}
		assert.Equal(t, int64(len(resp.Data)), resp.Total, "COUNT 與資料列一致")
		return names
	}

	// 整詞比對：「生產」不誤中「非生產」
	assert.Equal(t, []string{a1.Name}, list("生產"))
	// 萬用字元跳脫：db_prod 不誤中 dbxprod
	assert.Equal(t, []string{a3.Name}, list("db_prod"))
	// tag 含 %
	assert.Equal(t, []string{a5.Name}, list("100%"))
	// 多標籤 AND
	assert.Equal(t, []string{a1.Name}, list("生產", "資料庫"))
	assert.Empty(t, list("生產", "web"))
	// 大小寫不敏感
	assert.Equal(t, []string{a3.Name}, list("DB_PROD"))
}

func TestAssetService_List_TagsFilter_與節點疊加(t *testing.T) {
	db := setupTagsDB(t)
	svc := newTagsService(t)

	node := &model.AssetGroup{Name: "prod-node"}
	require.NoError(t, db.Create(node).Error)
	a1 := mkTagAsset(t, db, "a1", "生產")
	mkTagAsset(t, db, "a2", "生產") // 不掛節點
	require.NoError(t, db.Create(&model.AssetNode{AssetID: a1.ID, NodeID: node.ID}).Error)

	resp, err := svc.List(&AssetFilter{
		Tags: []string{"生產"}, NodeID: &node.ID, IncludeSubtree: true, Page: 1, PageSize: 50,
	})
	require.NoError(t, err)
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "a1", resp.Data[0].Name)
	assert.Equal(t, int64(1), resp.Total)

	resp, err = svc.List(&AssetFilter{
		Tags: []string{"非生產"}, NodeID: &node.ID, IncludeSubtree: true, Page: 1, PageSize: 50,
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Data)
}

func TestNormalizeTagsForWrite_歸一與驗證(t *testing.T) {
	db := setupTagsDB(t)
	svc := newTagsService(t)

	mkTagAsset(t, db, "seed", "DBA")

	// 大小寫歸一至既有書寫形
	got, err := svc.NormalizeTagsForWrite("Dba, web,,web")
	require.NoError(t, err)
	assert.Equal(t, "DBA,web", got)

	// 空輸入
	got, err = svc.NormalizeTagsForWrite("  ,, ")
	require.NoError(t, err)
	assert.Equal(t, "", got)

	// 上限違規
	_, err = svc.NormalizeTagsForWrite(strings.Repeat("字", maxTagRunes+1))
	assert.ErrorIs(t, err, ErrTagTooLong)

	parts := make([]string, maxTagsPerAsset+1)
	for i := range parts {
		parts[i] = string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	_, err = svc.NormalizeTagsForWrite(strings.Join(parts, ","))
	assert.ErrorIs(t, err, ErrTooManyTags)
}

func TestListTags_彙整去重排序(t *testing.T) {
	db := setupTagsDB(t)
	svc := newTagsService(t)

	mkTagAsset(t, db, "a1", "DBA,web")
	mkTagAsset(t, db, "a2", "dba,快取") // dba 與 DBA canonical 相等 → 首見書寫 DBA
	mkTagAsset(t, db, "a3", "")

	tags, err := svc.ListTags()
	require.NoError(t, err)
	assert.Equal(t, []TagCount{
		{Name: "DBA", Count: 2},
		{Name: "web", Count: 1},
		{Name: "快取", Count: 1},
	}, tags)
}

func TestRenameTag_合併去重與審計(t *testing.T) {
	db := setupTagsDB(t)
	svc := newTagsService(t)

	a1 := mkTagAsset(t, db, "a1", "DbA標籤,web")
	mkTagAsset(t, db, "a2", "DBA")
	a3 := mkTagAsset(t, db, "a3", "DbA標籤,DBA") // 合併後須去重
	mkTagAsset(t, db, "a4", "無關")

	var auditBefore int64
	require.NoError(t, db.Model(&model.AuditLog{}).Count(&auditBefore).Error)

	ctx := context.WithValue(context.WithValue(context.Background(),
		"userID", uint(42)), "username", "op-admin")
	affected, err := svc.RenameTag(ctx, "DbA標籤", "DBA")
	require.NoError(t, err)
	assert.Equal(t, int64(2), affected, "a1 與 a3 受影響；a2/a4 不含 from 不動")

	var got1, got3 model.Asset
	require.NoError(t, db.First(&got1, a1.ID).Error)
	assert.Equal(t, "DBA,web", got1.Tags)
	require.NoError(t, db.First(&got3, a3.ID).Error)
	assert.Equal(t, "DBA", got3.Tags, "合併去重：同資產不留兩個 DBA")

	// 治理操作逐資產留審計、帶操作者身分
	var logs []model.AuditLog
	require.NoError(t, db.Where("id > ?", auditBefore).
		Where("action = ? AND resource = ?", model.ActionUpdate, model.ResourceAsset).
		Find(&logs).Error)
	require.Len(t, logs, 2)
	for _, lg := range logs {
		assert.Equal(t, uint(42), lg.UserID)
		assert.Equal(t, "op-admin", lg.Username)
	}
}

func TestRenameTag_目標歸一至既有書寫(t *testing.T) {
	db := setupTagsDB(t)
	svc := newTagsService(t)

	a1 := mkTagAsset(t, db, "a1", "舊標")
	mkTagAsset(t, db, "a2", "DBA")

	// to=dba 與既有 DBA canonical 相等 → 歸一存 DBA
	affected, err := svc.RenameTag(context.Background(), "舊標", "dba")
	require.NoError(t, err)
	assert.Equal(t, int64(1), affected)

	var got model.Asset
	require.NoError(t, db.First(&got, a1.ID).Error)
	assert.Equal(t, "DBA", got.Tags)
}

func TestRenameTag_驗證(t *testing.T) {
	setupTagsDB(t)
	svc := newTagsService(t)

	_, err := svc.RenameTag(context.Background(), "", "x")
	assert.ErrorIs(t, err, ErrTagEmpty)
	_, err = svc.RenameTag(context.Background(), "a", "b,c")
	assert.ErrorIs(t, err, ErrTagContainsComma)
	_, err = svc.RenameTag(context.Background(), "a", strings.Repeat("字", maxTagRunes+1))
	assert.ErrorIs(t, err, ErrTagTooLong)
}

func TestDeleteTag_全面移除(t *testing.T) {
	db := setupTagsDB(t)
	svc := newTagsService(t)

	a1 := mkTagAsset(t, db, "a1", "廢棄,生產")
	a2 := mkTagAsset(t, db, "a2", "廢棄")
	a3 := mkTagAsset(t, db, "a3", "生產")

	affected, err := svc.DeleteTag(context.Background(), "廢棄")
	require.NoError(t, err)
	assert.Equal(t, int64(2), affected)

	var got1, got2, got3 model.Asset
	require.NoError(t, db.First(&got1, a1.ID).Error)
	assert.Equal(t, "生產", got1.Tags)
	require.NoError(t, db.First(&got2, a2.ID).Error)
	assert.Equal(t, "", got2.Tags)
	require.NoError(t, db.First(&got3, a3.ID).Error)
	assert.Equal(t, "生產", got3.Tags, "未含目標標籤的資產不動")
}

func TestParseTagsQuery_上限與去空(t *testing.T) {
	tags, err := ParseTagsQuery(",,生產, 資料庫,")
	require.NoError(t, err)
	assert.Equal(t, []string{"生產", "資料庫"}, tags)

	parts := make([]string, maxTagsPerQuery+1)
	for i := range parts {
		parts[i] = string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	_, err = ParseTagsQuery(strings.Join(parts, ","))
	assert.ErrorIs(t, err, ErrTooManyTags)
}
