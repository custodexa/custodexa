package asset

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/custodexa/backend/internal/model"
)

// 資料庫自改通道在資產服務層的相容性：redis 不得設定、資料庫資產改成 redis 時清空。

func TestDBNativeChannelRejectedOnRedisAtServiceBoundary(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)

	_, err := svc.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "redis-db-native", Protocol: model.ProtocolRedis, Host: "10.0.0.20", Port: 6379,
		Username: "default", RotationChannel: model.RotationChannelDBNative,
	})
	require.ErrorIs(t, err, ErrInvalidRotationChannel, "redis 資產不得設定 db_native")

	created, err := svc.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "redis-plain", Protocol: model.ProtocolRedis, Host: "10.0.0.21", Port: 6379,
		Username: "default",
	})
	require.NoError(t, err)

	channel := model.RotationChannelDBNative
	_, err = svc.Update(WithSystemCaller(updateCtx()), created.ID, &UpdateAssetRequest{RotationChannel: &channel})
	require.ErrorIs(t, err, ErrInvalidRotationChannel, "redis 資產更新為 db_native 須被拒")

	var stored model.Asset
	require.NoError(t, db.First(&stored, created.ID).Error)
	require.Empty(t, stored.RotationChannel, "驗證失敗時資產不得被部分寫入")
}

func TestDBNativeChannelClearedWhenMySQLBecomesRedis(t *testing.T) {
	db := setupAllowedDBTestDB(t)
	svc := newAllowedDBService(t)

	created, err := svc.Create(WithSystemCaller(context.Background()), &CreateAssetRequest{
		Name: "mysql-db-native", Protocol: model.ProtocolMySQL, Host: "10.0.0.22", Port: 3306,
		Username: "app", RotationChannel: model.RotationChannelDBNative,
	})
	require.NoError(t, err)
	require.Equal(t, model.RotationChannelDBNative, created.RotationChannel)

	// 請求不帶任何通道欄位，伺服端仍須清空
	redis := model.ProtocolRedis
	updated, err := svc.Update(WithSystemCaller(updateCtx()), created.ID, &UpdateAssetRequest{Protocol: &redis})
	require.NoError(t, err)
	require.Empty(t, updated.RotationChannel)

	var stored model.Asset
	require.NoError(t, db.First(&stored, created.ID).Error)
	require.Empty(t, stored.RotationChannel, "改成 redis 後不得留 db_native 殘值")
	require.Equal(t, model.RotationChannelNone, stored.EffectiveRotationChannel(), "redis 推導為不改密")
}
