package authz

import (
	"github.com/custodexa/backend/internal/database"
	"github.com/custodexa/backend/internal/model"
	"github.com/custodexa/backend/internal/modules/asset"
)

// 授權分支 DTO 的節點資訊填充。
//
// **搬遷**：原為 `(*AssetService).FillNodeInfoForDTOs`，
// 住在 asset_service.go。asset 搬進獨立包後，該方法會把 authz 的
// `AuthorizedAssetDTO` 一起帶進 asset 模組，構成 asset→authz 出向邊——那正是
// 它「歸屬錯了」的理由。
//
// **改成 authz 的方法而非 asset 的方法**：DTO 是 authz 的型別，填充動作是
// authz 列表流程的一步；asset 只提供「一批資產的節點資訊」這個能力
// （`asset.FillNodeInfo`）。**零行為變更**：欄位、順序、錯誤傳遞逐字相同，
// 改變的只是誰是接收者。
func (s *AssetAuthorizationService) FillNodeInfoForDTOs(dtos []*AuthorizedAssetDTO) error {
	if len(dtos) == 0 {
		return nil
	}
	assets := make([]model.Asset, len(dtos))
	for i := range dtos {
		assets[i] = dtos[i].Asset
	}
	if err := asset.FillNodeInfo(database.DB, assets); err != nil {
		return err
	}
	for i := range dtos {
		dtos[i].Asset.NodeIDs = assets[i].NodeIDs
		dtos[i].Asset.NodePaths = assets[i].NodePaths
	}
	return nil
}
