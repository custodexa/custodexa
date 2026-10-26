import request from './request'

/**
 * 使用者權限一覽（唯讀）。回應由伺服器算好，前端只呈現，不推算集合、範圍或交集。
 */

const unwrap = (res, key) => (res && res[key] !== undefined ? res : res?.data || res)

/** 單一使用者的權限一覽：{ user_id, username, management, connection }；範圍外台數在 connection.out_of_scope_asset_count（條件性）。 */
export const getPermissionOverview = async (userId) =>
  unwrap(await request({ url: `/users/${userId}/permission-overview`, method: 'get' }), 'management')

/**
 * 查一台資產：{ user_id, asset_id, manage, connect }。
 * 查無此資產（含檢視者看不到的資產）由呼叫端自行呈現，不 toast。
 */
export const probePermissionAsset = async (userId, assetId) =>
  unwrap(
    await request({
      url: `/users/${userId}/permission-overview/assets/${assetId}`,
      method: 'get',
      skipErrorToast: true,
    }),
    'manage',
  )

/** 查無此資產的錯誤碼（與資產不存在同形） */
export const PROBE_NOT_FOUND = 'NOTFOUND_ASSET'
