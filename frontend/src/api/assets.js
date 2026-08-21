import request from './request'

/**
 * 取得資產列表
 * @param {Object} params - 查詢參數
 * @param {string} params.search - 搜尋關鍵字（名稱、主機）
 * @param {string} params.protocol - 協議過濾 (ssh/rdp/vnc)
 * @param {boolean} params.active - 啟用狀態過濾
 * @param {boolean} params.authorized_only - 只返回已授權資產
 * @param {number} params.page - 頁碼（從 1 開始）
 * @param {number} params.page_size - 每頁大小
 * @returns {Promise}
 */
export function getAssetList(params) {
  return request({
    url: '/assets',
    method: 'get',
    params,
  })
}

/**
 * 取得資產詳情
 * @param {number} id - 資產 ID
 * @returns {Promise}
 */
export function getAsset(id) {
  return request({
    url: `/assets/${id}`,
    method: 'get',
  })
}

/**
 * 列出 K8s 資產 namespace 內的活 pod（連線時選 pod）
 * @param {number} id - 資產 ID
 * @returns {Promise} { pods: [...] }
 */
export function listK8sPods(id) {
  return request({
    url: `/assets/${id}/k8s/pods`,
    method: 'get',
  })
}

/**
 * 上傳檔案到 K8s 容器（kubectl cp）
 * @param {number} id - 資產 ID
 * @param {FormData} formData - pod / container / dest_path / file
 * @returns {Promise} { path, size }
 */
export function uploadK8sFile(id, formData) {
  return request({
    url: `/assets/${id}/k8s/upload`,
    method: 'post',
    data: formData,
    headers: { 'Content-Type': 'multipart/form-data' },
  })
}

/**
 * 從 K8s 容器下載檔案（kubectl cp）
 * @param {number} id - 資產 ID
 * @param {Object} params - pod / container / path
 * @returns {Promise<Blob>}
 */
export function downloadK8sFile(id, params) {
  return request({
    url: `/assets/${id}/k8s/download`,
    method: 'get',
    params,
    responseType: 'blob',
    // 錯誤 body 是 Blob，全域攔截器讀不到 .error 會誤報「請求失敗」；
    // 由 caller 解析 blob 顯示後端精準訊息（避免雙 toast）
    skipErrorToast: true,
  })
}

/**
 * 創建資產
 * @param {Object} data - 資產資料
 * @param {string} data.name - 資產名稱
 * @param {string} data.protocol - 協議 (ssh/rdp/vnc)
 * @param {string} data.host - 主機位址
 * @param {number} data.port - 埠號
 * @param {string} data.username - 使用者名稱
 * @param {string} data.password - 密碼（選填）
 * @param {string} data.private_key - SSH 私鑰（選填）
 * @param {string} data.description - 描述
 * @param {string} data.tags - 標籤（逗號分隔）
 * @param {number} data.group_id - 分組 ID（選填）
 * @returns {Promise}
 */
export function createAsset(data) {
  return request({
    url: '/assets',
    method: 'post',
    data,
  })
}

/**
 * 更新資產
 * @param {number} id - 資產 ID
 * @param {Object} data - 更新資料（部分更新）
 * @returns {Promise}
 */
export function updateAsset(id, data) {
  return request({
    url: `/assets/${id}`,
    method: 'put',
    data,
  })
}

/**
 * 刪除資產
 * @param {number} id - 資產 ID
 * @returns {Promise}
 */
export function deleteAsset(id) {
  return request({
    url: `/assets/${id}`,
    method: 'delete',
  })
}

/**
 * 測試資產連線（db-protocol-connection-test 4.1）
 *
 * skipErrorToast：撥測失敗由 Assets.vue 以撥測語義呈現。走全域攔截器會把
 * 伺服端可正常服務的撥測失敗誤報成「網路錯誤」，叫使用者去查防火牆。
 * timeout：per-request 35 秒 > 後端逾時上界 30 秒。全域 10 秒會先於後端斷線，
 * 使已完成的撥測結果永遠取不到（逾時倒置）。
 * @param {number} id - 資產 ID
 * @returns {Promise}
 */
export function testAssetConnection(id) {
  return request({
    url: `/assets/${id}/test-connection`,
    method: 'post',
    skipErrorToast: true,
    timeout: 35000,
  })
}

/** 資產 host key 指紋（host-key-verification） */
export function getAssetHostKey(id) {
  return request({ url: `/assets/${id}/host-key`, method: 'get', skipErrorToast: true })
}

/** 重置資產 host key（admin，主機重灌後） */
export function resetAssetHostKey(id) {
  return request({ url: `/assets/${id}/host-key`, method: 'delete' })
}

/** 節點平面列表（asset-node-tree：含 parent_id/path/直掛 assets） */
export function getAssetGroups() {
  return request({ url: '/asset-groups', method: 'get' })
}

/** 節點樹惰性載入（parent_id 空＝根層；含直掛/含子樹計數與 has_children） */
export function getAssetNodeTree(parentId) {
  const params = {}
  if (parentId != null) params.parent_id = parentId
  return request({ url: '/asset-groups/tree', method: 'get', params })
}

/** 建立節點（admin；parent_id 空＝根節點，深度上限 10、同層同名 409） */
export function createAssetGroup(data) {
  return request({ url: '/asset-groups', method: 'post', data })
}

/** 更新節點名稱/描述（admin；位置不動，搬移走 moveAssetGroup） */
export function updateAssetGroup(id, data) {
  return request({ url: `/asset-groups/${id}`, method: 'put', data })
}

/** 搬移節點（admin；parent_id null＝搬到根層；環路/深度/同名由後端驗證） */
export function moveAssetGroup(id, parentId) {
  return request({ url: `/asset-groups/${id}/move`, method: 'put', data: { parent_id: parentId } })
}

/** 刪除節點（admin；僅空節點可刪，節點授權與審核範圍連動撤銷） */
export function deleteAssetGroup(id) {
  return request({ url: `/asset-groups/${id}`, method: 'delete' })
}

/**
 * 取得既有標籤清單（authz-tag-node-filters D3）：canonical 去重＋使用數，
 * 供篩選下拉、表單自動完成與治理介面共用；僅 admin/auditor
 * @returns {Promise} { data: [{ name, count }] }
 */
export function getAssetTags() {
  return request({
    url: '/assets/tags',
    method: 'get',
  })
}

/**
 * 標籤全面改名（D8）：from→to 套用至所有含 from 的資產；to 既存即合併。admin only
 * @returns {Promise} { affected }
 */
export function renameAssetTag(from, to) {
  return request({
    url: '/assets/tags/rename',
    method: 'post',
    data: { from, to },
  })
}

/**
 * 標籤全面刪除（D8）：自所有資產移除。admin only
 * @returns {Promise} { affected }
 */
export function deleteAssetTag(name) {
  return request({
    url: '/assets/tags/delete',
    method: 'post',
    data: { name },
  })
}
