import request from './request'

/**
 * 角色定義 API。讀取需要角色檢視能力；寫入是否為超級管理者由後端裁決。
 * 寫入本文只送各函式註明的欄位，不夾帶範圍或節點欄位。
 */

/** 角色列表：{ data: [...], total, can_define } */
export const listRoleDefinitions = () => request({ url: '/role-definitions', method: 'get' })

/** 編輯描述：{ entries, capabilities, fixed_entries } */
export const getRoleDescriptors = () => request({ url: '/role-definitions/descriptors', method: 'get' })

/** 單筆角色（含權限鍵、版本、摘要、缺依賴） */
export const getRoleDefinition = (id) => request({ url: `/role-definitions/${id}`, method: 'get' })

/** 草稿摘要（不寫入）：本文恰為 { permissions } */
export const summarizeRoleDraft = (permissions) =>
  request({ url: '/role-definitions/summary', method: 'post', data: { permissions }, skipErrorToast: true })

/** 新增：{ name, description, permissions, template_role_id? }；無範本時不送 template_role_id */
export const createRoleDefinition = ({ name, description, permissions, templateRoleId }) => {
  const data = { name, description, permissions }
  if (templateRoleId) data.template_role_id = templateRoleId
  return request({ url: '/role-definitions', method: 'post', data, skipErrorToast: roleErrorHandledByCaller })
}

/** 複製：本文恰為 { name } */
export const copyRoleDefinition = (id, name) =>
  request({ url: `/role-definitions/${id}/copy`, method: 'post', data: { name } })

/** 修改：{ name, description, permissions, expected_version } */
export const updateRoleDefinition = (id, { name, description, permissions, expectedVersion }) =>
  request({
    url: `/role-definitions/${id}`,
    method: 'put',
    data: { name, description, permissions, expected_version: expectedVersion },
    skipErrorToast: roleErrorHandledByCaller,
  })

/** 刪除：無本文，期望版本走查詢參數 */
export const deleteRoleDefinition = (id, expectedVersion) =>
  request({
    url: `/role-definitions/${id}`,
    method: 'delete',
    params: { expected_version: expectedVersion },
    skipErrorToast: roleErrorHandledByCaller,
  })

/** 版本衝突與使用中由頁面自行呈現，其餘錯誤照常 toast */
export const ROLE_ERROR_CONFLICT = 'ROLE_DEFINITION_CONFLICT'
export const ROLE_ERROR_IN_USE = 'ROLE_DEFINITION_IN_USE'
function roleErrorHandledByCaller(error) {
  const data = error?.response?.data
  const body = data && typeof data.error === 'object' ? data.error : data
  const code = body && typeof body.code === 'string' ? body.code : ''
  return code === ROLE_ERROR_CONFLICT || code === ROLE_ERROR_IN_USE
}

/** 影響預覽（建議性）：失敗不 toast，由呼叫端標示「暫時無法取得」 */
export const previewRoleAssignment = (body) =>
  request({ url: '/role-assignment-previews', method: 'post', data: body, skipErrorToast: true })

export const roleErrorCode = (error) => {
  const data = error?.response?.data
  const body = data && typeof data.error === 'object' ? data.error : data
  return body && typeof body.code === 'string' ? body.code : ''
}

/**
 * 管理者指派集的整組替換：本文為 { manual_roles }，只在有改動範圍的角色時多帶 role_nodes
 * （鍵為角色名稱；null 改回全系統、陣列為節點 ID；未列出的角色保留現有範圍）。
 * 受保護角色與範圍相關的已知錯誤由頁面就地呈現該碼的譯文，不另外 toast。
 */
const ASSIGN_INLINE_CODES = new Set([
  'AUTH_PROTECTED_ROLE_ASSIGNMENT',
  'VALIDATION_ROLE_BINDING_NODES_EMPTY',
  'VALIDATION_ROLE_BINDING_NODES_INVALID',
  'VALIDATION_ROLE_NOT_NODE_SCOPABLE',
])
export const assignManualRoles = (userId, manualRoles, roleNodes) => {
  const data = { manual_roles: manualRoles }
  if (roleNodes && Object.keys(roleNodes).length > 0) data.role_nodes = roleNodes
  return request({
    url: `/users/${userId}/roles`,
    method: 'put',
    data,
    skipErrorToast: (error) => ASSIGN_INLINE_CODES.has(roleErrorCode(error)),
  })
}

/** 指派用的節點清單與角色可限定節點的判定；只對持有指派角色權限者開放 */
export const getRoleAssignmentOptions = () =>
  request({ url: '/role-assignment-options', method: 'get', skipErrorToast: true })

/** 使用者的角色指派與節點範圍（每列 role_id、role_name、source，節點範圍列多 node_ids） */
export const getUserRoleBindings = (userId) =>
  request({ url: `/users/${userId}/role-bindings`, method: 'get', skipErrorToast: true })
