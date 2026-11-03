/**
 * 「只有審核者角色」拒絕的機器碼與回應解析。
 * 直接指派三入口回 VALIDATION_ROLE_SET_APPROVER_ONLY（無參數）；
 * 群組三入口回 VALIDATION_USER_GROUP_APPROVER_ONLY_MEMBERS，params.count 為轉入總人數，
 * details.affected_users 為 [{ id, username }]（依 id 升冪，最多 20 筆）。
 * 這兩個碼由畫面就近呈現，不另外 toast。
 */
export const ROLE_SET_APPROVER_ONLY = 'VALIDATION_ROLE_SET_APPROVER_ONLY'
export const GROUP_APPROVER_ONLY = 'VALIDATION_USER_GROUP_APPROVER_ONLY_MEMBERS'

const bodyOf = (error) => {
  const data = error?.response?.data
  return data && typeof data.error === 'object' ? data.error : data
}

export const errorCodeOf = (error) => {
  const body = bodyOf(error)
  return body && typeof body.code === 'string' ? body.code : ''
}

export const isRoleSetApproverOnly = (error) => errorCodeOf(error) === ROLE_SET_APPROVER_ONLY
export const isGroupApproverOnly = (error) => errorCodeOf(error) === GROUP_APPROVER_ONLY

/**
 * 群組拒絕的人數與帳號清單；不是這個碼時回 null。
 * 人數缺漏或小於清單筆數時以清單筆數為準。
 */
export function groupApproverOnlyDetail(error) {
  if (!isGroupApproverOnly(error)) return null
  const data = error.response.data
  const body = bodyOf(error)
  const details = body?.details || data?.details || {}
  const list = Array.isArray(details.affected_users) ? details.affected_users : []
  const users = list
    .filter((u) => u && Number.isInteger(u.id) && typeof u.username === 'string')
    .map((u) => ({ id: u.id, username: u.username }))
  const raw = Number(body?.params?.count ?? data?.params?.count)
  const count = Number.isFinite(raw) && raw >= users.length ? raw : users.length
  return { count, users }
}
