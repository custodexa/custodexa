/**
 * 群組是否帶有「只有超級管理者能增減」的角色：交叉 role-bindings 與角色定義列表的
 * assignment_state（伺服器依操作者算出的分類）。回傳第一個受保護角色的名稱，沒有則為空字串。
 * 只讀伺服器下發的分類，不以角色名或操作者身分判斷。
 */
export function protectedRoleOf(bindings, definitions) {
  const byId = new Map((definitions || []).map((d) => [d.id, d]))
  for (const b of bindings || []) {
    const def = byId.get(b.role_id)
    if (def && def.assignment_state === 'protected') return def.name
  }
  return ''
}

/** 群組綁定中屬管理類的角色名稱（依角色定義的 management_class） */
export function managementRoleNames(roleIds, definitions) {
  const byId = new Map((definitions || []).map((d) => [d.id, d]))
  return (roleIds || [])
    .map((id) => byId.get(id))
    .filter((d) => d && d.management_class)
    .map((d) => d.name)
}
