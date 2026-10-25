// 角色編輯器：入口狀態的判定。
//
// 入口的態取「集合完整涵蓋的最高態」；未涵蓋管理態全部鍵、卻持有該入口任一寫入鍵者為部分管理。
// 寫入鍵由伺服器在編輯描述的 write_keys 給出，前端不自行推導。

export const PARTIAL = 'partial'

// perms 為 Set<string>。
export function entryStateOf(entry, perms) {
  let cur = entry.states[0].name
  for (const s of entry.states.slice(1)) {
    if (s.keys.length && s.keys.every((k) => perms.has(k))) cur = s.name
  }
  if (cur !== 'manage' && (entry.write_keys || []).some((k) => perms.has(k))) return PARTIAL
  return cur
}

// 切換其他入口時要保留的鍵。完整態：該態的集合；部分管理：各態鍵的聯集與已持有者的交集
// （它實際持有的唯讀鍵、寫入鍵與借用的依賴鍵）。
export function protectedKeysOf(entry, perms) {
  const name = entryStateOf(entry, perms)
  if (name === PARTIAL) {
    const held = new Set()
    for (const s of entry.states) for (const k of s.keys) if (perms.has(k)) held.add(k)
    return [...held]
  }
  const cur = entry.states.find((s) => s.name === name)
  return cur ? cur.keys : []
}

// 細項以不重複的權限鍵計：多個細項共用同一個鍵時只算一次。
export function distinctDetailCount(entry, perms) {
  const keys = new Set((entry.details || []).map((d) => d.key))
  let n = 0
  for (const k of keys) if (perms.has(k)) n += 1
  return { n, m: keys.size }
}

// 與細項 d 共用同一個權限鍵、且排在它前面的細項（沒有則回 null）。
export function sharedKeyDetailOf(entry, d) {
  const list = entry.details || []
  const idx = list.findIndex((x) => x.id === d.id)
  for (let i = 0; i < idx; i += 1) {
    if (list[i].key === d.key) return list[i]
  }
  return null
}

// 把入口 e 切到態 name，回傳新的權限集合：其他入口目前持有的鍵（含部分管理入口實際持有者）
// 與獨立能力的鍵一律保留，只移除 e 自己各態中沒人需要的鍵。
export function applyEntryState(entries, perms, e, name, capabilityKeys) {
  const protect = new Set(capabilityKeys)
  for (const o of entries) {
    if (o.id === e.id) continue
    protectedKeysOf(o, perms).forEach((k) => protect.add(k))
  }
  const next = new Set(perms)
  for (const s of e.states) {
    for (const k of s.keys) if (!protect.has(k)) next.delete(k)
  }
  e.states.find((s) => s.name === name).keys.forEach((k) => next.add(k))
  return next
}
