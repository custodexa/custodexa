// 連線政策段位的比較（與後端 policy.EffectiveTier／ClassifyOverrideChange 同一套規則）。
// 前端判斷只是提示：降級確認用它決定要不要問一次，告警與審計一律以後端為準。

/** 單台覆寫可權限點：存取政策權限點（完整鍵比對，不看角色名） */
export const ACCESS_POLICY_PERM = 'access_policy:manage'

const RANK = Object.freeze({ open: 0, reason: 1, approval: 2 })

export const isValidTier = (v) => Object.prototype.hasOwnProperty.call(RANK, v)

/**
 * 判斷單台覆寫變更是否為降級。
 * before／after 為覆寫值（'' 或 null 表示跟隨全域）；globalDefault 為已知的全域預設，
 * 讀不到（非設定組主體、讀取失敗）時傳空值。
 *
 * 全域預設未知時：清除覆寫一律視為需要確認（unknownDefault=true）；
 * 從跟隨全域改為明確的 open／reason 也無法排除降級，同樣確認。寧可多問一次，也不漏問。
 *
 * @returns {{ downgrade: boolean, unknownDefault: boolean, from: string|null, to: string|null }}
 */
export function classifyOverrideChange(before, after, globalDefault) {
  const b = isValidTier(before) ? before : ''
  const a = isValidTier(after) ? after : ''
  const none = { downgrade: false, unknownDefault: false, from: null, to: null }
  if (a === b) return none
  const known = isValidTier(globalDefault)
  const effective = (v) => (v !== '' ? v : known ? globalDefault : null)
  const from = effective(b)
  const to = effective(a)
  if (from !== null && to !== null) {
    return { downgrade: RANK[to] < RANK[from], unknownDefault: false, from, to }
  }
  // 全域預設未知：只要有可能降級就問
  const mayLower = a === '' ? true : a !== 'approval'
  return { downgrade: mayLower, unknownDefault: mayLower, from, to }
}
