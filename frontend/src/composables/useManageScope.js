import { computed, unref } from 'vue'
import { useCapabilities } from '@/composables/useCapabilities'

/**
 * 頁首「你可管理」範圍行的來源解析。只讀伺服器投影，不走節點樹、不由權限集合推算。
 * 回傳 null＝不顯示此行；否則 { nodes: [...路徑], notAssigned: boolean }。
 */

/**
 * 能力狀態 scope_summary 中某權限點的節點範圍：
 * 沒有該點、或任一條目為全域，都不顯示；只有節點條目時列出其節點路徑聯集。
 */
export function lineFromScopeSummary(summary, perm) {
  if (!perm || !Array.isArray(summary)) return null
  const rows = summary.filter((e) => e && e.permission === perm)
  if (!rows.length || rows.some((e) => e.binding_scope !== 'nodes')) return null
  const nodes = []
  const seen = new Set()
  for (const e of rows) {
    for (const n of Array.isArray(e.nodes) ? e.nodes : []) {
      const key = Array.isArray(n?.path) ? n.path.join('\u0000') : String(n?.path ?? '')
      if (!key || seen.has(key)) continue
      seen.add(key)
      nodes.push(n.path)
    }
  }
  return nodes.length ? { nodes, notAssigned: false } : null
}

/** 資產列表回應的 management_scope（只對範圍化檢視者出現）。 */
export function lineFromManagementScope(ms) {
  if (!ms || typeof ms !== 'object') return null
  if (Number(ms.effective_node_count) === 0) return { nodes: [], notAssigned: true }
  const nodes = (Array.isArray(ms.nodes) ? ms.nodes : []).map((n) => n?.path).filter((p) => typeof p === 'string' && p !== '')
  return nodes.length ? { nodes, notAssigned: false } : null
}

/** perm 可為字串、ref 或 getter（資產授權管理頁依分頁切換）。 */
export function useManageScopeLine(perm) {
  const { scopeSummary } = useCapabilities()
  return computed(() => lineFromScopeSummary(scopeSummary.value, typeof perm === 'function' ? perm() : unref(perm)))
}
