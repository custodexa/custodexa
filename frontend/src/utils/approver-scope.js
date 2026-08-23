/**
 * 審核範圍條目顯示唯一事實源。
 * 值域硬拷後端 model/approver_scope.go（審核方恰一：approver_id/approver_group_id；
 * 客體四維恰一：asset_id/asset_group_id/subject_user_id/subject_group_id）；
 * 完備性由 approver-scope.spec.js 釘住——後端加維度時此處補一筆，
 * 矩陣頁與 Users 對話框同步連動，勿在頁面手寫 map。
 */

import { computed } from 'vue'
import { t } from '@/i18n'

// 譯文住 locale 檔 enum.scopeType/actorType.*，getter 回 t()
const typeMeta = (ns, value, tagType) => ({
  tagType,
  get label() {
    return t(`enum.${ns}.${value}`)
  },
})

export const SCOPE_TYPES = {
  asset: typeMeta('scopeType', 'asset', 'primary'),
  asset_group: typeMeta('scopeType', 'asset_group', 'warning'),
  subject_user: typeMeta('scopeType', 'subject_user', 'success'),
  subject_group: typeMeta('scopeType', 'subject_group', 'info'),
}

/** 審核方型別（個人 XOR 使用者群組） */
export const ACTOR_TYPES = {
  user: typeMeta('actorType', 'user', 'primary'),
  group: typeMeta('actorType', 'group', 'warning'),
}

/** 審核方型別鍵（審核方恰一，後端 CHECK 保證） */
export const actorType = (scope) => (scope.approver_group_id ? 'group' : 'user')

/** 審核方顯示（個人 username／群組名；查無回 #id 誠實降級） */
export const actorLabel = (scope) => {
  if (scope.approver_group_id) {
    return scope.approver_group?.name || `#${scope.approver_group_id}`
  }
  return scope.approver?.username || `#${scope.approver_id}`
}

/** 範圍條目的維度鍵（四維恰一，後端 CHECK 保證） */
export const scopeType = (scope) => {
  if (scope.asset_id) return 'asset'
  if (scope.asset_group_id) return 'asset_group'
  if (scope.subject_user_id) return 'subject_user'
  return 'subject_group'
}

export const scopeTypeLabel = (scope) => SCOPE_TYPES[scopeType(scope)]?.label || '—'
export const scopeTypeTagType = (scope) => SCOPE_TYPES[scopeType(scope)]?.tagType || 'info'

/**
 * buildGroupPaths 節點 id → 全路徑（如「prod / db」）：前端由 parent_id 自組，
 * 解決同名節點不可分辨。環路防禦：深度上限 20
 */
export const buildGroupPaths = (groups) => {
  const byId = new Map((groups || []).map((g) => [g.id, g]))
  const paths = {}
  for (const g of groups || []) {
    const parts = []
    let cur = g
    let depth = 0
    while (cur && depth < 20) {
      parts.unshift(cur.name)
      cur = cur.parent_id ? byId.get(cur.parent_id) : null
      depth++
    }
    paths[g.id] = parts.join(' / ')
  }
  return paths
}

/** 範圍客體顯示（節點帶全路徑；查無名稱時回 #id 誠實降級） */
export const scopeTargetLabel = (scope, groupPaths = {}) => {
  switch (scopeType(scope)) {
    case 'asset':
      return scope.asset?.name || `#${scope.asset_id}`
    case 'asset_group':
      return groupPaths[scope.asset_group_id] || scope.asset_group?.name || `#${scope.asset_group_id}`
    case 'subject_user':
      return scope.subject_user?.username || `#${scope.subject_user_id}`
    default:
      return scope.subject_group?.name || `#${scope.subject_group_id}`
  }
}

/**
 * 範圍語義說明（矩陣頁與 Users 對話框共用同文案，spec「一致文案明示範圍語義」）。
 * computed 供 <script setup> 頂層 import 後模板自動解包，切語言即時重算
 */
export const SCOPE_SEMANTICS_LINES = computed(() => [
  t('approverScope.semantics1'),
  t('approverScope.semantics2'),
  t('approverScope.semantics3'),
  t('approverScope.semantics4'),
  t('approverScope.semantics5'),
])
