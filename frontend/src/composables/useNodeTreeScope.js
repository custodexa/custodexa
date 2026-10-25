// 節點樹的列級旗標呈現規則。
// 回應帶旗標（範圍化檢視者）時，選單逐項依 can_* 決定；沒有旗標時沿用既有的
// 單一能力判斷。這裡只決定「顯示什麼、停用原因是什麼」，授權仍由伺服器判定。

/** 節點是否帶列級旗標（只有範圍化檢視者的回應才有） */
export const hasRowFlags = (node) => typeof node?.can_rename === 'boolean'

const ACTIONS = [
  { command: 'create-child', flag: 'can_create_child', lockable: false },
  { command: 'rename', flag: 'can_rename', lockable: true },
  { command: 'move', flag: 'can_move', lockable: true },
  { command: 'delete', flag: 'can_delete', lockable: true },
]

/**
 * 逐項的呈現狀態。
 * - 旗標為 true：可用。
 * - 旗標為 false 且是自己的範圍根：停用，原因為範圍根限制。
 * - 旗標為 false 但節點在管理可視內：停用，原因為限超級管理者。
 * - 其餘（例如只作為上層路徑出現的節點）：不顯示該項。
 * 新增子節點沒有範圍根限制，旗標為 false 時不顯示。
 */
export const scopedActionStates = (node) => {
  const states = {}
  for (const { command, flag, lockable } of ACTIONS) {
    if (node[flag] === true) {
      states[command] = { visible: true, disabled: false, reason: '' }
    } else if (!lockable) {
      states[command] = { visible: false, disabled: true, reason: '' }
    } else if (node.scope_root === true) {
      states[command] = { visible: true, disabled: true, reason: 'nodeTree.scopeRootLocked' }
    } else if (node.manageable === true) {
      states[command] = { visible: true, disabled: true, reason: 'nodeTree.superAdminOnly' }
    } else {
      states[command] = { visible: false, disabled: true, reason: '' }
    }
  }
  return states
}

/** 四項動作旗標是否至少一項為 true（全為 false 時不顯示選單） */
export const hasAnyAction = (node) => ACTIONS.some(({ flag }) => node[flag] === true)

/**
 * 搬移目的候選：列帶 can_create_child 旗標時只列其為 true 的節點，
 * 無此旗標的列（非範圍化檢視者）全部保留。最終仍由伺服器判定。
 */
export const filterMoveCandidates = (flat) =>
  flat.filter((n) => typeof n.can_create_child !== 'boolean' || n.can_create_child === true)
