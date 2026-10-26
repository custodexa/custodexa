import { te } from '@/i18n'

/**
 * 「建立群組並設定角色與範圍」三個寫入的結果判讀。
 *
 * 失敗不等於沒有寫入：提交之後才組回應的路徑、逾時與回應遺失都可能讓寫入已生效。
 * 所以「確定被拒絕」只認下表（每個寫入一組狀態加錯誤碼，皆為交易提交之前就回應、
 * 依現行伺服器可證明沒有留下寫入者）；表外的任何失敗一律是「結果未確認」，要先讀回核對。
 * 日後伺服器新增錯誤碼或改動提交後的路徑，須重新指認後才可加入此表。
 */
export const WRITE_GROUP = 'group'
export const WRITE_ROLES = 'roles'
export const WRITE_RULE = 'rule'

const PERMISSION = [403, 'AUTH_PERMISSION_DENIED']

// 映射規則的清單刻意收窄：只收可證明沒有留下寫入的碼。清單外的碼（含指派規則的其他拒絕碼）
// 一律先核對再判讀，方向保守：最多多讀一次，不會把可能已寫入的情形判成被拒絕。不要為了對齊而擴清單。
const REJECTED = {
  [WRITE_GROUP]: [
    PERMISSION,
    [400, 'VALIDATION_BAD_PARAMS'],
    [409, 'CONFLICT_USER_GROUP_NAME_EXISTS'],
  ],
  [WRITE_ROLES]: [
    PERMISSION,
    [400, 'VALIDATION_INVALID_ID'],
    [400, 'VALIDATION_BAD_PARAMS'],
    [404, 'NOTFOUND_USER_GROUP'],
    [400, 'VALIDATION_ROLE_NOT_FOUND'],
    [400, 'VALIDATION_ROLE_NOT_GROUP_BINDABLE'],
    [403, 'AUTH_PROTECTED_ROLE_ASSIGNMENT'],
    [400, 'VALIDATION_ROLE_BINDING_SCOPE_UNSUPPORTED'],
    [400, 'VALIDATION_ROLE_NOT_NODE_SCOPABLE'],
    [400, 'VALIDATION_ROLE_BINDING_NODES_EMPTY'],
    [400, 'VALIDATION_ROLE_BINDING_NODES_INVALID'],
  ],
  [WRITE_RULE]: [
    PERMISSION,
    [400, 'VALIDATION_INVALID_ID'],
    [400, 'VALIDATION_BAD_REQUEST'],
    [400, 'MAPPING_SCOPE_FIELD_REJECTED'],
    [400, 'VALIDATION_BAD_PARAMS'],
    [400, 'VALIDATION_MAPPING_MATCH_VALUE_DN'],
    [404, 'NOTFOUND_LDAP_DIRECTORY'],
    [404, 'NOTFOUND_OIDC_PROVIDER'],
    [404, 'NOTFOUND_USER_GROUP'],
    [403, 'AUTH_PROTECTED_ROLE_ASSIGNMENT'],
    [400, 'VALIDATION_EXTERNAL_GROUP_NOTE_TOO_LONG'],
  ],
}

/** 取出 HTTP 狀態與機器碼（頂層與包在 error 物件內兩種外框都認）；沒有回應時狀態為 0 */
export function errorInfo(error) {
  const status = Number(error?.response?.status) || 0
  const data = error?.response?.data
  const nested = data && typeof data === 'object' ? data.error : null
  const body = nested && typeof nested === 'object' ? nested : data
  const code = body && typeof body === 'object' && typeof body.code === 'string' ? body.code : ''
  const meta = (body && typeof body === 'object' && body.meta) || {}
  return { status, code, meta }
}

/** 判讀一次寫入失敗：'rejected'（確定沒有寫入）或 'unconfirmed'（結果未確認，先核對） */
export function classifyWriteFailure(write, error) {
  const { status, code } = errorInfo(error)
  const table = REJECTED[write] || []
  const rejected = table.some(([s, c]) => s === status && c === code)
  return { kind: rejected ? 'rejected' : 'unconfirmed', status, code }
}

/** 錯誤碼對應的既有文字；沒有對應時回 null，由呼叫端用通用失敗句 */
export function apiErrorText(code, t) {
  const key = `apiError.${code}`
  return code && te(key) ? t(key) : null
}

/**
 * 讀回的角色指派與送出的是否相同：角色集合相同，且每個角色的範圍種類與節點集合相同。
 * 送出的範圍：roleNodes 有該角色的鍵時 null 為全系統、陣列為節點；沒有鍵時沿用編輯器基底
 * （baseline：回第 2 步改選時帶入的讀回指派）裡該角色的原範圍，基底也沒有該角色（新群組沒有舊範圍）則為全系統。
 */
export function sameAssignment(readBack, roleIds, roleNodes, baseline = []) {
  const base = new Map((baseline || []).map((b) => [b.role_id, b]))
  const back = new Map((readBack || []).map((b) => [b.role_id, b]))
  if (back.size !== roleIds.length || !roleIds.every((id) => back.has(id))) return false
  return roleIds.every((id) => {
    const b = back.get(id)
    const hasKey = roleNodes && Object.prototype.hasOwnProperty.call(roleNodes, String(id))
    const origin = base.get(id)
    const sent = hasKey ? roleNodes[String(id)] : origin?.scope === 'nodes' ? origin.node_ids || [] : null
    const sentNodes = Array.isArray(sent) ? [...sent].sort((x, y) => x - y) : null
    const readNodes = b.scope === 'nodes' ? [...(b.node_ids || [])].sort((x, y) => x - y) : null
    if (sentNodes === null || readNodes === null) return sentNodes === null && readNodes === null
    return sentNodes.length === readNodes.length && sentNodes.every((v, i) => v === readNodes[i])
  })
}
