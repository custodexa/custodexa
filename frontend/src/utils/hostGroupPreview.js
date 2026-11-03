// 「主機特權群組（POSIX）」政策值的解析預覽：只供畫面呈現，權威驗證在後端。
// 規則與後端同一口徑：以逗號切分、去首尾空白、略過空項與重複；
// 單項不得含冒號或控制字元、不得超過 256 位元組；項數上限 32。

export const GROUP_LIST_MAX_ITEMS = 32
export const GROUP_NAME_MAX_BYTES = 256
export const HOST_GROUPS_POLICY_KEY = 'host_privileged_groups_posix'

const CONTROL_RE = /\p{Cc}/u
const encoder = new TextEncoder()

/**
 * @param {string} raw 編輯中的原始值
 * @returns {{items: Array<{name: string, problem: ''|'colon'|'badChar'|'tooLong'|'overLimit'}>, rejected: boolean}}
 */
export function parseGroupList(raw) {
  const seen = new Set()
  const items = []
  for (const part of String(raw ?? '').split(',')) {
    const name = part.trim()
    if (name === '' || seen.has(name)) continue
    seen.add(name)
    let problem = ''
    if (name.includes(':')) problem = 'colon'
    else if (CONTROL_RE.test(name)) problem = 'badChar'
    else if (encoder.encode(name).length > GROUP_NAME_MAX_BYTES) problem = 'tooLong'
    else if (items.length >= GROUP_LIST_MAX_ITEMS) problem = 'overLimit'
    items.push({ name, problem })
  }
  // 超過項數上限時，後端以整體退回；前端把超出的項標警示
  if (items.length > GROUP_LIST_MAX_ITEMS) {
    for (let i = GROUP_LIST_MAX_ITEMS; i < items.length; i++) {
      if (!items[i].problem) items[i].problem = 'overLimit'
    }
  }
  return { items, rejected: items.some((x) => x.problem !== '') }
}
