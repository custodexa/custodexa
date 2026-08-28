/**
 * 來源位址／允許網段的**格式層**輔助。
 *
 * 這裡刻意只做「看起來像不像位址或網段」的就近提示。
 * **判定權在後端**：正規化（IPv6 縮寫、IPv4-mapped 還原、遮罩去主機位元）、
 * 有效涵蓋狀態、以及「某個來源落不落入清單」一律由
 * `POST /users/source-policy/check` 與各強制點的同一份實作回答。
 * 前端自己解析 CIDR 必與強制點分歧，而分歧的那一側正是自鎖警告會說錯話的地方。
 *
 * 判準方向是**寬鬆**：前端可以放過後端會拒的（例如 `10.0.0.999/24`，
 * 送出後由端點回 `invalid` 就近顯示），但不可擋下後端會收的——擋錯的那一項
 * 使用者連送都送不出去，而畫面不會告訴他其實是合法的。
 * 共用測試向量（`backend/internal/sourceip/testdata/policy_vectors.json`）
 * 對此方向逐條把關。
 */

/** 每個帳號的清單上限（與後端 `sourceip` 同值；超過由端點回 `too_many`） */
export const SOURCE_POLICY_MAX_ENTRIES = 32

/** 允許網段清單的三種有效涵蓋狀態（伺服端衍生，前端只消費不推算） */
export const SOURCE_POLICY_STATUS = {
  UNRESTRICTED: 'unrestricted',
  EFFECTIVELY_UNRESTRICTED: 'effectively_unrestricted',
  RESTRICTED: 'restricted',
}

// 純位址（不帶前綴長度）。IPv6 允許 zone（`fe80::1%eth0`）與 IPv4-mapped 寫法
const IPV4_LIKE = /^\d{1,3}(?:\.\d{1,3}){3}$/
// 冒號刻意不放進段內字元集：若段內也能吃冒號，同一個輸入就有多種分割方式，
// 引擎必須逐一回溯，耗時隨長度呈平方成長（實測 n=8000 時約 200ms）。
// 改為「不含冒號的段」以冒號串接後，每個冒號只有一種消費方式，耗時回到線性。
// 判定結果與先前完全相同（見 sourcePolicyFormat.spec.js 的差分表）——
// 本式的語義一如函式名，是「看起來像不像位址」而非嚴格驗證，故 `:`／`::::`
// 這類非合法位址仍為接受，改寫不得順手收緊。
const IPV6_LIKE = /^[0-9A-Fa-f.]*(?::[0-9A-Fa-f.]*)+(?:%[0-9A-Za-z._-]+)?$/

/**
 * 看起來像不像一個位址（不接受前綴長度）。工作台的位址樞紐自由輸入用。
 * @param {string} value
 * @returns {boolean}
 */
export function looksLikeSourceAddress(value) {
  const v = typeof value === 'string' ? value.trim() : ''
  if (!v) return false
  return IPV4_LIKE.test(v) || IPV6_LIKE.test(v)
}

/**
 * 看起來像不像一個位址或網段（裸位址視為單一主機，前綴長度可省略）。
 * 使用者表單的清單項目用。
 * @param {string} value
 * @returns {boolean}
 */
export function looksLikeSourcePrefix(value) {
  const v = typeof value === 'string' ? value.trim() : ''
  if (!v) return false
  const slash = v.lastIndexOf('/')
  if (slash < 0) return looksLikeSourceAddress(v)
  const host = v.slice(0, slash)
  const bits = v.slice(slash + 1)
  // 前綴長度只驗「是不是十進位數字」；上界（IPv4 32／IPv6 128）由後端判，
  // 前端多擋一層只會在 IPv6 的合法長度上誤判
  if (!/^\d{1,3}$/.test(bits)) return false
  return looksLikeSourceAddress(host)
}

/**
 * 把後端回的位址家族陣列收斂成一個文案鍵尾碼。
 * 三句分寫而非以分隔符拼接家族名：各語言的並列連接詞不同，
 * 拼接會在其中一語產出讀不通的句子。
 * @param {Array<string>|undefined} families `['v4']`／`['v6']`／兩者
 * @returns {'v4'|'v6'|'both'|''}
 */
export function sourceFamiliesKey(families) {
  const list = Array.isArray(families) ? families : []
  const v4 = list.includes('v4')
  const v6 = list.includes('v6')
  if (v4 && v6) return 'both'
  if (v4) return 'v4'
  if (v6) return 'v6'
  return ''
}
