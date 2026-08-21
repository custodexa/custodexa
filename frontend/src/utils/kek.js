// 本地 KEK 材料的前端生成、解碼與格式檢查（kek-provider-modularization D8 路 2、
// kek-encoding-and-unseal-entry）。
//
// **前端檢查是輸入輔助，不是把關**：伺服端 crypto.DecodeKEKMaterial／
// crypto.ValidateKEKMaterialFormat／config.ValidateKEKMaterial 才是唯一權威
// （另含出廠預設值與指紋碰撞等本端無從判定的規則）。本檔的存在理由是讓使用者在
// 送出前就看得到「哪裡不合格」，而非讓呼叫端據此宣稱材料已合格。
//
// 誠實界定（沿伺服端同一措辭）：格式檢查是降低常見弱值風險的務實手段，
// 系統不宣稱能由單一值驗證其熵。
//
// **「輸入編碼」與「金鑰」是兩件事**：KEK 是一把 32 **位元組**的金鑰，
// 它可以用三種寫法輸入。判定規則逐條對齊伺服端 pkg/crypto/kek_material.go，
// 兩端不得各自漂移。

// 原字元形態的字元集與金鑰長度（位元組），須與伺服端
// crypto.KEKAlphabet／crypto.KEKMaterialLength 逐字一致。
export const KEK_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
export const KEK_LENGTH = 32

// 三種形態解出 32 位元組所需的輸入長度。三者互斥，故判定順序不影響任何輸入的結果
// （base64 解出 32 位元組只能是 43／44；hex 只能是 64；原字元固定 32）。
const HEX_LENGTH = KEK_LENGTH * 2
const B64_RAW_LENGTH = 43
const B64_PADDED_LENGTH = 44

export const KEK_FORM_RAW = 'raw'
export const KEK_FORM_HEX = 'hex'
export const KEK_FORM_BASE64 = 'base64'

// 拒絕取樣的上界：256 - (256 % 62) = 248。>= 248 的位元組一律丟棄後重抽，
// 使 62 個字元等機率——直接取模會讓前 8 個字元多出約 1.6% 機率（模偏差）。
const REJECTION_LIMIT = 256 - (256 % KEK_ALPHABET.length)

/**
 * 以 CSPRNG 生成一把本地 KEK 材料（32 字元、A-Za-z0-9＝原字元形態）。
 * 僅使用 crypto.getRandomValues；不可用時直接拋錯，**不得**退回 Math.random——
 * 靜默降級為可預測隨機源正是本函式要防的失敗模式。
 * @returns {string}
 */
export function generateKEKMaterial() {
  const rng = globalThis.crypto
  if (!rng || typeof rng.getRandomValues !== 'function') {
    throw new Error('瀏覽器未提供 crypto.getRandomValues，無法在本機生成 KEK')
  }
  const out = []
  const buf = new Uint8Array(KEK_LENGTH * 2)
  while (out.length < KEK_LENGTH) {
    rng.getRandomValues(buf)
    for (const byte of buf) {
      if (byte >= REJECTION_LIMIT) continue
      out.push(KEK_ALPHABET[byte % KEK_ALPHABET.length])
      if (out.length === KEK_LENGTH) break
    }
  }
  return out.join('')
}

const utf8 = new TextEncoder()

const HEX_RE = /^[0-9a-fA-F]+$/
const B64_STD_RE = /^[A-Za-z0-9+/]+=*$/
const B64_URL_RE = /^[A-Za-z0-9\-_]+=*$/

function hexToBytes(s) {
  const out = new Uint8Array(s.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function bytesToBase64(bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

/**
 * 嚴格 base64 解碼：接受標準與 URL-safe 兩套字母表、接受有無 padding，
 * 但**拒絕混用字母表**、拒絕 padding 數量不合、拒絕非規範編碼（多餘位元非零）。
 *
 * 非規範編碼以「重新編碼後逐字比對」判定——比逐位元檢查最末量子更難寫錯，
 * 且與伺服端 base64 的 Strict 模式同語義。
 * @returns {Uint8Array|null}
 */
function decodeBase64Strict(s) {
  let normalized
  if (B64_STD_RE.test(s)) normalized = s
  else if (B64_URL_RE.test(s)) normalized = s.replace(/-/g, '+').replace(/_/g, '/')
  else return null // 混用兩套字母表：不是任何一種編碼的輸出

  // 32 位元組的 base64 恰為 43 字元（無 padding）或 44 字元（一個 `=`）
  if (s.length === B64_PADDED_LENGTH && !/^[^=]{43}=$/.test(normalized)) return null
  if (s.length === B64_RAW_LENGTH && normalized.includes('=')) return null

  const padded = s.length === B64_RAW_LENGTH ? `${normalized}=` : normalized
  let bin
  try {
    bin = atob(padded)
  } catch {
    return null
  }
  if (bin.length !== KEK_LENGTH) return null
  const out = new Uint8Array(KEK_LENGTH)
  for (let i = 0; i < KEK_LENGTH; i += 1) out[i] = bin.charCodeAt(i)
  // 規範性：重新編碼必須得回同一份標準字母表寫法
  if (bytesToBase64(out) !== padded) return null
  return out
}

/**
 * 把輸入的 KEK 材料解為 32 位元組金鑰。判定順序與伺服端逐條一致：
 *
 *   1. 恰 32 位元組（**不 trim**）→ 原樣即金鑰；
 *   2. trim 後恰 32 位元組 → 原樣即金鑰；
 *   3. trim 後恰 64 個十六進位字元 → 解碼；
 *   4. trim 後 43／44 個字元的 base64 → 解碼，且結果須恰 32 位元組。
 *
 * 第 1 步刻意不 trim：伺服端有兩個入口接受任意 32 位元組（其中可含前後空白），
 * 先 trim 會把那種材料削成 31 位元組。
 *
 * @param {string} material
 * @returns {{key: Uint8Array|null, form: string, reason: '' | 'empty' | 'format'}}
 */
export function decodeKEKMaterial(material) {
  const value = material ?? ''
  const raw = utf8.encode(value)
  if (raw.length === KEK_LENGTH) return { key: raw, form: KEK_FORM_RAW, reason: '' }

  const s = value.trim()
  if (!s) return { key: null, form: '', reason: 'empty' }

  const trimmed = utf8.encode(s)
  if (trimmed.length === KEK_LENGTH) return { key: trimmed, form: KEK_FORM_RAW, reason: '' }

  if (s.length === HEX_LENGTH && HEX_RE.test(s)) {
    return { key: hexToBytes(s), form: KEK_FORM_HEX, reason: '' }
  }
  if (s.length === B64_RAW_LENGTH || s.length === B64_PADDED_LENGTH) {
    const key = decodeBase64Strict(s)
    if (key) return { key, form: KEK_FORM_BASE64, reason: '' }
  }
  return { key: null, form: '', reason: 'format' }
}

/**
 * 前端格式檢查。回空字串＝本端無異議（**不等於伺服端會接受**）；
 * 否則回穩定的原因碼，由呼叫端查譯（不在此組字串，避免文案散落）。
 *
 * 字元集只約束**原字元形態**——十六進位與 base64 形態的合法字元由編碼本身界定。
 * @param {string} material
 * @returns {'' | 'empty' | 'format' | 'charset'}
 */
export function validateKEKMaterialFormat(material) {
  if (!(material ?? '').trim()) return 'empty'
  const { key, form, reason } = decodeKEKMaterial(material)
  if (reason) return reason
  if (form === KEK_FORM_RAW) {
    for (const b of key) {
      if (!KEK_ALPHABET.includes(String.fromCharCode(b))) return 'charset'
    }
  }
  return ''
}

/**
 * 計算材料指紋（SHA-256 前 8 bytes 的小寫 hex），與伺服端 crypto.Fingerprint 同演算法。
 * 供「與現行 KEK 相同」的前端預警之用。
 *
 * **雜湊的是解碼後的金鑰**（不是輸入字串）：同一把金鑰的三種寫法必須算出同一個指紋，
 * 否則以 hex 或 base64 輸入時預警會靜默失效（伺服端仍會擋，但使用者失去即時回饋）。
 *
 * **best-effort**：crypto.subtle 僅存在於 secure context（https 或 localhost），
 * 取不到時回 null 代表「本端無法判定」——呼叫端 SHALL 據此不做任何斷言，
 * 由伺服端的 CONFLICT_KEY_REWRAP_TARGET_CURRENT 把關。
 * @param {string} material
 * @returns {Promise<string|null>}
 */
export async function kekFingerprint(material) {
  const subtle = globalThis.crypto?.subtle
  if (!subtle || !material) return null
  const { key } = decodeKEKMaterial(material)
  if (!key) return null
  try {
    const digest = await subtle.digest('SHA-256', key)
    return Array.from(new Uint8Array(digest).slice(0, 8))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  } catch {
    return null
  }
}
