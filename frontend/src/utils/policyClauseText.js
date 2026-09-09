/**
 * 條文、要求與判定結果的人話呈現（純函式）。
 *
 * 合規對照頁、政策組管理頁與條文對話框共用同一套詞彙：三處各寫一份的話，
 * 同一個結果會在三個畫面上叫三個名字，而稽核人員要在這三處之間對帳。
 *
 * 詞彙的譯文集中在 `complianceMap.*`——判定結果的名字只該有一個出處，
 * 管理頁與對話框沿用它而不各自建一份。
 *
 * 判定本身一律由後端計算；本檔只把後端給的機器碼換成人看得懂的字。
 */
import i18n, { t } from '@/i18n'
import { formatKeyValue, policyLabel } from '@/utils/policyFormat'
import { translated } from '@/utils/i18nDisplay'

// 判定結果的機器碼 → 譯文鍵。條文層的兩種狀態（機構自述、系統內建保護）
// 不是鍵層判定，但在畫面上與判定結果並列，故收在同一張表內。
const RESULT_LABEL_KEYS = {
  compliant: 'complianceMap.resultCompliant',
  deviating: 'complianceMap.resultDeviating',
  needs_review: 'complianceMap.resultNeedsReview',
  review: 'complianceMap.resultReview',
  unmapped: 'complianceMap.resultUnmapped',
  self_attested: 'complianceMap.resultSelfAttested',
  builtin_protection: 'complianceMap.resultBuiltinProtection',
}

// 結果對應的標籤色。**顏色不是唯一線索**：呼叫端一律同時顯示文字，
// 色盲與黑白列印的稽核報表都讀得出結果
const RESULT_TAG_TYPES = {
  compliant: 'success',
  deviating: 'danger',
  needs_review: 'warning',
  review: 'warning',
  unmapped: 'info',
  self_attested: 'info',
  builtin_protection: 'info',
}

/** resultLabel 判定結果的人話；未知碼原樣回傳（不假裝認得） */
export function resultLabel(result) {
  const key = RESULT_LABEL_KEYS[result]
  return key ? t(key) : result || ''
}

/** resultTagType 判定結果的標籤色 */
export function resultTagType(result) {
  return RESULT_TAG_TYPES[result] || 'info'
}

/**
 * reasonLabel 判定理由的人話。
 *
 * 理由碼的譯文住 `verdictReason.*`（設定頁抽屜與本頁共用）。查無譯文時回原碼
 * 而不是空字串：稽核場景寧可看到一個機器碼，也不要一個沒有理由的判定。
 */
export function reasonLabel(reason) {
  if (!reason) return ''
  const key = `verdictReason.${reason}`
  return i18n.global.te(key) ? t(key) : reason
}

/**
 * displayPolicyValue 設定值的人話。
 *
 * 開關與枚舉走既有的枚舉文案；數值沿共用格式化補單位與零值語義。
 * 單位來自判定回應帶的顯示中繼資料（`unit_key`／`zero_disables`）——同一頁上
 * 混著天、秒、分鐘與字元，只印「10」不足以判讀；沒有中繼資料時退回不加單位，
 * 寧可少一個字，也不要把「12」寫成「12 天」而其實是字元數。
 *
 * @param {string} key 政策鍵
 * @param {string} raw 值
 * @param {Object} [meta] { unit_key, unit, zero_disables }
 */
export function displayPolicyValue(key, raw, meta = {}) {
  if (raw === undefined || raw === null || raw === '') return t('complianceMap.expectNone')
  if (!key) return raw
  return formatKeyValue(key, raw, meta)
}

/** settingLabel 設定鍵的顯示名（沿用政策頁同一套譯文） */
export function settingLabel(key) {
  return policyLabel({ key })
}

/**
 * expectationText 一項要求的人話。
 *
 * @param {Object} control { policy_key, comparator, expected_value, reference_only }
 * @param {Object} [meta] 顯示中繼資料 { unit_key, unit, zero_disables }；
 *   合規頁取自判定結果，管理頁取自設定清單。缺了只少單位，不影響要求本身
 */
export function expectationText(control, meta = {}) {
  if (!control) return t('complianceMap.expectNone')
  const value = displayPolicyValue(control.policy_key, control.expected_value, meta)
  if (control.comparator === 'review') return t('complianceMap.expectReview')
  if (control.reference_only) return t('complianceMap.expectReference', { value })
  if (control.comparator === 'min') return t('complianceMap.expectMin', { value })
  if (control.comparator === 'max') return t('complianceMap.expectMax', { value })
  if (control.comparator === 'equals') return t('complianceMap.expectEquals', { value })
  return t('complianceMap.expectNone')
}

// 國字數字 → 阿拉伯數字。條號的款次寫成國字（15-3(一)），直接放進 locale 鍵
// 會讓鍵名隨語言排版而變，先換成數字再組鍵。
const CJK_DIGITS = {
  一: '1', 二: '2', 三: '3', 四: '4', 五: '5',
  六: '6', 七: '7', 八: '8', 九: '9', 十: '10',
}

/**
 * clauseLocaleKey 條號 → locale 安全的鍵名。
 *
 * 條號帶點、連字號與括號（8.3.4、15-3(一)、21-8(七)1），而譯文查找以點分層，
 * 條號原樣當鍵會被拆成不存在的層級。規則：國字換數字、其餘非英數字元併成單一
 * 底線、前綴 c 讓鍵不以數字開頭。內建兩組共 56 條在此規則下無同名。
 */
export function clauseLocaleKey(clauseNo) {
  if (!clauseNo) return ''
  const arabic = String(clauseNo).replace(
    /[一二三四五六七八九十]/g,
    (ch) => CJK_DIGITS[ch]
  )
  // 切段後再接回來，而不是先併底線再修去頭尾的底線：後者的收尾樣式會隨輸入
  // 長度回溯，處理長字串時耗時遠超過字串長度本身。切段是單趟掃描
  const slug = arabic.split(/[^0-9A-Za-z]+/).filter(Boolean).join('_')
  return slug ? `c${slug}` : ''
}

/**
 * clauseText 條文標題或摘要的顯示文字。
 *
 * 資料庫存的是中文正本，換語言不會跟著換。內建組的條文另有三語譯文，故先查
 * 譯文、查無才回落資料庫文字——機構自建的條文沒有譯文可查，永遠走回落，畫面
 * 上以該組登記的原文語言呈現。
 */
function clauseText(clause, field) {
  const fallback = clause?.[field] || ''
  if (!clause?.group_code) return fallback
  const slug = clauseLocaleKey(clause.clause_no)
  if (!slug) return fallback
  const key = `policyClause.${clause.group_code}.${slug}.${field}`
  return translated(key, () => t(key)) || fallback
}

/** clauseTitle 條文標題（合規對照頁與政策組管理頁共用） */
export function clauseTitle(clause) {
  return clauseText(clause, 'title')
}

/** clauseSummary 條文摘要；條文沒有摘要時回空字串，由呼叫端決定不顯示 */
export function clauseSummary(clause) {
  return clauseText(clause, 'summary')
}

/**
 * clauseResult 一條條文的整體結果。
 *
 * 取最嚴的一個：一條條文對三個鍵，只要有一個偏離，這一條就是偏離——
 * 取多數或取第一個都會讓偏離在條文層消失，而稽核人員是從條文層開始讀的。
 */
const RESULT_SEVERITY = ['deviating', 'needs_review', 'review', 'compliant']

export function clauseResult(clause, verdicts) {
  if (!clause) return ''
  if (clause.kind === 'self_attested' || clause.kind === 'builtin_protection') {
    return clause.kind
  }
  const own = verdicts.filter(
    (v) => v.group_code === clause.group_code && v.clause_no === clause.clause_no
  )
  for (const result of RESULT_SEVERITY) {
    if (own.some((v) => v.result === result)) return result
  }
  return own.length ? own[0].result : 'unmapped'
}
