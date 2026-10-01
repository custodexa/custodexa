/**
 * 批次新增的錯誤清單 CSV。
 *
 * 這份檔會回寫使用者填的值，而使用者多半用 Excel 打開它。以 `=` `+` `-` `@`
 * 或 Tab、CR 開頭的儲存格會被試算表當成公式執行（CSV 公式注入），故這類值一律
 * 前置單引號 `'`，讓試算表把它當純文字。其餘值原樣輸出；輸入端不剝不改。
 * 檔首帶 UTF-8 BOM：沒有 BOM 時 Excel 以系統編碼開檔，中文會變亂碼。
 */

const FORMULA_PREFIXES = ['=', '+', '-', '@', '\t', '\r']

/** 單一儲存格：先防公式，再依 RFC 4180 加引號 */
export function csvCell(value) {
  let v = value == null ? '' : String(value)
  if (FORMULA_PREFIXES.some((p) => v.startsWith(p))) v = `'${v}`
  if (/[",\r\n]/.test(v)) v = `"${v.replace(/"/g, '""')}"`
  return v
}

/**
 * @param {string[]} header 表頭（列｜欄位｜填寫內容｜問題）
 * @param {Array<Array<string|number>>} rows
 * @returns {string} 帶 BOM 的 CSV 文字（CRLF 換行，與 Excel 一致）
 */
export function buildErrorReportCsv(header, rows) {
  const lines = [header, ...rows].map((cells) => cells.map(csvCell).join(','))
  return `\uFEFF${lines.join('\r\n')}\r\n`
}
