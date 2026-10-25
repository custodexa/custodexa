/**
 * 操作日誌列上的授權分級標記（自我授權、管理類發放）。
 *
 * 標記來自兩處，任一有值即可：列的 details 的 `grant_marks` 陣列（分級列本身），
 * 或後端回傳的原因參數 `marks`（逗號串接）。文字走 `enum.grantMark.*`。
 */
import { t, te } from '@/i18n'

// 與告警分級顏色一致：管理類發放為中（warning）、自我授權為高（danger）
const MARK_TAG_TYPE = new Map([
  ['management_grant', 'warning'],
  ['self_authorization', 'danger'],
])

const parseDetails = (details) => {
  if (!details) return null
  if (typeof details !== 'string') return details
  try {
    return JSON.parse(details)
  } catch {
    return null
  }
}

/** 一列帶的標記（去重、只留已知值，保持出現順序） */
export function grantMarksOf(row) {
  const fromDetails = parseDetails(row?.details)?.grant_marks
  const fromReason = String(row?.reason_params?.marks || '')
    .split(',')
    .map((mark) => mark.trim())
  const raw = Array.isArray(fromDetails) ? fromDetails : fromReason
  return [...new Set(raw)].filter((mark) => MARK_TAG_TYPE.has(mark))
}

/** 動作欄標籤資料：[{ mark, label, type }] */
export function grantMarkTags(row) {
  return grantMarksOf(row).map((mark) => ({
    mark,
    label: te(`enum.grantMark.${mark}`) ? t(`enum.grantMark.${mark}`) : mark,
    type: MARK_TAG_TYPE.get(mark),
  }))
}
