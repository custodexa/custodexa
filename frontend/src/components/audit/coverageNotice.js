/**
 * 保留期覆蓋狀態的說明句組裝（auditor-workbench）。
 *
 * **任何空白區間都不得無標記**——沒有這份標記，一段空白會被稽核員讀成
 * 「紀錄被刪」，工作台自己製造竄改誤報。
 *
 * 文案紀律：一律「已依保留政策清除」，SHALL NOT 寫成「已全部刪除」
 *（分批清除、部分完成、區間化過度保留都可能有殘留），且全頁不得對
 * 完整性作任何宣稱——那是檢查點驗證頁的職權。
 *
 * 本模組只組句、不決定載體：佈局重排後說明由類別 chips 的 popover 承載
 *（原常駐 el-alert 退場），語義與句子本身逐字不變。
 */
import { t as globalT } from '@/i18n'
import { typeLabel } from './timelineSummary'
import { formatDateTime } from '@/utils/format'

export const coverageEntry = (coverage, type) =>
  (coverage || []).find((c) => c.type === type) || null

export const coverageState = (coverage, type) =>
  coverageEntry(coverage, type)?.state || 'present'

const purgedText = (type, entry, t) => {
  const category = typeLabel(type)
  const base =
    entry.policy_days !== null && entry.policy_days !== undefined && entry.last_purge_at
      ? t('auditorWorkbench.coverage.purgedDetail', {
          category,
          days: entry.policy_days,
          time: formatDateTime(entry.last_purge_at),
        })
      : t('auditorWorkbench.coverage.purgedDetailPlain', { category })
  return entry.partial ? `${base}${t('auditorWorkbench.coverage.partial')}` : base
}

/**
 * 單一類別的覆蓋說明。
 *
 * 回傳 null ＝**這一類沒有需要標記的空白**（present 且有資料）：有資料就不必
 * 多話。其餘三種情形（purged／not_retained／present 但 0 筆）一律給句子，
 * 讓每一段空白都有歸因。
 *
 * @returns {{type:string,state:string,level:string,text:string,seqRange:object|null}|null}
 */
export function coverageNotice(type, { coverage, counts, t = globalT } = {}) {
  const entry = coverageEntry(coverage, type)
  const state = entry?.state || 'present'
  const category = typeLabel(type)

  if (state === 'purged') {
    return {
      type,
      state,
      level: 'warning',
      text: purgedText(type, entry, t),
      seqRange: entry.checkpoint_seq_range || null,
    }
  }
  if (state === 'not_retained') {
    return {
      type,
      state,
      level: 'info',
      text: t('auditorWorkbench.coverage.notRetainedDetail', { category }),
      seqRange: null,
    }
  }
  if ((counts?.[type] ?? 0) === 0) {
    return {
      type,
      state,
      level: 'info',
      text: t('auditorWorkbench.coverage.emptyPresent', { category }),
      seqRange: null,
    }
  }
  return null
}
