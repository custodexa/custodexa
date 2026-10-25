/**
 * 批次新增的錯誤清單：畫面上的「列｜欄位｜填寫內容｜問題」與其 CSV 下載。
 * 「填寫內容」取使用者在表格中看到的值（CSV 無法轉型的原文優先），
 * 下載檔經 errorReportCsv 防公式注入
 */
import { computed } from 'vue'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { buildErrorReportCsv } from '@/utils/errorReportCsv'
import { downloadBlob, timestampSuffix } from '@/utils/download'

// 錯誤欄位（伺服端機器欄名）→ 表格欄名（與表頭同一組既有字串）
const FIELD_LABEL_KEYS = {
  name: 'common.name',
  protocol: 'common.protocol',
  host: 'assets.host',
  port: 'assets.port',
  credential_id: 'assets.credentialSection.title',
  tags: 'common.tags',
  nodes: 'common.node',
  description: 'common.description',
  access_policy: 'assets.accessPolicy',
  db_name: 'assets.dbName',
  rdp_security: 'assets.rdpSecurity',
  db_tls_mode: 'assets.tlsMode',
}

// 兩個匯入專屬碼：節點與共用憑證「不存在」和「你無法使用」對使用者是同一句話，
// 不分辨哪一種；其他碼照通用錯誤譯文
const IMPORT_PROBLEM_KEYS = {
  NOTFOUND_ASSET_IMPORT_NODE_PATH: 'assets.bulk.problemNodeUnavailable',
  NOTFOUND_CREDENTIAL: 'assets.bulk.problemCredentialUnavailable',
}

/** 錯誤清單、儲存格提示與下載 CSV 共用的「問題」文字 */
export function bulkProblemText(e) {
  const key = IMPORT_PROBLEM_KEYS[e?.code]
  return key ? t(key) : resolveApiError({ code: e?.code, params: e?.params })
}

export const bulkFieldLabel = (field) =>
  field === 'k8s_namespace' ? 'Namespace' : FIELD_LABEL_KEYS[field] ? t(FIELD_LABEL_KEYS[field]) : field

function displayValue(row, field, resolvedPaths) {
  switch (field) {
    case 'credential_id':
      if (row.raw.credential_id) return row.raw.credential_id
      return row.credential_id == null ? '' : `#${row.credential_id}`
    case 'nodes':
      return (row.node_paths.length ? row.node_paths : resolvedPaths || []).join(';')
    default:
      return row[field] ?? ''
  }
}

export function useBulkErrorReport({ rows, check, lines }) {
  const errorItems = computed(() => {
    if (!check.value) return []
    const byKey = new Map(rows.value.map((r) => [r.key, r]))
    const reports = check.value.preview?.rows || []
    const items = []
    check.value.keys.forEach((key, index) => {
      const row = byKey.get(key)
      const errs = check.value.errors[key]
      if (!row || !errs?.length) return
      for (const e of errs) {
        items.push({
          key,
          line: lines.value[key],
          field: e.field,
          fieldLabel: bulkFieldLabel(e.field),
          value: displayValue(row, e.field, reports[index]?.resolved?.node_paths),
          problem: bulkProblemText(e),
        })
      }
    })
    return items
  })

  function downloadErrors() {
    const header = [
      t('assets.bulk.colLine'),
      t('assets.bulk.colField'),
      t('assets.bulk.colValue'),
      t('assets.bulk.colProblem'),
    ]
    const body = errorItems.value.map((i) => [i.line, i.fieldLabel, i.value, i.problem])
    const csv = buildErrorReportCsv(header, body)
    downloadBlob(new Blob([csv], { type: 'text/csv;charset=utf-8' }), `asset-import-problems-${timestampSuffix()}.csv`)
  }

  return { errorItems, downloadErrors }
}
