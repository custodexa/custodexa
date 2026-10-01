<template>
  <el-dialog
    :model-value="modelValue"
    :title="t('assets.bulk.title')"
    width="min(1200px, 96vw)"
    top="5vh"
    class="asset-bulk-dialog"
    :close-on-click-modal="false"
    :before-close="handleBeforeClose"
    data-test="bulk-dialog"
    @update:model-value="(v) => emit('update:modelValue', v)"
    @open="reset"
  >
    <div
      v-loading="importing"
      :element-loading-text="t('assets.bulk.importing')"
      class="body"
    >
      <el-steps
        :active="step"
        finish-status="success"
        class="steps"
      >
        <el-step :title="t('assets.bulk.stepFill')" />
        <el-step :title="t('assets.bulk.stepCheck')" />
        <el-step :title="t('assets.bulk.stepDone')" />
      </el-steps>

      <template v-if="done">
        <div
          class="done"
          data-test="bulk-done"
        >
          <div class="done-title">
            {{ t('assets.bulk.done', { total: done.created }) }}
          </div>
          <div
            v-if="done.pending"
            class="done-line"
          >
            {{ t('assets.bulk.donePending', { pending: done.pending }) }}
            <el-button
              link
              type="primary"
              data-test="bulk-view-pending"
              @click="viewPending"
            >
              {{ t('assets.bulk.viewPending') }}
            </el-button>
          </div>
          <div
            v-if="done.caCount"
            class="done-ca"
            data-test="bulk-done-ca"
          >
            {{ t('assets.bulk.doneCaHint', { count: done.caCount }) }}
          </div>
        </div>
      </template>

      <template v-else>
        <div class="mode-bar">
          <el-radio-group
            v-model="mode"
            data-test="bulk-mode"
          >
            <el-radio-button value="form">
              {{ t('assets.bulk.modeForm') }}
            </el-radio-button>
            <el-radio-button value="csv">
              {{ t('assets.bulk.modeCsv') }}
            </el-radio-button>
          </el-radio-group>
          <el-popover
            trigger="click"
            placement="bottom-end"
            :width="860"
          >
            <template #reference>
              <el-button
                link
                type="primary"
                data-test="bulk-field-help-link"
              >
                {{ t('assets.bulk.fieldHelp') }}
                <el-icon class="help-icon">
                  <Info />
                </el-icon>
              </el-button>
            </template>
            <BulkFieldHelp />
          </el-popover>
        </div>

        <BulkCsvPanel
          v-if="mode === 'csv'"
          :loading="csvLoading"
          :file-error="fileError"
          @file="onFile"
        />

        <template v-else>
          <div
            v-if="loaded && !check"
            class="loaded-banner"
            data-test="bulk-loaded-banner"
          >
            {{ t('assets.bulk.loadedBanner', loaded) }}
          </div>
          <BulkCheckSummary
            v-if="summaryState"
            v-model:filter="filter"
            :state="summaryState"
            :summary="check.summary"
          />
          <BulkAssetTable
            ref="tableRef"
            :rows="visibleRows"
            :errors="check ? check.errors : {}"
            :lines="lines"
            :credentials="credentials"
            :node-options="nodeOptions"
            :tag-names="tagNames"
            @protocol-change="onProtocolChange"
            @duplicate="duplicate"
            @remove="remove"
          />
          <div class="add-rows">
            <el-button
              link
              type="primary"
              data-test="bulk-add-row"
              @click="addRows(1)"
            >
              <el-icon><Plus /></el-icon>
              {{ t('assets.bulk.addRow') }}
            </el-button>
            <el-button
              link
              type="primary"
              data-test="bulk-add-rows-10"
              @click="addRows(10)"
            >
              <el-icon><Plus /></el-icon>
              {{ t('assets.bulk.addRows10') }}
            </el-button>
          </div>
          <BulkErrorList
            v-if="showErrorList"
            :items="errorItems"
            @jump="jumpTo"
            @download="downloadErrors"
          />
        </template>
      </template>
    </div>

    <template #footer>
      <div class="footer">
        <span
          v-if="!done"
          class="footer-count"
          data-test="bulk-footer-count"
        >
          {{ t('assets.bulk.footerCount', { total: entries.length, pending: pendingCount }) }}
        </span>
        <span v-else />
        <div class="footer-actions">
          <template v-if="done">
            <el-button
              type="primary"
              data-test="bulk-finish"
              @click="emit('update:modelValue', false)"
            >
              {{ t('assets.bulk.stepDone') }}
            </el-button>
          </template>
          <template v-else>
            <el-button @click="handleBeforeClose(() => emit('update:modelValue', false))">
              {{ t('common.cancel') }}
            </el-button>
            <el-button
              v-if="canImport"
              type="primary"
              data-test="bulk-import"
              @click="runImport"
            >
              {{ t('assets.bulk.importN', { total: check.summary.total }) }}
            </el-button>
            <el-button
              v-else
              type="primary"
              :loading="checking"
              data-test="bulk-check"
              @click="runCheck"
            >
              {{ checking ? t('assets.bulk.checking') : t('assets.bulk.check') }}
            </el-button>
          </template>
        </div>
      </div>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 資產批次新增對話框：線上填寫與上傳 CSV 兩個入口共用同一張表，
 * 「檢查」呼叫預檢端點，全部通過才可匯入；匯入在伺服端是單一交易，任一台失敗全部不建。
 *
 * 檢查結果綁定送檢當下的內容快照：任一格改過即視為過期，匯入鈕退回「檢查」——
 * 寫入本文取自預檢回應的 values（含 node_ids 與 node_paths），內容一變就不再是同一批。
 */
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Info, Plus } from 'lucide-vue-next'
import BulkAssetTable from './BulkAssetTable.vue'
import BulkCsvPanel from './BulkCsvPanel.vue'
import BulkFieldHelp from './BulkFieldHelp.vue'
import BulkCheckSummary from './BulkCheckSummary.vue'
import BulkErrorList from './BulkErrorList.vue'
import { importAssets, previewAssetImport } from '@/api/assets'
import { listCredentials } from '@/api/credentials'
import { resolveApiError } from '@/api/error'
import {
  applyProtocolChange,
  clearIncompatibleCredential,
  countVerifyWithoutCa,
  duplicateRow,
  importPayloadFromPreview,
  isBlankRow,
  isCredentialPendingRow,
  newRow,
  rowFromReport,
  rowToPayload,
} from '@/utils/assetBulk'
import { useBulkErrorReport } from '@/composables/useBulkErrorReport'

defineProps({
  modelValue: { type: Boolean, default: false },
  nodeOptions: { type: Array, default: () => [] },
  tagNames: { type: Array, default: () => [] },
})

const emit = defineEmits(['update:modelValue', 'imported', 'view-pending'])

const { t } = useI18n()

const INITIAL_ROWS = 5

const rows = ref([])
const mode = ref('form')
const source = ref('form')
const loaded = ref(null)
const fileError = ref('')
const csvLoading = ref(false)
const checking = ref(false)
const importing = ref(false)
const check = ref(null)
const filter = ref('all')
const done = ref(null)
const tableRef = ref(null)
const credentials = reactive({})
const credentialLoads = {}

function reset() {
  rows.value = Array.from({ length: INITIAL_ROWS }, () => newRow())
  mode.value = 'form'
  source.value = 'form'
  loaded.value = null
  fileError.value = ''
  check.value = null
  filter.value = 'all'
  done.value = null
  ensureCredentials('ssh')
}

// —— 共用憑證清單（依協定向伺服端取相容者；同一協定只取一次）——
function ensureCredentials(protocol) {
  if (!protocol) return Promise.resolve(null)
  if (!credentialLoads[protocol]) {
    credentialLoads[protocol] = listCredentials({ scope: 'shared', protocol })
      .then((res) => {
        credentials[protocol] = res?.data || []
        return credentials[protocol]
      })
      .catch(() => {
        delete credentialLoads[protocol]
        return null
      })
  }
  return credentialLoads[protocol]
}

async function onProtocolChange(row, protocol) {
  applyProtocolChange(row, protocol)
  const list = await ensureCredentials(protocol)
  if (list) clearIncompatibleCredential(row, list.map((c) => c.id))
}

// —— 列操作 ——
const entries = computed(() => rows.value.filter((r) => !isBlankRow(r)))
const pendingCount = computed(() => entries.value.filter(isCredentialPendingRow).length)

// 畫面列號：CSV 列用檔案列號，其餘列依序接在最大的檔案列號之後（純線上填寫即 1、2、3…）——
// 送檢時同一個號碼也作為列號送出，伺服端回報「與第 N 列重名」時指的才是畫面上同一個 N，
// CSV 載入後再新增的列也不會和檔案列號撞號
const lines = computed(() => {
  const out = {}
  let next = Math.max(0, ...rows.value.map((r) => r.line ?? 0))
  rows.value.forEach((r) => {
    out[r.key] = r.line ?? (next += 1)
  })
  return out
})

function addRows(n) {
  rows.value.push(...Array.from({ length: n }, () => newRow()))
}

function duplicate(row) {
  const i = rows.value.indexOf(row)
  rows.value.splice(i + 1, 0, duplicateRow(row))
}

function remove(row) {
  rows.value = rows.value.filter((r) => r !== row)
}

// —— 檢查 ——
function buildBatch() {
  const items = entries.value.map((r) => {
    const { row, localErrors } = rowToPayload(r)
    return { key: r.key, row: { ...row, line: lines.value[r.key] }, localErrors, raw: r.raw }
  })
  const snapshot = JSON.stringify(items.map((i) => [i.row, i.raw]))
  return { items, snapshot }
}

const stale = computed(() => !!check.value && buildBatch().snapshot !== check.value.snapshot)

const summaryState = computed(() => {
  if (!check.value) return ''
  if (stale.value) return 'stale'
  if (check.value.stateChanged) return 'stateChanged'
  return check.value.ok ? 'passed' : 'errors'
})

const showDetails = computed(() => ['errors', 'stateChanged'].includes(summaryState.value))
const canImport = computed(() => summaryState.value === 'passed')
const step = computed(() => (done.value ? 2 : check.value ? 1 : 0))

const visibleRows = computed(() => {
  if (!showDetails.value || filter.value === 'all') return rows.value
  const errs = check.value.errors
  const checked = new Set(check.value.keys)
  return rows.value.filter((r) =>
    filter.value === 'invalid' ? errs[r.key]?.length : checked.has(r.key) && !errs[r.key]?.length
  )
})

// 一列的錯誤：伺服端回報＋送出前本地發現的（同欄同碼不重複）
function mergeErrors(serverErrors, localErrors) {
  const out = [...(serverErrors || [])]
  for (const e of localErrors) {
    if (!out.some((s) => s.field === e.field && s.code === e.code)) out.push(e)
  }
  return out
}

function applyResult(keys, reports, localByKey, extra) {
  const errors = {}
  for (const rep of reports) {
    const key = keys[rep.index]
    if (key == null) continue
    const merged = mergeErrors(rep.errors, localByKey[key] || [])
    if (merged.length) errors[key] = merged
  }
  for (const [key, local] of Object.entries(localByKey)) {
    if (local.length && !errors[key]) errors[key] = local
  }
  const total = keys.length
  const invalid = Object.keys(errors).length
  return {
    ...extra,
    keys,
    errors,
    ok: invalid === 0,
    summary: { total, invalid, valid: total - invalid, pending: pendingCount.value },
  }
}

async function runCheck() {
  const { items, snapshot } = buildBatch()
  if (!items.length) {
    ElMessage.warning(t('assets.bulk.emptyTable'))
    return
  }
  checking.value = true
  try {
    const batch = { source: source.value, rows: items.map((i) => i.row) }
    const preview = await previewAssetImport(batch)
    const keys = items.map((i) => i.key)
    const localByKey = Object.fromEntries(items.map((i) => [i.key, i.localErrors]))
    check.value = applyResult(keys, preview.rows || [], localByKey, { snapshot, preview, stateChanged: false })
    filter.value = check.value.ok ? 'all' : 'invalid'
  } catch (err) {
    ElMessage.error(resolveApiError(err?.response?.data, err?.response?.status))
  } finally {
    checking.value = false
  }
}

// —— 匯入 ——
async function runImport() {
  const summary = check.value.summary
  try {
    await ElMessageBox.confirm(
      t('assets.bulk.confirm', { total: summary.total, pending: summary.pending }),
      t('assets.bulk.title'),
      { confirmButtonText: t('assets.bulk.confirmOk'), cancelButtonText: t('assets.bulk.back') }
    )
  } catch {
    return
  }
  const payload = importPayloadFromPreview(source.value, check.value.preview)
  importing.value = true
  try {
    const res = await importAssets(payload)
    done.value = {
      created: res.created,
      pending: res.credential_pending,
      caCount: countVerifyWithoutCa(payload.rows),
    }
    emit('imported', res)
  } catch (err) {
    onImportError(err)
  } finally {
    importing.value = false
  }
}

// 409（預檢後狀態變了）與 400（寫入前重驗不過）都已整批回滾：回到檢查步驟、標出出事的列
function onImportError(err) {
  const data = err?.response?.data
  const code = data?.code
  if (
    (code === 'CONFLICT_ASSET_IMPORT_STATE_CHANGED' || code === 'VALIDATION_ASSET_IMPORT_ROWS_INVALID') &&
    Array.isArray(data.rows)
  ) {
    const prev = check.value
    check.value = applyResult(prev.keys, data.rows, {}, {
      snapshot: prev.snapshot,
      preview: prev.preview,
      stateChanged: true,
    })
    filter.value = 'invalid'
    return
  }
  ElMessage.error(resolveApiError(data, err?.response?.status))
}

function viewPending() {
  emit('view-pending')
  emit('update:modelValue', false)
}

// —— CSV ——
async function onFile(file) {
  fileError.value = ''
  csvLoading.value = true
  let preview
  try {
    preview = await previewAssetImport(file, { csv: true })
  } catch (err) {
    fileError.value = resolveApiError(err?.response?.data, err?.response?.status)
    return
  } finally {
    csvLoading.value = false
  }
  const count = entries.value.length
  if (count > 0) {
    try {
      await ElMessageBox.confirm(t('assets.bulk.replaceConfirm', { count }), t('assets.bulk.title'), {
        confirmButtonText: t('assets.bulk.replace'),
        cancelButtonText: t('common.cancel'),
      })
    } catch {
      return
    }
  }
  rows.value = (preview.rows || []).map(rowFromReport)
  source.value = 'csv'
  check.value = null
  filter.value = 'all'
  loaded.value = { file: file.name, count: rows.value.length }
  mode.value = 'form'
  new Set(rows.value.map((r) => r.protocol)).forEach(ensureCredentials)
}

// —— 錯誤清單 ——
const showErrorList = computed(() => showDetails.value && Object.keys(check.value.errors).length > 0)
const { errorItems, downloadErrors } = useBulkErrorReport({ rows, check, lines })

function jumpTo(item) {
  if (filter.value === 'valid') filter.value = 'invalid'
  tableRef.value?.focusCell(item.key, item.field)
}

// —— 關閉防呆 ——
async function handleBeforeClose(doneFn) {
  const count = entries.value.length
  if (done.value || count === 0 || importing.value) {
    if (!importing.value) doneFn()
    return
  }
  try {
    await ElMessageBox.confirm(t('assets.bulk.closeConfirm', { count }), t('assets.bulk.title'), {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
    })
    doneFn()
  } catch {
    // 使用者選擇留下
  }
}

defineExpose({ rows, mode, check, runCheck, runImport, onFile, reset })
</script>

<style scoped>
.body {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}

.steps {
  max-width: 520px;
}

/* 已完成的步驟用中性白而非成功綠：步驟條表示進度，不是檢查結果 */
.steps :deep(.el-step__head.is-success),
.steps :deep(.el-step__title.is-success) {
  color: var(--ot-text-primary);
  border-color: var(--ot-text-primary);
}

.mode-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-bottom: var(--ot-space-sm);
  border-bottom: 1px solid var(--ot-border-subtle);
}

.help-icon {
  margin-left: 2px;
}

.loaded-banner {
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid color-mix(in srgb, var(--el-color-primary) 45%, transparent);
  border-radius: var(--ot-radius-md);
  background: color-mix(in srgb, var(--el-color-primary) 12%, transparent);
  color: var(--el-color-primary);
  font-size: var(--ot-font-size-sm);
}

.add-rows {
  display: flex;
  gap: var(--ot-space-md);
}

.footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.footer-count {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.done {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-lg) var(--ot-space-sm);
}

.done-title {
  color: var(--ot-success);
  font-size: var(--ot-font-size-lg, 18px);
  font-weight: 600;
}

.done-line {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
}

.done-ca {
  color: var(--ot-warning);
  font-size: var(--ot-font-size-sm);
}
</style>
