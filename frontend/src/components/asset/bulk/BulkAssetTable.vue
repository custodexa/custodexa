<template>
  <div
    ref="rootRef"
    class="bulk-table"
    data-test="bulk-table"
  >
    <el-table
      :data="rows"
      row-key="key"
      size="small"
      max-height="52vh"
      class="table"
    >
      <el-table-column
        label="#"
        width="56"
        fixed="left"
      >
        <template #default="{ row }">
          <span
            class="line"
            :data-test="`bulk-line-${row.key}`"
          >
            <span
              v-if="rowHasErrors(row)"
              class="err-dot"
              data-test="bulk-err-dot"
            />
            {{ lineOf(row) }}
          </span>
        </template>
      </el-table-column>

      <el-table-column
        :label="`${t('common.name')}*`"
        width="160"
        fixed="left"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-name`"
          >
            <el-input
              v-model="row.name"
              size="small"
              :class="{ 'is-error': hasErr(row, 'name') }"
              data-test="bulk-name"
            />
            <CellMessages :messages="errs(row, 'name')" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="`${t('common.protocol')}*`"
        width="120"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-protocol`"
          >
            <el-select
              :model-value="row.protocol"
              size="small"
              :class="{ 'is-error': hasErr(row, 'protocol') }"
              data-test="bulk-protocol"
              @update:model-value="(v) => emit('protocol-change', row, v)"
            >
              <el-option
                v-for="p in BULK_PROTOCOLS"
                :key="p"
                :label="p"
                :value="p"
              />
            </el-select>
            <CellMessages :messages="errs(row, 'protocol')" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="`${t('assets.host')}*`"
        width="150"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-host`"
          >
            <el-input
              v-model="row.host"
              size="small"
              class="mono-input"
              :class="{ 'is-error': hasErr(row, 'host') }"
              data-test="bulk-host"
            />
            <CellMessages :messages="errs(row, 'host')" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('assets.port')"
        width="120"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-port`"
          >
            <el-input
              :model-value="row.port"
              size="small"
              inputmode="numeric"
              :placeholder="portPlaceholder(row)"
              :class="{ 'is-error': hasErr(row, 'port') }"
              data-test="bulk-port"
              @update:model-value="(v) => (row.port = String(v).replace(/\D/g, ''))"
            />
            <CellMessages :messages="errs(row, 'port')" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('assets.credentialSection.title')"
        width="250"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-credential_id`"
          >
            <el-select
              :model-value="row.credential_id ?? ''"
              size="small"
              filterable
              :placeholder="row.raw.credential_id || t('assets.bulk.credentialLater')"
              :class="{ 'is-error': hasErr(row, 'credential_id') }"
              data-test="bulk-credential"
              @update:model-value="(v) => setCredential(row, v)"
            >
              <el-option
                :label="t('assets.bulk.credentialLater')"
                value=""
              />
              <el-option
                v-for="c in credentialOptionsFor(row)"
                :key="c.id"
                :label="credentialLabel(c)"
                :value="c.id"
              />
            </el-select>
            <CellMessages :messages="errs(row, 'credential_id')" />
            <CellHint :hint="row.hints.credential_id" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('common.node')"
        width="190"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-nodes`"
          >
            <el-tree-select
              :model-value="row.node_ids"
              :data="nodeOptions"
              :props="{ label: 'name', children: 'children' }"
              node-key="id"
              multiple
              check-strictly
              default-expand-all
              collapse-tags
              collapse-tags-tooltip
              size="small"
              :placeholder="row.node_paths.join(';')"
              :class="{ 'is-error': hasErr(row, 'nodes') }"
              data-test="bulk-nodes"
              @update:model-value="(v) => setNodes(row, v)"
            />
            <CellMessages :messages="errs(row, 'nodes')" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('common.tags')"
        width="150"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-tags`"
          >
            <el-autocomplete
              v-model="row.tags"
              size="small"
              :fetch-suggestions="tagSuggestions"
              :trigger-on-focus="false"
              :class="{ 'is-error': hasErr(row, 'tags') }"
              data-test="bulk-tags"
              @select="(item) => pickTag(row, item)"
            />
            <CellMessages :messages="errs(row, 'tags')" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('common.description')"
        width="180"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-description`"
          >
            <el-input
              v-model="row.description"
              size="small"
              :class="{ 'is-error': hasErr(row, 'description') }"
            />
            <CellMessages :messages="errs(row, 'description')" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('assets.accessPolicy')"
        width="190"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-access_policy`"
          >
            <el-select
              v-model="row.access_policy"
              size="small"
              :empty-values="[null, undefined]"
              :class="{ 'is-error': hasErr(row, 'access_policy') }"
            >
              <el-option
                :label="t('assets.inheritPolicy')"
                value=""
              />
              <el-option
                v-for="(label, value) in accessPolicyEnumLabels"
                :key="value"
                :label="label"
                :value="value"
              />
            </el-select>
            <CellMessages :messages="errs(row, 'access_policy')" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('assets.dbName')"
        width="150"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-db_name`"
          >
            <el-input
              v-if="editable(row, 'db_name')"
              v-model="row.db_name"
              size="small"
              :class="{ 'is-error': hasErr(row, 'db_name') }"
            />
            <NotApplicable v-else />
            <CellMessages :messages="errs(row, 'db_name')" />
            <CellHint :hint="row.hints.db_name" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('assets.tlsMode')"
        width="220"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-db_tls_mode`"
          >
            <div
              v-if="editable(row, 'db_tls_mode')"
              class="with-icon"
            >
              <el-select
                v-model="row.db_tls_mode"
                size="small"
                :empty-values="[null, undefined]"
                :class="{ 'is-error': hasErr(row, 'db_tls_mode') }"
                data-test="bulk-db-tls"
              >
                <el-option
                  v-for="o in DB_TLS_OPTIONS"
                  :key="o.value"
                  :label="t(o.label)"
                  :value="o.value"
                />
              </el-select>
              <el-tooltip
                v-if="DB_TLS_VERIFY_MODES.includes(row.db_tls_mode)"
                :content="t('assets.bulk.caAfterImport')"
                placement="top"
              >
                <el-icon
                  class="info-icon"
                  data-test="bulk-ca-hint"
                >
                  <Info />
                </el-icon>
              </el-tooltip>
            </div>
            <NotApplicable v-else />
            <CellMessages :messages="errs(row, 'db_tls_mode')" />
            <CellHint :hint="row.hints.db_tls_mode" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('assets.rdpSecurity')"
        width="150"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-rdp_security`"
          >
            <el-select
              v-if="editable(row, 'rdp_security')"
              v-model="row.rdp_security"
              size="small"
              :empty-values="[null, undefined]"
              :class="{ 'is-error': hasErr(row, 'rdp_security') }"
            >
              <el-option
                v-for="o in RDP_OPTIONS"
                :key="o.value"
                :label="t(o.label)"
                :value="o.value"
              />
            </el-select>
            <NotApplicable v-else />
            <CellMessages :messages="errs(row, 'rdp_security')" />
            <CellHint :hint="row.hints.rdp_security" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        label="Namespace"
        width="140"
      >
        <template #default="{ row }">
          <div
            class="cell"
            :data-cell="`${row.key}-k8s_namespace`"
          >
            <el-input
              v-if="editable(row, 'k8s_namespace')"
              v-model="row.k8s_namespace"
              size="small"
              :class="{ 'is-error': hasErr(row, 'k8s_namespace') }"
              data-test="bulk-k8s-namespace"
            >
              <template
                v-if="row.protocol === 'k8s'"
                #prefix
              >
                <span class="required-mark">*</span>
              </template>
            </el-input>
            <NotApplicable v-else />
            <CellMessages :messages="errs(row, 'k8s_namespace')" />
            <CellHint :hint="row.hints.k8s_namespace" />
          </div>
        </template>
      </el-table-column>

      <el-table-column
        :label="t('common.actions')"
        width="150"
      >
        <template #default="{ row }">
          <el-button
            link
            type="primary"
            size="small"
            data-test="bulk-duplicate"
            @click="emit('duplicate', row)"
          >
            {{ t('assets.bulk.duplicateRow') }}
          </el-button>
          <el-button
            link
            type="danger"
            size="small"
            data-test="bulk-remove"
            @click="emit('remove', row)"
          >
            {{ t('common.delete') }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup>
/**
 * 批次新增的可編輯表格（線上填寫與 CSV 載入後共用）。
 *
 * 表格只負責呈現與就地編輯；列陣列由上層持有，協定改變交回上層處理
 * （清掉不適用的值與不相容的憑證要先取得新協定的相容清單）。
 * 不適用該列協定的欄呈「—」且不可編輯；但 CSV 帶進來的不適用值要讓使用者看得到、清得掉，
 * 故「有值」時仍開放編輯，清空後才收成「—」。
 */
import { h, ref, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { Info } from 'lucide-vue-next'
import { accessPolicyEnumLabels } from '@/utils/policyFormat'
import { credentialDisplayName } from '@/constants/credentials'
import { resolveApiError } from '@/api/error'
import { PROTOCOL_DEFAULT_PORTS } from '@/utils/protocol'
import { BULK_PROTOCOLS, DB_TLS_VERIFY_MODES, fieldApplies } from '@/utils/assetBulk'

const props = defineProps({
  rows: { type: Array, required: true },
  // 列 key → 該列的錯誤（{ field, code, params }[]）
  errors: { type: Object, default: () => ({}) },
  // 列 key → 畫面列號
  lines: { type: Object, default: () => ({}) },
  // 協定 → 相容的共用憑證清單
  credentials: { type: Object, default: () => ({}) },
  nodeOptions: { type: Array, default: () => [] },
  tagNames: { type: Array, default: () => [] },
})

const emit = defineEmits(['protocol-change', 'duplicate', 'remove'])

const { t } = useI18n()
const rootRef = ref(null)

const DB_TLS_OPTIONS = [
  { value: '', label: 'assets.bulk.dbTlsDefault' },
  { value: 'disable', label: 'assets.bulk.dbTlsDisable' },
  { value: 'require', label: 'assets.bulk.dbTlsRequire' },
  { value: 'verify-ca', label: 'assets.bulk.dbTlsVerifyCa' },
  { value: 'verify-full', label: 'assets.bulk.dbTlsVerifyFull' },
]

const RDP_OPTIONS = [
  { value: '', label: 'assets.bulk.rdpSecurityAuto' },
  { value: 'nla', label: 'assets.bulk.rdpSecurityNla' },
  { value: 'tls', label: 'assets.bulk.rdpSecurityTls' },
]

const CellMessages = (p) =>
  (p.messages || []).map((m) => h('div', { class: 'cell-error', 'data-test': 'bulk-cell-error' }, m))
CellMessages.props = ['messages']

const CellHint = (p) =>
  p.hint ? h('div', { class: 'cell-hint', 'data-test': 'bulk-cell-hint' }, t(`assets.bulk.${p.hint}`)) : null
CellHint.props = ['hint']

const NotApplicable = () => h('div', { class: 'not-applicable' }, t('assets.bulk.notApplicable'))

const lineOf = (row) => props.lines[row.key] ?? ''

const rowErrors = (row) => props.errors[row.key] || []
const rowHasErrors = (row) => rowErrors(row).length > 0
const hasErr = (row, field) => rowErrors(row).some((e) => e.field === field)
const errs = (row, field) =>
  rowErrors(row)
    .filter((e) => e.field === field)
    .map((e) => resolveApiError({ code: e.code, params: e.params }))

const editable = (row, field) => fieldApplies(field, row.protocol) || row[field] !== ''

const portPlaceholder = (row) => {
  const port = PROTOCOL_DEFAULT_PORTS[row.protocol]
  return port ? t('assets.bulk.portDefault', { port }) : ''
}

const credentialLabel = (c) => {
  const name = credentialDisplayName(c)
  if (!name && !c.username) return `#${c.id}`
  return `#${c.id} ${name} · ${c.username || ''}`.trim()
}

// 已選的憑證不在相容清單時（CSV 帶進來的編號、或清單尚未載入）仍要顯示得出它是誰
function credentialOptionsFor(row) {
  const list = props.credentials[row.protocol] || []
  if (row.credential_id == null || list.some((c) => c.id === row.credential_id)) return list
  const known = row.credential_ref
  const extra = known
    ? { id: row.credential_id, name: known.name, username: known.username, scope: 'shared' }
    : { id: row.credential_id, name: '', username: '', scope: 'shared' }
  return [extra, ...list]
}

function setCredential(row, value) {
  row.credential_id = value === '' || value == null ? null : value
  const picked = (props.credentials[row.protocol] || []).find((c) => c.id === row.credential_id)
  row.credential_ref = picked ? { id: picked.id, name: credentialDisplayName(picked), username: picked.username } : null
  row.raw = {}
  row.hints = { ...row.hints, credential_id: undefined }
}

// 改以選擇器選節點：路徑作廢，改以 node_ids 送出
function setNodes(row, ids) {
  row.node_ids = ids
  row.node_paths = []
}

// 標籤建議：比對逗號後正在輸入的那一段
function tagSuggestions(query, cb) {
  const last = (query || '').split(',').pop().trim().toLowerCase()
  if (!last) return cb([])
  cb(
    props.tagNames
      .filter((n) => n.toLowerCase().includes(last))
      .slice(0, 20)
      .map((value) => ({ value }))
  )
}

function pickTag(row, item) {
  const parts = (row.tags || '').split(',').map((s) => s.trim())
  parts[parts.length - 1] = item.value
  row.tags = parts.filter(Boolean).join(',')
}

/** 錯誤清單點列：捲到該格並聚焦 */
async function focusCell(key, field) {
  await nextTick()
  const cell = rootRef.value?.querySelector(`[data-cell="${key}-${field}"]`)
  if (!cell) return
  cell.scrollIntoView({ block: 'center', inline: 'center', behavior: 'smooth' })
  cell.querySelector('input')?.focus()
}

defineExpose({ focusCell })
</script>

<style scoped>
.bulk-table {
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  overflow: hidden;
}

.table :deep(.el-table__cell) {
  vertical-align: top;
}

.line {
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
  padding-top: 4px;
  color: var(--ot-text-secondary);
}

.err-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--ot-danger);
}

.cell {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.cell :deep(.el-select),
.cell :deep(.el-autocomplete) {
  width: 100%;
}

.cell :deep(.is-error .el-input__wrapper),
.cell :deep(.is-error .el-select__wrapper),
.cell :deep(.el-input.is-error .el-input__wrapper) {
  box-shadow: 0 0 0 1px var(--ot-danger) inset;
}

.mono-input :deep(input) {
  font-family: var(--ot-font-mono);
}

.with-icon {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
}

.info-icon {
  color: var(--ot-text-secondary);
  cursor: help;
}

.required-mark {
  color: var(--ot-danger);
}

.not-applicable {
  height: 24px;
  line-height: 22px;
  padding: 0 var(--ot-space-sm);
  border: 1px dashed var(--ot-border-subtle);
  border-radius: var(--ot-radius-sm);
  color: var(--ot-text-secondary);
}

:deep(.cell-error) {
  color: var(--ot-danger);
  font-size: var(--ot-font-size-xs);
  line-height: 1.4;
}

:deep(.cell-hint) {
  color: var(--ot-warning);
  font-size: var(--ot-font-size-xs);
  line-height: 1.4;
}
</style>
