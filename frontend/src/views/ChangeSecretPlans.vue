<template>
  <div class="change-secret-plans">
    <PageHeader
      :title="$t('menu.changeSecretPlans')"
      :description="$t('changeSecretPlans.description')"
    >
      <template #actions>
        <el-button
          type="primary"
          @click="openCreate"
        >
          {{ $t('changeSecretPlans.createPlan') }}
        </el-button>
      </template>
    </PageHeader>

    <div class="list-panel">
      <el-table
        v-loading="loading"
        :data="plans"
        stripe
      >
        <el-table-column
          prop="name"
          :label="$t('common.name')"
          min-width="140"
        />
        <el-table-column
          :label="$t('changeSecretPlans.colAssetCount')"
          width="90"
        >
          <template #default="{ row }">
            {{ parseAssetIds(row.asset_ids).length }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretPlans.colAccountScope')"
          min-width="120"
        >
          <template #default="{ row }">
            <span v-if="isAllAccounts(row.accounts)">{{ $t('changeSecretPlans.accountScopeAll') }}</span>
            <span v-else>{{ parseAccounts(row.accounts).join(', ') }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretPlans.colSecretType')"
          width="110"
        >
          <template #default="{ row }">
            <el-tag :type="row.secret_type === 'ssh_key' ? 'warning' : 'info'">
              {{ secretTypeText(row.secret_type) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretPlans.colSchedule')"
          min-width="120"
        >
          <template #default="{ row }">
            <code v-if="row.cron">{{ row.cron }}</code>
            <span
              v-else
              class="muted"
            >{{ $t('changeSecretPlans.manualOnly') }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.enabled')"
          width="80"
        >
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'">
              {{ row.enabled ? $t('common.enabled') : $t('common.disabled') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="300"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              size="small"
              type="warning"
              link
              @click="triggerRun(row)"
            >
              {{ $t('changeSecretPlans.runNow') }}
            </el-button>
            <el-button
              size="small"
              link
              @click="openRecords(row)"
            >
              {{ $t('changeSecretPlans.records') }}
            </el-button>
            <el-button
              size="small"
              type="primary"
              link
              @click="openEdit(row)"
            >
              {{ $t('common.edit') }}
            </el-button>
            <el-button
              size="small"
              type="danger"
              link
              @click="removePlan(row)"
            >
              {{ $t('common.delete') }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            :title="$t('changeSecretPlans.emptyTitle')"
            :hint="$t('changeSecretPlans.emptyHint')"
          />
        </template>
      </el-table>
    </div>

    <div class="list-panel candidates-panel">
      <div class="panel-head">
        <h3>{{ $t('changeSecretPlans.candidatesTitle') }}</h3>
        <el-button
          size="small"
          link
          @click="loadCandidates"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </div>
      <p class="muted">
        {{ $t('changeSecretPlans.candidatesHint') }}
      </p>
      <el-table
        v-loading="candidatesLoading"
        :data="candidates"
        size="small"
      >
        <el-table-column
          :label="$t('common.asset')"
          min-width="140"
        >
          <template #default="{ row }">
            {{ assetName(row.asset_id) }}
          </template>
        </el-table-column>
        <el-table-column
          prop="account_username"
          :label="$t('changeSecretPlans.colAccount')"
          min-width="110"
        />
        <el-table-column
          :label="$t('changeSecretPlans.colSecretType')"
          width="100"
        >
          <template #default="{ row }">
            {{ secretTypeText(row.secret_type) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretPlans.colState')"
          width="150"
        >
          <template #default="{ row }">
            <el-tag :type="candidateTagType(row)">
              {{ candidateStateText(row) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="attempt_count"
          :label="$t('changeSecretPlans.colAttempts')"
          width="90"
        />
        <el-table-column
          :label="$t('changeSecretPlans.colNextAttempt')"
          width="170"
        >
          <template #default="{ row }">
            {{ row.abandoned ? '-' : formatDateTime(row.next_attempt_at) }}
          </template>
        </el-table-column>
        <el-table-column
          prop="last_error"
          :label="$t('changeSecretPlans.colLastError')"
          min-width="180"
          show-overflow-tooltip
        >
          <template #default="{ row }">
            {{ reasonText(row.last_error) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="160"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              size="small"
              type="primary"
              link
              @click="retryCandidate(row)"
            >
              {{ $t('changeSecretPlans.retryNow') }}
            </el-button>
            <el-button
              size="small"
              type="danger"
              link
              @click="discardCandidate(row)"
            >
              {{ $t('changeSecretPlans.discard') }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState :title="$t('changeSecretPlans.candidatesEmpty')" />
        </template>
      </el-table>
    </div>

    <!-- 建立/編輯 -->
    <el-dialog
      v-model="dialogVisible"
      :title="editingId ? $t('changeSecretPlans.editPlan') : $t('changeSecretPlans.createPlan')"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-form
        ref="formRef"
        :model="form"
        :rules="formRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.name')"
          prop="name"
        >
          <el-input
            v-model="form.name"
            maxlength="128"
          />
        </el-form-item>
        <el-form-item
          :label="$t('common.asset')"
          prop="asset_ids"
        >
          <el-select
            v-model="form.asset_ids"
            multiple
            filterable
            :placeholder="$t('changeSecretPlans.selectSshAsset')"
            style="width: 100%"
          >
            <el-option
              v-for="a in sshAssets"
              :key="a.id"
              :label="`${a.name} (${a.host})`"
              :value="a.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('changeSecretPlans.accountScope')">
          <el-radio-group v-model="form.accountScopeMode">
            <el-radio-button value="all">
              {{ $t('changeSecretPlans.accountScopeAll') }}
            </el-radio-button>
            <el-radio-button value="named">
              {{ $t('changeSecretPlans.accountScopeNamed') }}
            </el-radio-button>
          </el-radio-group>
          <el-select
            v-if="form.accountScopeMode === 'named'"
            v-model="form.accounts"
            multiple
            filterable
            allow-create
            default-first-option
            :reserve-keyword="false"
            :placeholder="$t('changeSecretPlans.accountPlaceholder')"
            style="width: 100%; margin-top: 8px"
          >
            <el-option
              v-for="name in knownAccountNames"
              :key="name"
              :label="name"
              :value="name"
            />
          </el-select>
          <div
            v-else
            class="muted"
          >
            {{ $t('changeSecretPlans.accountScopeHint') }}
          </div>
        </el-form-item>
        <el-form-item :label="$t('changeSecretPlans.secretType')">
          <el-radio-group v-model="form.secret_type">
            <el-radio-button value="password">
              {{ $t('changeSecretPlans.secretTypePassword') }}
            </el-radio-button>
            <el-radio-button value="ssh_key">
              {{ $t('changeSecretPlans.secretTypeSshKey') }}
            </el-radio-button>
          </el-radio-group>
        </el-form-item>
        <template v-if="form.secret_type === 'ssh_key'">
          <el-form-item :label="$t('changeSecretPlans.keyStrategy')">
            <el-select
              v-model="form.key_strategy"
              style="width: 100%"
            >
              <el-option
                value="append_replace"
                :label="$t('changeSecretPlans.keyStrategyAppendReplace')"
              />
              <el-option
                value="exclusive"
                :label="$t('changeSecretPlans.keyStrategyExclusive')"
              />
            </el-select>
            <el-alert
              v-if="form.key_strategy === 'exclusive'"
              type="warning"
              :closable="false"
              show-icon
              :title="$t('changeSecretPlans.keyStrategyExclusiveWarning')"
              style="margin-top: 8px"
            />
          </el-form-item>
        </template>
        <template v-else>
          <el-form-item :label="$t('changeSecretPlans.passwordPolicy')">
            <div class="policy-row">
              <span class="policy-label">{{ $t('changeSecretPlans.passwordLength') }}</span>
              <el-input-number
                v-model="form.password_length"
                :min="12"
                :max="64"
              />
            </div>
            <div class="policy-row">
              <el-checkbox v-model="form.password_include_symbol">
                {{ $t('changeSecretPlans.passwordIncludeSymbol') }}
              </el-checkbox>
              <el-checkbox v-model="form.password_exclude_ambiguous">
                {{ $t('changeSecretPlans.passwordExcludeAmbiguous') }}
              </el-checkbox>
            </div>
            <div class="muted">
              {{ $t('changeSecretPlans.passwordLengthHint') }}
            </div>
          </el-form-item>
        </template>
        <el-form-item :label="$t('changeSecretPlans.scheduleCron')">
          <el-input
            v-model="form.cron"
            :placeholder="$t('changeSecretPlans.cronPlaceholder')"
          />
        </el-form-item>
        <el-form-item :label="$t('common.enabled')">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="saving"
          :disabled="!form.name || !form.asset_ids.length"
          @click="submit"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 執行記錄 -->
    <el-dialog
      v-model="recordsVisible"
      :title="$t('changeSecretPlans.recordsTitle', { name: recordsPlanName })"
      width="680px"
    >
      <el-table
        :data="records"
        size="small"
        max-height="400"
      >
        <el-table-column
          :label="$t('common.asset')"
          min-width="140"
        >
          <template #default="{ row }">
            {{ assetName(row.asset_id) }}
          </template>
        </el-table-column>
        <el-table-column
          prop="account_username"
          :label="$t('changeSecretPlans.colAccount')"
          min-width="110"
        />
        <el-table-column
          :label="$t('common.status')"
          width="120"
        >
          <template #default="{ row }">
            <el-tag :type="recordTagType(row.status)">
              {{ recordStatusText(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          prop="error"
          :label="$t('changeSecretPlans.colMessage')"
          min-width="200"
          show-overflow-tooltip
        >
          <template #default="{ row }">
            {{ reasonText(row.error) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.time')"
          width="170"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.executed_at) }}
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { formatDateTime } from '@/utils/format'
import { t, te } from '@/i18n'
import { getAssetList } from '@/api/assets'
import {
  getChangeSecretPlans,
  createChangeSecretPlan,
  updateChangeSecretPlan,
  deleteChangeSecretPlan,
  runChangeSecretPlan,
  getChangeSecretRecords,
  getChangeSecretCandidates,
  retryChangeSecretCandidate,
  discardChangeSecretCandidate,
} from '@/api/changeSecret'

const plans = ref([])
const sshAssets = ref([])
const loading = ref(false)
const saving = ref(false)
const dialogVisible = ref(false)
const editingId = ref(null)
const formRef = ref(null)
const form = ref(emptyForm())

// 出廠預設與後端 applyPlanFields 一致：未帶欄位時取「含符號、排除易混淆、長度 16」，
// 不是 Go 零值——否則「沒填」會靜默變成「關閉」
function emptyForm() {
  return {
    name: '',
    asset_ids: [],
    accountScopeMode: 'all',
    accounts: [],
    secret_type: 'password',
    key_strategy: 'append_replace',
    password_length: 16,
    password_include_symbol: true,
    password_exclude_ambiguous: true,
    cron: '',
    enabled: true,
  }
}

const candidates = ref([])
const candidatesLoading = ref(false)

const formRules = computed(() => ({
  name: [
    { required: true, message: t('changeSecretPlans.nameRequired'), trigger: 'blur' },
  ],
  asset_ids: [
    { required: true, type: 'array', min: 1, message: t('changeSecretPlans.assetRequired'), trigger: 'change' },
  ],
}))

const recordsVisible = ref(false)
const records = ref([])
const recordsPlanName = ref('')

// 執行記錄以資產名稱呈現（查無對照時退回 ID）
function assetName(assetId) {
  const asset = sshAssets.value.find((a) => a.id === assetId)
  return asset ? asset.name : t('changeSecretPlans.assetFallback', { id: assetId })
}

// 帳號範圍：空值一律讀成 @ALL（與後端 PlanAccountScope 的回歸安全方向一致）
function parseAccounts(jsonStr) {
  try {
    return JSON.parse(jsonStr) || []
  } catch {
    return []
  }
}

function isAllAccounts(jsonStr) {
  const list = parseAccounts(jsonStr)
  return list.length === 0 || list.includes('@ALL')
}

function secretTypeText(type) {
  return type === 'ssh_key'
    ? t('changeSecretPlans.secretTypeSshKey')
    : t('changeSecretPlans.secretTypePassword')
}

function candidateTagType(row) {
  if (row.abandoned) return 'danger'
  return row.applied ? 'warning' : 'info'
}

function candidateStateText(row) {
  if (row.abandoned) return t('changeSecretPlans.stateAbandoned')
  return row.applied
    ? t('changeSecretPlans.stateApplied')
    : t('changeSecretPlans.stateUnknown')
}

// 既有計劃的帳號名稱聯集，供輸入時挑選（仍允許自由輸入）
const knownAccountNames = computed(() => {
  const set = new Set()
  plans.value.forEach((p) => {
    parseAccounts(p.accounts).forEach((name) => {
      if (name !== '@ALL') set.add(name)
    })
  })
  candidates.value.forEach((c) => {
    if (c.account_username) set.add(c.account_username)
  })
  return [...set]
})

function parseAssetIds(jsonStr) {
  try {
    return JSON.parse(jsonStr) || []
  } catch {
    return []
  }
}

async function load() {
  loading.value = true
  try {
    const res = await getChangeSecretPlans()
    plans.value = res.data || []
  } catch (err) {
    console.error('[ChangeSecret] 載入計劃失敗:', err)
  } finally {
    loading.value = false
  }
}

async function loadAssets() {
  try {
    const res = await getAssetList({ page: 1, page_size: 100 })
    sshAssets.value = (res.data || []).filter((a) => a.protocol === 'ssh')
  } catch (err) {
    console.error('[ChangeSecret] 載入資產失敗:', err)
  }
}

function openCreate() {
  editingId.value = null
  form.value = emptyForm()
  dialogVisible.value = true
}

function openEdit(row) {
  editingId.value = row.id
  const named = parseAccounts(row.accounts).filter((a) => a !== '@ALL')
  form.value = {
    name: row.name,
    asset_ids: parseAssetIds(row.asset_ids),
    accountScopeMode: isAllAccounts(row.accounts) ? 'all' : 'named',
    accounts: named,
    secret_type: row.secret_type || 'password',
    key_strategy: row.key_strategy || 'append_replace',
    password_length: row.password_length || 16,
    password_include_symbol: row.password_include_symbol !== false,
    password_exclude_ambiguous: row.password_exclude_ambiguous !== false,
    cron: row.cron,
    enabled: row.enabled,
  }
  dialogVisible.value = true
}

// buildPayload 把表單的 UI 狀態轉成後端契約：帳號範圍以 @ALL 表達「全部」，
// 密碼策略在金鑰型別下仍照送（後端只在密碼路徑讀它，送了不影響語義）
function buildPayload() {
  const f = form.value
  return {
    name: f.name,
    asset_ids: f.asset_ids,
    accounts: f.accountScopeMode === 'all' ? ['@ALL'] : f.accounts,
    secret_type: f.secret_type,
    key_strategy: f.key_strategy,
    password_length: f.password_length,
    password_include_symbol: f.password_include_symbol,
    password_exclude_ambiguous: f.password_exclude_ambiguous,
    cron: f.cron,
    enabled: f.enabled,
  }
}

async function loadCandidates() {
  candidatesLoading.value = true
  try {
    const res = await getChangeSecretCandidates()
    candidates.value = res.data || []
  } catch (err) {
    console.error('[ChangeSecret] 載入未驗證憑證失敗:', err)
  } finally {
    candidatesLoading.value = false
  }
}

async function retryCandidate(row) {
  try {
    const res = await retryChangeSecretCandidate(row.id)
    ElMessage.success(
      res.promoted
        ? t('changeSecretPlans.retryPromoted')
        : t('changeSecretPlans.retryStillFailing')
    )
    loadCandidates()
  } catch (err) {
    console.error('[ChangeSecret] 重試候選憑證失敗:', err)
  }
}

async function discardCandidate(row) {
  try {
    await ElMessageBox.confirm(
      t('changeSecretPlans.discardConfirm', {
        asset: assetName(row.asset_id),
        account: row.account_username,
      }),
      t('changeSecretPlans.discardConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return // 使用者取消
  }
  try {
    await discardChangeSecretCandidate(row.id)
    ElMessage.success(t('changeSecretPlans.discarded'))
    loadCandidates()
  } catch (err) {
    console.error('[ChangeSecret] 清除候選憑證失敗:', err)
  }
}

async function submit() {
  try {
    await formRef.value.validate()
  } catch {
    return // 驗證未過，紅字就近提示
  }
  saving.value = true
  try {
    const payload = buildPayload()
    if (editingId.value) {
      await updateChangeSecretPlan(editingId.value, payload)
    } else {
      await createChangeSecretPlan(payload)
    }
    ElMessage.success(t('changeSecretPlans.saved'))
    dialogVisible.value = false
    load()
  } catch (err) {
    console.error('[ChangeSecret] 儲存失敗:', err)
  } finally {
    saving.value = false
  }
}

async function triggerRun(row) {
  try {
    await ElMessageBox.confirm(
      t('changeSecretPlans.runConfirm', { name: row.name, count: parseAssetIds(row.asset_ids).length }),
      t('changeSecretPlans.runConfirmTitle'),
      { type: 'warning' }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await runChangeSecretPlan(row.id)
    ElMessage.success(t('changeSecretPlans.runTriggered'))
  } catch (err) {
    console.error('[ChangeSecret] 觸發執行失敗:', err)
  }
}

async function openRecords(row) {
  recordsPlanName.value = row.name
  try {
    const res = await getChangeSecretRecords(row.id)
    records.value = res.data || []
    recordsVisible.value = true
  } catch (err) {
    console.error('[ChangeSecret] 載入記錄失敗:', err)
  }
}

async function removePlan(row) {
  try {
    await ElMessageBox.confirm(
      t('changeSecretPlans.deleteConfirm', { name: row.name }),
      t('common.deleteConfirmTitle'),
      { confirmButtonText: t('common.deleteConfirmButton'), cancelButtonText: t('common.cancel'), type: 'warning' }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await deleteChangeSecretPlan(row.id)
    ElMessage.success(t('changeSecretPlans.deleted'))
    load()
  } catch (err) {
    console.error('[ChangeSecret] 刪除計劃失敗:', err)
  }
}

function recordTagType(status) {
  return { success: 'success', failed: 'danger', unverified: 'warning', skipped: 'info' }[status] || 'info'
}

// reasonText 改密結果原因碼 → 在地化文案。
//
// 後端的 record.error／candidate.last_error 只回機器碼（遠端回傳的原文一律
// 不進這兩欄——那是攻擊者可控輸入，且會隨告警離開產品邊界），遠端細節只留在
// 伺服器日誌，故對應文案會提示「詳細遠端訊息見伺服器日誌」。
// 找不到對應鍵（歷史資料留下的舊散文訊息）則原樣顯示。
function reasonText(code) {
  if (!code) return ''
  const key = `changeSecretPlans.reason.${code}`
  return te(key) ? t(key) : code
}

function recordStatusText(status) {
  return {
    success: t('changeSecretPlans.recordStatus.success'),
    failed: t('changeSecretPlans.recordStatus.failed'),
    unverified: t('changeSecretPlans.recordStatus.unverified'),
    skipped: t('changeSecretPlans.recordStatus.skipped'),
  }[status] || status
}

onMounted(() => {
  load()
  loadAssets()
  loadCandidates()
})
</script>

<style scoped>
.list-panel {
  background: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
  padding: var(--ot-space-md);
  min-height: 400px;
}

.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}

.candidates-panel {
  margin-top: var(--ot-space-md);
  min-height: 0;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.panel-head h3 {
  margin: 0;
  font-size: 15px;
}

.policy-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-md);
  margin-bottom: 8px;
}

.policy-label {
  font-size: 13px;
  color: var(--el-text-color-regular);
}
</style>
