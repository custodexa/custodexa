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

    <!-- 升級時查不到可歸屬發起者的排程計畫：cron 與啟用設定都在，只是暫停；
         一個按鈕改由目前操作者承接（之後仍以其當下權限逐次重驗），不要求逐筆編輯 -->
    <el-alert
      v-if="pausedPlans.length"
      type="warning"
      :closable="false"
      show-icon
      class="paused-banner"
      :title="$t('changeSecretPlans.reauthorize.banner', { count: pausedPlans.length })"
      data-test="paused-plans-banner"
    >
      <el-button
        type="warning"
        size="small"
        :loading="reauthorizing"
        data-test="reauthorize-plans"
        @click="reauthorizePaused"
      >
        {{ $t('changeSecretPlans.reauthorize.button') }}
      </el-button>
    </el-alert>

    <div class="list-panel">
      <el-table
        v-loading="loading"
        :data="plans"
        stripe
      >
        <el-table-column
          :label="$t('common.name')"
          min-width="140"
        >
          <template #default="{ row }">
            {{ row.name }}
            <!-- 上界暫停：與「升級後無法確認發起者」的橫幅分開，原因逐筆寫在計畫旁 -->
            <div
              v-if="needsReconfirmation(row)"
              class="reconfirm-reason"
              :data-test="`plan-reconfirm-reason-${row.id}`"
            >
              <el-tag
                size="small"
                type="warning"
              >
                {{ $t('changeSecretPlans.reconfirmTag') }}
              </el-tag>
              {{ reasonText('CHANGE_SECRET_SCOPE_BOUND_EXCEEDED') }}
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('changeSecretPlans.colAssetCount')"
          width="90"
        >
          <template #default="{ row }">
            {{ parseAssetIds(row.asset_ids).length }}
            <el-tag
              v-if="row.out_of_scope_asset_count > 0"
              size="small"
              type="info"
              :data-test="`plan-assets-out-${row.id}`"
            >
              {{ $t('credentials.outOfScopeChip', { count: row.out_of_scope_asset_count }) }}
            </el-tag>
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
            <template v-if="row.cron">
              <code v-if="isCustomSchedule(row.cron)">{{ row.cron }}</code>
              <span
                v-else
                :data-test="`plan-schedule-${row.id}`"
              >{{ describeSchedule(row.cron) }}</span>
              <div
                v-if="nextRunText(row.cron)"
                class="muted"
              >
                {{ nextRunText(row.cron) }}
              </div>
            </template>
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
              v-if="canRun(row)"
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
              v-if="needsReconfirmation(row) && !isScopeMasked(row)"
              size="small"
              type="warning"
              link
              :data-test="`plan-reconfirm-${row.id}`"
              @click="startReconfirm(row)"
            >
              {{ $t('changeSecretPlans.reconfirmButton') }}
            </el-button>
            <el-button
              v-if="!isScopeMasked(row)"
              size="small"
              type="primary"
              link
              @click="openEdit(row)"
            >
              {{ $t('common.edit') }}
            </el-button>
            <el-tooltip
              v-else
              :content="$t('changeSecretPlans.scopedMaskedNote')"
              placement="top"
            >
              <el-tag
                size="small"
                type="info"
                :data-test="`plan-scoped-readonly-${row.id}`"
              >
                {{ $t('changeSecretPlans.scopedReadOnly') }}
              </el-tag>
            </el-tooltip>
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
          :label="$t('changeSecretPlans.colChannel')"
          width="150"
        >
          <template #default="{ row }">
            <el-tag
              v-if="assetChannelText(row.asset_id)"
              size="small"
              :type="assetChannelTagType(row.asset_id)"
              effect="plain"
            >
              {{ assetChannelText(row.asset_id) }}
            </el-tag>
            <span
              v-else
              class="muted"
            >—</span>
          </template>
        </el-table-column>
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
            <span
              v-if="!row.abandoned && isHostIdentityStopped(row)"
              data-test="candidate-host-identity-pending"
            >{{ $t('changeSecretPlans.hostIdentityPending') }}</span>
            <template v-else>
              {{ row.abandoned ? '-' : formatDateTime(row.next_attempt_at) }}
            </template>
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
            :placeholder="$t('changeSecretPlans.selectAsset')"
            style="width: 100%"
            data-test="plan-assets"
          >
            <!-- 只列有效通道非 none 的資產；通道 tag 讓管理者在選的當下就看到
                 這台會走哪條路（http 的 WinRM 走 warning 色，與傳輸階梯同向） -->
            <el-option
              v-for="a in rotatableAssets"
              :key="a.id"
              :label="`${a.name} (${a.host})`"
              :value="a.id"
            >
              <span class="asset-option">
                <span class="asset-option__name">{{ a.name }}</span>
                <span class="asset-option__host muted">{{ a.host }}:{{ a.port }}</span>
                <el-tag
                  size="small"
                  :type="rotationChannelTagType(a)"
                  effect="plain"
                  class="asset-option__channel"
                >
                  {{ rotationChannelText(a) }}
                </el-tag>
              </span>
            </el-option>
          </el-select>
          <div
            class="muted"
            data-test="plan-assets-hint"
          >
            {{ $t('changeSecretPlans.assetPickerHint') }}
          </div>
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
          <div
            v-if="form.secret_type === 'ssh_key' && selectedWindowsAssets.length"
            class="muted"
            data-test="secret-type-windows-hint"
          >
            {{ $t('changeSecretPlans.secretTypeWindowsHint') }}
          </div>
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
          <ScheduleFrequencyPicker
            v-model="form.cron"
            v-model:valid="scheduleValid"
            allow-empty
            :custom-placeholder="$t('changeSecretPlans.cronPlaceholder')"
            data-test="plan-schedule-picker"
          />
        </el-form-item>
        <!-- 憑證最長使用天數覆蓋：只影響輪替證據報告的適用天數，
             不改變本計劃的執行時機或改密行為。0＝沿用全域政策鍵 -->
        <el-form-item :label="$t('changeSecretPlans.maxAgeDays')">
          <el-input-number
            v-model="form.max_age_days"
            :min="0"
            :max="3650"
            :step="1"
            step-strictly
            data-test="plan-max-age-days"
          />
          <div class="muted">
            {{ $t('changeSecretPlans.maxAgeDaysHint') }}
          </div>
        </el-form-item>
        <el-form-item :label="$t('common.enabled')">
          <el-switch v-model="form.enabled" />
        </el-form-item>
      </el-form>
      <el-alert
        :title="$t('changeSecretPlans.saveNotice')"
        type="info"
        :closable="false"
        show-icon
        data-test="plan-save-notice"
      />
      <template #footer>
        <el-button @click="dialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="saving"
          :disabled="!form.name || !form.asset_ids.length || !scheduleValid"
          @click="submit"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 重新確認：範圍外只給台數，由其他管理者負責，這裡不列出 -->
    <el-dialog
      :model-value="reconfirmVisible"
      :title="impactMode === 'edit' ? $t('credentials.impact.title') : $t('changeSecretPlans.reconfirmTitle')"
      width="520px"
      :close-on-click-modal="false"
      data-test="reconfirm-dialog"
      @update:model-value="(v) => { if (!v) cancelReconfirm() }"
    >
      <p
        v-if="impactMode !== 'edit'"
        data-test="reconfirm-body"
      >
        {{ $t('changeSecretPlans.reconfirmBody', { count: reconfirmCount }) }}
      </p>
      <el-checkbox
        v-model="reconfirmAck"
        data-test="reconfirm-ack"
      >
        {{ impactMode === 'edit'
          ? $t('credentials.impact.ackRotate', { count: reconfirmCount })
          : $t('changeSecretPlans.reconfirmAck', { count: reconfirmCount }) }}
      </el-checkbox>
      <template #footer>
        <el-button @click="cancelReconfirm">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="reconfirmWorking"
          :disabled="!reconfirmAck"
          data-test="reconfirm-submit"
          @click="submitReconfirm"
        >
          {{ $t('changeSecretPlans.reconfirmSubmit') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 執行記錄 -->
    <el-dialog
      v-model="recordsVisible"
      :title="$t('changeSecretPlans.recordsTitle', { name: recordsPlanName })"
      width="960px"
    >
      <p
        class="muted"
        data-test="records-summary"
      >
        {{ $t('changeSecretPlans.recordsSummary', recordsSummary) }}
      </p>
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
        <!-- 通道由資產現況推得（記錄本身不存通道）：資產已改通道或已刪時顯示佔位 -->
        <el-table-column
          :label="$t('changeSecretPlans.colChannel')"
          width="150"
          class-name="col-channel"
        >
          <template #default="{ row }">
            <el-tag
              v-if="assetChannelText(row.asset_id)"
              size="small"
              :type="assetChannelTagType(row.asset_id)"
              effect="plain"
            >
              {{ assetChannelText(row.asset_id) }}
            </el-tag>
            <span
              v-else
              class="muted"
            >—</span>
          </template>
        </el-table-column>
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
      <p
        class="muted"
        data-test="records-note"
      >
        {{ $t('changeSecretPlans.recordsNote') }}
      </p>
    </el-dialog>
    <HostIdentityConfirmDialog
      v-model="hostIdentityDialog.visible"
      :asset="hostIdentityDialog.asset"
      :account="hostIdentityDialog.account"
      :identity="hostIdentityDialog.identity"
      kind="candidate"
      :submitting="hostIdentityDialog.submitting"
      @confirm="confirmHostIdentity"
    />
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import ScheduleFrequencyPicker from '@/components/ScheduleFrequencyPicker.vue'
import HostIdentityConfirmDialog from '@/components/HostIdentityConfirmDialog.vue'
import { formatDateTime } from '@/utils/format'
import { CUSTOM_MODE, describeSchedule, formatRunTime, parseCron } from '@/utils/cron-shape'
import { t, te } from '@/i18n'
import { can } from '@/composables/useCapabilities'
import { useCredentialImpactFlow, skipImpactConflictToast, isImpactConflict } from '@/composables/useCredentialImpactFlow'
import { resolveApiError } from '@/api/error'
import { getAssetList } from '@/api/assets'
import { getScheduleNextRuns } from '@/api/schedules'
import {
  effectiveRotationChannel,
  isRotatableAsset,
  rotationChannelText,
  rotationChannelTagType,
} from '@/constants/rotationChannel'
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
  reauthorizeChangeSecretPlans,
} from '@/api/changeSecret'

const plans = ref([])

// 排程時刻：列表講人話，下次執行時刻問後端（同一個時刻表只問一次）。
// 取不到就不顯示那一行——列表不是交代失敗原因的地方，編輯表單才是。
const scheduleValid = ref(true)
const nextRunByCron = ref({})

const isCustomSchedule = (cron) => parseCron(cron).mode === CUSTOM_MODE

function nextRunText(cron) {
  const run = nextRunByCron.value[cron]
  return run ? t('scheduleFrequency.nextRun', { time: run }) : ''
}

async function loadNextRuns(crons) {
  const distinct = [...new Set(crons.filter(Boolean))]
  const pairs = await Promise.all(
    distinct.map(async (cron) => {
      try {
        const res = await getScheduleNextRuns({ cron, count: 1 }, { skipErrorToast: true })
        const run = Array.isArray(res?.runs) ? res.runs[0] : null
        return [cron, run ? formatRunTime(run) : '']
      } catch {
        return [cron, '']
      }
    })
  )
  nextRunByCron.value = Object.fromEntries(pairs.filter(([, run]) => run))
}

// 全部資產供名稱與通道查表（記錄可能指向已不參與改密的資產）；
// 下拉只列有效通道非 none 者——未設通道的 rdp 資產在這裡就選不到，
// 而不是選了才在執行期被記為略過
const assets = ref([])
const rotatableAssets = computed(() => assets.value.filter(isRotatableAsset))

function assetById(assetId) {
  return assets.value.find((a) => a.id === assetId)
}

// 記錄與候選的通道欄由資產現況推得（兩者本身不存通道）；查無資產或通道為 none 回空字串
function assetChannelText(assetId) {
  const asset = assetById(assetId)
  return asset ? rotationChannelText(asset) : ''
}

function assetChannelTagType(assetId) {
  const asset = assetById(assetId)
  return asset ? rotationChannelTagType(asset) : 'info'
}

// 已選資產中走 Windows 通道者：金鑰型別對它們只會記為略過，選型時就提示
const selectedWindowsAssets = computed(() =>
  (form.value.asset_ids || [])
    .map(assetById)
    .filter((a) => a && effectiveRotationChannel(a).startsWith('windows_'))
)
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
    max_age_days: 0,
    enabled: true,
    target_kind: 'account',
    target_credential_id: 0,
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

// 記錄對話框的結果統計（四態計數，與 recordStatusText 的狀態集一致）
const recordsSummary = computed(() => {
  const counts = { total: records.value.length, success: 0, failed: 0, unverified: 0, skipped: 0 }
  records.value.forEach((r) => {
    if (r.status in counts) counts[r.status] += 1
  })
  return counts
})

// 執行記錄以資產名稱呈現（查無對照時退回 ID）
function assetName(assetId) {
  const asset = assetById(assetId)
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
    await loadNextRuns(plans.value.map((plan) => plan.cron))
  } catch (err) {
    console.error('[ChangeSecret] 載入計劃失敗:', err)
  } finally {
    loading.value = false
  }
}

async function loadAssets() {
  try {
    const res = await getAssetList({ page: 1, page_size: 100 })
    assets.value = res.data || []
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
    max_age_days: row.max_age_days || 0,
    enabled: row.enabled,
    // 目標欄不在表單上編輯，但儲存時要原樣帶回；漏帶會讓憑證目標計畫被存成帳號目標
    target_kind: row.target_kind || 'account',
    target_credential_id: row.target_credential_id || 0,
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
    max_age_days: f.max_age_days,
    enabled: f.enabled,
    // 帳號目標維持原本的請求本文（不帶目標欄），憑證目標才帶
    ...(f.target_kind === 'credential'
      ? { target_kind: 'credential', target_credential_id: f.target_credential_id }
      : {}),
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

const HOST_IDENTITY_STOP_CODE = 'CHANGE_SECRET_HOST_IDENTITY_CHANGED'
const TARGET_CHANGED_CODE = 'CHANGE_SECRET_AUTHZ_TARGET_CHANGED'

// 背景每輪仍會取出並在連線前擋下，排程時間會讓人以為之後自動處理，故改顯示待確認
function isHostIdentityStopped(row) {
  return row.last_error === HOST_IDENTITY_STOP_CODE
}

const hostIdentityDialog = ref({
  visible: false,
  row: null,
  asset: '',
  account: '',
  identity: null,
  submitting: false,
})

function openHostIdentityDialog(row, identity) {
  hostIdentityDialog.value = {
    visible: true,
    row,
    asset: assetName(row.asset_id),
    account: row.account_username,
    identity,
    submitting: false,
  }
}

function closeHostIdentityDialog() {
  hostIdentityDialog.value = { ...hostIdentityDialog.value, visible: false, submitting: false }
}

// 409 的 detail 由後端放在回應本文；對應說明沿用對話框既有文案
const CONFLICT_DETAIL_KEY = {
  not_confirmable: 'hostIdentityConfirm.blocked.contactAdmin',
  different_key_not_accepted: 'hostIdentityConfirm.differentKey.title',
  confirmation_pending: 'hostIdentityConfirm.result.moved',
}

function handleConfirmConflict(err) {
  const detail = err?.response?.data?.detail
  // API 層已關閉此請求的全域錯誤 toast，只由這裡顯示一則（error 等級）
  ElMessage.error(t(CONFLICT_DETAIL_KEY[detail] || 'hostIdentityConfirm.result.moved'))
  closeHostIdentityDialog()
  loadCandidates()
}

// confirmBody 為空：一般重試；有值：帶主機身分確認重送
async function retryCandidate(row, confirmBody) {
  const confirming = !!confirmBody
  try {
    const res = confirming
      ? await retryChangeSecretCandidate(row.id, { confirm_host_identity: confirmBody })
      : await retryChangeSecretCandidate(row.id)
    if (res?.host_identity) {
      // 主機身分變更而停下：交給使用者確認，不當成已排入重試
      if (confirming) ElMessage.error(t('hostIdentityConfirm.result.moved'))
      openHostIdentityDialog(row, res.host_identity)
      loadCandidates()
      return
    }
    if (confirming) {
      closeHostIdentityDialog()
      if (res?.promoted) {
        ElMessage.success(t('hostIdentityConfirm.result.verified'))
      } else if (res?.reason === TARGET_CHANGED_CODE) {
        ElMessage.warning(reasonText(res.reason))
      } else {
        // 確認只驗證一次，不會自動再排程，不沿用「已排入下次重試」
        ElMessage.warning(t('hostIdentityConfirm.result.notVerified'))
      }
    } else if (res?.reason === TARGET_CHANGED_CODE) {
      ElMessage.warning(reasonText(res.reason))
    } else {
      ElMessage.success(
        res.promoted
          ? t('changeSecretPlans.retryPromoted')
          : t('changeSecretPlans.retryStillFailing')
      )
    }
    loadCandidates()
  } catch (err) {
    if (confirming && err?.response?.status === 409 &&
        err.response.data?.code === 'CONFLICT_HOST_IDENTITY_MOVED') {
      handleConfirmConflict(err)
      return
    }
    if (confirming) closeHostIdentityDialog()
    console.error('[ChangeSecret] 重試候選憑證失敗:', err)
  }
}

async function confirmHostIdentity(payload) {
  const row = hostIdentityDialog.value.row
  if (!row) return
  hostIdentityDialog.value = { ...hostIdentityDialog.value, submitting: true }
  await retryCandidate(row, payload)
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
    const id = editingId.value
    const send = (extra = {}) =>
      id
        ? updateChangeSecretPlan(id, { ...payload, ...extra }, { skipErrorToast: skipImpactConflictToast })
        : createChangeSecretPlan({ ...payload, ...extra }, { skipErrorToast: skipImpactConflictToast })
    if (payload.target_kind === 'credential') {
      // 共用憑證目標：先送出計畫本文；只有後端要求影響確認才取確認並開對話框，
      // 這樣沒有輪替能力的計畫管理者改名、停用不會被確認端點擋住
      impactCredentialId.value = payload.target_credential_id
      afterImpactSent = afterSaved
      impactMode.value = 'edit'
      if (await startSendFirst(send)) await afterSaved()
    } else {
      await send()
      await afterSaved()
    }
  } catch (err) {
    console.error('[ChangeSecret] 儲存失敗:', err)
    reportImpactConflict(err)
  } finally {
    saving.value = false
  }
}

// 影響確認的 409 已被關掉全域提示；走到這裡代表重查後無法完成，要讓使用者看到原因
function reportImpactConflict(err) {
  if (isImpactConflict(err)) ElMessage.error(resolveApiError(err.response.data, err.response.status))
}

async function afterSaved() {
  ElMessage.success(t('changeSecretPlans.saved'))
  dialogVisible.value = false
  await load()
}

// 立即執行需要對應的語義能力：帳號目標看帳號改密、憑證目標看憑證輪替。
// 這裡只決定要不要顯示按鈕，強制點在後端（執行前逐次重驗）
// 計畫含檢視範圍外的目標憑證或資產時，伺服器已遮蔽這些識別；以遮蔽後的內容儲存會改掉計畫，故只允許檢視。
const isScopeMasked = (row) => !!row.credential_out_of_scope || row.out_of_scope_asset_count > 0

function canRun(row) {
  return can(row.target_kind === 'credential' ? 'credential:rotate' : 'account:rotate')
}

// 上界暫停（needs_reconfirmation）：憑證新增了發起者未確認過的範圍外主機。
// 範圍化發起者只能重新確認並儲存；確認台數取自伺服器的確認回應，前端不自行計算範圍
const needsReconfirmation = (row) => row.authorization_state === 'needs_reconfirmation'

// 影響確認流程由「重新確認」與一般儲存共用；確認後的收尾各自指定
const impactCredentialId = ref(null)
// 'reconfirm'＝計畫已被暫停、確認後恢復執行；'edit'＝一般編輯儲存，文案不提恢復
const impactMode = ref('reconfirm')
let afterImpactSent = null
const reconfirmAck = ref(false)
const {
  visible: reconfirmVisible,
  impact: reconfirmImpact,
  working: reconfirmWorking,
  epoch: reconfirmEpoch,
  start: startImpact,
  startSendFirst,
  confirm: confirmImpact,
  cancel: cancelReconfirm,
} = useCredentialImpactFlow(() => impactCredentialId.value, 'rotate')
const reconfirmCount = computed(() => reconfirmImpact.value?.outOfScopeCount ?? 0)
watch(reconfirmEpoch, () => { reconfirmAck.value = false })

// 以現行計畫內容原樣重存（只換確認欄），不經編輯表單
function payloadFromRow(row) {
  const named = parseAccounts(row.accounts).filter((a) => a !== '@ALL')
  return {
    name: row.name,
    asset_ids: parseAssetIds(row.asset_ids),
    accounts: isAllAccounts(row.accounts) ? ['@ALL'] : named,
    secret_type: row.secret_type || 'password',
    key_strategy: row.key_strategy || 'append_replace',
    password_length: row.password_length || 16,
    password_include_symbol: row.password_include_symbol !== false,
    password_exclude_ambiguous: row.password_exclude_ambiguous !== false,
    cron: row.cron,
    max_age_days: row.max_age_days || 0,
    enabled: row.enabled,
    target_kind: row.target_kind,
    target_credential_id: row.target_credential_id,
  }
}

async function startReconfirm(row) {
  impactCredentialId.value = row.target_credential_id
  afterImpactSent = afterReconfirmed
  impactMode.value = 'reconfirm'
  const send = (extra) =>
    updateChangeSecretPlan(row.id, { ...payloadFromRow(row), ...extra }, { skipErrorToast: skipImpactConflictToast })
  try {
    if (await startImpact(send)) await afterReconfirmed()
  } catch (err) {
    console.error('[ChangeSecret] 重新確認失敗:', err)
  }
}

async function submitReconfirm() {
  if (!reconfirmAck.value) return
  try {
    if (await confirmImpact()) await afterImpactSent()
  } catch (err) {
    console.error('[ChangeSecret] 重新確認失敗:', err)
    reportImpactConflict(err)
  }
}

async function afterReconfirmed() {
  ElMessage.success(t('changeSecretPlans.reconfirmDone'))
  await load()
}

const pausedPlans = computed(() => plans.value.filter((plan) => plan.authorization_state === 'needs_reauthorization'))
const reauthorizing = ref(false)

async function reauthorizePaused() {
  try {
    await ElMessageBox.confirm(
      t('changeSecretPlans.reauthorize.confirm', { count: pausedPlans.value.length }),
      t('changeSecretPlans.reauthorize.confirmTitle'),
      { type: 'warning' }
    )
  } catch {
    return // 使用者取消
  }
  reauthorizing.value = true
  try {
    const res = await reauthorizeChangeSecretPlans()
    ElMessage.success(t('changeSecretPlans.reauthorize.done', { count: res?.count ?? 0 }))
    if (res?.skipped_plan_ids?.length) {
      ElMessage.warning(t('changeSecretPlans.reauthorize.skipped', { skipped: res.skipped_plan_ids.length }))
    }
    await load()
  } catch (err) {
    console.error('[ChangeSecret] 重新授權失敗:', err)
  } finally {
    reauthorizing.value = false
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
.reconfirm-reason {
  margin-top: 4px;
  font-size: 12px;
  color: var(--ot-text-secondary);
}

.paused-banner {
  margin-bottom: 12px;
}

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

.asset-option {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
}

.asset-option__host {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.asset-option__channel {
  flex: none;
}
</style>
