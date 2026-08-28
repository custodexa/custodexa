<template>
  <div class="key-management">
    <PageHeader
      :title="$t('menu.keyManagement')"
      :description="$t('keyManagement.description')"
    >
      <template #actions>
        <el-button @click="loadInventory">
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 狀態橫幅：KEK 重包待切換（legacy 遷移橫幅已隨過渡機制拆除） -->
    <el-alert
      v-if="inventory.rewrap_pending"
      type="warning"
      :closable="false"
      show-icon
      class="status-banner"
      :title="$t('keyManagement.rewrapPendingTitle')"
    >
      <!-- 「怎麼完成切換」依執行期 KEK provider 分岔（見 script 的 kekGuideMode）：
           ui 模式照 env 版本操作＝把根金鑰以明文寫上磁碟 -->
      <p class="rewrap-pending-desc">
        {{ rewrapPendingDescText }}
      </p>
      <el-button
        type="danger"
        text
        :loading="abandoning"
        class="abandon-rewrap-btn"
        @click="handleAbandonRewrap"
      >
        {{ $t('keyManagement.abandonRewrap') }}
      </el-button>
    </el-alert>
    <!-- 切換收尾雙態：retire_backlog>0＝收斂失敗 degraded（warning，指引重啟收斂）；
         僅 finalize_pending>0＝正常待切換（info）。並存時 degraded 優先，只顯示一則 -->
    <el-alert
      v-if="switchoverBanner"
      :type="switchoverBanner.type"
      :closable="false"
      show-icon
      class="status-banner"
      :title="switchoverBanner.title"
      :description="switchoverBanner.description"
    />
    <el-alert
      v-if="inventory.rotation_pending > 0"
      type="warning"
      :closable="false"
      show-icon
      class="status-banner"
      :title="$t('keyManagement.rotationPendingTitle')"
      :description="$t('keyManagement.rotationPendingDesc', { n: inventory.rotation_pending })"
    />
    <el-alert
      v-if="overCryptoperiodKeys.length > 0"
      type="info"
      :closable="false"
      show-icon
      class="status-banner"
      :title="$t('keyManagement.cryptoperiodTitle')"
      :description="$t('keyManagement.cryptoperiodDesc', {
        keys: overCryptoperiodKeys.map((k) => purposeLabel(k.purpose) + ' v' + k.version).join($t('common.listSeparator')),
        days: inventory.reminder_days,
      })"
    />

    <!-- 金鑰政策鍵設定區（域收編）：
         提醒天數與清冊同頁；儲存後重載清冊，超齡提醒即時反映 -->
    <PolicyPciBanner
      :loading="policyLoading"
      :saving="saving"
      :is-dirty="isDirty"
      :deviation-count="pageDeviationCount"
      :deviation-text="$t('policyForm.pageDeviation', { n: pageDeviationCount }, pageDeviationCount)"
      :overview-count="totalDeviationCount"
      :epayment-deviation-count="pageEPaymentDeviationCount"
      @apply="applyPagePCI"
      @apply-epayment="applyPageEPayment"
      @reset="resetForm"
      @save="handleSavePolicies"
    />

    <PolicyKeySections
      :sections="visibleSections"
      :form-values="formValues"
      :saved-values="savedValues"
      @update:value="(key, value) => (formValues[key] = value)"
    />

    <!-- DB 側金鑰版本鏈 -->
    <el-card
      v-loading="loading"
      class="section-card"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('keyManagement.systemKeysTitle') }}</span>
          <span class="card-hint">{{ $t('keyManagement.systemKeysHint') }}</span>
          <!-- 退役列呈現治理：退役列因稽核需求永久保留、只增不減，與現行列混排會讓
               現行鑰在數次輪替後被歷史淹沒。預設只顯示現行鑰，退役列由此切換帶出。
               零退役時整個控制不出現（全新安裝第一天零噪音） -->
          <el-checkbox
            v-if="retiredKeyCount > 0"
            v-model="showRetiredKeys"
            class="retired-toggle"
          >
            {{ $t('keyManagement.showRetiredKeys', { n: retiredKeyCount }) }}
          </el-checkbox>
        </div>
      </template>
      <el-table
        :data="displayedKeys"
        :row-class-name="keyRowClass"
        class="keys-table"
      >
        <el-table-column
          :label="$t('keyManagement.colPurpose')"
          min-width="160"
        >
          <template #default="{ row }">
            {{ purposeLabel(row.purpose) }}
          </template>
        </el-table-column>
        <!-- 欄寬 110：90 容不下 ja-JP 欄頭「バージョン」，會折成兩行 -->
        <el-table-column
          :label="$t('keyManagement.colVersion')"
          width="110"
        >
          <template #default="{ row }">
            <span class="mono-text">v{{ row.version }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.status')"
          width="110"
        >
          <template #default="{ row }">
            <el-tag
              :type="row.status === 'active' ? 'success' : 'info'"
              :class="{ 'retired-status-tag': row.status !== 'active' }"
              size="small"
            >
              {{ row.status === 'active' ? $t('keyManagement.statusActive') : $t('keyManagement.statusRetired') }}
            </el-tag>
            <!-- 已清理佔位：材料已顯式銷毀，指紋仍列供稽核比對 -->
            <el-tag
              v-if="row.material_purged && row.status === 'retired'"
              type="warning"
              size="small"
              effect="plain"
            >
              {{ $t('keyManagement.cleanedTag') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('keyManagement.colAge')"
          width="140"
        >
          <template #default="{ row }">
            {{ $t('format.durationDays', row.age_days) }}
            <el-tag
              v-if="row.over_cryptoperiod"
              type="warning"
              size="small"
              effect="plain"
            >
              {{ $t('keyManagement.overCryptoperiodTag') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.createdAt')"
          min-width="170"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('keyManagement.colRetiredAt')"
          min-width="170"
        >
          <template #default="{ row }">
            {{ row.retired_at ? formatDateTime(row.retired_at) : '—' }}
          </template>
        </el-table-column>
      </el-table>
      <div class="card-actions">
        <el-button
          type="primary"
          :loading="rotating === 'data'"
          :disabled="rotateDisabled('data')"
          @click="confirmRotate('data')"
        >
          {{ $t('keyManagement.rotateData') }}
        </el-button>
        <el-button
          :loading="rotating === 'audit_integrity'"
          :disabled="rotateDisabled('audit_integrity')"
          @click="confirmRotate('audit_integrity')"
        >
          {{ $t('keyManagement.rotateAudit') }}
        </el-button>
        <el-button
          :disabled="inventory.rewrap_pending || !!rotating"
          @click="openRewrapWizard"
        >
          {{ $t('keyManagement.rewrapWizard') }}
        </el-button>
        <!-- 顯式清理退役材料：唯一的材料銷毀點。未全收斂時禁用，
             tooltip 說明原因（後端亦有 409 全收斂閘） -->
        <el-tooltip
          :content="cleanupDisabledReason"
          :disabled="!cleanupDisabledReason"
          placement="top"
        >
          <span class="cleanup-btn-wrap">
            <el-button
              type="danger"
              plain
              :loading="cleaning"
              :disabled="cleanupDisabled"
              @click="handleCleanupRetired"
            >
              {{ $t('keyManagement.cleanupRetired') }}
            </el-button>
          </span>
        </el-tooltip>
      </div>
    </el-card>

    <!-- env 側金鑰：部署方管理 -->
    <el-card
      v-loading="loading"
      class="section-card"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('keyManagement.envKeysTitle') }}</span>
          <span class="card-hint">{{ $t('keyManagement.envKeysHint') }}</span>
          <!-- 封印態：與 degraded 為正交兩軸，各自獨立呈現、互不覆蓋亦不互相推導。
               後端未提供該欄時整個徽章不出現（不以「未知」或預設值頂替） -->
          <el-tag
            v-if="inventory.seal_state"
            size="small"
            effect="plain"
            :type="SEAL_STATE_TAG_TYPES[inventory.seal_state] || 'info'"
          >
            {{ sealStateLabel(inventory.seal_state) }}
          </el-tag>
          <span
            v-if="inventory.unsealed_at"
            class="card-hint"
          >
            {{ $t('keyManagement.sealUnsealedAt', { time: formatDateTime(inventory.unsealed_at) }) }}
          </span>
        </div>
      </template>
      <el-table :data="inventory.env_keys">
        <el-table-column
          :label="$t('keyManagement.colKeyName')"
          min-width="200"
        >
          <template #default="{ row }">
            {{ keyEnvName(row) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('keyManagement.colFingerprint')"
          min-width="200"
        >
          <template #default="{ row }">
            <div class="fingerprint-cell">
              <span class="mono-text">{{ row.fingerprint || '—' }}</span>
              <!-- Ed25519 匯出簽章鑰：指紋為公鑰指紋（可公開），以小標籤/tooltip 區分於對稱鑰指紋 -->
              <el-tooltip
                v-if="row.public_key"
                :content="$t('keyManagement.pubKeyFingerprintLabel')"
                placement="top"
              >
                <el-tag
                  size="small"
                  effect="plain"
                  type="success"
                >
                  {{ $t('keyManagement.pubKeyTag') }}
                </el-tag>
              </el-tooltip>
            </div>
          </template>
        </el-table-column>
        <!-- provider／key_ref：**由後端的執行期 provider 物件導出**，
             前端只呈現。欄位缺席時整欄不渲染——空欄比沒有欄更容易被誤讀為
             「本部署沒有 provider」，而真相是這版後端還沒送這個欄位 -->
        <el-table-column
          v-if="hasProviderColumns"
          :label="$t('keyManagement.colProvider')"
          width="120"
        >
          <template #default="{ row }">
            <el-tag
              v-if="row.provider"
              size="small"
              effect="plain"
            >
              {{ providerLabel(row.provider) }}
            </el-tag>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column
          v-if="hasProviderColumns"
          :label="$t('keyManagement.colKeyRef')"
          min-width="220"
        >
          <template #default="{ row }">
            <span class="mono-text">{{ row.key_ref || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('keyManagement.colManagedBy')"
          width="120"
        >
          <template #default="{ row }">
            <el-tag
              size="small"
              effect="plain"
            >
              {{ row.managed_by === 'deployer' ? $t('keyManagement.managedByDeployer') : $t('keyManagement.managedBySystem') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('keyManagement.colNote')"
          min-width="280"
        >
          <template #default="{ row }">
            {{ keyEnvNote(row) }}
          </template>
        </el-table-column>
        <!-- 公鑰取用：僅 Ed25519 匯出簽章鑰列（有 public_key）顯示複製／下載 -->
        <el-table-column
          :label="$t('common.actions')"
          width="240"
        >
          <template #default="{ row }">
            <template v-if="row.public_key">
              <el-button
                size="small"
                @click="copyPublicKey(row)"
              >
                {{ $t('keyManagement.copyPublicKey') }}
              </el-button>
              <el-button
                size="small"
                @click="downloadPublicKey(row)"
              >
                {{ $t('keyManagement.downloadPublicKey') }}
              </el-button>
            </template>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- KEK 退役史：歷次切換退役的舊 KEK 列（永久保留供稽核，不含金鑰材料） -->
    <el-card
      v-if="inventory.kek_history && inventory.kek_history.length > 0"
      v-loading="loading"
      class="section-card"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('keyManagement.kekHistoryTitle') }}</span>
          <span class="card-hint">{{ $t('keyManagement.kekHistoryHint') }}</span>
        </div>
      </template>
      <el-table :data="inventory.kek_history">
        <el-table-column
          :label="$t('keyManagement.kekHistoryColFrom')"
          min-width="180"
        >
          <template #default="{ row }">
            <span class="mono-text">{{ row.from_kek_id }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('keyManagement.kekHistoryColTo')"
          min-width="180"
        >
          <template #default="{ row }">
            <span class="mono-text">{{ row.to_kek_id }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('keyManagement.kekHistoryColRetiredAt')"
          min-width="170"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.retired_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('keyManagement.kekHistoryColRows')"
          width="120"
        >
          <template #default="{ row }">
            {{ row.rows }}
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- KEK 重包精靈（明文流向反轉）：材料由使用者輸入或本地生成，伺服端不生成不回傳。
         關窗不再受限——舊流程鎖住關閉鍵是因為新 KEK 只在回應中出現一次，關掉就永久遺失；
         反轉後材料自始至終在使用者手上，鎖住關閉只剩妨礙 -->
    <el-dialog
      v-model="rewrapVisible"
      :title="$t('keyManagement.rewrapWizard')"
      width="680px"
      :close-on-click-modal="false"
      @closed="onRewrapDialogClosed"
    >
      <el-steps
        :active="rewrapStep"
        align-center
        finish-status="success"
        class="rewrap-steps"
      >
        <el-step :title="$t('keyManagement.rewrapStep1')" />
        <el-step :title="$t('keyManagement.rewrapStep2')" />
        <el-step :title="$t('keyManagement.rewrapStep3')" />
      </el-steps>

      <div
        v-if="rewrapStep === 0"
        class="rewrap-body"
      >
        <i18n-t
          keypath="keyManagement.rewrapIntro1"
          tag="p"
          scope="global"
        >
          <template #emphasis>
            <strong>{{ $t('keyManagement.rewrapIntro1Emphasis') }}</strong>
          </template>
        </i18n-t>
        <!-- 流程說明依執行期 KEK provider 分岔：最後一步（新 KEK 怎麼進入行程）
             各模式不同，env 版本對 ui 模式部署是有害指示 -->
        <i18n-t
          :keypath="rewrapIntro2Key"
          tag="p"
          scope="global"
        >
          <template #code>
            <code>ENCRYPTION_KEY</code>
          </template>
          <template #dotenv>
            <code>.env</code>
          </template>
          <template #mode>
            <code>{{ kekProviderRaw }}</code>
          </template>
        </i18n-t>

        <!-- 重包目標（discriminated union 的判別子）：本地與委託為互斥變體。
             委託目標本版未提供——以停用選項明示，不讓使用者送出後才吃 501 -->
        <div class="kek-field">
          <span
            id="kek-rewrap-target-label"
            class="kek-label"
          >{{ $t('keyManagement.rewrapTargetLabel') }}</span>
          <el-radio-group
            v-model="rewrapMode"
            aria-labelledby="kek-rewrap-target-label"
          >
            <el-radio
              v-for="opt in REWRAP_TARGET_OPTIONS"
              :key="opt.mode"
              :label="opt.mode"
              :disabled="!opt.available"
            >
              {{ $t(opt.labelKey) }}
              <span
                v-if="!opt.available"
                class="kek-hint"
              >{{ $t('keyManagement.rewrapTargetUnavailable') }}</span>
            </el-radio>
          </el-radio-group>
        </div>

        <el-alert
          type="warning"
          :closable="false"
          show-icon
          :title="$t('keyManagement.kekOnceTitle')"
          :description="$t('keyManagement.kekOnceDesc')"
        />
      </div>

      <div
        v-else-if="rewrapStep === 1"
        class="rewrap-body"
      >
        <el-alert
          type="error"
          :closable="false"
          show-icon
          :title="$t('keyManagement.kekSaveNowTitle')"
          :description="$t('keyManagement.kekSaveNowDesc')"
          class="rewrap-once-alert"
        />
        <div class="kek-field">
          <span
            id="kek-new-label"
            class="kek-label"
          >{{ $t('keyManagement.kekInputLabel') }}</span>
          <div class="kek-input-row">
            <el-input
              v-model="newKek"
              aria-labelledby="kek-new-label"
              class="kek-input"
              spellcheck="false"
              autocomplete="off"
              :placeholder="$t('keyManagement.kekInputPlaceholder')"
            />
            <el-button @click="generateLocalKek">
              {{ $t('keyManagement.generateLocal') }}
            </el-button>
            <el-button
              :disabled="!newKek"
              @click="copyKEK"
            >
              {{ $t('common.copy') }}
            </el-button>
          </div>
          <p
            v-if="kekFormatMessage"
            class="kek-error"
          >
            {{ kekFormatMessage }}
          </p>
          <p
            v-else-if="kekIsCurrent"
            class="kek-error"
          >
            {{ $t('keyManagement.kekSameAsCurrent') }}
          </p>
          <p class="kek-hint">
            {{ $t('keyManagement.kekFormatHint') }}
          </p>
          <KEKGenerateCommands />
        </div>
        <div class="kek-field">
          <span
            id="kek-confirm-label"
            class="kek-label"
          >{{ $t('keyManagement.kekConfirmLabel') }}</span>
          <el-input
            v-model="newKekConfirm"
            aria-labelledby="kek-confirm-label"
            class="kek-input"
            spellcheck="false"
            autocomplete="off"
            :placeholder="$t('keyManagement.kekConfirmPlaceholder')"
          />
          <p
            v-if="kekConfirmMismatch"
            class="kek-error"
          >
            {{ $t('keyManagement.kekConfirmMismatch') }}
          </p>
          <p class="kek-hint">
            {{ $t('keyManagement.kekConfirmHint') }}
          </p>
        </div>
        <el-checkbox v-model="kekSavedConfirmed">
          {{ $t('keyManagement.kekSavedCheckbox') }}
        </el-checkbox>
      </div>

      <div
        v-else
        class="rewrap-body"
      >
        <i18n-t
          keypath="keyManagement.kekMeta"
          tag="p"
          class="kek-meta"
          scope="global"
        >
          <template #id>
            <span class="mono-text">{{ rewrapResult.new_kek_id }}</span>
          </template>
          <template #count>
            {{ rewrapResult.rewrapped_keys }}
          </template>
        </i18n-t>
        <!-- 最後步驟依執行期 KEK provider 分岔。
             四個分支不是四種措辭，是四條不同的操作路徑：
             env＝寫入環境變數後重啟；ui＝重啟後於解封頁輸入（且明確禁止寫入 .env）；
             kms／hsm＝部署層 provider 遷移，逐步程序未在產品內定案故指向營運文件；
             unknown＝列出各模式做法要操作者辨識，**不回落 env**（誤判代價不對稱） -->
        <template v-if="kekGuideMode === 'env'">
          <p>{{ $t('keyManagement.finalStepsIntro') }}</p>
          <ol class="rewrap-guide">
            <i18n-t
              keypath="keyManagement.finalStep1"
              tag="li"
              scope="global"
            >
              <template #env>
                <code>ENCRYPTION_KEY</code>
              </template>
              <template #dotenv>
                <code>.env</code>
              </template>
            </i18n-t>
            <li>{{ $t('keyManagement.finalStep2') }}</li>
          </ol>
        </template>
        <template v-else-if="kekGuideMode === 'ui'">
          <!-- 否定先於步驟：使用者可能已在其他文件讀過 env 做法，只是不再指示錯事
               並不足以阻止他沿用；故把「不要寫入 .env」放在最前面且用警示區塊 -->
          <el-alert
            type="warning"
            :closable="false"
            show-icon
            :title="$t('keyManagement.uiNoEnvTitle')"
            :description="$t('keyManagement.uiNoEnvDesc')"
            class="rewrap-once-alert"
          />
          <p>{{ $t('keyManagement.finalStepsIntroUi') }}</p>
          <ol class="rewrap-guide">
            <li>{{ $t('keyManagement.finalStep1Ui') }}</li>
            <li>{{ $t('keyManagement.finalStep2Ui') }}</li>
          </ol>
        </template>
        <template v-else-if="kekGuideMode === 'delegated'">
          <p>{{ $t('keyManagement.finalStepsIntroDelegated', { mode: kekProviderRaw }) }}</p>
          <p>{{ $t('keyManagement.finalStepsDelegatedBody') }}</p>
        </template>
        <template v-else>
          <p>{{ $t('keyManagement.finalStepsIntroUnknown') }}</p>
          <ul class="rewrap-guide">
            <li>{{ $t('keyManagement.finalStepUnknownEnv') }}</li>
            <li>{{ $t('keyManagement.finalStepUnknownUi') }}</li>
            <li>{{ $t('keyManagement.finalStepUnknownDelegated') }}</li>
          </ul>
        </template>
        <p>{{ $t('keyManagement.finalNote') }}</p>
      </div>

      <template #footer>
        <el-button
          v-if="rewrapStep === 0"
          @click="rewrapVisible = false"
        >
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          v-if="rewrapStep === 0"
          type="primary"
          @click="rewrapStep = 1"
        >
          {{ $t('keyManagement.rewrapNext') }}
        </el-button>
        <el-button
          v-if="rewrapStep === 1"
          @click="rewrapStep = 0"
        >
          {{ $t('keyManagement.rewrapBack') }}
        </el-button>
        <el-button
          v-if="rewrapStep === 1"
          type="primary"
          :loading="rewrapping"
          :disabled="rewrapSubmitDisabled"
          @click="executeRewrap"
        >
          {{ $t('keyManagement.submitRewrap') }}
        </el-button>
        <el-button
          v-if="rewrapStep === 2"
          type="primary"
          @click="closeRewrap"
        >
          {{ $t('keyManagement.finish') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, h, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import PageHeader from '@/components/PageHeader.vue'
import PolicyPciBanner from '@/components/PolicyPciBanner.vue'
import PolicyKeySections from '@/components/PolicyKeySections.vue'
import { usePolicyForm } from '@/composables/usePolicyForm'
import { KEY_SECTIONS } from '@/constants/policyDomains'
import {
  getKeyInventory,
  rotateKey,
  rewrapKEK,
  abandonRewrap,
  cleanupRetiredMaterial,
} from '../api/keys'
import { resolveApiError } from '@/api/error'
// 本頁三處確認框皆為不可逆／高後果操作（清理材料、輪替、放棄重包）：
// 一律走共用件——autofocus:false 讓「Enter 關掉這個框」不再等同執行，
// 確認鈕帶 danger 樣式（DESIGN_SPEC C3）。詳見 utils/confirm.js 的說明
import { confirmDestructive } from '@/utils/confirm'
import { keyEnvName, keyEnvNote } from '@/utils/keyDisplay'
import { formatDateTime } from '@/utils/format'
import {
  generateKEKMaterial,
  kekFingerprint,
  validateKEKMaterialFormat,
} from '@/utils/kek'
import KEKGenerateCommands from '@/components/KEKGenerateCommands.vue'
import { t } from '@/i18n'

// 金鑰政策鍵（域收編）：儲存後重載清冊，超齡提醒 banner 即時反映新提醒天數
const {
  loading: policyLoading,
  saving,
  formValues,
  savedValues,
  visibleSections,
  isDirty,
  pageDeviationCount,
  pageEPaymentDeviationCount,
  totalDeviationCount,
  loadPolicies,
  applyPagePCI,
  applyPageEPayment,
  resetForm,
  save,
} = usePolicyForm(KEY_SECTIONS)

const loading = ref(false)
const inventory = ref({
  keys: [],
  env_keys: [],
  kek_history: [],
  rotation_pending: 0,
  rewrap_pending: false,
  retire_backlog: 0,
  finalize_pending: 0,
  reminder_days: 0,
})
const rotating = ref('')

// 輪替互斥：任一輪替進行中禁用另一顆；重包待切換期間全禁（後端亦 409 守衛）
const rotateDisabled = (purpose) =>
  (!!rotating.value && rotating.value !== purpose) || inventory.value.rewrap_pending

const rewrapVisible = ref(false)
const rewrapStep = ref(0)
const rewrapping = ref(false)
const abandoning = ref(false)
// 回應恰三鍵，**無任何明文欄**：new_kek 已自契約消失，此處不得再有該欄
const rewrapResult = ref({ target_mode: '', new_kek_id: '', rewrapped_keys: 0 })
const rewrapMode = ref('local')
const newKek = ref('')
const newKekConfirm = ref('')
const kekSavedConfirmed = ref(false)
// 「與現行 KEK 相同」的前端預警；指紋算不出來時恆 false（本端無法判定即不宣稱）
const kekIsCurrent = ref(false)

// 重包目標（union 判別子）。委託目標的契約已定但本版後端回 501，
// 故以 available=false 標示為本版未提供，而不是讓使用者送出後才收到錯誤
const REWRAP_TARGET_OPTIONS = [
  { mode: 'local', labelKey: 'keyManagement.rewrapTargetLocal', available: true },
  { mode: 'kms', labelKey: 'keyManagement.rewrapTargetKms', available: false },
  { mode: 'hsm', labelKey: 'keyManagement.rewrapTargetHsm', available: false },
]

// 前端格式檢查的原因碼 → 文案。**檢查僅為輸入輔助，權威在伺服端**（見 utils/kek.js）
const KEK_FORMAT_TEXT_KEYS = {
  empty: 'keyManagement.kekErrorEmpty',
  format: 'keyManagement.kekErrorFormat',
  charset: 'keyManagement.kekErrorCharset',
}
const kekFormatReason = computed(() =>
  newKek.value ? validateKEKMaterialFormat(newKek.value) : ''
)
const kekFormatMessage = computed(() => {
  const reason = kekFormatReason.value
  if (!reason) return ''
  return t(KEK_FORMAT_TEXT_KEYS[reason])
})
const kekConfirmMismatch = computed(
  () => !!newKekConfirm.value && newKekConfirm.value !== newKek.value
)
// 送出前置：格式無異議、paste-back 逐字相符且非空、保存確認已勾、非現行 KEK。
// 這是 UX 前置，不是授權——伺服端對同一組條件另有獨立且權威的驗證
const rewrapSubmitDisabled = computed(
  () =>
    !newKek.value ||
    !!kekFormatReason.value ||
    newKekConfirm.value !== newKek.value ||
    !kekSavedConfirmed.value ||
    kekIsCurrent.value
)

// 與現行 KEK 相同的預警：指紋演算法與伺服端一致，但 crypto.subtle 不可用時
// 回 null＝本端無法判定，此時不阻擋（由伺服端 409 把關）
watch(newKek, async (value) => {
  kekIsCurrent.value = false
  if (!value || validateKEKMaterialFormat(value)) return
  const current = inventory.value.kek_id
  if (!current) return
  const fingerprint = await kekFingerprint(value)
  // 比對期間輸入可能已變動：只對仍是當下值的結果生效
  if (fingerprint && fingerprint === current && newKek.value === value) {
    kekIsCurrent.value = true
  }
})

const purposeLabel = (p) =>
  ({
    data: t('keyManagement.purposeData'),
    audit_integrity: t('keyManagement.purposeAudit'),
  })[p] || p

// KEK provider 與封印態的顯示。清冊的 provider 欄由後端的執行期 provider
// 物件導出（不重讀 env），前端僅負責查譯；未知值原樣顯示，不猜、不歸類
const providerLabel = (p) =>
  ({
    env: t('keyManagement.providerEnv'),
    ui: t('keyManagement.providerUi'),
    kms: t('keyManagement.providerKms'),
    hsm: t('keyManagement.providerHsm'),
  })[p] || p

// 完成切換的指示**依執行期 provider 分岔**。
//
// 無條件顯示 env 版本（「把新 KEK 存入 ENCRYPTION_KEY 後重啟」）對 ui 模式部署是
// **有害**的：照做等於把根金鑰以明文寫上磁碟，而 ui 模式的唯一意義就是材料永不落地。
// 2026-08-17 使用者實走踩到此坑，且實測確認 ui 的正確路徑為「重啟 → 於解封頁輸入新 KEK」。
//
// provider 來源＝清冊回應的頂層 `provider` 欄，由後端執行期 provider 物件導出，
// 不重讀 env、不由前端推論（例如以「有封印狀態」反推模式為 ui——那是推論不是事實）。
const KEK_GUIDE_MODE_BY_PROVIDER = {
  env: 'env',
  ui: 'ui',
  kms: 'delegated',
  hsm: 'delegated',
}
// **取不到 provider 時不回落 env**：清冊載入失敗（loadInventory 只記 console）、後端未送
// 該欄、或值為白名單外的新模式，一律走 unknown 分支列出各模式做法。誤判代價不對稱——
// 對 env 部署多一行「請確認你的模式」只是多讀一行；對 ui 部署預設顯示 env 版本則是
// 把根金鑰寫上磁碟。fail-safe 的方向是要操作者辨識模式，不是猜一個最常見的
// 查表後**驗證結果落在已知分支集合**才採用：物件字面量帶原型鏈，`constructor`／
// `toString` 這類 provider 值會取到繼承屬性。實務上 provider 由後端 enum 導出不會是
// 這些值，但「白名單命中才分類」本來就是這裡的語義，交給原型鏈決定是把語義外包出去
const KEK_GUIDE_MODES = ['env', 'ui', 'delegated']
const kekGuideMode = computed(() => {
  const mode = KEK_GUIDE_MODE_BY_PROVIDER[inventory.value.provider]
  return KEK_GUIDE_MODES.includes(mode) ? mode : 'unknown'
})
// 委託模式文案帶出實際的 provider 值（kms／hsm 的雲端與硬體程序不同，
// 只寫「委託模式」會讓操作者仍得回頭查自己跑的是哪一個）
const kekProviderRaw = computed(() => inventory.value.provider || '')

// 五處切換指示的鍵表。**env 一律指向既有鍵**——那些文案本來就是對的，本次只在旁邊
// 加分支，不改寫（其值於 git diff 上必須零變動）
const REWRAP_INTRO2_KEYS = {
  env: 'keyManagement.rewrapIntro2',
  ui: 'keyManagement.rewrapIntro2Ui',
  delegated: 'keyManagement.rewrapIntro2Delegated',
  unknown: 'keyManagement.rewrapIntro2Unknown',
}
const REWRAP_PENDING_DESC_KEYS = {
  env: 'keyManagement.rewrapPendingDesc',
  ui: 'keyManagement.rewrapPendingDescUi',
  delegated: 'keyManagement.rewrapPendingDescDelegated',
  unknown: 'keyManagement.rewrapPendingDescUnknown',
}
const SWITCHOVER_PENDING_DESC_KEYS = {
  env: 'keyManagement.switchoverPendingDesc',
  ui: 'keyManagement.switchoverPendingDescUi',
  delegated: 'keyManagement.switchoverPendingDescDelegated',
  unknown: 'keyManagement.switchoverPendingDescUnknown',
}
const rewrapIntro2Key = computed(() => REWRAP_INTRO2_KEYS[kekGuideMode.value])
const rewrapPendingDescText = computed(() =>
  t(REWRAP_PENDING_DESC_KEYS[kekGuideMode.value], { mode: kekProviderRaw.value })
)

const SEAL_STATE_TAG_TYPES = {
  sealed: 'warning',
  unsealing: 'warning',
  unsealed: 'success',
  'sealed-faulted': 'danger',
}
const sealStateLabel = (state) =>
  ({
    sealed: t('unseal.stateSealed'),
    unsealing: t('unseal.stateUnsealing'),
    unsealed: t('unseal.stateUnsealed'),
    'sealed-faulted': t('unseal.stateSealedFaulted'),
  })[state] || state

// provider／key_ref 兩欄只在後端真的送了該欄位時出現（見 template 註解）
const hasProviderColumns = computed(() =>
  (inventory.value.env_keys || []).some((row) => !!row.provider)
)

const overCryptoperiodKeys = computed(() =>
  (inventory.value.keys || []).filter((k) => k.over_cryptoperiod)
)

// 退役列呈現治理（純呈現層，不動清冊 API）：退役列永久保留供稽核、只增不減，
// 預設隱藏使現行鑰恆在視野內。過濾狀態刻意不持久化——刷新回預設，
// 避免使用者在「已展開」的狀態下誤把歷史列當成現況。
// 注意：清理確認清單（buildCleanupConfirmMessage）與超齡提醒仍讀 inventory.keys 全集，
// 不受本過濾影響——顯示過濾不得改變「會被銷毀什麼」的告知範圍。
const showRetiredKeys = ref(false)
const activeKeys = computed(() =>
  (inventory.value.keys || []).filter((k) => k.status === 'active')
)

// 退役列的唯一排序基準＝退役時間新到舊。version 是**每個 purpose 各自獨立的序列**，
// 跨用途比大小既不是時序也不是分組（HMAC v1 比 DEK v3 晚退役卻被排在後面）。
// 缺 retired_at／值不可解析時視為 0（排到最後而非插隊到最前）；同一時刻退役才以版本 desc 收斂。
// 表格與清理確認清單共用本函式——兩份清單要能逐項對照，順序必須同源
const retiredAtMillis = (k) => {
  const ms = k.retired_at ? new Date(k.retired_at).getTime() : NaN
  return Number.isFinite(ms) ? ms : 0
}
const byRetiredAtDesc = (a, b) =>
  retiredAtMillis(b) - retiredAtMillis(a) || (b.version ?? 0) - (a.version ?? 0)

// filter 已產生新陣列，sort 不會回頭改動 inventory
const retiredKeys = computed(() =>
  (inventory.value.keys || []).filter((k) => k.status !== 'active').sort(byRetiredAtDesc)
)
const retiredKeyCount = computed(() => retiredKeys.value.length)
// active 恆在最前（依用途分組維持後端既有次序），退役列按退役時間新到舊接續其後
const displayedKeys = computed(() =>
  showRetiredKeys.value ? [...activeKeys.value, ...retiredKeys.value] : activeKeys.value
)

// 退役列整列視覺降階：展開後多數列是歷史，僅靠狀態欄一顆
// 小 tag 區分不足。文字降階以 token 為之、不動 tag 自身配色（tag 對比已驗過 AA）；
// 交界列再加一條分隔線，讓「以下都是歷史」有明確起點
const keyRowClass = ({ row, rowIndex }) => {
  if (row.status === 'active') return ''
  return rowIndex === activeKeys.value.length
    ? 'retired-key-row retired-key-row--first'
    : 'retired-key-row'
}

// 切換收尾雙態橫幅：degraded（退役收斂失敗）優先於待切換（正常工作流）。
// 兩者皆無時回 null，不渲染橫幅
const switchoverBanner = computed(() => {
  // 收斂狀態讀取失敗＝未知態（fail-close）：
  // 不得以 0 呈現假健康——顯示警示並由 cleanupDisabled 保守禁用清理
  if (inventory.value.converge_state_error) {
    return {
      type: 'warning',
      title: t('keyManagement.switchoverUnknownTitle'),
      description: t('keyManagement.switchoverUnknownDesc'),
    }
  }
  const backlog = inventory.value.retire_backlog || 0
  const finalize = inventory.value.finalize_pending || 0
  if (backlog > 0) {
    return {
      type: 'warning',
      title: t('keyManagement.switchoverDegradedTitle'),
      description: t('keyManagement.switchoverDegradedDesc', { n: backlog }),
    }
  }
  if (finalize > 0) {
    return {
      type: 'info',
      title: t('keyManagement.switchoverPendingTitle'),
      // 「怎麼讓新 KEK 生效」依執行期 provider 分岔（見 kekGuideMode 的說明）
      description: t(SWITCHOVER_PENDING_DESC_KEYS[kekGuideMode.value], {
        n: finalize,
        mode: kekProviderRaw.value,
      }),
    }
  }
  return null
})

// 清理退役材料的前置全收斂閘（與後端 409 同語義，UI 先行禁用並說明原因）
const cleaning = ref(false)
const cleanupDisabledReason = computed(() => {
  const inv = inventory.value
  if (inv.converge_state_error) {
    return t('keyManagement.cleanupDisabledStateUnknown')
  }
  if ((inv.finalize_pending || 0) > 0 || (inv.retire_backlog || 0) > 0) {
    return t('keyManagement.cleanupDisabledNotConverged')
  }
  if (inv.rewrap_pending) return t('keyManagement.cleanupDisabledRewrapPending')
  if (rotating.value) return t('keyManagement.cleanupDisabledRotating')
  return ''
})
const cleanupDisabled = computed(() => !!cleanupDisabledReason.value)

const loadInventory = async () => {
  loading.value = true
  try {
    inventory.value = await getKeyInventory()
  } catch (error) {
    console.error('載入金鑰清冊失敗:', error)
  } finally {
    loading.value = false
  }
}

// 輪替確認：data 會批次重加密（可中斷續跑）；audit 僅新章換鑰、歷史不重算
const confirmRotate = async (purpose) => {
  const messages = {
    data: t('keyManagement.rotateDataConfirm'),
    audit_integrity: t('keyManagement.rotateAuditConfirm'),
  }
  try {
    // 破壞性語義：輪替一經送出即產生新版本並退役舊版（data 還會批次重加密存量密文），
    // 沒有「取消輪替」這條路——與刪除同級的不可逆，故套 confirmDestructive
    await confirmDestructive(messages[purpose], t('keyManagement.rotateConfirmTitle'), {
      confirmButtonText: t('keyManagement.rotate'),
      cancelButtonText: t('common.cancel'),
    })
  } catch {
    return
  }
  rotating.value = purpose
  try {
    const result = await rotateKey(purpose)
    if (purpose === 'data') {
      if (result.failed > 0 || result.pending > 0) {
        ElMessage.warning(
          t('keyManagement.rotateDataPartial', {
            version: result.to_version,
            reencrypted: result.reencrypted,
            pending: result.pending,
          })
        )
      } else {
        ElMessage.success(
          t('keyManagement.rotateDataDone', {
            from: result.from_version,
            to: result.to_version,
            reencrypted: result.reencrypted,
          })
        )
      }
    } else {
      ElMessage.success(
        t('keyManagement.rotateAuditDone', {
          from: result.from_version,
          to: result.to_version,
        })
      )
    }
    await loadInventory()
  } catch (error) {
    console.error('輪替失敗:', error)
  } finally {
    rotating.value = ''
  }
}

const openRewrapWizard = () => {
  rewrapStep.value = 0
  rewrapMode.value = 'local'
  rewrapResult.value = { target_mode: '', new_kek_id: '', rewrapped_keys: 0 }
  clearRewrapSecret()
  rewrapVisible.value = true
}

// 本地生成：CSPRNG 直接產出合格材料，並同步填入 paste-back 欄——
// 使用者剛剛「看到」的就是這個值，再要求他抄一次只會誘發複製貼上而非確認
const generateLocalKek = () => {
  try {
    const material = generateKEKMaterial()
    newKek.value = material
    newKekConfirm.value = material
  } catch (error) {
    console.error('本地生成 KEK 失敗:', error)
    ElMessage.error(t('keyManagement.kekGenerateFailed'))
  }
}

const executeRewrap = async () => {
  rewrapping.value = true
  try {
    // 本地變體的精確鍵集：多一鍵、少一鍵或 mode 與欄位不符皆 400，
    // 故此處逐字對齊契約，不夾帶任何額外欄位。
    // 兩欄套**同一次**修剪：貼上 `openssl rand -hex 32` 的輸出會帶結尾換行，
    // 而伺服端的 paste-back 比對的是原始位元組，兩欄修剪不一致就會誤判不符
    const payload = {
      mode: 'local',
      new_kek: newKek.value.trim(),
      new_kek_confirm: newKekConfirm.value.trim(),
      confirm_saved: kekSavedConfirmed.value,
    }
    // skipErrorToast：由此 catch 統一呈現（衝突時需合併後端訊息＋恢復指引），避免與攔截器重複 toast
    rewrapResult.value = await rewrapKEK(payload, { skipErrorToast: true })
    rewrapStep.value = 2
  } catch (error) {
    const status = error.response?.status
    // 一律刷新清冊：若後端已建 pending，「KEK 重包尚未切換」banner 與
    // 「放棄本次切換」鈕即現，指引恢復
    await loadInventory()
    if (status === 409) {
      // 衝突（已有待切換 pending／退役 backlog）：顯示後端訊息並引導恢復（先完成切換或放棄後重做）
      ElMessage.error(
        t('keyManagement.rewrapConflict', {
          detail: resolveApiError(error.response?.data, status),
        })
      )
      rewrapVisible.value = false
    } else {
      ElMessage.error(resolveApiError(error.response?.data, status))
    }
  } finally {
    rewrapping.value = false
    // 明文清除時機之一：送出後（不分成敗）。失敗後需重新輸入或重新生成是刻意的
    // ——材料留在元件狀態裡等待重試，就是把「暫存明文」的窗口交給不確定的重試節奏
    clearRewrapSecret()
  }
}

const copyKEK = async () => {
  try {
    await navigator.clipboard.writeText(newKek.value)
    ElMessage.success(t('keyManagement.kekCopied'))
  } catch {
    ElMessage.warning(t('common.copyFailed'))
  }
}

// 複製 Ed25519 匯出簽章公鑰（base64）：供離線核對匯出簽章
const copyPublicKey = async (row) => {
  try {
    await navigator.clipboard.writeText(row.public_key)
    ElMessage.success(t('keyManagement.publicKeyCopied'))
  } catch {
    ElMessage.warning(t('common.copyFailed'))
  }
}

// 下載公鑰檔案：canonical JSON（algorithm+public_key），檔名帶指紋，MIME application/json
const downloadPublicKey = (row) => {
  const content = JSON.stringify({ algorithm: 'Ed25519', public_key: row.public_key })
  const blob = new Blob([content], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  // 檔名依 name_code 分流：清冊上有兩把 Ed25519（匯出簽章鑰、檢查點簽章鑰），
  // 硬編單一前綴會讓下載下來的兩個檔看起來是同一把鑰的兩份
  a.download = `${row.name_code || 'signing'}-pubkey-${row.fingerprint}.json`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// 清除持有的新 KEK 明文（**元件狀態層**；不承諾 JS 記憶體抹除——字串不可變，
// 這裡放棄的是參考而非覆寫位元組）。三時機皆須呼叫：送出後、對話框關閉、元件卸載。
// rewrapResult 不在此清除：回應無明文欄（僅指紋與列數），且步驟 2 還要顯示它
const clearRewrapSecret = () => {
  newKek.value = ''
  newKekConfirm.value = ''
  kekSavedConfirmed.value = false
  kekIsCurrent.value = false
}

// 對話框關閉事件：先清明文再刷新清冊
const onRewrapDialogClosed = () => {
  clearRewrapSecret()
  loadInventory()
}

// 關閉即觸發 dialog @closed → 清明文＋loadInventory，無需在此重複處理
const closeRewrap = () => {
  rewrapVisible.value = false
}

onUnmounted(clearRewrapSecret)

// 放棄未切換的 KEK 重包：軟退役未切換的新 KEK 包裹列（材料保留至顯式清理）、回現行 KEK 狀態，解鎖介面
const handleAbandonRewrap = async () => {
  try {
    // 破壞性語義：放棄即軟退役整批已用新 KEK 包裹的金鑰列，該次重包的工作全數作廢、
    // 要重來只能從頭再跑一次精靈——不可逆，故套 confirmDestructive
    await confirmDestructive(
      t('keyManagement.abandonRewrapConfirm'),
      t('keyManagement.abandonRewrap'),
      {
        confirmButtonText: t('keyManagement.abandonRewrap'),
        cancelButtonText: t('common.cancel'),
      },
    )
  } catch {
    return // 取消
  }
  abandoning.value = true
  try {
    await abandonRewrap()
    // 縱深防禦：放棄鈕只在對話框關閉後的橫幅出現，明文早已由 @closed 清除；
    // 此處覆蓋「放棄入口未來移入對話框內」的情境（故無法以測試非空泛地釘住）
    clearRewrapSecret()
    ElMessage.success(t('keyManagement.abandonRewrapSuccess'))
    await loadInventory()
  } catch (error) {
    console.error('放棄 KEK 重包失敗:', error)
  } finally {
    abandoning.value = false
  }
}

// 拒清項摘要：逐項說明「為什麼不能清」（稽核需求須可辨識保護依據），
// reason 為後端保護類別的原因碼；未知碼降級為存量密文文案（保守措辭）
const CLEANUP_SKIP_TEXT_KEYS = {
  audit_referenced: 'keyManagement.cleanupSkippedAudit',
  version_referenced: 'keyManagement.cleanupSkippedVersion',
  unregistered_purpose: 'keyManagement.cleanupSkippedUnregistered',
}
const skippedItemText = (item) =>
  t(
    CLEANUP_SKIP_TEXT_KEYS[item.reason] || 'keyManagement.cleanupSkippedVersion',
    {
      purpose: purposeLabel(item.purpose),
      version: item.version,
      refs: item.refs,
    }
  )

// 顯式清理退役金鑰材料：不可逆銷毀，先確認再送；成功後摘要 purged／skipped 並刷新清冊。
// 確認內容列明銷毀候選（退役且材料尚存的版本＋退役 KEK 包裹列數）與
// 「先重啟所有實例」提醒（多實例舊快取寫入舊版密文的緩解）。
//
// 呈現為結構化 VNode 而非單段散文：本框的核心告知是「會被銷毀什麼」，
// 埋在 6 行連續散文中段等於要求使用者逐字讀完才找得到清單。專案既有慣例即 VNode
// （api/connect.js confirmTransmissionRisks），不引入 dangerouslyUseHTMLString。
// 樣式走 inline：MessageBox 被 teleport 到 body，scoped CSS 到不了。
//
// 候選清單與表格共用 byRetiredAtDesc——使用者要在框與表之間逐項對照，兩份順序必須一致。
// 注意排序前先複製：inventory.keys 是原始回應陣列，sort 就地改動會連帶洗掉表格既有次序
const buildCleanupConfirmMessage = () => {
  const inv = inventory.value
  const muted = 'color: var(--el-text-color-secondary);'
  const candidates = (inv.keys || [])
    .filter((k) => k.status === 'retired' && !k.material_purged)
    .slice()
    .sort(byRetiredAtDesc)
  const kekRows = (inv.kek_history || []).reduce((sum, r) => sum + (r.material_rows || 0), 0)

  const blocks = [
    h('p', { style: 'margin: 0 0 8px;' }, t('keyManagement.cleanupRetiredConfirm')),
    h(
      'p',
      { style: 'margin: 0 0 12px; color: var(--el-color-danger); font-weight: 600;' },
      t('keyManagement.cleanupConfirmIrreversible')
    ),
  ]
  if (candidates.length > 0) {
    blocks.push(
      h('p', { style: 'margin: 0 0 6px; font-weight: 600;' }, t('keyManagement.cleanupConfirmCandidatesTitle')),
      h(
        'ul',
        { class: 'cleanup-confirm-list', style: 'margin: 0 0 12px; padding-left: 20px; line-height: 1.8;' },
        candidates.map((k) =>
          h('li', { key: `${k.purpose}-${k.version}` }, [
            `${purposeLabel(k.purpose)} v${k.version}`,
            h('span', { style: muted }, [
              ' — ',
              t('keyManagement.cleanupConfirmCandidateRetiredAt', {
                time: k.retired_at ? formatDateTime(k.retired_at) : '—',
              }),
            ]),
          ])
        )
      )
    )
  }
  if (kekRows > 0) {
    blocks.push(h('p', { style: 'margin: 0 0 12px;' }, t('keyManagement.cleanupConfirmKekRows', { n: kekRows })))
  }
  blocks.push(
    h(
      'p',
      {
        style:
          'margin: 0 0 12px; padding-left: 10px; border-left: 3px solid var(--el-color-warning); line-height: 1.6;',
      },
      t('keyManagement.cleanupConfirmRestartNotice')
    ),
    h('p', { style: 'margin: 0; font-weight: 600;' }, t('keyManagement.cleanupConfirmQuestion'))
  )
  return h('div', { class: 'cleanup-confirm-body' }, blocks)
}

const handleCleanupRetired = async () => {
  try {
    await confirmDestructive(
      buildCleanupConfirmMessage(),
      t('keyManagement.cleanupRetired'),
      {
        confirmButtonText: t('keyManagement.cleanupRetiredConfirmButton'),
        cancelButtonText: t('common.cancel'),
        // C5 標準表單檔：420 預設寬把清單擠成六行散文
        customStyle: { width: '560px', maxWidth: '92vw' },
      }
    )
  } catch {
    return // 取消
  }
  cleaning.value = true
  try {
    const result = await cleanupRetiredMaterial({ skipErrorToast: true })
    const purged = result?.purged || []
    const skipped = result?.skipped || []
    ElMessage.success(t('keyManagement.cleanupRetiredDone', { n: purged.length }))
    if (skipped.length > 0) {
      ElMessage.warning({
        message: t('keyManagement.cleanupRetiredSkipped', {
          n: skipped.length,
          items: skipped.map(skippedItemText).join(t('common.listSeparator')),
        }),
        duration: 8000,
      })
    }
    await loadInventory()
  } catch (error) {
    const status = error.response?.status
    ElMessage.error(resolveApiError(error.response?.data, status))
    // 409（未收斂／鎖忙）多因清冊狀態已漂移：刷新使按鈕禁用態與後端一致
    if (status === 409) await loadInventory()
  } finally {
    cleaning.value = false
  }
}

const handleSavePolicies = async () => {
  await save()
  loadInventory()
}

onMounted(() => {
  loadPolicies()
  loadInventory()
})
</script>

<style scoped>
.status-banner {
  margin-bottom: 12px;
}

.section-card {
  margin-bottom: 16px;
}

/* wrap＋標題不縮：nowrap 時 768 寬會保住 129px 的切換鈕、
   把區塊標題壓到 47px 折成兩行——優先犧牲的順序反了。窄幅讓控制換行到下一列即可 */
.card-header {
  display: flex;
  align-items: baseline;
  gap: 12px;
  flex-wrap: wrap;
}

.card-title {
  font-weight: 600;
  flex-shrink: 0;
}

.card-hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

/* 切換控制推到表頭右側，與標題／說明同一行 */
.retired-toggle {
  margin-left: auto;
}

/* 「已退役」須讀作中性、非健康狀態。本專案把 --el-color-info 覆寫成 teal
   （--ot-info #14b8a6，見 styles/tokens.css），沿用 el-tag info 配色會讓退役列
   與現行鑰的 success 綠只差色相，語義被讀成「正常」。此處把該 tag 的三個色
   變數改綁中性灰 token（不動全域 --el-color-info，其他頁的 info 語義不受影響） */
.retired-status-tag {
  --el-tag-bg-color: var(--el-fill-color-light);
  --el-tag-border-color: var(--el-border-color);
  --el-tag-text-color: var(--el-text-color-secondary);
}

/* 退役列整列降階：只降儲存格文字色，不加 opacity——整列透明會連 tag 一起
   拉低對比（退役 tag 實測 5.4:1，扣掉透明度就掉出 AA）。交界線標出歷史區的起點 */
.keys-table :deep(.retired-key-row .cell) {
  color: var(--el-text-color-secondary);
}

.keys-table :deep(.retired-key-row--first > td.el-table__cell) {
  border-top: 2px solid var(--el-border-color);
}

.card-actions {
  margin-top: 16px;
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

/* disabled 的 el-button 不發 mouse 事件，包一層 span 讓 tooltip 仍可觸發 */
.cleanup-btn-wrap {
  display: inline-flex;
}

.mono-text {
  font-family: var(--ot-font-mono, monospace);
}

.fingerprint-cell {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.rewrap-steps {
  margin-bottom: 20px;
}

.rewrap-body p {
  margin: 8px 0;
  line-height: 1.6;
}

.rewrap-once-alert {
  margin-bottom: 12px;
}

.kek-field {
  margin-bottom: 16px;
}

.kek-label {
  display: block;
  font-weight: 600;
  margin-bottom: 6px;
}

.kek-input-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.kek-input {
  flex: 1;
}

/* 材料逐字比對靠人眼（0/O、1/l）：輸入框本體必須等寬字型 */
.kek-input :deep(.el-input__inner) {
  font-family: var(--ot-font-mono, monospace);
}

.kek-error {
  margin: 6px 0 0;
  font-size: 12px;
  color: var(--el-color-danger);
}

.kek-hint {
  margin: 6px 0 0;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.kek-meta {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.rewrap-guide {
  padding-left: 20px;
  line-height: 1.8;
}
</style>
