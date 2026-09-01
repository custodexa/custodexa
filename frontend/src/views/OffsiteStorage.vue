<template>
  <div
    ref="rootRef"
    class="offsite-storage"
  >
    <PageHeader
      :title="$t('menu.offsiteStorage')"
      :description="$t('offsite.headerDesc')"
    >
      <template #actions>
        <el-button
          v-if="canDisable"
          type="danger"
          plain
          :loading="disabling"
          data-test="offsite-disable"
          @click="handleDisable"
        >
          {{ $t('offsite.disable') }}
        </el-button>
        <el-button
          :loading="loading"
          data-test="offsite-refresh"
          @click="refreshPage"
        >
          <el-icon><Refresh /></el-icon>
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <!-- 讀取失敗必須真的擋在表單之前（沿 LDAP 目錄頁的同一條教訓）：
         只放一則 alert 而儲存鈕照樣可按，空白表單送出去就是一次靜默的設定覆寫。
         警示只說「我們替你停了什麼」，怎麼復原由狀態帶承擔 -->
    <el-alert
      v-if="loadFailed"
      class="page-alert"
      type="error"
      :title="$t('offsite.loadFailedGuardTitle')"
      :description="$t('offsite.loadFailedGuardDesc')"
      :closable="false"
      show-icon
    />

    <!-- 憑證解密失敗＝金鑰事故，**不得呈現為「未設定」**：
         上傳與取回都會停在失敗態，而它的成因與設定無關，故獨立成一則錯誤警示 -->
    <el-alert
      v-if="credentialState === 'failed'"
      class="page-alert"
      type="error"
      data-test="offsite-credential-failed"
      :title="$t('offsite.credentialFailedTitle')"
      :description="$t('offsite.credentialFailedDesc')"
      :closable="false"
      show-icon
    />

    <!-- 狀態帶述說的是**已儲存**的事實，不隨表單草稿變動；
         第一次成功讀取之前不宣稱任何事實（loading 態） -->
    <div class="status-strip">
      <span class="status-strip__label">{{ $t('offsite.statusTitle') }}</span>
      <el-tag
        :type="statusTagType"
        effect="plain"
        data-test="offsite-status-tag"
      >
        {{ statusLabel }}
      </el-tag>
      <span class="status-strip__hint">{{ statusHint }}</span>
      <span
        v-if="savedPlaintextRisk"
        class="status-strip__risk"
        data-test="offsite-plaintext-risk"
      >{{ $t('offsite.plaintextRisk') }}</span>
    </div>

    <!-- 空狀態的判準是**帳冊零列**，不是「沒有現行世代」：
         停止離機後仍有歷史物件的部署，失敗清單與取回失敗原因必須看得見，
         否則關閉後的黑洞只是換個地方出現 -->
    <EmptyState
      v-if="showEmptyState"
      class="ledger-empty"
      data-test="offsite-empty"
      :title="$t('offsite.emptyTitle')"
      :hint="$t('offsite.emptyHint')"
    />

    <!-- 已設定摘要卡：**不顯示任何密鑰**，端點只顯示正規化 origin（無 path／query） -->
    <el-card
      v-if="showSummary"
      class="section-card"
      data-test="offsite-summary"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('offsite.summaryTitle') }}</span>
          <span class="card-hint">{{ $t('offsite.summaryHint') }}</span>
        </div>
      </template>
      <el-descriptions
        :column="2"
        border
        size="small"
      >
        <el-descriptions-item :label="$t('offsite.field.provider')">
          {{ providerLabel(saved.provider) }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('offsite.field.endpointOrigin')">
          {{ saved.endpoint_origin || $t('offsite.endpointDefault') }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('offsite.field.bucket')">
          {{ saved.bucket || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('offsite.field.prefix')">
          {{ saved.prefix || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('offsite.field.region')">
          {{ saved.region || '-' }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('offsite.field.credentialMode')">
          {{ credentialModeLabel(saved.credential_mode) }}
        </el-descriptions-item>
        <el-descriptions-item :label="$t('offsite.field.fingerprint')">
          <code data-test="offsite-summary-fingerprint">{{ saved.profile_fingerprint || '-' }}</code>
        </el-descriptions-item>
        <el-descriptions-item :label="$t('offsite.field.generationId')">
          {{ saved.generation_id || '-' }}
        </el-descriptions-item>
      </el-descriptions>
      <!-- bucket 治理現況是資訊性揭露：中性呈現、不判好壞 -->
      <div
        v-if="governance"
        class="governance"
        data-test="offsite-governance"
      >
        {{ $t('offsite.governanceVersioning', { state: versioningLabel(governance.versioning) }) }}
        <span v-if="governance.retention_detail"> · {{ governance.retention_detail }}</span>
      </div>
    </el-card>

    <!-- 設定表單（C6 rules＋validate、C7 label-position=top）。
         停用態同樣渲染：它就是「重新設定入口」 -->
    <el-form
      ref="formRef"
      v-loading="loading"
      :model="form"
      :rules="formRules"
      label-position="top"
      class="settings-form"
      data-test="offsite-settings-form"
    >
      <el-card class="section-card">
        <template #header>
          <div class="card-header">
            <span class="card-title">{{ $t('offsite.sectionTarget') }}</span>
            <span class="card-hint">{{ $t('offsite.sectionTargetHint') }}</span>
          </div>
        </template>

        <el-form-item
          :label="$t('offsite.field.provider')"
          prop="provider"
        >
          <el-radio-group
            v-model="form.provider"
            data-test="offsite-provider"
          >
            <el-radio
              v-for="p in OFFSITE_PROVIDERS"
              :key="p"
              :value="p"
            >
              {{ providerLabel(p) }}
            </el-radio>
          </el-radio-group>
        </el-form-item>

        <el-form-item
          :label="$t('offsite.field.bucket')"
          prop="bucket"
        >
          <el-input
            v-model="form.bucket"
            data-test="offsite-bucket"
            :placeholder="$t('offsite.placeholder.bucket')"
            maxlength="255"
          />
        </el-form-item>

        <el-form-item
          :label="$t('offsite.field.prefix')"
          prop="prefix"
        >
          <el-input
            v-model="form.prefix"
            :placeholder="$t('offsite.placeholder.prefix')"
            maxlength="255"
          />
          <div class="field-hint">
            {{ $t('offsite.hint.prefix') }}
          </div>
        </el-form-item>

        <el-form-item
          :label="$t('offsite.field.endpoint')"
          prop="endpoint"
        >
          <el-input
            v-model="form.endpoint"
            data-test="offsite-endpoint"
            :placeholder="$t('offsite.placeholder.endpoint')"
            maxlength="255"
          />
          <div class="field-hint">
            {{ isS3 ? $t('offsite.hint.endpointS3') : $t('offsite.hint.endpointGcs') }}
          </div>
          <!-- 明文端點的出站風險就近揭露：憑證與證據內容都會走這條連線 -->
          <div
            v-if="endpointIsPlaintext"
            class="field-warning"
            data-test="offsite-endpoint-plaintext"
          >
            {{ $t('offsite.hint.endpointPlaintext') }}
          </div>
        </el-form-item>

        <template v-if="isS3">
          <el-form-item
            :label="$t('offsite.field.region')"
            prop="region"
          >
            <el-input
              v-model="form.region"
              data-test="offsite-region"
              :placeholder="$t('offsite.placeholder.region')"
              maxlength="64"
            />
            <div class="field-hint">
              {{ $t('offsite.hint.region') }}
            </div>
          </el-form-item>

          <el-form-item :label="$t('offsite.field.pathStyle')">
            <el-switch v-model="form.path_style" />
            <div class="field-hint">
              {{ $t('offsite.hint.pathStyle') }}
            </div>
          </el-form-item>
        </template>
      </el-card>

      <el-card class="section-card">
        <template #header>
          <div class="card-header">
            <span class="card-title">{{ $t('offsite.sectionCredentials') }}</span>
            <span class="card-hint">{{ $t('offsite.sectionCredentialsHint') }}</span>
          </div>
        </template>

        <!-- 憑證狀態徽章：**只說有沒有，不說是什麼**。
             既有憑證不回填、也不以遮罩呈現——遮罩仍會洩漏長度與前綴 -->
        <div class="credential-state">
          <span class="credential-state__label">{{ $t('offsite.field.credentialMode') }}</span>
          <el-tag
            :type="credentialModeTagType"
            effect="plain"
            data-test="offsite-credential-mode"
          >
            {{ credentialModeLabel(saved.credential_mode) }}
          </el-tag>
          <span
            v-if="saved.credentials_cleared_at"
            class="credential-state__hint"
          >
            {{ $t('offsite.credentialsClearedAt', { at: formatDateTime(saved.credentials_cleared_at) }) }}
          </span>
        </div>

        <template v-if="isS3">
          <el-form-item :label="$t('offsite.field.accessKeyId')">
            <el-input
              v-model="form.access_key_id"
              data-test="offsite-access-key"
              autocomplete="off"
              :disabled="form.clear_credentials"
              :placeholder="credentialPlaceholder"
            />
          </el-form-item>
          <el-form-item :label="$t('offsite.field.secretAccessKey')">
            <el-input
              v-model="form.secret_access_key"
              type="password"
              show-password
              data-test="offsite-secret-key"
              autocomplete="new-password"
              :disabled="form.clear_credentials"
              :placeholder="credentialPlaceholder"
            />
          </el-form-item>
        </template>
        <el-form-item
          v-else
          :label="$t('offsite.field.serviceAccountJson')"
        >
          <el-input
            v-model="form.service_account_json"
            type="textarea"
            :rows="4"
            data-test="offsite-sa-json"
            autocomplete="off"
            :disabled="form.clear_credentials"
            :placeholder="credentialPlaceholder"
          />
        </el-form-item>

        <el-checkbox
          v-if="saved.has_credentials"
          v-model="form.clear_credentials"
          class="clear-secret"
          data-test="offsite-clear-credentials"
        >
          {{ $t('offsite.clearCredentials') }}
        </el-checkbox>
        <div
          v-if="form.clear_credentials"
          class="field-warning"
        >
          {{ $t('offsite.clearCredentialsHint') }}
        </div>

        <div class="field-hint">
          {{ $t('offsite.hint.credentialWriteOnly') }}
        </div>
        <!-- 落點變更而憑證留空：後端會以靜態拒因擋下（換位址必須重輸），
             這裡只是在按下儲存之前就講明，省一次來回。
             既存無憑證時不提示——當下沒有憑證可被沿用到新位址 -->
        <div
          v-if="targetChangedNeedsCredentials"
          class="field-warning"
          data-test="offsite-move-needs-credentials"
        >
          {{ $t('offsite.hint.moveNeedsCredentials') }}
        </div>
      </el-card>
    </el-form>

    <el-alert
      v-if="formError"
      class="page-alert"
      type="error"
      data-test="offsite-form-error"
      :title="formError"
      :closable="false"
      show-icon
    />

    <div class="action-bar">
      <el-button
        :loading="testing"
        data-test="offsite-test"
        @click="handleTest"
      >
        {{ $t('offsite.test') }}
      </el-button>
      <el-button
        type="primary"
        :loading="saving"
        :disabled="loadFailed || loading"
        data-test="offsite-save"
        @click="handleSave"
      >
        {{ $t('common.save') }}
      </el-button>
      <span
        v-if="isDirty"
        class="action-bar__dirty"
      >{{ $t('offsite.unsavedChanges') }}</span>
      <span class="action-bar__hint">{{ $t('offsite.testHint') }}</span>
    </div>

    <!-- 連線測試結果：兩段分組（治理揭露／寫讀刪實測）是本端點存在的理由 -->
    <el-card
      v-if="testError || testResult"
      ref="resultCardRef"
      class="section-card result-card"
      data-test="offsite-test-result"
      aria-live="polite"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('offsite.testResultTitle') }}</span>
        </div>
      </template>

      <!-- 結果與表單已不對應：本頁的工作流是「先測後存」，結果卡因此會與
           使用者接下來的編輯並存。上一輪那句綠色「通過」會被讀成在替**現在**
           這份設定背書，逐步的綠色「通過」同理——過期即整份收起，只留中性聲明 -->
      <div
        v-if="testResultStale"
        class="field-warning result-stale"
        data-test="offsite-test-stale"
      >
        {{ $t('offsite.testResultStale') }}
      </div>

      <template v-else>
        <!-- 測試「未能執行」與「跑完但失敗」是兩件事：
             前者沒有階梯可看，混在一起呈現會讓人以為已經連上去過 -->
        <el-alert
          v-if="testError"
          type="error"
          data-test="offsite-test-error"
          :title="testError"
          :closable="false"
          show-icon
        />

        <template v-else>
          <el-alert
            :type="testHeadlineType"
            data-test="offsite-test-headline"
            :title="testHeadline"
            :closable="false"
            show-icon
          />
          <div
            v-for="group in testGroups"
            :key="group.id"
            class="stage-group"
          >
            <div class="stage-group__title">
              {{ $t(`offsite.testGroup.${group.id}`) }}
            </div>
            <div class="stage-group__hint">
              {{ $t(`offsite.testGroupHint.${group.id}`) }}
            </div>
            <ul class="stage-list">
              <li
                v-for="stage in group.stages"
                :key="stage.step"
                class="stage-item"
                :class="`stage-item--${stage.outcome}`"
                :data-test="`offsite-stage-${stage.step}`"
              >
                <el-icon class="stage-item__icon">
                  <CircleCheck v-if="stage.outcome === 'ok'" />
                  <CircleClose v-else-if="stage.outcome === 'fail'" />
                  <WarningFilled v-else-if="stage.outcome === 'warn'" />
                  <Minus v-else />
                </el-icon>
                <span class="stage-item__name">{{ $t(`offsite.testStep.${stage.step}`) }}</span>
                <span class="stage-item__state">
                  {{ $t(`offsite.testOutcome.${stage.outcome}`) }}
                </span>
                <div
                  v-if="stage.code"
                  class="stage-item__reason"
                >
                  {{ testCodeLabel(stage.code) }}
                </div>
                <div
                  v-else-if="stage.detail"
                  class="stage-item__detail"
                >
                  {{ stage.detail }}
                </div>
              </li>
            </ul>
          </div>
        </template>
      </template>
    </el-card>

    <!-- 佇列摘要。停用態隱藏上傳車道欄位（不再有新上傳），
         存量面照常曝光（停用態表） -->
    <el-card
      v-if="showLedgerPanels"
      class="section-card"
      data-test="offsite-queue"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('offsite.queueTitle') }}</span>
          <el-button
            v-if="!disabled"
            type="primary"
            link
            :loading="retryingAll"
            data-test="offsite-retry-failed"
            @click="handleRetryFailed"
          >
            {{ $t('offsite.retryFailed') }}
          </el-button>
        </div>
      </template>
      <div
        v-if="disabled"
        class="queue-note"
        data-test="offsite-disabled-note"
      >
        {{ $t('offsite.disabledNote') }}
      </div>
      <div class="queue-grid">
        <div
          v-for="item in queueItems"
          :key="item.key"
          class="queue-item"
          :data-test="`offsite-count-${item.key}`"
        >
          <span class="queue-item__value">{{ item.value }}</span>
          <span class="queue-item__label">{{ item.label }}</span>
        </div>
      </div>
      <div
        v-if="oldestPendingRows.length > 0"
        class="queue-ages"
        data-test="offsite-oldest-pending"
      >
        <span
          v-for="row in oldestPendingRows"
          :key="row.origin"
          class="queue-ages__item"
        >
          {{ $t('offsite.oldestPending', {
            origin: $t(`offsite.origin.${row.origin}`),
            age: formatDurationSeconds(row.seconds),
          }) }}
        </span>
      </div>
    </el-card>

    <!-- 失敗清單（分頁；距保留到期近者在前）。
         「距到期天數」欄必須每頁都看得見——排序只在頁內成立 -->
    <el-card
      v-if="showLedgerPanels"
      class="section-card"
      data-test="offsite-failures"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('offsite.failuresTitle') }}</span>
          <span class="card-hint">{{ $t('offsite.failuresHint') }}</span>
        </div>
      </template>
      <el-table
        v-loading="failuresLoading"
        :data="failures"
        size="small"
      >
        <el-table-column
          :label="$t('offsite.column.kind')"
          width="110"
        >
          <template #default="{ row }">
            {{ kindLabel(row?.kind) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('offsite.column.owner')">
          <template #default="{ row }">
            <router-link
              v-if="row.kind === 'recording'"
              :to="`/sessions/${row.owner_id}`"
              class="owner-link"
            >
              {{ row.label || `#${row.owner_id}` }}
            </router-link>
            <router-link
              v-else
              to="/audit/exports"
              class="owner-link"
            >
              {{ row.label || `#${row.owner_id}` }}
            </router-link>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('offsite.column.failedAt')"
          width="170"
        >
          <template #default="{ row }">
            {{ formatDateTime(row.updated_at) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('offsite.column.reason')"
          width="220"
        >
          <template #default="{ row }">
            {{ errorCodeLabel(row.error_code) }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('offsite.column.attempts')"
          width="90"
        >
          <template #default="{ row }">
            {{ row.attempts }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('offsite.column.deadline')"
          width="140"
        >
          <template #default="{ row }">
            <span
              v-if="row.days_to_deadline === undefined || row.days_to_deadline === null"
              class="muted"
            >{{ $t('offsite.noDeadline') }}</span>
            <span
              v-else
              :class="row.days_to_deadline <= 0 ? 'deadline-overdue' : ''"
              :data-test="`offsite-deadline-${row.object_id}`"
            >
              {{ row.days_to_deadline <= 0
                ? $t('offsite.deadlinePassed')
                : $t('offsite.daysToDeadline', { days: row.days_to_deadline }) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="90"
        >
          <template #default="{ row }">
            <el-button
              type="primary"
              link
              size="small"
              :data-test="`offsite-retry-${row.object_id}`"
              @click="handleRetryObject(row.object_id)"
            >
              {{ $t('offsite.retry') }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            :title="$t('offsite.noFailures')"
            :hint="$t('offsite.noFailuresHint')"
          />
        </template>
      </el-table>
      <el-pagination
        v-if="failuresTotal > failuresPageSize"
        class="pager"
        layout="prev, pager, next, total"
        :current-page="failuresPage"
        :page-size="failuresPageSize"
        :total="failuresTotal"
        @current-change="handleFailuresPage"
      />
    </el-card>

    <!-- 歷史世代列表：撤銷憑證是不可逆動作，走破壞性確認（C3） -->
    <el-card
      v-if="showLedgerPanels"
      class="section-card"
      data-test="offsite-profiles"
    >
      <template #header>
        <div class="card-header">
          <span class="card-title">{{ $t('offsite.profilesTitle') }}</span>
          <span class="card-hint">{{ $t('offsite.profilesHint') }}</span>
        </div>
      </template>
      <el-table
        v-loading="profilesLoading"
        :data="profiles"
        size="small"
      >
        <el-table-column
          :label="$t('offsite.column.generationId')"
          width="90"
        >
          <template #default="{ row }">
            {{ row.generation_id }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('offsite.column.fingerprint')"
          width="150"
        >
          <template #default="{ row }">
            <code>{{ row.profile_fingerprint }}</code>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('offsite.column.provider')"
          width="110"
        >
          <template #default="{ row }">
            {{ providerLabel(row.provider) }}
          </template>
        </el-table-column>
        <el-table-column :label="$t('offsite.column.location')">
          <template #default="{ row }">
            <div>{{ row.endpoint_origin || $t('offsite.endpointDefault') }}</div>
            <div class="muted">
              {{ row.bucket }}<span v-if="row.prefix">/{{ row.prefix }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('offsite.column.lifecycle')"
          width="200"
        >
          <template #default="{ row }">
            <div>{{ formatDateTime(row.activated_at || row.created_at) }}</div>
            <div class="muted">
              {{ row.retired_at
                ? $t('offsite.retiredAt', { at: formatDateTime(row.retired_at) })
                : $t('offsite.currentGeneration') }}
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('offsite.column.objectCount')"
          width="90"
        >
          <template #default="{ row }">
            {{ row.object_count }}
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('offsite.column.credentialMode')"
          width="150"
        >
          <template #default="{ row }">
            <el-tag
              :type="credentialModeTag(row.credential_mode)"
              effect="plain"
              size="small"
              :data-test="`offsite-profile-cred-${row.generation_id}`"
            >
              {{ credentialModeLabel(row.credential_mode) }}
            </el-tag>
            <div
              v-if="row.credentials_cleared_at"
              class="muted"
            >
              {{ formatDateTime(row.credentials_cleared_at) }}
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="110"
        >
          <template #default="{ row }">
            <el-button
              v-if="row.credential_mode === 'stored'"
              type="danger"
              link
              size="small"
              :data-test="`offsite-revoke-${row.generation_id}`"
              @click="handleRevoke(row)"
            >
              {{ $t('offsite.revokeCredentials') }}
            </el-button>
            <span
              v-else
              class="muted"
            >—</span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 本機副本保留天數（政策域 offsite）：到期只刪本機檔，
         錄影仍可自離機副本取回——它是磁碟預算旋鈕而不是保留期 -->
    <template v-if="showPolicySection">
      <PolicyPciBanner
        :loading="policyLoading"
        :saving="policySaving"
        :is-dirty="policyDirty"
        :deviation-count="pageDeviationCount"
        :deviation-text="$t('policyForm.pageDeviation', { n: pageDeviationCount }, pageDeviationCount)"
        :overview-count="totalDeviationCount"
        :epayment-deviation-count="pageEPaymentDeviationCount"
        @apply="applyPagePCI"
        @apply-epayment="applyPageEPayment"
        @reset="resetPolicyForm"
        @save="handleSavePolicies"
      />
      <PolicyKeySections
        :sections="visibleSections"
        :form-values="formValues"
        :saved-values="savedValues"
        @update:value="(key, value) => (formValues[key] = value)"
      />
    </template>

    <!-- 世代切換確認（C5 寬 560）：說清楚舊世代的三個去向，
         確認後才呼叫 confirm 端點並把回應帶回的兩個值**原樣**送出 -->
    <el-dialog
      v-model="confirmVisible"
      :title="$t('offsite.switchDialogTitle')"
      width="560px"
      data-test="offsite-switch-dialog"
    >
      <p class="switch-lead">
        {{ $t('offsite.switchLead', { count: pendingConfirm.object_count }) }}
      </p>
      <ul class="switch-consequences">
        <li>{{ $t('offsite.switchConsequence1') }}</li>
        <li>{{ $t('offsite.switchConsequence2') }}</li>
        <li>{{ $t('offsite.switchConsequence3') }}</li>
      </ul>
      <template #footer>
        <el-button
          data-test="offsite-switch-cancel"
          @click="confirmVisible = false"
        >
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="confirming"
          data-test="offsite-switch-confirm"
          @click="handleConfirmSwitch"
        >
          {{ $t('offsite.switchConfirm') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  CircleCheck,
  CircleClose,
  Minus,
  Refresh,
  WarningFilled,
} from '@element-plus/icons-vue'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import PolicyPciBanner from '@/components/PolicyPciBanner.vue'
import PolicyKeySections from '@/components/PolicyKeySections.vue'
import { usePolicyForm } from '@/composables/usePolicyForm'
import { OFFSITE_SECTIONS } from '@/constants/policyDomains'
import {
  OFFSITE_PROVIDERS,
  OFFSITE_TEST_CODES,
  OFFSITE_TEST_STEPS,
  OFFSITE_TEST_STEPS_DISCLOSURE,
  OFFSITE_TEST_STEPS_ROUNDTRIP,
  OFFSITE_ERROR_CODES,
  OFFSITE_VERSIONING_STATES,
} from '@/constants/offsite'
import { t } from '@/i18n'
import { confirmDestructive } from '@/utils/confirm'
import { apiErrorSummary } from '@/api/redact'
import { resolveApiError } from '@/api/error'
import { formatDateTime, formatDurationSeconds } from '@/utils/format'
import {
  confirmOffsiteGenerationSwitch,
  disableOffsiteStorage,
  getOffsiteFailures,
  getOffsiteStatus,
  listOffsiteProfiles,
  retryOffsiteFailed,
  retryOffsiteObject,
  revokeOffsiteProfileCredentials,
  saveOffsiteSettings,
  testOffsiteConnection,
} from '@/api/offsiteStorage'

// 元件層日誌只留白名單欄位：本頁請求本文帶儲存端憑證
const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const defaultForm = () => ({
  provider: 's3',
  endpoint: '',
  bucket: '',
  prefix: '',
  region: '',
  path_style: false,
  access_key_id: '',
  secret_access_key: '',
  service_account_json: '',
  clear_credentials: false,
})

const rootRef = ref(null)
const formRef = ref(null)
const resultCardRef = ref(null)

const loading = ref(false)
const loaded = ref(false)
const loadFailed = ref(false)
const saving = ref(false)
const testing = ref(false)
const disabling = ref(false)
const confirming = ref(false)
const retryingAll = ref(false)
const formError = ref('')

const form = reactive(defaultForm())

// 伺服端**已儲存**的事實（與表單草稿分離）：摘要卡、憑證徽章與落點變更提示
// 三者都必須以此為基準，否則會把草稿當成現況
const saved = ref({})
const credentialState = ref('')
const counts = ref({})
const totalObjects = ref(0)
const oldestPendingAges = ref({})
const governance = ref(null)

const configured = computed(() => saved.value.configured === true)
const disabled = computed(() => saved.value.disabled === true)
const canDisable = computed(() => configured.value && !disabled.value)

const testResult = ref(null)
const testError = ref('')
const testedSignature = ref('')

const failures = ref([])
const failuresTotal = ref(0)
const failuresPage = ref(1)
const failuresPageSize = 20
const failuresLoading = ref(false)

const profiles = ref([])
const profilesLoading = ref(false)

const confirmVisible = ref(false)
const pendingConfirm = ref({
  object_count: 0,
  expected_current_generation_id: 0,
  settings_digest: '',
  payload: null,
})

// 本機副本保留天數（政策域收編，沿金鑰管理頁承載金鑰政策的先例）
const {
  loading: policyLoading,
  saving: policySaving,
  formValues,
  savedValues,
  visibleSections,
  isDirty: policyDirty,
  pageDeviationCount,
  pageEPaymentDeviationCount,
  totalDeviationCount,
  loadPolicies,
  applyPagePCI,
  applyPageEPayment,
  resetForm: resetPolicyForm,
  save: savePolicies,
} = usePolicyForm(OFFSITE_SECTIONS)

const isS3 = computed(() => form.provider === 's3')

// ── 顯示層查譯（全部走前端閉集，未知值不顯示裸機器碼） ───────────────────

const providerLabel = (p) =>
  OFFSITE_PROVIDERS.includes(p) ? t(`offsite.provider.${p}`) : p || '-'

const CREDENTIAL_MODE_TAGS = {
  stored: 'success',
  default_chain: 'info',
  revoked: 'danger',
}
const credentialModeTag = (mode) => CREDENTIAL_MODE_TAGS[mode] || 'info'
const credentialModeLabel = (mode) =>
  CREDENTIAL_MODE_TAGS[mode] ? t(`offsite.credentialMode.${mode}`) : t('offsite.credentialMode.none')
const credentialModeTagType = computed(() => credentialModeTag(saved.value.credential_mode))

// el-table 會以空的 scope 求值一次 default slot（量測用），`row` 因此可能是
// undefined——直接把值串進 i18n 鍵會噴 "Not found offsite.kind.undefined"
const OFFSITE_KINDS = ['recording', 'export']
const kindLabel = (kind) => (OFFSITE_KINDS.includes(kind) ? t(`offsite.kind.${kind}`) : '')

const versioningLabel = (state) =>
  OFFSITE_VERSIONING_STATES.includes(state)
    ? t(`offsite.versioning.${state}`)
    : t('offsite.versioning.unknown')

// 機器碼帶 `offsite.` 前綴，而 vue-i18n 的鍵路徑以 `.` 分段——
// 直接串進去會被解成三層巢狀。查譯前先去前綴（去不掉就是未知值）
const codeSuffix = (code) => String(code || '').replace(/^offsite\./, '')

const testCodeLabel = (code) =>
  OFFSITE_TEST_CODES.includes(code)
    ? t(`offsite.testCode.${codeSuffix(code)}`)
    : t('offsite.testCodeUnknown')

const errorCodeLabel = (code) =>
  OFFSITE_ERROR_CODES.includes(code)
    ? t(`offsite.errorCode.${codeSuffix(code)}`)
    : t('offsite.errorCodeUnknown')

// ── 狀態帶 ────────────────────────────────────────────────────────────────

// 第一次成功讀取之前不得宣稱任何事實（沿 LDAP 目錄頁的教訓：loading 期間
// 以全對比度寫著「尚未設定」，而伺服器上可能正躺著一份已啟用的設定）
const status = computed(() => {
  if (loadFailed.value) return 'load_failed'
  if (!loaded.value) return 'loading'
  if (!configured.value) return 'unconfigured'
  return disabled.value ? 'disabled' : 'enabled'
})

const STATUS_TAG_TYPES = {
  enabled: 'success',
  disabled: 'warning',
  unconfigured: 'info',
  loading: 'info',
  load_failed: 'danger',
}
const statusTagType = computed(() => STATUS_TAG_TYPES[status.value] || 'info')
const statusLabel = computed(() => t(`offsite.status.${status.value}`))
const statusHint = computed(() => t(`offsite.statusHint.${status.value}`))

// 已儲存的端點是明文 http://：判的是**已儲存**值而非表單草稿
const savedPlaintextRisk = computed(
  () =>
    configured.value &&
    !loadFailed.value &&
    /^http:\/\//i.test(saved.value.endpoint_origin || '')
)

const endpointIsPlaintext = computed(() => /^http:\/\//i.test(form.endpoint.trim()))

// ── 面板可見性（空狀態口徑＝帳冊零列） ────────────────

const ledgerEmpty = computed(() => totalObjects.value === 0)
const showEmptyState = computed(() => loaded.value && ledgerEmpty.value)
const showLedgerPanels = computed(() => loaded.value && !ledgerEmpty.value)
const showSummary = computed(() => loaded.value && configured.value && !disabled.value)
// 保留天數旋鈕在「從未設定」時不出現：那是關於離機副本的設定，
// 而此時一份離機副本都不存在
const showPolicySection = computed(() => loaded.value && configured.value)

// ── 佇列摘要 ──────────────────────────────────────────────────────────────

// 停用態隱藏上傳車道欄位（不再有新上傳），存量面照常曝光（停用態表）
const UPLOAD_LANE_KEYS = ['pending', 'uploading']
const QUEUE_KEYS = [
  'pending',
  'uploading',
  'uploaded',
  'failed',
  'integrity_mismatch',
  'foreign',
  'local_purged',
]

const queueItems = computed(() => {
  const keys = disabled.value
    ? QUEUE_KEYS.filter((k) => !UPLOAD_LANE_KEYS.includes(k))
    : QUEUE_KEYS
  const items = keys.map((key) => ({
    key,
    value: counts.value[key] ?? 0,
    label: t(`offsite.count.${key}`),
  }))
  items.push({ key: 'total', value: totalObjects.value, label: t('offsite.count.total') })
  return items
})

// 無待上傳件的車道**不出現在回應中**（缺席與 0 是兩件事）；停用態不顯示
const oldestPendingRows = computed(() => {
  if (disabled.value) return []
  return Object.entries(oldestPendingAges.value || {}).map(([origin, seconds]) => ({
    origin,
    seconds: Math.round(Number(seconds) || 0),
  }))
})

// ── 測試連線 ──────────────────────────────────────────────────────────────

const TEST_GROUPS = [
  { id: 'disclosure', steps: OFFSITE_TEST_STEPS_DISCLOSURE },
  { id: 'roundtrip', steps: OFFSITE_TEST_STEPS_ROUNDTRIP },
]

// 恆列六步：回應未提及的步驟＝沒跑到，標為未執行而非消失——
// 分段回報存在的理由就是讓人看出「走到哪一步、還差幾步」
const testGroups = computed(() => {
  const reported = new Map(
    (testResult.value?.stages || [])
      .filter((s) => OFFSITE_TEST_STEPS.includes(s.step))
      .map((s) => [s.step, s])
  )
  return TEST_GROUPS.map((group) => ({
    id: group.id,
    stages: group.steps.map((step) => {
      const hit = reported.get(step)
      if (!hit) return { step, outcome: 'skipped', code: '', detail: '' }
      return { step, outcome: hit.outcome, code: hit.code || '', detail: hit.detail || '' }
    }),
  }))
})

const testHasWarn = computed(() =>
  (testResult.value?.stages || []).some((s) => s.outcome === 'warn')
)

const testHeadlineType = computed(() => {
  if (!testResult.value) return 'error'
  if (!testResult.value.passed) return 'error'
  return testHasWarn.value ? 'warning' : 'success'
})

const testHeadline = computed(() => {
  if (!testResult.value) return ''
  if (!testResult.value.passed) return t('offsite.testFailed')
  return testHasWarn.value ? t('offsite.testPassedWithWarnings') : t('offsite.testPassed')
})

// ── 草稿與過期判定 ────────────────────────────────────────────────────────

const settingsPayload = () => ({
  provider: form.provider,
  endpoint: form.endpoint.trim(),
  bucket: form.bucket.trim(),
  prefix: form.prefix.trim(),
  region: isS3.value ? form.region.trim() : '',
  path_style: isS3.value ? form.path_style : false,
  access_key_id: isS3.value ? form.access_key_id : '',
  secret_access_key: isS3.value ? form.secret_access_key : '',
  service_account_json: isS3.value ? '' : form.service_account_json,
  clear_credentials: form.clear_credentials,
})

const snapshotOf = () => JSON.stringify({ ...form })
const savedSnapshot = ref(snapshotOf())
const isDirty = computed(() => snapshotOf() !== savedSnapshot.value)

// 畫面上的測試結果是否已與表單脫節。比較的是**送去測試的那份 payload**——
// 表單任一欄變動即過期（test-then-save）
const testSignature = () => JSON.stringify(settingsPayload())
const testResultStale = computed(
  () =>
    Boolean(testResult.value || testError.value) &&
    testedSignature.value !== '' &&
    testedSignature.value !== testSignature()
)

// 落點（provider／端點／bucket）變更而憑證留空：後端會以靜態拒因擋下。
// **既存無憑證時不提示**——當下沒有憑證可被沿用到新位址
const targetChangedNeedsCredentials = computed(() => {
  if (!configured.value || saved.value.has_credentials !== true) return false
  if (form.clear_credentials) return false
  if (hasCredentialInput.value) return false
  return (
    form.provider !== saved.value.provider ||
    form.bucket.trim() !== (saved.value.bucket || '') ||
    !sameEndpointOrigin(form.endpoint.trim(), saved.value.endpoint_origin || '')
  )
})

const hasCredentialInput = computed(() =>
  isS3.value
    ? Boolean(form.access_key_id.trim() || form.secret_access_key)
    : Boolean(form.service_account_json.trim())
)

// 端點比對只到 origin：伺服端存的是完整正規化端點，回應給的是 origin
// （不回顯 path）。以 origin 比對會在「只改 path」時漏提示一次，
// 誤差方向落在「後端會擋、使用者多一次來回」而非「前端替它放行」
const sameEndpointOrigin = (a, b) => {
  const norm = (v) => {
    if (!v) return ''
    try {
      const u = new URL(v)
      return `${u.protocol}//${u.host}`.toLowerCase()
    } catch {
      return v.trim().toLowerCase()
    }
  }
  return norm(a) === norm(b)
}

const credentialPlaceholder = computed(() => {
  if (form.clear_credentials) return t('offsite.placeholder.credentialCleared')
  return saved.value.has_credentials
    ? t('offsite.placeholder.credentialKeep')
    : t('offsite.placeholder.credentialNew')
})

// ── 表單驗證（C6；伺服端才是權威，此處只提前擋住明顯錯誤） ──────────────

// 端點淨化與後端同判準：userinfo／query／fragment 三成分任一即拒。
// **訊息不回顯值**（回顯等於把使用者貼進去的密碼再印一次）
const validateEndpoint = (rule, value, callback) => {
  const raw = (value || '').trim()
  if (!raw) {
    if (isS3.value && !form.region.trim()) {
      callback(new Error(t('offsite.rule.regionOrEndpoint')))
      return
    }
    callback()
    return
  }
  let url
  try {
    url = new URL(raw)
  } catch {
    callback(new Error(t('offsite.rule.endpointInvalid')))
    return
  }
  if (!/^https?:$/.test(url.protocol) || !url.hostname) {
    callback(new Error(t('offsite.rule.endpointInvalid')))
    return
  }
  if (url.username || url.password || url.search || url.hash) {
    callback(new Error(t('offsite.rule.endpointHasSecrets')))
    return
  }
  callback()
}

// region 有自己的規則，**不能共用端點的驗證器**：region 是自由字串
// （`ap-northeast-1`），拿 URL 解析去驗它會使每一份填了區域的設定都被擋在本機，
// 連儲存鈕都按不下去
const validateRegionPair = (rule, value, callback) => {
  if (!isS3.value) {
    callback()
    return
  }
  if (!String(value || '').trim() && !form.endpoint.trim()) {
    callback(new Error(t('offsite.rule.regionOrEndpoint')))
    return
  }
  callback()
}

const formRules = computed(() => ({
  bucket: [
    { required: true, message: t('offsite.rule.bucketRequired'), trigger: 'blur' },
  ],
  endpoint: [{ validator: validateEndpoint, trigger: 'blur' }],
  region: [{ validator: validateRegionPair, trigger: 'blur' }],
}))

// 勾選「清除憑證」時一併清掉輸入框：欄位只是 disabled，
// 先打字再勾選會讓 model 仍留著那串字，送出的 body 同時帶新憑證與清除旗標，
// 而伺服端以「不可同時輸入新憑證與勾選清除憑證」拒絕——畫面上的欄位是灰的，
// 使用者看不出自己「填了」什麼
watch(
  () => form.clear_credentials,
  (on) => {
    if (on) {
      form.access_key_id = ''
      form.secret_access_key = ''
      form.service_account_json = ''
    }
  }
)

// ── 載入 ──────────────────────────────────────────────────────────────────

const applyView = (view) => {
  saved.value = view || {}
  const next = defaultForm()
  if (view?.configured === true) {
    next.provider = OFFSITE_PROVIDERS.includes(view.provider) ? view.provider : 's3'
    // **端點只回填 origin**：伺服端不回顯 path。使用者若原本填了帶 path
    // 的端點，重存時必須重新輸入完整值——這是刻意的，不猜
    next.endpoint = view.endpoint_origin || ''
    next.bucket = view.bucket || ''
    next.prefix = view.prefix || ''
    next.region = view.region || ''
    next.path_style = view.path_style === true
  }
  // 憑證欄**恆為空**：讀取回應永不含憑證，也不含遮罩值
  Object.assign(form, next)
  savedSnapshot.value = snapshotOf()
}

const fetchStatus = async () => {
  loading.value = true
  try {
    const res = await getOffsiteStatus()
    applyView(res)
    credentialState.value = res?.credential_state || ''
    counts.value = res?.counts || {}
    totalObjects.value = Number(res?.total_objects) || 0
    oldestPendingAges.value = res?.oldest_pending_age_seconds || {}
    governance.value = res?.governance || null
    loadFailed.value = false
    loaded.value = true
  } catch (error) {
    // 讀取失敗不清空表單：使用者可能正在編輯，靜默重置比顯示陳舊值更糟
    loadFailed.value = true
    logFailure('offsite_status_load_failed', error)
  } finally {
    loading.value = false
  }
}

const fetchFailures = async () => {
  failuresLoading.value = true
  try {
    const res = await getOffsiteFailures({ page: failuresPage.value, size: failuresPageSize })
    failures.value = res?.data || []
    failuresTotal.value = Number(res?.total) || 0
  } catch (error) {
    logFailure('offsite_failures_load_failed', error)
  } finally {
    failuresLoading.value = false
  }
}

const fetchProfiles = async () => {
  profilesLoading.value = true
  try {
    const res = await listOffsiteProfiles()
    profiles.value = res?.data || []
  } catch (error) {
    logFailure('offsite_profiles_load_failed', error)
  } finally {
    profilesLoading.value = false
  }
}

const handleFailuresPage = (page) => {
  failuresPage.value = page
  fetchFailures()
}

const refreshPage = async () => {
  if (isDirty.value) {
    try {
      await ElMessageBox.confirm(
        t('offsite.discardChangesConfirm'),
        t('offsite.discardChangesTitle'),
        {
          confirmButtonText: t('offsite.discardChangesButton'),
          cancelButtonText: t('common.cancel'),
          type: 'warning',
        }
      )
    } catch {
      return
    }
  }
  await Promise.all([fetchStatus(), fetchFailures(), fetchProfiles()])
}

// ── 錯誤呈現 ──────────────────────────────────────────────────────────────

// 狀態過期／摘要不符：不是設定錯誤，而是「你看到的畫面已經不是現況」。
// 提示重新讀取、**不自動重送**、不呈現成功樣態
const STALE_CODES = new Set([
  'CONFLICT_OFFSITE_SETTINGS_STALE_CONFIRMATION',
  'CONFLICT_OFFSITE_SETTINGS_DIGEST_MISMATCH',
])

const describeApiError = (resp, fallbackKey) =>
  resolveApiError(resp?.data, resp?.status, t(fallbackKey))

// ── 儲存與世代切換 ────────────────────────────────────────────────────────

// 寫入端點的回應同樣是伺服端權威視圖：存檔成功後狀態帶已有事實可說。
// **憑證三態不在此更新**——它由 `/status` 提供，緊接的 fetchStatus 會帶回來；
// 在這裡猜一個值等於用草稿冒充現況
const applySavedResult = (view) => {
  applyView(view)
  loadFailed.value = false
  loaded.value = true
  // 設定已改變，先前的測試結果不再對應現在的表單
  testResult.value = null
  testError.value = ''
  testedSignature.value = ''
}

const handleSave = async () => {
  formError.value = ''
  if (formRef.value) {
    let invalidFields = null
    const valid = await formRef.value.validate().catch((fields) => {
      invalidFields = fields
      return false
    })
    if (!valid) {
      await focusFirstInvalid(invalidFields)
      return
    }
  }

  saving.value = true
  const payload = settingsPayload()
  try {
    const res = await saveOffsiteSettings(payload, { skipErrorToast: true })
    if (res?.needs_confirmation === true) {
      pendingConfirm.value = {
        object_count: Number(res.object_count) || 0,
        // **原樣攜回**：0 是合法期望值（＝預期目前無現行世代），
        // 不可用「falsy 就省略」的寫法
        expected_current_generation_id: res.expected_current_generation_id,
        settings_digest: res.settings_digest,
        payload,
      }
      confirmVisible.value = true
      return
    }
    applySavedResult(res)
    ElMessage.success(t('offsite.saved'))
    await Promise.all([fetchStatus(), fetchProfiles()])
  } catch (error) {
    if (error?.response) {
      formError.value = describeApiError(error.response, 'offsite.saveFailed')
      logFailure('offsite_settings_save_failed', error)
    }
  } finally {
    saving.value = false
  }
}

const handleConfirmSwitch = async () => {
  confirming.value = true
  formError.value = ''
  try {
    const view = await confirmOffsiteGenerationSwitch(
      pendingConfirm.value.payload,
      pendingConfirm.value.expected_current_generation_id,
      pendingConfirm.value.settings_digest,
      { skipErrorToast: true }
    )
    confirmVisible.value = false
    applySavedResult(view)
    ElMessage.success(t('offsite.switched'))
    await Promise.all([fetchStatus(), fetchProfiles(), fetchFailures()])
  } catch (error) {
    const resp = error?.response
    if (!resp) return
    confirmVisible.value = false
    // 過期確認：提示重新讀取設定，**不自動重送**、不留成功樣態
    formError.value = STALE_CODES.has(resp.data?.code)
      ? t('offsite.staleConfirmation')
      : describeApiError(resp, 'offsite.switchFailed')
    logFailure('offsite_settings_confirm_failed', error)
  } finally {
    confirming.value = false
  }
}

const handleDisable = async () => {
  try {
    await confirmDestructive(t('offsite.disableConfirm'), t('offsite.disableConfirmTitle'), {
      confirmButtonText: t('offsite.disableConfirmButton'),
      cancelButtonText: t('common.cancel'),
    })
  } catch {
    return
  }
  disabling.value = true
  formError.value = ''
  try {
    const view = await disableOffsiteStorage({ skipErrorToast: true })
    applySavedResult(view)
    ElMessage.success(t('offsite.disabled'))
    await Promise.all([fetchStatus(), fetchProfiles()])
  } catch (error) {
    if (error?.response) {
      formError.value = describeApiError(error.response, 'offsite.disableFailed')
      logFailure('offsite_disable_failed', error)
    }
  } finally {
    disabling.value = false
  }
}

const handleRevoke = async (row) => {
  try {
    await confirmDestructive(
      t('offsite.revokeConfirm', { generation: row.generation_id, count: row.object_count }),
      t('offsite.revokeConfirmTitle'),
      {
        confirmButtonText: t('offsite.revokeConfirmButton'),
        cancelButtonText: t('common.cancel'),
      }
    )
  } catch {
    return
  }
  try {
    await revokeOffsiteProfileCredentials(row.generation_id, { skipErrorToast: true })
    ElMessage.success(t('offsite.revoked'))
    await Promise.all([fetchProfiles(), fetchStatus()])
  } catch (error) {
    if (error?.response) {
      formError.value = describeApiError(error.response, 'offsite.revokeFailed')
      logFailure('offsite_revoke_failed', error)
    }
  }
}

// ── 測試連線與重試 ────────────────────────────────────────────────────────

const revealTestResult = async () => {
  await nextTick()
  resultCardRef.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'nearest' })
}

const handleTest = async () => {
  formError.value = ''
  testError.value = ''
  testResult.value = null
  testing.value = true
  // 送出當下的值即本次結果所對應的設定
  testedSignature.value = testSignature()
  try {
    testResult.value = await testOffsiteConnection(settingsPayload(), { skipErrorToast: true })
  } catch (error) {
    const resp = error?.response
    if (!resp) return
    testError.value = describeApiError(resp, 'offsite.testFailedGeneric')
    logFailure('offsite_test_failed', error)
  } finally {
    testing.value = false
    if (testResult.value || testError.value) revealTestResult()
  }
}

const handleRetryFailed = async () => {
  try {
    await ElMessageBox.confirm(
      t('offsite.retryFailedConfirm'),
      t('offsite.retryFailedConfirmTitle'),
      {
        confirmButtonText: t('offsite.retry'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return
  }
  retryingAll.value = true
  try {
    const res = await retryOffsiteFailed()
    ElMessage.success(t('offsite.retryQueued', { count: Number(res?.retried) || 0 }))
    await Promise.all([fetchStatus(), fetchFailures()])
  } catch (error) {
    logFailure('offsite_retry_failed', error)
  } finally {
    retryingAll.value = false
  }
}

const handleRetryObject = async (objectId) => {
  try {
    await retryOffsiteObject(objectId)
    ElMessage.success(t('offsite.retryQueued', { count: 1 }))
    await Promise.all([fetchStatus(), fetchFailures()])
  } catch (error) {
    logFailure('offsite_retry_object_failed', error)
  }
}

const handleSavePolicies = async () => {
  await savePolicies()
}

// 驗證失敗時把第一個出問題的欄位捲進視野並取得焦點：
// 動作列在分區卡之後，從頁尾按下儲存而驗證擋下時，視窗內可能毫無變化
const focusFirstInvalid = async (fields) => {
  const first = fields && typeof fields === 'object' ? Object.keys(fields)[0] : ''
  try {
    if (first) formRef.value?.scrollToField?.(first)
  } catch {
    // jsdom／happy-dom 無 scrollIntoView：捲不動不該讓存檔流程整個爆掉
  }
  await nextTick()
  rootRef.value?.querySelector?.('.el-form-item.is-error input')?.focus?.()
}

onMounted(() => {
  // 四路獨立：任一方失敗不得吞掉另一方
  fetchStatus()
  fetchFailures()
  fetchProfiles()
  loadPolicies()
})
</script>

<style scoped>
.page-alert {
  margin-bottom: var(--ot-space-md);
}

.status-strip {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-md);
}

.status-strip__label {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.status-strip__hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

/* 明文端點風險獨佔一行：接在 hint 後面同一行會被讀成同一句的補述，
   而它講的是相反方向的事 */
.status-strip__risk {
  width: 100%;
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.ledger-empty {
  margin-bottom: var(--ot-space-md);
}

.section-card {
  margin-bottom: var(--ot-space-md);
}

.card-header {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 12px;
}

.card-title {
  font-weight: 600;
}

.card-hint {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.field-hint {
  width: 100%;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: 4px;
}

.field-warning {
  width: 100%;
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  margin-top: 4px;
}

.credential-state {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-sm);
}

.credential-state__label {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.credential-state__hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.clear-secret {
  width: 100%;
}

.action-bar {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
}

.action-bar__hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.action-bar__dirty {
  color: var(--ot-warning, #e6a23c);
  font-size: var(--ot-font-size-xs);
}

/* 結果過期聲明置於結果卡最上方：它限定的是整張卡的可信度 */
.result-stale {
  margin-top: 0;
  margin-bottom: var(--ot-space-xs);
}

.stage-group {
  margin-top: var(--ot-space-sm);
}

.stage-group__title {
  font-weight: 600;
  font-size: var(--ot-font-size-sm);
}

.stage-group__hint {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.stage-list {
  list-style: none;
  margin: var(--ot-space-xs) 0 0;
  padding: 0;
}

.stage-item {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
  padding: 4px 0;
}

.stage-item--ok {
  color: var(--el-color-success);
}

.stage-item--warn {
  color: var(--ot-warning, #e6a23c);
}

.stage-item--fail {
  color: var(--el-color-danger);
}

/* 未執行：次要色。不可與失敗同色——「沒跑到」不是「失敗」 */
.stage-item--skipped {
  color: var(--ot-text-secondary);
}

.stage-item__name {
  color: var(--ot-text-primary);
}

.stage-item__state,
.stage-item__detail {
  font-size: var(--ot-font-size-xs);
}

.stage-item__detail {
  width: 100%;
  color: var(--ot-text-secondary);
  line-height: 1.6;
}

.stage-item__reason {
  width: 100%;
  color: var(--el-color-danger);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.governance {
  margin-top: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.queue-note {
  margin-bottom: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.queue-grid {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-lg);
}

.queue-item {
  display: flex;
  flex-direction: column;
  min-width: 88px;
}

.queue-item__value {
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
}

.queue-item__label {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.queue-ages {
  margin-top: var(--ot-space-sm);
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-md);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.pager {
  margin-top: var(--ot-space-sm);
  justify-content: flex-end;
}

.owner-link {
  color: var(--el-color-primary);
}

.muted {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

/* 已逾保留期：本機副本隨時會被清掉，而遠端還沒有副本——
   這一列是唯一可能永久失去證據的情形，必須與其他列分色 */
.deadline-overdue {
  color: var(--el-color-danger);
  font-weight: 600;
}

.switch-lead {
  margin: 0 0 var(--ot-space-sm);
}

.switch-consequences {
  margin: 0;
  padding-left: 1.2em;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.8;
}
</style>
