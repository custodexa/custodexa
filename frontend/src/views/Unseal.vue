<template>
  <PreservicePage
    :messages="statusMessages"
    :tone="isFreshInstall ? 'danger' : 'default'"
    :right-class="['unseal-card', { 'is-initialization': isFreshInstall }]"
  >
    <!-- 封存期語言切換（i18n「Language switching」）：封存時本頁是唯一可達頁面，
         沒有切換入口＝看不懂預設語言的操作者被卡在一個擋住全部服務的頁面上。
         純前端（setLanguage 只寫 i18n locale 與 localStorage），故後端 503 不影響它 -->
    <template #lang>
      <div class="lang-switch">
        <el-dropdown @command="setLanguage">
          <span class="lang-switch-label">
            {{ LOCALE_LABELS[locale] }}
            <el-icon class="el-icon--right"><ChevronDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item
                v-for="l in SUPPORTED_LOCALES"
                :key="l"
                :command="l"
                :disabled="l === locale"
              >
                {{ LOCALE_LABELS[l] }}
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </template>

    <!-- 左欄：現在是什麼狀態、什麼不能弄丟。此欄的內容增減不影響右欄版位 -->
    <template #left>
      <header class="unseal-header">
        <h1 class="unseal-title">
          {{ $t('unseal.title') }}
        </h1>
        <p class="unseal-subtitle">
          {{ $t(delegated ? 'unseal.delegatedSubtitle' : 'unseal.subtitle') }}
        </p>
      </header>

      <!-- 狀態區：四態徽章＋世代＋手動重整（解封中自動輪詢） -->
      <div
        v-loading="statusLoading"
        class="status-row"
      >
        <el-tag
          :type="stateTagType"
          effect="dark"
          class="state-badge"
        >
          {{ stateLabel }}
        </el-tag>
        <span class="status-meta">{{ $t('unseal.generation', { n: status.generation ?? 0 }) }}</span>
        <el-button
          text
          :loading="statusLoading"
          @click="loadStatus"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </div>

      <!-- 遺失警語（i18n「遺失警語之版面優先度」）：左欄在文件順序上先於右欄，
           故它恆在任何解封表單之前，且不隨狀態訊息增減而被推走。
           委託模式換成對應陳述（主金鑰在外部保管處，失去同樣救不回），版面優先度相同。
           已解封時不顯示：該狀態下這句不可行動，恆掛只會訓練使用者忽略它 -->
      <div
        v-if="!isUnsealed"
        class="loss-callout"
      >
        <el-icon class="loss-icon">
          <TriangleAlert />
        </el-icon>
        <div>
          <p class="loss-title">
            {{ $t(delegated ? 'unseal.delegatedLossTitle' : 'unseal.lossTitle') }}
          </p>
          <p class="loss-body">
            {{ $t(delegated ? 'unseal.delegatedLossBody' : 'unseal.lossBody') }}
          </p>
        </div>
      </div>
      <p
        v-if="delegated && !isUnsealed"
        class="field-hint credential-memory-note"
      >
        {{ $t('unseal.credentialMemoryNote') }}
      </p>
      <p
        v-if="status.cleanup_pending || state === 'sealed-faulted'"
        class="field-hint"
      >
        {{ $t('unseal.cleanupGuidance') }}
      </p>
    </template>

    <!-- 右欄：唯一要做的那件事。**板與板之間互斥**——阻擋／停止／逾時／進行中／
         失敗四板皆 SHALL NOT 渲染任何秘密輸入欄，故它們與精靈是同一層的 v-if 鏈，
         不是疊在精靈之上的提示 -->
    <template #right>
      <!-- 已解封：不再提供解封表單（再送只會拿到 409） -->
      <template v-if="isUnsealed">
        <h2 class="section-title is-success">
          {{ $t('unseal.unsealedTitle') }}
        </h2>
        <p class="section-desc">
          {{ $t('unseal.unsealedDesc') }}
        </p>
        <el-button
          type="primary"
          class="submit-btn goto-login"
          @click="goLogin"
        >
          {{ $t('unseal.goLogin') }}
        </el-button>
      </template>

      <!-- 狀態未知的阻擋頁：路徑判定只有後端權威，猜錯的代價是把憑證交給
           判定錯誤的流程，故這裡不預設任一路徑、也不渲染任何輸入欄 -->
      <section
        v-else-if="statusUnknown"
        class="board blocked-board"
      >
        <h2 class="section-title">
          {{ $t('unseal.blockedTitle') }}
        </h2>
        <p class="section-desc">
          {{ $t('unseal.blockedDesc') }}
        </p>
        <el-button
          type="primary"
          class="submit-btn"
          :loading="statusLoading"
          @click="loadStatus"
        >
          {{ $t('unseal.blockedAction') }}
        </el-button>
        <p class="field-hint">
          {{ $t('unseal.blockedNote') }}
        </p>
      </section>

      <!-- 逾時導引板：初始化可能已部分完成，重送等於在未知狀態上再跑一次，
           故這裡**不重呈秘密表單**，只給「查詢最新狀態」 -->
      <section
        v-else-if="outcome === 'timeout'"
        class="board timeout-board"
      >
        <h2 class="section-title">
          {{ $t('unseal.timeoutBoardTitle') }}
        </h2>
        <p class="section-desc">
          {{ $t('unseal.timeoutBoardDesc') }}
        </p>
        <el-button
          type="primary"
          class="submit-btn"
          :loading="statusLoading"
          @click="probeAfterTimeout"
        >
          {{ $t('unseal.timeoutCheckStatus') }}
        </el-button>
        <p
          v-if="timeoutProbe"
          class="timeout-probe"
        >
          {{ $t(TIMEOUT_PROBE_TEXT_KEYS[timeoutProbe]) }}
        </p>
        <el-button
          v-if="timeoutProbe === 'sealed'"
          class="submit-btn timeout-retry"
          @click="resumeAfterTimeout"
        >
          {{ $t('unseal.timeoutRetry') }}
        </el-button>
      </section>

      <!-- 進行中：粗粒度階段，前端不以計時宣布成功或失敗 -->
      <section
        v-else-if="outcome === 'working'"
        class="board working-board"
      >
        <h2 class="section-title">
          {{ $t('unseal.workingTitle') }}
        </h2>
        <div class="working-row">
          <span class="working-spinner" />
          <span>{{ $t('unseal.workingDesc') }}</span>
        </div>
        <p class="field-hint">
          {{ $t('unseal.workingNote') }}
        </p>
      </section>

      <!-- 可區分的失敗三類：只在通過帳密驗證後才由後端給出細分 -->
      <section
        v-else-if="outcome === 'failed'"
        class="board failure-board"
      >
        <h2 class="section-title">
          {{ $t('unseal.failureTitle') }}
        </h2>
        <div class="failure-callout">
          <el-icon class="failure-icon">
            <TriangleAlert />
          </el-icon>
          <div>
            <p class="failure-title">
              {{ $t(FAILURE_TEXT_KEYS[failureCode].title) }}
            </p>
            <p class="failure-body">
              {{ $t(FAILURE_TEXT_KEYS[failureCode].desc) }}
            </p>
          </div>
        </div>
        <p class="field-hint">
          {{ $t('unseal.failureNote') }}
        </p>
        <el-button
          type="primary"
          class="submit-btn"
          @click="retryAfterFailure"
        >
          {{ $t('unseal.failureRetry') }}
        </el-button>
      </section>

      <!-- 冷卻倒數：系統暫停接受輸入，故這段期間不呈現表單 -->
      <section
        v-else-if="inCooldown"
        class="board cooldown-board"
      >
        <h2 class="section-title">
          {{ $t('unseal.cooldownTitle') }}
        </h2>
        <div class="cooldown-row">
          <el-tag
            type="warning"
            effect="dark"
          >
            {{ $t('unseal.cooldownBadge') }}
          </el-tag>
          <span class="cooldown-remaining">
            {{ $t('unseal.cooldownRemainingLabel', { remaining: cooldownRemainingText }) }}
          </span>
        </div>
        <p class="section-desc">
          {{ $t('unseal.cooldownBody') }}
        </p>
        <p class="field-hint">
          {{ $t('unseal.cooldownNote') }}
        </p>
      </section>

      <!-- 拓撲不相符的停止頁：只給停止指引，**沒有改位址或換保管處的捷徑** -->
      <section
        v-else-if="stopped"
        class="board stop-board"
      >
        <h2 class="section-title is-danger">
          {{ $t('unseal.stopTitle') }}
        </h2>
        <p class="section-desc">
          {{ $t('unseal.stopDesc') }}
        </p>
        <ol class="board-steps">
          <li>{{ $t('unseal.stopStep1') }}</li>
          <li>{{ $t('unseal.stopStep2') }}</li>
          <li>{{ $t('unseal.stopStep3') }}</li>
        </ol>
        <p class="field-hint">
          {{ $t('unseal.stopNote') }}
        </p>
        <el-button
          class="submit-btn"
          @click="stopped = false"
        >
          {{ $t('unseal.stopBack') }}
        </el-button>
      </section>

      <!-- 精靈本體：既有部署三步、全新安裝四步，共用同一條狀態列與版位 -->
      <template v-else>
        <ol class="step-rail">
          <li
            v-for="(key, index) in steps"
            :key="key"
            class="step-rail-item"
            :class="{
              'is-done': index < activeStep,
              'is-active': index === activeStep,
            }"
          >
            <span class="step-rail-num">{{ index < activeStep ? '✓' : index + 1 }}</span>
            <span class="step-rail-label">{{ $t(STEP_LABEL_KEYS[key]) }}</span>
          </li>
        </ol>

        <!-- 第 1 步（既有部署）：驗證身分。秘密欄在此之前一律不渲染 -->
        <section
          v-if="currentStep === 'verify'"
          class="form-section verify-section"
          role="group"
          aria-labelledby="unseal-admin-label"
        >
          <h2
            id="unseal-admin-label"
            class="section-title"
          >
            {{ $t('unseal.verifyTitle') }}
          </h2>
          <p class="section-desc">
            {{ $t('unseal.verifyDesc') }}
          </p>
          <div class="field-row">
            <el-input
              v-model="username"
              class="admin-input"
              autocomplete="off"
              :aria-label="$t('unseal.usernamePlaceholder')"
              :placeholder="$t('unseal.usernamePlaceholder')"
            />
            <el-input
              v-model="password"
              class="admin-input"
              type="password"
              autocomplete="off"
              :aria-label="$t('unseal.passwordPlaceholder')"
              :placeholder="$t('unseal.passwordPlaceholder')"
              @keyup.enter="verifyIdentity"
            />
          </div>
          <el-button
            type="primary"
            class="submit-btn verify-btn"
            :loading="verifying"
            :disabled="!username || !password || verifying"
            @click="verifyIdentity"
          >
            {{ $t('unseal.verifyAction') }}
          </el-button>
          <p class="field-hint">
            {{ $t('unseal.verifyBackoffHint') }}
          </p>
        </section>

        <!-- 第 1 步（全新安裝）：初始管理者驗證。初始管理員由段 1 的種子於解封
             之前建立，故這一步是驗證那組部署提供的帳密，不是在此建立帳號 -->
        <section
          v-else-if="currentStep === 'createAdmin'"
          class="form-section create-admin-section"
          role="group"
          aria-labelledby="unseal-init-admin-label"
        >
          <h2
            id="unseal-init-admin-label"
            class="section-title init-title"
          >
            {{ $t('unseal.initAdminTitle') }}
          </h2>
          <p class="section-desc">
            {{ $t('unseal.initAdminDesc') }}
          </p>
          <div class="field-row">
            <el-input
              v-model="username"
              class="admin-input"
              autocomplete="off"
              :aria-label="$t('unseal.usernamePlaceholder')"
              :placeholder="$t('unseal.usernamePlaceholder')"
            />
            <el-input
              v-model="password"
              class="admin-input"
              type="password"
              autocomplete="off"
              :aria-label="$t('unseal.passwordPlaceholder')"
              :placeholder="$t('unseal.passwordPlaceholder')"
            />
          </div>
          <p class="field-hint">
            {{ $t('unseal.initAdminHint') }}
          </p>
          <div class="step-actions">
            <el-button
              type="primary"
              :loading="verifying"
              :disabled="!username || !password || verifying"
              @click="authorizeFreshInstall"
            >
              {{ $t('unseal.nextStep') }}
            </el-button>
          </div>
        </section>

        <!-- 第 2 步（既有部署）：核對保管處。唯讀，確認相符才進憑證步驟 -->
        <section
          v-else-if="currentStep === 'review'"
          class="form-section review-section"
        >
          <div class="verified-banner">
            <span class="verified-text">{{ $t('unseal.verifiedAs', { name: verifiedUser }) }}</span>
            <el-button
              text
              class="change-account"
              @click="changeAccount"
            >
              {{ $t('unseal.changeAccount') }}
            </el-button>
          </div>
          <h2 class="section-title">
            {{ $t('unseal.reviewTitle') }}
          </h2>
          <p class="section-desc">
            {{ $t('unseal.reviewDesc') }}
          </p>
          <el-alert
            v-if="topologyChanged"
            type="warning"
            :closable="false"
            show-icon
            :title="$t('unseal.reviewChanged')"
          />
          <div
            v-if="topologyRows.length"
            class="topology-card"
          >
            <dl class="topology-grid">
              <template
                v-for="row in topologyRows"
                :key="row.label"
              >
                <dt>{{ $t(row.label) }}</dt>
                <dd class="topology-value">
                  {{ row.value || $t('unseal.reviewUnset') }}
                </dd>
              </template>
            </dl>
          </div>
          <p
            v-else
            class="field-error"
          >
            {{ $t('unseal.reviewUnavailable') }}
          </p>
          <p class="field-hint">
            {{ $t('unseal.reviewNote') }}
          </p>
          <div class="step-actions">
            <el-button
              class="reject-btn"
              @click="rejectTopology"
            >
              {{ $t('unseal.reviewReject') }}
            </el-button>
            <el-button
              type="primary"
              :disabled="!topologyRows.length"
              @click="confirmTopology"
            >
              {{ $t('unseal.reviewConfirm') }}
            </el-button>
          </div>
        </section>

        <!-- 第 2 步（全新安裝）：設定保管處。服務商唯讀（部署檔宣告），此處只收拓撲 -->
        <section
          v-else-if="currentStep === 'topology'"
          class="form-section topology-section"
        >
          <h2 class="section-title">
            {{ $t('unseal.initTopologyTitle') }}
          </h2>
          <p class="section-desc">
            {{ $t('unseal.initTopologyDesc', { provider: providerLabel }) }}
          </p>
          <div
            v-for="field in topologyFields"
            :key="field.model"
            class="field-block"
          >
            <span
              :id="`unseal-topo-${field.model}-label`"
              class="field-sublabel"
            >{{ $t(field.label) }}</span>
            <el-input
              v-model="topologyDraft[field.model]"
              class="topo-input"
              spellcheck="false"
              autocomplete="off"
              :aria-labelledby="`unseal-topo-${field.model}-label`"
            />
          </div>
          <p
            v-if="topologyFields.some((f) => f.model === 'key_ref')"
            class="field-hint"
          >
            {{ $t('unseal.topoKeyRefHint') }}
          </p>
          <div class="step-actions">
            <el-button @click="goPrevFreshStep">
              {{ $t('unseal.prevStep') }}
            </el-button>
            <el-button
              type="primary"
              :disabled="!topologyDraftComplete"
              @click="goNextFreshStep"
            >
              {{ $t('unseal.nextStep') }}
            </el-button>
          </div>
        </section>

        <!-- 第 3 步：提供憑證（委託模式）。三家各自的秘密欄，一律遮蔽、不回顯 -->
        <section
          v-else-if="currentStep === 'credentials'"
          class="form-section credentials-section"
        >
          <div
            v-if="!isFreshInstall"
            class="verified-banner"
          >
            <span class="verified-text">
              {{ $t('unseal.credentialsReviewed', {
                provider: providerLabel,
                address: reviewedAddress,
              }) }}
            </span>
            <el-button
              text
              class="back-to-review"
              @click="backToReview"
            >
              {{ $t('unseal.backToReview') }}
            </el-button>
          </div>
          <h2 class="section-title">
            {{ $t(CREDENTIAL_TITLE_KEYS[credentialForm] || 'unseal.credentialsTitle') }}
          </h2>
          <p class="section-desc">
            {{ $t('unseal.credentialsDesc') }}
          </p>

          <!-- AWS：兩欄 -->
          <template v-if="credentialForm === 'aws'">
            <div class="field-block">
              <span
                id="unseal-aws-key-label"
                class="field-sublabel"
              >{{ $t('unseal.awsAccessKeyId') }}</span>
              <el-input
                v-model="awsAccessKeyId"
                class="secret-input"
                type="password"
                spellcheck="false"
                autocomplete="off"
                aria-labelledby="unseal-aws-key-label"
              />
            </div>
            <div class="field-block">
              <span
                id="unseal-aws-secret-label"
                class="field-sublabel"
              >{{ $t('unseal.awsSecretAccessKey') }}</span>
              <el-input
                v-model="awsSecretAccessKey"
                class="secret-input"
                type="password"
                spellcheck="false"
                autocomplete="off"
                aria-labelledby="unseal-aws-secret-label"
              />
            </div>
          </template>

          <!-- GCP：金鑰檔內容只顯示大小。輸入框本身恆不持有內容
               （每次輸入即移交記憶體變數並清空節點），故沒有可回顯的副本 -->
          <template v-else-if="credentialForm === 'gcp'">
            <div class="field-block">
              <span
                id="unseal-gcp-label"
                class="field-sublabel"
              >{{ $t('unseal.gcpServiceAccount') }}</span>
              <textarea
                ref="gcpInputRef"
                class="gcp-input"
                rows="4"
                spellcheck="false"
                autocomplete="off"
                aria-labelledby="unseal-gcp-label"
                :placeholder="$t('unseal.gcpPlaceholder')"
                @input="onGcpInput"
              />
            </div>
            <p class="field-hint gcp-size">
              {{ gcpJson ? $t('unseal.gcpPasted', { size: gcpSizeText }) : $t('unseal.gcpEmpty') }}
            </p>
            <el-button
              v-if="gcpJson"
              text
              class="gcp-clear"
              @click="clearGcp"
            >
              {{ $t('unseal.gcpClear') }}
            </el-button>
          </template>

          <!-- Vault：角色密鑰與直接權杖二選一，切換即清空前一種 -->
          <template v-else>
            <el-radio-group
              v-model="vaultMethod"
              class="vault-method"
              @change="onVaultMethodChange"
            >
              <el-radio-button value="role">
                {{ $t('unseal.vaultMethodRole') }}
              </el-radio-button>
              <el-radio-button value="token">
                {{ $t('unseal.vaultMethodToken') }}
              </el-radio-button>
            </el-radio-group>
            <div
              v-if="vaultMethod === 'role'"
              class="field-block"
            >
              <span
                id="unseal-vault-secret-label"
                class="field-sublabel"
              >{{ $t('unseal.vaultSecretId') }}</span>
              <el-input
                v-model="vaultSecretId"
                class="secret-input"
                type="password"
                spellcheck="false"
                autocomplete="off"
                aria-labelledby="unseal-vault-secret-label"
              />
              <p class="field-hint">
                {{ $t('unseal.vaultSecretIdHint') }}
              </p>
            </div>
            <div
              v-else
              class="field-block"
            >
              <span
                id="unseal-vault-token-label"
                class="field-sublabel"
              >{{ $t('unseal.vaultToken') }}</span>
              <el-input
                v-model="vaultToken"
                class="secret-input"
                type="password"
                spellcheck="false"
                autocomplete="off"
                aria-labelledby="unseal-vault-token-label"
              />
              <p class="field-hint">
                {{ $t('unseal.vaultTokenHint') }}
              </p>
            </div>
          </template>

          <p class="field-hint">
            {{ $t('unseal.credentialsIssuer') }}
          </p>
          <div
            v-if="isFreshInstall"
            class="step-actions"
          >
            <el-button @click="goPrevFreshStep">
              {{ $t('unseal.prevStep') }}
            </el-button>
            <el-button
              type="primary"
              :disabled="!credentialsReady"
              @click="goNextFreshStep"
            >
              {{ $t('unseal.nextStep') }}
            </el-button>
          </div>
          <el-button
            v-else
            type="primary"
            class="submit-btn"
            :loading="submitting"
            :disabled="submitDisabled"
            @click="submit"
          >
            {{ $t('unseal.submitCredentials') }}
          </el-button>
          <p class="field-hint">
            {{ $t('unseal.credentialsSecretNote') }}
          </p>
        </section>

        <!-- 第 4 步（全新安裝）：建立金鑰並啟用。一次送出前三步收到的全部內容 -->
        <section
          v-else-if="currentStep === 'activate'"
          class="form-section activate-section"
        >
          <h2 class="section-title">
            {{ $t('unseal.initActivateTitle') }}
          </h2>
          <p class="section-desc">
            {{ $t('unseal.initActivateDesc') }}
          </p>
          <ul class="summary-list">
            <li>{{ $t('unseal.initSummaryAdmin', { name: username }) }}</li>
            <li>
              {{ $t('unseal.initSummaryCustody', {
                provider: providerLabel,
                address: draftAddressText,
              }) }}
            </li>
            <li>{{ $t('unseal.initSummaryCredential') }}</li>
          </ul>
          <p class="field-hint">
            {{ $t('unseal.initActivateNote') }}
          </p>
          <div class="step-actions">
            <el-button @click="goPrevFreshStep">
              {{ $t('unseal.prevStep') }}
            </el-button>
            <el-button
              type="primary"
              class="activate-btn"
              :loading="submitting"
              :disabled="submitDisabled"
              @click="submit"
            >
              {{ $t('unseal.initActivateAction') }}
            </el-button>
          </div>
        </section>

        <!-- ui 模式：提供本地主金鑰。初始化路徑另收逐字確認與保存確認 -->
        <section
          v-else-if="currentStep === 'material'"
          class="form-section"
          :class="isFreshInstall ? 'init-section' : 'normal-section'"
        >
          <h2
            class="section-title"
            :class="{ 'init-title': isFreshInstall }"
          >
            {{ $t(isFreshInstall ? 'unseal.initTitle' : 'unseal.normalTitle') }}
          </h2>
          <p
            class="section-desc"
            :class="{ 'init-desc': isFreshInstall }"
          >
            {{ $t(isFreshInstall ? 'unseal.initWarningTitle' : 'unseal.normalDesc') }}
          </p>
          <p
            v-if="isFreshInstall"
            class="field-hint"
          >
            {{ $t('unseal.initWarningDesc') }}
          </p>

          <div class="field-block">
            <span
              :id="materialLabelId"
              class="field-sublabel"
            >{{ $t('unseal.materialLabel') }}</span>
            <div class="field-row">
              <el-input
                v-model="material"
                :aria-labelledby="materialLabelId"
                class="material-input"
                spellcheck="false"
                autocomplete="off"
                :placeholder="$t('unseal.materialPlaceholder')"
              />
              <el-button
                v-if="isFreshInstall"
                @click="generateLocalMaterial"
              >
                {{ $t('unseal.generateLocal') }}
              </el-button>
            </div>
            <p
              v-if="materialFormatMessage"
              class="field-error"
            >
              {{ materialFormatMessage }}
            </p>
            <template v-if="isFreshInstall">
              <span
                id="unseal-init-confirm-label"
                class="field-sublabel"
              >{{ $t('unseal.materialConfirmLabel') }}</span>
              <el-input
                v-model="materialConfirm"
                aria-labelledby="unseal-init-confirm-label"
                class="material-input"
                spellcheck="false"
                autocomplete="off"
                :placeholder="$t('unseal.materialConfirmPlaceholder')"
              />
              <p
                v-if="confirmMismatch"
                class="field-error"
              >
                {{ $t('unseal.materialConfirmMismatch') }}
              </p>
            </template>
            <p class="field-hint">
              {{ $t('unseal.materialSizeHint') }}
            </p>
            <UnsealFormatDetails />
          </div>

          <el-checkbox
            v-if="isFreshInstall"
            v-model="confirmSaved"
          >
            {{ $t('unseal.confirmSavedCheckbox') }}
          </el-checkbox>

          <el-button
            type="primary"
            class="submit-btn"
            :loading="submitting"
            :disabled="submitDisabled"
            @click="submit"
          >
            {{ $t('unseal.submit') }}
          </el-button>
        </section>

        <!-- env 模式：重讀部署來源，不在這裡輸入任何金鑰 -->
        <section
          v-else-if="currentStep === 'reload'"
          class="form-section env-section"
        >
          <h2 class="section-title">
            {{ $t('unseal.envTitle') }}
          </h2>
          <p class="section-desc">
            {{ $t('unseal.envDesc') }}
          </p>
          <p class="field-hint">
            {{ $t('unseal.envGuidance') }}
          </p>
          <el-button
            type="primary"
            class="submit-btn"
            :loading="submitting"
            :disabled="submitDisabled"
            @click="submit"
          >
            {{ $t('unseal.envAction') }}
          </el-button>
        </section>
      </template>
    </template>
  </PreservicePage>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { ChevronDown, TriangleAlert } from 'lucide-vue-next'
import { getSealStatus, sealAuthorize, unseal } from '@/api/seal'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
import { generateKEKMaterial, validateKEKMaterialFormat } from '@/utils/kek'
import { publishSealStatus } from '@/utils/sealPhase'
import PreservicePage from '@/components/PreservicePage.vue'
import UnsealFormatDetails from '@/components/UnsealFormatDetails.vue'
import { SUPPORTED_LOCALES, LOCALE_LABELS, setLanguage, t } from '@/i18n'

// 解封頁。封存期可達且**不需已登入的工作階段**，但自本版起一律先驗管理員帳密：
// 第一段拿短效授權脈絡（grant），第二段才顯示任何秘密欄位。
// grant 只活在本元件的記憶體，不進任何 storage；秘密同此，且送出或離開即清空。
//
// 已封存狀態下只驗帳密、不驗動態驗證碼——種子是受資料金鑰保護的欄位，
// 封存時解不開，要求它會構成「先解封才能驗證、先驗證才能解封」的循環。

const router = useRouter()
const { locale } = useI18n()

const status = ref({})
const statusLoading = ref(false)
const statusError = ref('')
const submitting = ref(false)
const verifying = ref(false)

// —— 流程狀態 ——
const grant = ref('')
const verifiedUser = ref('')
const reviewedDigest = ref('')
const topologyChanged = ref(false)
const stopped = ref(false)
const freshStep = ref(0)
const outcome = ref('')
const failureCode = ref('')
const timeoutProbe = ref('')

// —— 輸入 ——
const username = ref('')
const password = ref('')
const material = ref('')
const materialConfirm = ref('')
const confirmSaved = ref(false)
const awsAccessKeyId = ref('')
const awsSecretAccessKey = ref('')
const gcpJson = ref('')
const gcpInputRef = ref(null)
const vaultMethod = ref('role')
const vaultSecretId = ref('')
const vaultToken = ref('')
const topologyDraft = reactive({
  address: '',
  transit_key_name: '',
  role_id: '',
  region: '',
  key_ref: '',
})

const now = ref(Date.now())
let clockTimer = null
let pollTimer = null

const SEAL_STATE_TAG_TYPES = {
  sealed: 'warning',
  unsealing: 'warning',
  unsealed: 'success',
  'sealed-faulted': 'danger',
}
const SEAL_STATE_TEXT_KEYS = {
  sealed: 'unseal.stateSealed',
  unsealing: 'unseal.stateUnsealing',
  unsealed: 'unseal.stateUnsealed',
  'sealed-faulted': 'unseal.stateSealedFaulted',
}
const STEP_LABEL_KEYS = {
  verify: 'unseal.stepVerify',
  review: 'unseal.stepReview',
  credentials: 'unseal.stepCredentials',
  material: 'unseal.stepMaterial',
  createAdmin: 'unseal.stepCreateAdmin',
  topology: 'unseal.stepTopology',
  activate: 'unseal.stepActivate',
  reload: 'unseal.envAction',
}
const CREDENTIAL_TITLE_KEYS = {
  aws: 'unseal.credentialsAwsTitle',
  gcp: 'unseal.credentialsGcpTitle',
  vault: 'unseal.credentialsVaultTitle',
}
const PROVIDER_LABELS = {
  aws: 'AWS KMS',
  gcp: 'GCP Cloud KMS',
  vault: 'HashiCorp Vault',
}
// 三類可辨識的憑證失敗（僅在帶有效授權脈絡時後端才給出細分）
const FAILURE_TEXT_KEYS = {
  SEAL_CUSTODY_UNREACHABLE: {
    title: 'unseal.failureUnreachableTitle',
    desc: 'unseal.failureUnreachableDesc',
  },
  SEAL_CREDENTIAL_REJECTED: {
    title: 'unseal.failureRejectedTitle',
    desc: 'unseal.failureRejectedDesc',
  },
  SEAL_KEY_MISMATCH: {
    title: 'unseal.failureKeyMismatchTitle',
    desc: 'unseal.failureKeyMismatchDesc',
  },
}
const TIMEOUT_PROBE_TEXT_KEYS = {
  sealed: 'unseal.timeoutResultSealed',
  cleanup: 'unseal.timeoutResultCleanup',
  unsealed: 'unseal.timeoutResultUnsealed',
}

const state = computed(() => status.value.state || '')
const stateTagType = computed(() => SEAL_STATE_TAG_TYPES[state.value] || 'info')
// 未知態原樣顯示：不歸類到任何已知態（歸類等於替後端的新狀態編造語義）
const stateLabel = computed(() =>
  SEAL_STATE_TEXT_KEYS[state.value] ? t(SEAL_STATE_TEXT_KEYS[state.value]) : state.value || '—'
)
const isUnsealed = computed(() => state.value === 'unsealed')
const mode = computed(() => status.value.mode || '')
const delegated = computed(() => mode.value === 'kms')
const credentialForm = computed(() => status.value.credential_form || '')
const topology = computed(() => status.value.topology || null)
const providerLabel = computed(
  () => PROVIDER_LABELS[topology.value?.provider || credentialForm.value] || credentialForm.value
)

// 路徑判定只有後端權威（`initialization_required`）。欄位缺席＝未知，
// 不以 false 頂替也不讓操作者手動指定——猜錯的代價是把憑證交給判定錯誤的流程
const statusUnknown = computed(
  () => !isUnsealed.value && typeof status.value.initialization_required !== 'boolean'
)
const isFreshInstall = computed(() => status.value.initialization_required === true)

const steps = computed(() => {
  if (isFreshInstall.value) {
    return delegated.value
      ? ['createAdmin', 'topology', 'credentials', 'activate']
      : ['createAdmin', 'material']
  }
  if (delegated.value) return ['verify', 'review', 'credentials']
  return ['verify', mode.value === 'env' ? 'reload' : 'material']
})

const activeStep = computed(() => {
  // 全新安裝也一律先驗帳密：沒有脈絡就停在第 1 步，秘密欄位不可能被渲染
  if (isFreshInstall.value) {
    if (!grant.value) return 0
    return Math.min(freshStep.value, steps.value.length - 1)
  }
  if (!grant.value) return 0
  if (delegated.value && !reviewedDigest.value) return 1
  return steps.value.length - 1
})
const currentStep = computed(() => steps.value[activeStep.value])

const topologyRows = computed(() => {
  const topo = topology.value
  if (!topo) return []
  const rows = [{ label: 'unseal.reviewProvider', value: providerLabel.value }]
  if (topo.address) rows.push({ label: 'unseal.reviewAddress', value: topo.address })
  if (topo.role_id) rows.push({ label: 'unseal.reviewRole', value: topo.role_id })
  if (topo.region) rows.push({ label: 'unseal.reviewRegion', value: topo.region })
  const key = topo.key_ref || topo.transit_key_name
  if (key) rows.push({ label: 'unseal.reviewKey', value: key })
  return rows.length > 1 ? rows : []
})
const reviewedAddress = computed(
  () => topology.value?.address || topology.value?.region || topology.value?.key_ref || '—'
)
const draftAddressText = computed(
  () => topologyDraft.address || topologyDraft.region || topologyDraft.key_ref || '—'
)

// 全新安裝的拓撲欄位（按服務商的精確集合，與送出的鍵集同源）
const TOPOLOGY_FIELDS = {
  aws: [
    { model: 'region', label: 'unseal.topoRegion' },
    { model: 'key_ref', label: 'unseal.topoKeyRef' },
  ],
  gcp: [{ model: 'key_ref', label: 'unseal.topoKeyRef' }],
  vault: [
    { model: 'address', label: 'unseal.topoAddress' },
    { model: 'transit_key_name', label: 'unseal.topoTransitKey' },
    { model: 'role_id', label: 'unseal.topoRoleId' },
  ],
}
const topologyFields = computed(() => TOPOLOGY_FIELDS[credentialForm.value] || [])
const topologyDraftComplete = computed(() =>
  topologyFields.value.every(
    (field) => field.model === 'role_id' || !!topologyDraft[field.model].trim()
  )
)

const credentialsReady = computed(() => {
  if (credentialForm.value === 'aws') return !!awsAccessKeyId.value && !!awsSecretAccessKey.value
  if (credentialForm.value === 'gcp') return !!gcpJson.value
  if (credentialForm.value === 'vault') {
    return vaultMethod.value === 'token' ? !!vaultToken.value : !!vaultSecretId.value
  }
  return false
})

const gcpSizeText = computed(() => {
  const bytes = new TextEncoder().encode(gcpJson.value).length
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`
})

const materialLabelId = computed(() =>
  isFreshInstall.value ? 'unseal-init-material-label' : 'unseal-material-label'
)

const faultText = computed(() =>
  status.value.fault_code ? resolveApiError({ code: status.value.fault_code }) : ''
)
const timeoutHintText = computed(() =>
  status.value.timeout_retry_hint_code
    ? resolveApiError({ code: status.value.timeout_retry_hint_code })
    : ''
)
const cleanupMetaText = computed(() =>
  t('unseal.cleanupPendingMeta', {
    generation: status.value.cleanup_generation ?? '—',
    reason: status.value.cleanup_reason || '—',
    since: status.value.cleanup_started_at
      ? formatDateTime(status.value.cleanup_started_at)
      : '—',
  })
)

const cooldownRemainingMs = computed(() => {
  if (!status.value.cooldown_until) return 0
  const until = new Date(status.value.cooldown_until).getTime()
  if (Number.isNaN(until)) return 0
  return Math.max(0, until - now.value)
})
const inCooldown = computed(() => cooldownRemainingMs.value > 0)
const cooldownRemainingText = computed(() => {
  const total = Math.ceil(cooldownRemainingMs.value / 1000)
  const minutes = Math.floor(total / 60)
  const seconds = total % 60
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
})

// 左欄的狀態訊息：成立的才進清單。順序固定（讀不到狀態 → 故障 → 稽核不可寫 →
// 待釋放 → 冷卻 → 逾時指引），故同一情境每次看到的排列相同
const statusMessages = computed(() => {
  const list = []
  if (statusError.value) {
    list.push({
      key: 'statusError',
      tone: 'warning',
      title: t('unseal.statusErrorTitle'),
      text: statusError.value,
    })
  }
  if (status.value.fault_code) {
    list.push({
      key: 'fault',
      tone: 'danger',
      title: t('unseal.faultTitle'),
      text: faultText.value,
    })
  }
  if (status.value.journal_faulted) {
    list.push({
      key: 'journalFaulted',
      tone: 'danger',
      title: t('unseal.journalFaultedTitle'),
      text: t('unseal.journalFaultedDesc'),
      steps: [
        t('unseal.journalFaultedStep1'),
        t('unseal.journalFaultedStep2'),
        t('unseal.journalFaultedStep3'),
      ],
      note: t('unseal.journalFaultedWhy'),
    })
  }
  if (status.value.cleanup_pending) {
    list.push({
      key: 'cleanupPending',
      tone: 'warning',
      title: t('unseal.cleanupPendingTitle'),
      text: t('unseal.cleanupPendingDesc'),
      note: cleanupMetaText.value,
    })
  }
  if (cooldownRemainingMs.value > 0) {
    list.push({
      key: 'cooldown',
      tone: 'warning',
      title: t('unseal.cooldownTitle'),
      text: t('unseal.cooldownDesc', {
        remaining: cooldownRemainingText.value,
        until: formatDateTime(status.value.cooldown_until),
      }),
    })
  }
  if (status.value.timeout_retry_hint_code) {
    list.push({
      key: 'timeoutHint',
      tone: 'warning',
      title: t('unseal.timeoutHintTitle'),
      text: timeoutHintText.value,
    })
  }
  return list
})

const MATERIAL_FORMAT_TEXT_KEYS = {
  empty: 'unseal.materialErrorEmpty',
  format: 'unseal.materialErrorFormat',
  charset: 'unseal.materialErrorCharset',
}
// 格式檢查只套用於初始化：既有 KEK 可能早於格式規則，前端擋掉它等於讓合法管理員
// 解不開自己的部署
const materialFormatReason = computed(() =>
  isFreshInstall.value && material.value ? validateKEKMaterialFormat(material.value) : ''
)
const materialFormatMessage = computed(() =>
  materialFormatReason.value ? t(MATERIAL_FORMAT_TEXT_KEYS[materialFormatReason.value]) : ''
)
const confirmMismatch = computed(
  () => !!materialConfirm.value && materialConfirm.value !== material.value
)

const submitDisabled = computed(() => {
  if (submitting.value || status.value.cleanup_pending || inCooldown.value) return true
  if (currentStep.value === 'reload') return false
  if (currentStep.value === 'material') {
    if (!material.value) return true
    if (!isFreshInstall.value) return false
    return (
      !!materialFormatReason.value ||
      materialConfirm.value !== material.value ||
      !confirmSaved.value ||
      !username.value ||
      !password.value
    )
  }
  if (currentStep.value === 'activate') return !credentialsReady.value
  return !credentialsReady.value
})

// —— 秘密清除（元件狀態層，不承諾 JS 記憶體抹除）：送出、返回、切換方式、卸載 ——
const clearSecrets = () => {
  material.value = ''
  materialConfirm.value = ''
  confirmSaved.value = false
  password.value = ''
  awsAccessKeyId.value = ''
  awsSecretAccessKey.value = ''
  gcpJson.value = ''
  if (gcpInputRef.value) gcpInputRef.value.value = ''
  vaultSecretId.value = ''
  vaultToken.value = ''
}

const loadStatus = async () => {
  statusLoading.value = true
  try {
    status.value = await getSealStatus({ skipErrorToast: true })
    // 導覽守衛的相位來源之一：少了這一步，解封成功後點「前往登入」會被守衛以
    // 陳舊的已封存相位彈回本頁
    publishSealStatus(status.value)
    statusError.value = ''
  } catch (error) {
    // 狀態讀不到不是解封失敗：明說讀取失敗，不覆蓋已知狀態、也不假裝已解封
    statusError.value = resolveApiError(error.response?.data, error.response?.status)
  } finally {
    statusLoading.value = false
  }
}

const verifyIdentity = async () => {
  verifying.value = true
  try {
    const result = await sealAuthorize(
      { username: username.value, password: password.value },
      { skipErrorToast: true }
    )
    grant.value = result?.grant || ''
    verifiedUser.value = username.value
    // 密碼在取得授權脈絡後即無用處，立刻清掉
    password.value = ''
  } catch (error) {
    // 帳密階段的回應刻意不可區分，前端 SHALL NOT 自行推測成因
    ElMessage.error(resolveApiError(error.response?.data, error.response?.status))
    await loadStatus()
  } finally {
    verifying.value = false
  }
}

// 全新安裝的第 1 步：以初始管理員的帳密換一個授權脈絡，其後三步都帶著它走。
// 初始管理員由段 1 的種子建立（解封之前就存在），故這一步是驗證那組部署提供的
// 帳密；畫面標題為「初始管理者驗證」。
//
// **密碼在此不清**（與既有部署的 verifyIdentity 不同）：全新安裝的請求本文仍帶
// username／password——脈絡證明的是「看到秘密欄位之前已通過驗證」，本文那一份
// 證明的是「誰有權宣告本部署的主金鑰」，兩者時點與用途不同，不互相代償。
const authorizeFreshInstall = async () => {
  verifying.value = true
  try {
    const result = await sealAuthorize(
      { username: username.value, password: password.value },
      { skipErrorToast: true }
    )
    grant.value = result?.grant || ''
    verifiedUser.value = username.value
    goNextFreshStep()
  } catch (error) {
    ElMessage.error(resolveApiError(error.response?.data, error.response?.status))
    await loadStatus()
  } finally {
    verifying.value = false
  }
}

const changeAccount = () => {
  grant.value = ''
  freshStep.value = 0
  verifiedUser.value = ''
  reviewedDigest.value = ''
  topologyChanged.value = false
  clearSecrets()
}

const confirmTopology = () => {
  reviewedDigest.value = topology.value?.digest || 'reviewed'
  topologyChanged.value = false
}

const rejectTopology = () => {
  stopped.value = true
  clearSecrets()
}

const backToReview = () => {
  reviewedDigest.value = ''
  clearSecrets()
}

const onVaultMethodChange = () => {
  // 兩種方式互斥：切換即清空前一種已輸入的值，送出的請求只含其中一種
  vaultSecretId.value = ''
  vaultToken.value = ''
}

const onGcpInput = (event) => {
  // 輸入節點恆不持有內容：讀走後立刻清空，故畫面上沒有可回顯的副本，
  // 只以大小回報「已貼上什麼量」
  gcpJson.value += event.target.value
  event.target.value = ''
}

const clearGcp = () => {
  gcpJson.value = ''
  if (gcpInputRef.value) gcpInputRef.value.value = ''
}

const generateLocalMaterial = () => {
  try {
    const generated = generateKEKMaterial()
    material.value = generated
    materialConfirm.value = generated
  } catch (error) {
    console.error('本地生成 KEK 失敗:', error)
    ElMessage.error(t('unseal.generateFailed'))
  }
}

const goNextFreshStep = () => {
  freshStep.value = Math.min(freshStep.value + 1, steps.value.length - 1)
}
const goPrevFreshStep = () => {
  freshStep.value = Math.max(freshStep.value - 1, 0)
}

// 逐分支的精確鍵集：後端以 DisallowUnknownFields 解析，夾帶多餘鍵即整包被拒
const delegatedSecretKeys = () => {
  if (credentialForm.value === 'aws') {
    return { access_key_id: awsAccessKeyId.value, secret_access_key: awsSecretAccessKey.value }
  }
  if (credentialForm.value === 'gcp') return { service_account_json: gcpJson.value }
  return vaultMethod.value === 'token'
    ? { vault_token: vaultToken.value }
    : { vault_secret_id: vaultSecretId.value }
}

const buildPayload = () => {
  if (mode.value === 'env') return {}
  if (!delegated.value) {
    const kek = material.value.trim()
    // 送出前對兩欄套同一次修剪：貼上 `openssl rand -hex 32` 的輸出會帶結尾換行，
    // 伺服端比對的是原始位元組，兩欄修剪不一致就會誤判不符
    return isFreshInstall.value
      ? {
          kek,
          kek_confirm: materialConfirm.value.trim(),
          confirm_saved: confirmSaved.value,
          username: username.value,
          password: password.value,
        }
      : { kek }
  }
  if (!isFreshInstall.value) {
    return { ...delegatedSecretKeys(), topology_digest: topology.value?.digest || '' }
  }
  const base = { username: username.value, password: password.value }
  if (credentialForm.value === 'aws') {
    return {
      ...base,
      region: topologyDraft.region.trim(),
      key_ref: topologyDraft.key_ref.trim(),
      ...delegatedSecretKeys(),
    }
  }
  if (credentialForm.value === 'gcp') {
    return { ...base, key_ref: topologyDraft.key_ref.trim(), ...delegatedSecretKeys() }
  }
  const vaultBase = {
    ...base,
    address: topologyDraft.address.trim(),
    transit_key_name: topologyDraft.transit_key_name.trim(),
  }
  return vaultMethod.value === 'token'
    ? { ...vaultBase, vault_token: vaultToken.value }
    : { ...vaultBase, role_id: topologyDraft.role_id.trim(), vault_secret_id: vaultSecretId.value }
}

const submit = async () => {
  const payload = buildPayload()
  submitting.value = true
  outcome.value = 'working'
  try {
    const result = await unseal(payload, { grant: grant.value, skipErrorToast: true })
    status.value = { ...status.value, ...result }
    publishSealStatus(status.value)
    outcome.value = ''
    ElMessage.success(t('unseal.submitSuccess'))
    await loadStatus()
  } catch (error) {
    const httpStatus = error.response?.status
    const code = error.response?.data?.code
    if (httpStatus === 504 || code === 'SEAL_STAGE2_TIMEOUT') {
      // 逾時既非成功也非失敗：初始化可能已部分完成，重送等於在未知狀態上再跑一次
      outcome.value = 'timeout'
      timeoutProbe.value = ''
    } else if (code === 'SEAL_TOPOLOGY_CHANGED') {
      outcome.value = ''
      reviewedDigest.value = ''
      topologyChanged.value = true
      await loadStatus()
    } else if (code === 'SEAL_GRANT_REQUIRED' || code === 'SEAL_GRANT_INVALID') {
      outcome.value = ''
      changeAccount()
      ElMessage.error(resolveApiError(error.response?.data, httpStatus))
      await loadStatus()
    } else if (FAILURE_TEXT_KEYS[code]) {
      outcome.value = 'failed'
      failureCode.value = code
      await loadStatus()
    } else {
      // 其餘一律走 resolveApiError：無授權脈絡時後端刻意不可區分，
      // 前端 SHALL NOT 自行推測成因
      outcome.value = ''
      ElMessage.error(resolveApiError(error.response?.data, httpStatus))
      await loadStatus()
    }
  } finally {
    submitting.value = false
    clearSecrets()
  }
}

const retryAfterFailure = () => {
  outcome.value = ''
  failureCode.value = ''
}

const probeAfterTimeout = async () => {
  await loadStatus()
  if (state.value === 'unsealed') timeoutProbe.value = 'unsealed'
  else if (status.value.cleanup_pending) timeoutProbe.value = 'cleanup'
  else timeoutProbe.value = 'sealed'
}

// 只在後端回報仍為已封存且清理完成時，才讓人回到憑證步驟重送
const resumeAfterTimeout = () => {
  if (timeoutProbe.value !== 'sealed') return
  outcome.value = ''
  timeoutProbe.value = ''
}

const goLogin = () => router.push('/login')

// 解封中輪詢：段 2 可能跑數十秒，讓管理員看得到它仍在進行而非卡死
const syncPolling = () => {
  const shouldPoll = state.value === 'unsealing' || status.value.cleanup_pending
  if (shouldPoll && !pollTimer) {
    pollTimer = setInterval(loadStatus, 5000)
  } else if (!shouldPoll && pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

// 拓撲在核對後被另一路徑改動即退回核對步驟：舊核對結果 SHALL NOT 授權新目的地
watch(
  () => topology.value?.digest,
  (digest) => {
    if (!reviewedDigest.value || !digest) return
    if (digest !== reviewedDigest.value) {
      reviewedDigest.value = ''
      topologyChanged.value = true
      clearSecrets()
    }
  }
)

// 狀態切換（含被重新封存、路徑改判）即清空秘密欄
watch([state, isFreshInstall], () => clearSecrets())

onMounted(async () => {
  await loadStatus()
  clockTimer = setInterval(() => {
    now.value = Date.now()
    syncPolling()
  }, 1000)
})

onUnmounted(() => {
  if (clockTimer) clearInterval(clockTimer)
  if (pollTimer) clearInterval(pollTimer)
  clearSecrets()
  grant.value = ''
})

// 測試驅動用（happy-dom 不跑 transition／timer 行為不穩）：狀態注入與提交入口
defineExpose({
  loadStatus,
  submit,
  verifyIdentity,
  status,
  material,
  materialConfirm,
  confirmSaved,
  grant,
  outcome,
})
</script>

<style scoped>
/* 語言切換：版位與類名沿用 Login.vue（同為未登入的整頁畫面） */
.lang-switch-label {
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.lang-switch-label:hover {
  color: var(--ot-primary);
}

.unseal-title {
  margin: 0 0 6px;
  font-size: var(--ot-font-size-xl);
  font-weight: 600;
}

.unseal-subtitle {
  margin: 0;
  color: var(--el-text-color-secondary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}

.status-row {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.status-meta {
  font-size: var(--ot-font-size-sm);
  color: var(--el-text-color-secondary);
}

/* 遺失警語：版面上必須壓過同頁其他說明。標題 15px/700，正文用 primary 文字色
   ——刻意不是 secondary（次要色等於把「唯一非知道不可的事」降級成註腳） */
.loss-callout {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border: 1px solid var(--el-color-danger);
  border-radius: var(--ot-radius-md);
  background: var(--el-color-danger-light-9);
}

.loss-icon {
  flex-shrink: 0;
  margin-top: 2px;
  font-size: 20px;
  color: var(--el-color-danger);
}

.loss-title {
  margin: 0 0 4px;
  font-size: 15px;
  font-weight: 700;
  line-height: 1.5;
  color: var(--el-color-danger);
}

.loss-body {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
  color: var(--el-text-color-primary);
}

/* 右欄：唯一動作 */
.section-title {
  margin: 0;
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
}

.init-title,
.section-title.is-danger {
  color: var(--el-color-danger);
}

.section-title.is-success {
  color: var(--el-color-success);
}

.section-desc {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--el-text-color-secondary);
}

.init-desc {
  color: var(--el-color-danger);
}

.form-section,
.board {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

/* 步驟列：三步與四步共用同一條軌道，全新安裝只是多兩格 */
.step-rail {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 0 0 4px;
  padding: 0 0 14px;
  border-bottom: 1px solid var(--el-border-color);
  list-style: none;
  flex-wrap: wrap;
}

.step-rail-item {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--el-text-color-secondary);
  font-size: var(--ot-font-size-sm);
}

.step-rail-num {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  border: 1px solid var(--el-border-color);
  font-size: var(--ot-font-size-xs);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.step-rail-item.is-active {
  color: var(--el-text-color-primary);
  font-weight: 600;
}

.step-rail-item.is-active .step-rail-num {
  border-color: var(--ot-primary);
  background: var(--ot-primary);
  color: #fff;
}

.step-rail-item.is-done .step-rail-num {
  border-color: var(--el-color-success);
  background: var(--el-color-success);
  color: #fff;
}

.step-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--ot-space-sm);
}

.verified-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-sm);
  padding: 8px 12px;
  border-radius: var(--ot-radius-md);
  background: var(--el-fill-color-light);
}

.verified-text {
  font-size: var(--ot-font-size-sm);
  color: var(--el-color-success);
}

/* 唯讀拓撲：識別字原樣呈現（截斷或改寫會讓核對失去意義），故用等寬字並允許換行 */
.topology-card {
  padding: 14px;
  border: 1px solid var(--el-border-color);
  border-radius: var(--ot-radius-md);
  background: var(--el-fill-color-blank);
}

.topology-grid {
  display: grid;
  grid-template-columns: 132px minmax(0, 1fr);
  gap: 8px 16px;
  margin: 0;
  font-size: var(--ot-font-size-sm);
}

.topology-grid dt {
  color: var(--el-text-color-secondary);
}

.topology-grid dd {
  margin: 0;
}

.topology-value {
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-xs);
  word-break: break-all;
}

.field-block {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.field-sublabel {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.field-row {
  display: flex;
  gap: var(--ot-space-sm);
  align-items: center;
}

.material-input,
.admin-input,
.secret-input,
.topo-input {
  flex: 1;
}

.material-input :deep(.el-input__inner) {
  font-family: var(--ot-font-mono, monospace);
}

/* 金鑰檔貼上區：內容永不停留在節點上（見 onGcpInput），故這裡只是一個投入口 */
.gcp-input {
  width: 100%;
  padding: 8px 11px;
  border: 1px solid var(--el-border-color);
  border-radius: var(--ot-radius-sm);
  background: var(--el-fill-color-blank);
  color: var(--el-text-color-primary);
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-xs);
  box-sizing: border-box;
  resize: vertical;
}

.vault-method,
.gcp-clear {
  align-self: flex-start;
}

.field-error {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--el-color-danger);
}

.field-hint {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
  color: var(--el-text-color-secondary);
}

.submit-btn {
  width: 100%;
  margin-top: var(--ot-space-xs);
  margin-left: 0;
}

.board-steps {
  margin: 0;
  padding-left: 20px;
  font-size: var(--ot-font-size-sm);
  line-height: 1.8;
}

.summary-list {
  margin: 0;
  padding-left: 20px;
  font-size: var(--ot-font-size-sm);
  line-height: 1.8;
}

.working-row {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: var(--ot-font-size-sm);
}

.working-spinner {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 2px solid var(--el-border-color);
  border-top-color: var(--ot-primary);
  flex-shrink: 0;
}

.failure-callout {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border: 1px solid var(--el-color-danger);
  border-radius: var(--ot-radius-md);
  background: var(--el-color-danger-light-9);
}

.failure-icon {
  flex-shrink: 0;
  margin-top: 2px;
  font-size: 20px;
  color: var(--el-color-danger);
}

.failure-title {
  margin: 0 0 4px;
  font-size: 15px;
  font-weight: 700;
  color: var(--el-color-danger);
}

.failure-body {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
  color: var(--el-text-color-primary);
}

.cooldown-row {
  display: flex;
  align-items: center;
  gap: 12px;
}

.cooldown-remaining {
  font-size: var(--ot-font-size-sm);
}

.timeout-probe {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
}
</style>
