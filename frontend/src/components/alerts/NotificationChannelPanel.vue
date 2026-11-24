<template>
  <div
    class="channel-panel"
    data-test="channel-panel"
  >
    <div class="list-card">
      <div class="toolbar">
        <el-button
          v-preview-write:create
          type="primary"
          @click="openChannelDialog()"
        >
          {{ $t('alerts.createChannel') }}
        </el-button>
      </div>
      <el-table
        v-loading="channelsLoading"
        :data="channels"
        :row-class-name="rowClassName"
        style="width: 100%"
      >
        <el-table-column
          :label="$t('common.name')"
          min-width="90"
        >
          <template #default="{ row }">
            <div>{{ row.name }}</div>
            <!-- 開了對個人派送的通道：名稱下方一個標籤，一眼看出私訊從哪個通道送出 -->
            <el-tag
              v-if="row.direct_message_enabled"
              type="success"
              size="small"
              class="dm-tag"
              data-test="channel-dm-tag"
            >
              <el-icon class="dm-tag__icon">
                <UserRound />
              </el-icon>{{ $t('alerts.dm.tag') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('alerts.channelType')"
          min-width="90"
        >
          <template #default="{ row }">
            <span data-test="channel-type-cell">{{ channelTypeShort(row.type) }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('alerts.destinationColumn')"
          min-width="130"
        >
          <template #default="{ row }">
            <div data-test="channel-dest-cell">
              <span
                v-if="row.url === CHANNEL_URL_UNREADABLE"
                class="dest-unreadable"
              >{{ $t('alerts.destUnreadable') }}</span>
              <template v-else-if="row.type === 'slack_app'">
                <div class="mono-text">
                  {{ $t('alerts.destChannel', { target: row.target }) }}
                </div>
                <div class="field-muted">
                  <template v-if="isSlackDefaultMasked(row.url)">
                    {{ $t('alerts.destSlackDefault') }}
                  </template>
                  <span
                    v-else
                    class="mono-text"
                  >{{ row.url }}</span>
                </div>
              </template>
              <span
                v-else
                class="mono-text"
              >{{ row.url }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('alerts.signatureColumn')"
          min-width="120"
        >
          <template #default="{ row }">
            <el-tag
              v-if="row.type === 'slack_app'"
              :type="row.has_secret ? 'success' : 'info'"
              size="small"
            >
              {{ row.has_secret ? $t('alerts.tokenSet') : $t('alerts.tokenUnset') }}
            </el-tag>
            <span
              v-else-if="row.type === 'slack'"
              class="field-muted"
            >{{ $t('alerts.notApplicable') }}</span>
            <el-tag
              v-else
              :type="row.has_secret ? 'success' : 'info'"
              size="small"
            >
              {{ row.has_secret ? $t('alerts.secretSet') : $t('alerts.unsigned') }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('alerts.languageColumn')"
          width="80"
        >
          <template #default="{ row }">
            <template v-if="rendersText(row.type)">
              {{ channelLanguageLabel(row.language) }}
            </template>
            <span
              v-else
              class="field-muted"
            >{{ $t('alerts.notApplicable') }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('alerts.channelPushColumn')"
          width="80"
        >
          <template #default="{ row }">
            <span :class="isNarrowedMinSeverity(row.min_severity) ? 'push-narrowed' : 'field-muted'">
              {{ channelMinSeverityLabel(row.min_severity) }}
            </span>
          </template>
        </el-table-column>
        <!-- 送達狀況：狀態標籤＋最近送達＋最近失敗與原因＋近 7 天放棄（只統計目的地最後變更之後排入的紀錄） -->
        <el-table-column
          :label="$t('alerts.healthColumn', { tz: utcOffsetText() })"
          min-width="195"
        >
          <template #default="{ row }">
            <div
              class="health"
              data-test="channel-health"
            >
              <el-tag
                :type="HEALTH_TAG_TYPES[healthStatus(row)]"
                :class="{ [NEUTRAL_TAG_CLASS]: NEUTRAL_HEALTH.includes(healthStatus(row)) }"
                size="small"
                data-test="channel-health-tag"
              >
                {{ $t(`alerts.health.${healthStatus(row)}`) }}
              </el-tag>
              <template v-if="healthStatus(row) === 'none' && row.enabled">
                <div class="health-line">
                  {{ row.destination_changed_at ? $t('alerts.health.noneSinceChange') : $t('alerts.health.noneHint') }}
                </div>
              </template>
              <template v-else-if="row.health">
                <div class="health-line">
                  <span class="health-key">{{ $t('alerts.health.lastOk') }}</span>
                  {{ row.health.last_delivered_at ? formatListTime(row.health.last_delivered_at) : $t('alerts.health.neverOk') }}
                </div>
                <div
                  class="health-line"
                  :class="{ 'health-fail': isFailing(row) }"
                >
                  <span class="health-key">{{ $t('alerts.health.lastFail') }}</span>
                  {{ row.health.last_failed_at ? formatListTime(row.health.last_failed_at) : $t('alerts.health.noFail') }}
                </div>
                <div
                  v-if="row.health.last_failed_at"
                  class="health-line health-reason"
                  :class="{ 'health-fail': isFailing(row) }"
                  data-test="channel-health-reason"
                >
                  {{ reasonText(row.health.last_failure_code, row.health.last_failure_reason) }}
                </div>
                <div
                  class="health-line"
                  :class="{ 'health-warn': Number(row.health.abandoned_7d) > 0 }"
                >
                  {{ $t('alerts.health.abandoned7d', { n: Number(row.health.abandoned_7d) || 0 }) }}
                </div>
              </template>
              <div
                v-if="row.destination_changed_at"
                class="health-line health-since"
                data-test="channel-health-since"
              >
                {{ $t('alerts.health.since', { at: formatListTime(row.destination_changed_at) }) }}
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.enabled')"
          width="70"
        >
          <template #default="{ row }">
            <el-switch
              v-preview-write
              :model-value="row.enabled"
              :aria-label="$t('alerts.channelEnabledToggle', { name: row.name })"
              @change="(val) => handleChannelToggle(row, val)"
            />
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="120"
          fixed="right"
        >
          <template #default="{ row }">
            <!-- 四個動作排成兩行，讓 1280 寬也不必水平捲動 -->
            <div class="row-actions">
              <el-button
                v-preview-write
                size="small"
                link
                type="primary"
                @click="handleTestChannel(row)"
              >
                {{ $t('alerts.testSend') }}
              </el-button>
              <el-button
                v-preview-write
                size="small"
                link
                type="primary"
                @click="openChannelDialog(row)"
              >
                {{ $t('common.edit') }}
              </el-button>
              <el-button
                size="small"
                link
                type="primary"
                data-test="channel-delivery-log"
                @click="openDeliveryLog(row)"
              >
                {{ $t('alerts.deliveryLog') }}
              </el-button>
              <el-button
                v-preview-write
                size="small"
                link
                type="danger"
                @click="handleDeleteChannel(row)"
              >
                {{ $t('common.delete') }}
              </el-button>
            </div>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            :icon="Send"
            :title="$t('alerts.emptyChannelsTitle')"
            :hint="$t('alerts.emptyChannelsHint')"
          />
        </template>
      </el-table>
      <!-- 「推送」只篩選一般告警；系統告警一律推送到每一個啟用中的通道 -->
      <p
        class="field-hint"
        data-test="channel-push-hint"
      >
        {{ $t('alerts.channelPushSystemHint') }}
      </p>
      <p
        class="field-hint retry-hint"
        data-test="channel-retry-hint"
      >
        {{ $t('alerts.retryPolicyHint') }}
      </p>
      <!-- 送達狀況只統計頻道紀錄；私訊的狀況看投遞紀錄（有能以個人為對象的通道時才需要這句） -->
      <p
        v-if="hasTargetUserChannel"
        class="field-hint retry-hint"
        data-test="channel-health-dm-hint"
      >
        {{ $t('alerts.health.channelOnlyHint') }}
      </p>
    </div>

    <!-- 新增 / 編輯通道對話框 -->
    <el-dialog
      v-model="channelDialogVisible"
      :title="editingChannelId ? $t('alerts.editChannel') : $t('alerts.createChannel')"
      width="560px"
      :close-on-click-modal="false"
    >
      <el-form
        ref="channelFormRef"
        class="channel-form"
        :model="channelForm"
        :rules="channelFormRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.name')"
          prop="name"
        >
          <el-input v-model="channelForm.name" />
        </el-form-item>
        <el-form-item
          :label="$t('alerts.channelType')"
          prop="type"
        >
          <el-select
            v-model="channelForm.type"
            style="width: 100%"
            popper-class="channel-type-popper"
            data-test="channel-type-select"
            @change="onTypeChange"
          >
            <el-option
              v-for="channelType in CHANNEL_TYPE_VALUES"
              :key="channelType"
              :label="$t(CHANNEL_TYPE_LABEL_KEYS[channelType])"
              :value="channelType"
            >
              <div class="type-option">
                <span>{{ $t(CHANNEL_TYPE_LABEL_KEYS[channelType]) }}</span>
                <span class="type-option__help">{{ $t(CHANNEL_TYPE_HELP_KEYS[channelType]) }}</span>
              </div>
            </el-option>
          </el-select>
        </el-form-item>

        <!-- 改了型別：舊型別的秘密一律清除；網址要重新填 -->
        <el-alert
          v-if="typeChanged"
          type="warning"
          :closable="false"
          show-icon
          class="form-notice"
          data-test="channel-type-change-notice"
          :title="typeChangeTitle"
        >
          {{ typeChangeBody }}
        </el-alert>

        <!-- Slack 應用程式：token、目標頻道、需要準備什麼、進階的 Slack 位址 -->
        <template v-if="isSlackApp">
          <el-form-item
            :label="$t('alerts.botToken')"
            prop="secret"
            :required="tokenRequired"
          >
            <div
              v-if="editingChannelId && !typeChanged"
              class="secret-status"
            >
              {{ $t('alerts.currentStatus') }}
              <el-tag
                :type="channelForm.hasSecret ? 'success' : 'info'"
                size="small"
              >
                {{ channelForm.hasSecret ? $t('alerts.tokenSetFull') : $t('alerts.tokenUnset') }}
              </el-tag>
            </div>
            <el-input
              v-model="channelForm.secret"
              type="password"
              show-password
              autocomplete="new-password"
              data-test="channel-token-input"
              :placeholder="editingChannelId && !typeChanged ? $t('alerts.tokenKeepPlaceholder') : $t('alerts.botTokenPlaceholder')"
            />
            <div class="field-hint">
              <template v-if="editingChannelId && !typeChanged && urlEdited">
                {{ $t('alerts.urlChangedTokenThisTime') }}
              </template>
              <template v-else-if="editingChannelId && !typeChanged">
                {{ $t('alerts.botTokenHintEdit') }}
              </template>
              <template v-else>
                {{ $t('alerts.botTokenHint') }}
              </template>
            </div>
          </el-form-item>
          <el-form-item
            :label="$t('alerts.targetChannel')"
            prop="target"
            required
          >
            <el-input
              v-model="channelForm.target"
              data-test="channel-target-input"
              :placeholder="$t('alerts.targetChannelPlaceholder')"
            />
            <div class="field-hint">
              {{ $t('alerts.targetChannelHint') }}
            </div>
          </el-form-item>
          <!-- 改了目標頻道：新舊頻道都會收到變更通知，token 不用重填 -->
          <el-alert
            v-if="targetChanged"
            type="info"
            :closable="false"
            show-icon
            class="form-notice"
            data-test="channel-target-change-notice"
            :title="$t('alerts.targetChangedNotice')"
          />
          <el-alert
            v-if="!editingChannelId"
            type="info"
            :closable="false"
            show-icon
            class="form-notice how-box"
            data-test="channel-slack-app-how"
            :title="$t('alerts.slackAppHowTitle')"
          >
            <ol class="how-list">
              <li
                v-for="n in 4"
                :key="n"
              >
                {{ $t(`alerts.slackAppHow${n}`) }}
              </li>
            </ol>
            <div class="how-docs">
              {{ $t('alerts.slackAppDocsLabel') }}
              <a
                href="https://docs.slack.dev/authentication/tokens"
                target="_blank"
                rel="noopener noreferrer"
              >{{ $t('alerts.slackAppDocsTokens') }}</a>
              <a
                href="https://docs.slack.dev/reference/methods/chat.postMessage"
                target="_blank"
                rel="noopener noreferrer"
              >{{ $t('alerts.slackAppDocsPost') }}</a>
            </div>
          </el-alert>
          <el-button
            link
            type="primary"
            class="advanced-toggle"
            data-test="channel-slack-address-toggle"
            @click="slackAddressOpen = !slackAddressOpen"
          >
            <el-icon :class="{ 'is-open': slackAddressOpen }">
              <ChevronRight />
            </el-icon>
            {{ slackAddressToggleLabel }}
          </el-button>
          <el-form-item
            v-if="slackAddressOpen"
            :label="$t('alerts.slackAddress')"
            prop="url"
            :required="typeChanged"
          >
            <div
              v-if="editingChannelId && !typeChanged"
              class="secret-status"
            >
              {{ $t('alerts.currentStatus') }}
              <span v-if="isSlackDefaultMasked(channelForm.maskedUrl)">{{ $t('alerts.destSlackDefault') }}</span>
              <span
                v-else
                class="mono-text"
              >{{ channelForm.maskedUrl }}</span>
            </div>
            <el-input
              v-model="channelForm.url"
              data-test="channel-url-input"
              :placeholder="editingChannelId && !typeChanged ? $t('alerts.urlKeepPlaceholder') : SLACK_APP_DEFAULT_URL"
            />
            <div class="field-hint">
              <template v-if="typeChanged">
                {{ $t('alerts.typeChangeSlackUrlHint') }}
              </template>
              <template v-else-if="editingChannelId">
                {{ $t('alerts.slackAddressKeepHint') }}
              </template>
              <template v-else>
                {{ $t('alerts.slackAddressHint') }}
              </template>
            </div>
          </el-form-item>
          <!-- 改了 Slack 位址：token 只會送往保存它時的位址，這一次要同時輸入 -->
          <el-alert
            v-if="editingChannelId && !typeChanged && urlEdited"
            type="warning"
            :closable="false"
            show-icon
            class="form-notice"
            data-test="channel-url-change-token-notice"
            :title="$t('alerts.urlChangedNeedToken')"
          >
            {{ $t('alerts.urlChangedNeedTokenBody') }}
          </el-alert>
        </template>

        <!-- Webhook 與 Slack（Incoming Webhook）：URL -->
        <template v-else>
          <el-form-item
            label="URL"
            prop="url"
            :required="!editingChannelId || typeChanged"
          >
            <div
              v-if="editingChannelId && !typeChanged"
              class="secret-status"
            >
              {{ $t('alerts.currentUrlMasked') }}
              <span class="mono-text">{{ channelForm.maskedUrl }}</span>
            </div>
            <el-input
              v-model="channelForm.url"
              data-test="channel-url-input"
              :placeholder="editingChannelId && !typeChanged
                ? $t('alerts.urlKeepPlaceholder')
                : (channelForm.type === 'slack'
                  ? 'https://hooks.slack.com/services/...'
                  : 'https://hooks.example.com/...')"
            />
          </el-form-item>
          <!-- 改網址：舊與新兩個目的地都會收到「通道已變更」通知 -->
          <el-alert
            v-if="editingChannelId && !typeChanged && channelForm.url"
            type="warning"
            :closable="false"
            show-icon
            class="url-change-notice"
            data-test="channel-url-change-notice"
            :title="$t('alerts.channelChangeNotice')"
          >
            <div>
              {{ $t('alerts.channelOldUrl') }}
              <span
                class="mono-text"
                data-test="channel-old-url"
              >{{ channelForm.maskedUrl }}</span>
            </div>
            <div>
              {{ $t('alerts.channelNewUrl') }}
              <span
                class="mono-text"
                data-test="channel-new-url"
              >{{ channelForm.url }}</span>
            </div>
          </el-alert>
        </template>

        <!-- 改網址且有未送達的通知：誰會用新網址、誰仍依排入當時的設定 -->
        <el-alert
          v-if="pendingNotice"
          type="info"
          :closable="false"
          show-icon
          class="form-notice"
          data-test="channel-pending-notice"
          :title="pendingNotice.title"
        >
          {{ pendingNotice.body }}
        </el-alert>

        <el-form-item
          v-if="channelForm.type === 'slack'"
          :label="$t('alerts.signingSecret')"
        >
          <div class="field-hint">
            {{ $t('alerts.slackNoSecretHint') }}
          </div>
        </el-form-item>
        <el-form-item
          v-else-if="channelForm.type === 'webhook'"
          :label="$t('alerts.signingSecret')"
        >
          <div
            v-if="editingChannelId && !typeChanged"
            class="secret-status"
          >
            {{ $t('alerts.currentStatus') }}
            <el-tag
              :type="channelForm.hasSecret ? 'success' : 'info'"
              size="small"
            >
              {{ channelForm.hasSecret ? $t('alerts.secretSetFull') : $t('alerts.secretUnsetFull') }}
            </el-tag>
          </div>
          <el-input
            v-model="channelForm.secret"
            type="password"
            show-password
            autocomplete="new-password"
            :disabled="channelForm.clearSecret"
            :placeholder="editingChannelId && !typeChanged
              ? (channelForm.hasSecret ? $t('alerts.secretKeepPlaceholder') : $t('alerts.secretFillPlaceholder'))
              : $t('alerts.secretNewPlaceholder')"
          />
          <el-checkbox
            v-if="editingChannelId && !typeChanged && channelForm.hasSecret"
            v-model="channelForm.clearSecret"
            class="clear-secret-check"
          >
            {{ $t('alerts.clearSecretLabel') }}
          </el-checkbox>
          <div
            v-if="typeChanged"
            class="field-hint"
          >
            {{ $t('alerts.secretOptionalAfterTypeChange') }}
          </div>
          <!-- 提示帶 <code> 標記：走 i18n-t 具名插槽插值，三語各自掌控語序 -->
          <i18n-t
            v-else
            keypath="alerts.secretHint"
            scope="global"
            tag="div"
            class="field-hint"
          >
            <template #cmd>
              <code>openssl rand -hex 32</code>
            </template>
          </i18n-t>
        </el-form-item>
        <!-- 已開啟對個人派送、改成不能送私訊的型別：儲存後自動關閉（不另跳確認框） -->
        <el-alert
          v-if="dmAutoOffReason === 'type'"
          type="warning"
          :closable="false"
          show-icon
          class="form-notice"
          data-test="channel-dm-auto-off"
          :title="$t('alerts.dm.autoOffWarn')"
        >
          {{ $t('alerts.dm.autoOffReasonType') }}
        </el-alert>
        <el-form-item
          :label="$t('alerts.channelLanguage')"
          prop="language"
        >
          <el-select
            v-model="channelForm.language"
            style="width: 100%"
          >
            <el-option
              v-for="lang in CHANNEL_LANGUAGE_VALUES"
              :key="lang"
              :label="channelLanguageLabel(lang)"
              :value="lang"
            />
          </el-select>
          <div class="field-hint">
            {{ $t('alerts.channelLanguageHint') }}
          </div>
        </el-form-item>
        <el-form-item
          :label="$t('alerts.channelMinSeverityLabel')"
          prop="minSeverity"
        >
          <el-radio-group
            v-model="channelForm.minSeverity"
            class="min-severity-group"
          >
            <el-radio
              v-for="level in CHANNEL_MIN_SEVERITY_VALUES"
              :key="level"
              :value="level"
            >
              {{ channelMinSeverityLabel(level) }}
              <span
                v-if="level === CHANNEL_MIN_SEVERITY_DEFAULT"
                class="field-muted"
              >{{ $t('alerts.channelMinSeverityLowHint') }}</span>
            </el-radio>
          </el-radio-group>
          <div class="field-hint">
            {{ $t('alerts.channelMinSeverityScopeHint') }}
          </div>
        </el-form-item>
        <!-- 對個人派送審核類通知：只有能以個人為對象的型別才有這一列 -->
        <el-form-item
          v-if="canTargetUser"
          :label="$t('alerts.dm.label')"
          data-test="channel-dm-item"
        >
          <div class="dm-switch-line">
            <el-switch
              v-model="channelForm.dm"
              :disabled="dmSwitchDisabled"
              :aria-label="$t('alerts.dm.label')"
              data-test="channel-dm-switch"
              @change="dmError = ''"
            />
            <span class="dm-switch-state">{{ channelForm.dm ? $t('alerts.dm.on') : $t('alerts.dm.off') }}</span>
          </div>
          <div
            v-if="dmUrlLocked"
            class="field-hint"
            data-test="channel-dm-not-allowed"
          >
            {{ $t('alerts.dm.notAllowed') }}
          </div>
          <div
            v-else
            class="field-hint"
          >
            {{ $t('alerts.dm.hint') }}
          </div>
          <div
            v-if="dmError"
            class="dm-error"
            role="alert"
            data-test="channel-dm-error"
          >
            {{ dmError }}
          </div>
        </el-form-item>
        <el-alert
          v-if="dmAutoOffReason === 'host'"
          type="warning"
          :closable="false"
          show-icon
          class="form-notice"
          data-test="channel-dm-auto-off"
          :title="$t('alerts.dm.autoOffWarnHost')"
        >
          {{ $t('alerts.dm.autoOffReasonHost') }}
        </el-alert>
        <!-- 開啟時的說明：誰會收到、怎麼對應帳號、需要的權限、頻道照送 -->
        <el-alert
          v-if="canTargetUser && channelForm.dm && !dmUrlLocked && !dmError && !dmAutoOffReason"
          type="info"
          :closable="false"
          show-icon
          class="form-notice how-box"
          data-test="channel-dm-how"
          :title="$t('alerts.dm.howTitle')"
        >
          <ol class="how-list">
            <li>{{ $t('alerts.dm.who1') }}</li>
            <li>{{ $t('alerts.dm.who2') }}</li>
            <li>{{ $t('alerts.dm.who3') }}</li>
          </ol>
          <p class="dm-how-para">
            {{ $t('alerts.dm.linkNote') }}
          </p>
          <div class="dm-how-title">
            {{ $t('alerts.dm.mapTitle') }}
          </div>
          <p class="dm-how-para">
            {{ $t('alerts.dm.mapBody') }}
          </p>
          <div class="dm-how-title">
            {{ $t('alerts.dm.scopeTitle') }}
          </div>
          <p class="dm-how-para">
            {{ $t('alerts.dm.scopeBody') }}
          </p>
          <p class="dm-how-para">
            {{ $t('alerts.dm.channelNote') }}
          </p>
          <div class="how-docs">
            {{ $t('alerts.dm.docsLabel') }}
            <a
              href="https://docs.slack.dev/reference/methods/users.lookupByEmail"
              target="_blank"
              rel="noopener noreferrer"
            >{{ $t('alerts.dm.docsLookup') }}</a>
            <a
              href="https://docs.slack.dev/reference/methods/chat.postMessage"
              target="_blank"
              rel="noopener noreferrer"
            >{{ $t('alerts.dm.docsPost') }}</a>
          </div>
        </el-alert>
        <el-form-item :label="$t('common.enabled')">
          <el-switch v-model="channelForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="channelDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          v-preview-write
          type="primary"
          :loading="channelSaving"
          @click="handleSaveChannel"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>

    <ChannelTestDialog
      v-model="testDialogVisible"
      :channel="testingChannel"
      @edit="editFromTest"
    />
    <ChannelDeliveryDrawer
      v-model="deliveryDrawerVisible"
      :channel="deliveryChannel"
    />
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ChevronRight, Send, UserRound } from 'lucide-vue-next'
import {
  getChannels,
  createChannel,
  updateChannel,
  deleteChannel,
  getChannelDeliveries,
} from '@/api/alerts'
import EmptyState from '@/components/EmptyState.vue'
import { t } from '@/i18n'
import { riskLabel } from '@/utils/transportDisplay'
import { resolveApiError } from '@/api/error'
import { confirmDestructive } from '@/utils/confirm'
import {
  CHANNEL_TYPE_VALUES,
  CHANNEL_TYPE_LABEL_KEYS,
  CHANNEL_TYPE_HELP_KEYS,
  CHANNEL_TYPE_SHORT_KEYS,
  CHANNEL_LANGUAGE_VALUES,
  CHANNEL_LANGUAGE_DEFAULT,
  channelLanguageLabel,
  CHANNEL_MIN_SEVERITY_VALUES,
  CHANNEL_MIN_SEVERITY_DEFAULT,
  SLACK_APP_DEFAULT_URL,
  CHANNEL_URL_UNREADABLE,
  isSlackDefaultMasked,
  SLACK_BOT_TOKEN_PATTERN,
  SLACK_TARGET_PATTERN,
  SLACK_TARGET_MAX_LEN,
  CHANNEL_TYPES_TARGET_USER,
  SLACK_DM_DEFAULT_HOST,
  urlHostOf,
} from '@/constants/notification-channels'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import ChannelTestDialog from './ChannelTestDialog.vue'
import ChannelDeliveryDrawer from './ChannelDeliveryDrawer.vue'
import {
  HEALTH_TAG_TYPES,
  NEUTRAL_TAG_CLASS,
  NEUTRAL_HEALTH,
  healthStatus,
  isFailing,
  reasonText,
  formatListTime,
  utcOffsetText,
} from './channelDelivery'

// 通道推送門檻：缺值（後端尚未回此欄）視同預設「全部告警」；未知值原樣顯示
const channelMinSeverityLabel = (level) => {
  const v = level || CHANNEL_MIN_SEVERITY_DEFAULT
  return CHANNEL_MIN_SEVERITY_VALUES.includes(v) ? t(`alerts.channelMinSeverity.${v}`) : v
}
// 限縮（中、高等級／只有高等級）以警示色提示此通道會略過部分告警
const isNarrowedMinSeverity = (level) => !!level && level !== CHANNEL_MIN_SEVERITY_DEFAULT

// 類型欄短名；未知型別原樣顯示
const channelTypeShort = (type) => {
  const v = type || 'webhook'
  return CHANNEL_TYPE_SHORT_KEYS[v] ? t(CHANNEL_TYPE_SHORT_KEYS[v]) : v
}
// 送出文字訊息的型別才有訊息語言
const rendersText = (type) => type === 'slack' || type === 'slack_app'

// 最近失敗晚於最近送達的列以淡紅底標示
const rowClassName = ({ row }) => (isFailing(row) ? 'is-failing' : '')

// ---- 通知通道 ----
const channels = ref([])
const channelsLoading = ref(false)
const channelDialogVisible = ref(false)
const channelSaving = ref(false)
const editingChannelId = ref(null)
const channelFormRef = ref(null)
const slackAddressOpen = ref(false)
const emptyForm = () => ({
  name: '', type: 'webhook', origType: '', url: '', maskedUrl: '', secret: '', clearSecret: false, hasSecret: false,
  target: '', origTarget: '', enabled: true, language: CHANNEL_LANGUAGE_DEFAULT, minSeverity: CHANNEL_MIN_SEVERITY_DEFAULT,
  // 對個人派送：dm 為表單值；origDm、urlAllowed 是編輯時讀到的現值（urlAllowed 依已保存的網址由伺服端計算）
  dm: false, origDm: false, urlAllowed: true,
})
const channelForm = ref(emptyForm())

const isSlackApp = computed(() => channelForm.value.type === 'slack_app')
// 編輯時改了型別（新增時沒有「原型別」）
const typeChanged = computed(() => !!editingChannelId.value && channelForm.value.type !== channelForm.value.origType)
// 編輯時有填網址（留空＝沿用）
const urlEdited = computed(() => !!editingChannelId.value && !!channelForm.value.url)
const targetChanged = computed(() =>
  !!editingChannelId.value && !typeChanged.value && isSlackApp.value
  && !!channelForm.value.target && channelForm.value.target !== channelForm.value.origTarget)
// Slack 應用程式的 token：新增、改型別、改網址時必填；其他編輯留空＝沿用
const tokenRequired = computed(() => isSlackApp.value && (!editingChannelId.value || typeChanged.value || urlEdited.value))

// ---- 對個人派送 ----
const dmError = ref('')
const canTargetUser = computed(() => CHANNEL_TYPES_TARGET_USER.includes(channelForm.value.type))
const hasTargetUserChannel = computed(() => channels.value.some((c) => CHANNEL_TYPES_TARGET_USER.includes(c.type)))
// 已保存的網址不在允許清單（且這次沒有改網址、沒有改型別）：開關停用並說明原因
const dmUrlLocked = computed(() =>
  !!editingChannelId.value && !typeChanged.value && !urlEdited.value && channelForm.value.urlAllowed === false)
// 停用時仍允許把已開啟的關掉
const dmSwitchDisabled = computed(() => dmUrlLocked.value && !channelForm.value.dm)
// 新填的網址是否確定在允許清單內：只有官方主機、或與已保存且被允許的網址同一主機時能確定
const newUrlKnownAllowed = computed(() => {
  const host = urlHostOf(channelForm.value.url)
  if (!host) return false
  if (host === SLACK_DM_DEFAULT_HOST) return true
  return channelForm.value.urlAllowed !== false && host === urlHostOf(channelForm.value.maskedUrl)
})
// 已開啟的通道改了型別或網址：儲存後伺服端會自動關閉，表單先提示（'type'、'host' 或空字串）
const dmAutoOffReason = computed(() => {
  const f = channelForm.value
  if (!editingChannelId.value || !f.origDm) return ''
  if (typeChanged.value && !CHANNEL_TYPES_TARGET_USER.includes(f.type)) return 'type'
  if (!typeChanged.value && urlEdited.value && !newUrlKnownAllowed.value) return 'host'
  return ''
})

const slackAddressToggleLabel = computed(() => {
  if (!editingChannelId.value || typeChanged.value) return t('alerts.slackAddressAdvanced')
  return isSlackDefaultMasked(channelForm.value.maskedUrl)
    ? t('alerts.slackAddressCurrentDefault')
    : t('alerts.slackAddressCurrentCustom')
})

// 改型別的提示：標題寫舊秘密的去向，內文寫新型別要填什麼
const typeChangeTitle = computed(() => {
  const { origType, type } = channelForm.value
  if (type === 'slack_app') return origType === 'webhook' ? t('alerts.typeToSlackApp') : t('alerts.typeToSlackAppFromSlack')
  if (type === 'webhook') return origType === 'slack_app' ? t('alerts.typeFromSlackApp') : t('alerts.typeToWebhookFromSlack')
  return origType === 'slack_app' ? t('alerts.typeToSlackFromSlackApp') : t('alerts.typeToSlackFromWebhook')
})
const typeChangeBody = computed(() => {
  const { type } = channelForm.value
  if (type === 'slack_app') return t('alerts.typeToSlackAppBody')
  if (type === 'webhook') return t('alerts.typeFromSlackAppBody')
  return t('alerts.typeToSlackBody')
})

const onTypeChange = (type) => {
  const f = channelForm.value
  f.secret = ''
  f.clearSecret = false
  if (!editingChannelId.value) {
    slackAddressOpen.value = false
    return
  }
  if (type === f.origType) {
    // 改回原型別：恢復「留空沿用」
    f.url = ''
    f.target = f.origTarget
    slackAddressOpen.value = false
  } else {
    // 改型別：網址欄清空並變成必填，Slack 應用程式預先帶入官方位址
    f.url = type === 'slack_app' ? SLACK_APP_DEFAULT_URL : ''
    f.target = ''
    slackAddressOpen.value = type === 'slack_app'
  }
  channelFormRef.value?.clearValidate?.()
}

// 改網址時未送達的通知筆數：投遞紀錄回應頂層的 pending_counts（等待中＋重送中，依類別分兩類）
const pendingCounts = ref(null)
let pendingCountsFor = null
const loadPendingCounts = async (id) => {
  if (pendingCountsFor === id) return
  pendingCountsFor = id
  try {
    const res = await getChannelDeliveries(id, { page: 1, page_size: 1 })
    const c = res?.pending_counts
    pendingCounts.value = c
      ? { general: Number(c.general) || 0, snapshot: Number(c.system_security_alert) || 0 }
      : null
  } catch {
    pendingCounts.value = null
  }
}
watch(urlEdited, (edited) => {
  if (edited && !typeChanged.value) void loadPendingCounts(editingChannelId.value)
})
const pendingNotice = computed(() => {
  if (!urlEdited.value || typeChanged.value) return null
  const c = pendingCounts.value
  if (!c || (c.general === 0 && c.snapshot === 0)) return null
  if (c.general === 0) {
    return {
      title: t('alerts.pendingSnapshotOnly', { n_snapshot: c.snapshot }),
      body: t('alerts.pendingStillOldDestBody', { n_snapshot: c.snapshot }),
    }
  }
  if (c.snapshot === 0) {
    return { title: t('alerts.pendingNewUrlOnly', { n_general: c.general }), body: t('alerts.pendingRecalcHint') }
  }
  return {
    title: t('alerts.pendingStillOldDest', { n_general: c.general, n_snapshot: c.snapshot }),
    body: t('alerts.pendingStillOldDestBody', { n_snapshot: c.snapshot }),
  }
})

const channelFormRules = computed(() => ({
  name: [
    { required: true, message: t('alerts.channelNameRequired'), trigger: 'blur' },
  ],
  type: [
    { required: true, message: t('alerts.channelTypeRequired'), trigger: 'change' },
  ],
  url: [
    {
      // 新增時必填（Slack 應用程式除外，留空＝官方位址）；編輯時留空＝沿用，但改了型別要重填
      validator: (rule, value, callback) => {
        if (typeChanged.value && !value) callback(new Error(t('alerts.typeChangeUrlRequired')))
        else if (!editingChannelId.value && !value && !isSlackApp.value) callback(new Error(t('alerts.channelUrlRequired')))
        else callback()
      },
      trigger: 'blur',
    },
  ],
  secret: [
    {
      validator: (rule, value, callback) => {
        if (!isSlackApp.value) return callback()
        if (!value) {
          if (!tokenRequired.value) return callback()
          return callback(new Error(urlEdited.value && !typeChanged.value ? t('alerts.urlChangedTokenError') : t('alerts.botTokenRequired')))
        }
        if (!SLACK_BOT_TOKEN_PATTERN.test(value)) return callback(new Error(t('alerts.botTokenFormatError')))
        callback()
      },
      trigger: 'blur',
    },
  ],
  target: [
    {
      validator: (rule, value, callback) => {
        if (!isSlackApp.value) return callback()
        if (!value) return callback(new Error(t('alerts.targetChannelRequired')))
        if (value.length > SLACK_TARGET_MAX_LEN || !SLACK_TARGET_PATTERN.test(value)) {
          return callback(new Error(t('alerts.targetChannelError')))
        }
        callback()
      },
      trigger: 'blur',
    },
  ],
}))

const fetchChannels = async () => {
  channelsLoading.value = true
  try {
    const response = await getChannels()
    channels.value = Array.isArray(response) ? response : response.data || []
  } catch (error) {
    console.error('取得通知通道失敗:', error)
  } finally {
    channelsLoading.value = false
  }
}

const openChannelDialog = (row = null) => {
  editingChannelId.value = row ? row.id : null
  slackAddressOpen.value = false
  pendingCounts.value = null
  pendingCountsFor = null
  // 編輯時 secret 與 url 皆留空＝沿用既有（後端回應的 url 已遮罩，
  // 回填會把遮罩字串存成真 URL）；maskedUrl 僅供顯示。token 一律不回填，只顯示是否已設定
  channelForm.value = row
    ? {
      ...emptyForm(),
      name: row.name,
      type: row.type || 'webhook',
      origType: row.type || 'webhook',
      maskedUrl: row.url,
      hasSecret: !!row.has_secret,
      target: row.target || '',
      origTarget: row.target || '',
      enabled: row.enabled,
      language: row.language || CHANNEL_LANGUAGE_DEFAULT,
      minSeverity: row.min_severity || CHANNEL_MIN_SEVERITY_DEFAULT,
      dm: !!row.direct_message_enabled,
      origDm: !!row.direct_message_enabled,
      urlAllowed: row.direct_message_url_allowed !== false,
    }
    : emptyForm()
  dmError.value = ''
  channelDialogVisible.value = true
  channelFormRef.value?.clearValidate?.()
}

// 傳輸政策 warn 檔存 http 通道：
// 後端回 400＋code=VALIDATION_TRANSMISSION_ACK_REQUIRED＋risks，前端確認後帶 risk_acknowledged 重送
const saveChannelOnce = (payload, ack) => {
  const body = { ...payload, risk_acknowledged: ack }
  const opts = { skipErrorToast: true }
  return editingChannelId.value
    ? updateChannel(editingChannelId.value, body, opts)
    : createChannel(body, opts)
}

const handleSaveChannel = async () => {
  try {
    await channelFormRef.value.validate()
  } catch {
    return // 驗證未過，紅字就近提示，不送出請求
  }
  // 手動關閉對個人派送：按「儲存」時先確認（尚未送出的私訊會取消）。
  // 改型別或網址造成的自動關閉不再跳確認框，表單上已有提示
  if (editingChannelId.value && channelForm.value.origDm && !channelForm.value.dm && canTargetUser.value) {
    try {
      await ElMessageBox.confirm(
        t('alerts.dm.offBody', { name: channelForm.value.name }),
        t('alerts.dm.offTitle'),
        {
          confirmButtonText: t('alerts.dm.offConfirm'),
          cancelButtonText: t('common.cancel'),
          type: 'warning',
          customClass: 'channel-dm-off-confirm',
        }
      )
    } catch {
      return // 取消：回到表單，什麼都沒存
    }
  }
  channelSaving.value = true
  dmError.value = ''
  const creatingSlackApp = !editingChannelId.value && isSlackApp.value
  try {
    // clearSecret（表單）→ clear_secret（API）；secret/url 留空＝後端沿用既有值。
    // 僅送後端欄位：hasSecret/maskedUrl/clearSecret/origType/origTarget 為表單顯示狀態不外送
    const f = channelForm.value
    const payload = {
      name: f.name,
      type: f.type,
      url: f.url,
      secret: f.secret,
      enabled: f.enabled,
      // Slack 應用程式的 token 不提供清除
      clear_secret: f.type === 'slack_app' ? false : f.clearSecret,
      // 通道語系：Create 未給＝後端預設 zh-TW、Update 省略＝保留，
      // 表單恆有值故一律送出（白名單外由後端 VALIDATION 碼擋）
      language: f.language,
      // 推送門檻：表單恆有值故一律送出；列表的啟用開關刻意不送（後端省略＝保留）
      min_severity: f.minSeverity,
    }
    // 目標頻道只屬於 Slack 應用程式
    if (f.type === 'slack_app') payload.target = f.target
    // 對個人派送：新增時照表單送；編輯時只在值改變才送（不帶＝不變，讓改網址、改型別的
    // 自動關閉由伺服端判斷）。型別不能以個人為對象時一律不送
    if (CHANNEL_TYPES_TARGET_USER.includes(f.type) && (!editingChannelId.value || f.dm !== f.origDm)) {
      payload.direct_message_enabled = f.dm
    }
    let acknowledged = false
    for (;;) {
      try {
        await saveChannelOnce(payload, acknowledged)
        break
      } catch (error) {
        const resp = error?.response
        if (resp?.status === 400 && resp.data?.code === 'VALIDATION_TRANSMISSION_ACK_REQUIRED' && !acknowledged) {
          const risks = Array.isArray(resp.data.risks) ? resp.data.risks : []
          // 使用者取消＝reject → 中止儲存（對話框保持開啟）
          await ElMessageBox.confirm(
            t('alerts.channelRiskConfirm', {
              risks: risks.map((r) => riskLabel(r)).join(t('common.listSeparator')),
            }),
            t('connect.risksTitle'),
            { confirmButtonText: t('connect.risksConfirm'), cancelButtonText: t('common.cancel'), type: 'warning' }
          )
          acknowledged = true
          continue
        }
        // 對個人派送的兩種拒絕就近顯示在開關下方（衝突時帶那個通道的名稱）
        const code = resp?.data?.code
        if (resp?.status === 400 && code === 'VALIDATION_CHANNEL_DM_CONFLICT') {
          dmError.value = t('alerts.dm.conflict', { name: resp.data?.params?.name || '' })
          throw error
        }
        if (resp?.status === 400 && code === 'VALIDATION_CHANNEL_DM_URL_NOT_ALLOWED') {
          dmError.value = t('alerts.dm.notAllowed')
          throw error
        }
        // 其他錯誤：skipErrorToast 已關掉全域 toast，此處補回呈現
        ElMessage.error(resolveApiError(resp?.data, resp?.status, t('alerts.channelSaveFailed')))
        throw error
      }
    }
    let message = t('alerts.channelUpdated')
    if (!editingChannelId.value) message = creatingSlackApp ? t('alerts.channelCreatedTestHint') : t('alerts.channelCreated')
    ElMessage.success(message)
    channelDialogVisible.value = false
    void fetchChannels()
  } catch (error) {
    // 使用者取消同意（cancel）或錯誤已呈現；對話框保持開啟供修正
    console.error('儲存通道失敗:', error)
  } finally {
    channelSaving.value = false
  }
}

// 關閉啟用先確認（會取消尚未送出的一般告警與系統事件）；開啟不需確認
const handleChannelToggle = async (row, val) => {
  if (!val) {
    try {
      await ElMessageBox.confirm(
        t('alerts.disableChannelConfirm', { name: row.name }),
        t('alerts.disableChannelTitle'),
        { confirmButtonText: t('alerts.disableChannelButton'), cancelButtonText: t('common.cancel'), type: 'warning' }
      )
    } catch {
      return // 取消：開關維持開啟
    }
  }
  try {
    // 不送 url：row.url 是遮罩值，送出會把遮罩存成真 URL；空值＝後端沿用既有
    await updateChannel(row.id, { name: row.name, type: row.type, enabled: val })
    row.enabled = val
    void fetchChannels()
  } catch (error) {
    console.error('切換通道狀態失敗:', error)
    void fetchChannels()
  }
}

// 測試發送：三種型別都先開對話框
const testDialogVisible = ref(false)
const testingChannel = ref(null)
const handleTestChannel = (row) => {
  testingChannel.value = row
  testDialogVisible.value = true
}
const editFromTest = (row) => {
  testDialogVisible.value = false
  openChannelDialog(row)
}

// 投遞紀錄抽屜
const deliveryDrawerVisible = ref(false)
const deliveryChannel = ref(null)
const openDeliveryLog = (row) => {
  deliveryChannel.value = row
  deliveryDrawerVisible.value = true
}

const handleDeleteChannel = async (row) => {
  try {
    await confirmDestructive(
      [
        t('alerts.deleteChannelConfirm', { name: row.name }),
        t('alerts.channelDeleteNotice'),
        t('alerts.channelDeleteCancelNotice'),
        t('alerts.channelDeleteLogNotice'),
      ].join('\n'),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
        customClass: 'channel-delete-confirm',
      }
    )
  } catch {
    return // 使用者取消
  }

  try {
    await deleteChannel(row.id)
    ElMessage.success(t('alerts.channelDeleted'))
    void fetchChannels()
  } catch (error) {
    console.error('刪除通道失敗:', error)
  }
}

// 頁籤切換時由告警頁呼叫，重載通道列表
defineExpose({ refresh: fetchChannels })
</script>

<style scoped>
.clear-secret-check {
  margin-top: 6px;
}

.secret-status {
  width: 100%;
  margin-bottom: 6px;
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.field-muted {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.field-hint {
  margin-top: 6px;
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
  line-height: 1.5;
}

.field-hint code {
  padding: 1px 5px;
  border-radius: var(--ot-radius-sm);
  background: var(--el-fill-color-light);
  font-size: var(--ot-font-size-xs);
}

/* 推送門檻：三個單選直排；限縮檔在列表以警示色標示 */
.min-severity-group {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
}

.min-severity-group .field-muted {
  margin-left: 6px;
}

.list-card {
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.toolbar {
  display: flex;
  justify-content: flex-end;
  margin-bottom: var(--ot-space-md);
}

/* 欄位錯誤可能兩行：改為文件流內排版，不壓到下一個欄位的標籤 */
.channel-form :deep(.el-form-item__error) {
  position: static;
  padding-top: 4px;
  line-height: 1.5;
}

.row-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 2px 10px;
}

.row-actions .el-button + .el-button {
  margin-left: 0;
}

.retry-hint {
  margin-top: 0;
}

.push-narrowed {
  color: var(--ot-warning);
  font-weight: 600;
}

.url-change-notice,
.form-notice {
  margin-bottom: var(--ot-space-md);
}

.dest-unreadable {
  color: var(--ot-danger);
  font-size: var(--ot-font-size-xs);
}

/* 送達狀況欄 */
.health {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  font-size: var(--ot-font-size-xs);
  line-height: 1.5;
}

.health-key {
  display: inline-block;
  min-width: 4.5em;
  margin-right: 6px;
  font-weight: 600;
}

.health-reason {
  padding-left: calc(4.5em + 6px);
}

.health-fail {
  color: var(--ot-danger);
}

.health-warn {
  color: var(--ot-warning);
}

.health-since {
  margin-top: 2px;
  padding-top: 2px;
  border-top: 1px dashed var(--ot-border-subtle);
  color: var(--el-text-color-secondary);
}

:deep(.el-table__row.is-failing > td.el-table__cell) {
  background-color: color-mix(in srgb, var(--ot-danger) 8%, transparent);
}

.type-option {
  display: flex;
  flex-direction: column;
  line-height: 1.4;
  padding: 4px 0;
}

.type-option__help {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.how-list {
  margin: 4px 0;
  padding-left: 1.4em;
  line-height: 1.6;
}

.how-docs a {
  margin-left: 8px;
}

.dm-tag {
  margin-top: 4px;
}

.dm-tag__icon {
  margin-right: 2px;
  vertical-align: -2px;
}

.dm-switch-line {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  width: 100%;
}

.dm-switch-state {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.dm-error {
  margin-top: 4px;
  color: var(--ot-danger);
  font-size: var(--ot-font-size-xs);
  line-height: 1.5;
}

.dm-how-title {
  margin-top: var(--ot-space-sm);
  font-weight: 600;
}

.dm-how-para {
  margin: 4px 0;
  line-height: 1.6;
}

.advanced-toggle {
  margin-bottom: var(--ot-space-sm);
}

.advanced-toggle .el-icon {
  transition: transform 0.15s;
}

.advanced-toggle .el-icon.is-open {
  transform: rotate(90deg);
}
</style>

<style>
/* 型別選單每項兩行：放寬選項高度（popper 在 body 下，不受 scoped 影響） */
.channel-type-popper .el-select-dropdown__item {
  height: auto;
}

/* 刪除確認框：一句一行 */
.channel-delete-confirm .el-message-box__message p {
  white-space: pre-line;
}
</style>
