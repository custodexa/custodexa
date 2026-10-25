<template>
  <div
    class="channel-panel"
    data-test="channel-panel"
  >
    <div class="list-card">
      <div class="toolbar">
        <el-button
          type="primary"
          @click="openChannelDialog()"
        >
          {{ $t('alerts.createChannel') }}
        </el-button>
      </div>
      <el-table
        v-loading="channelsLoading"
        :data="channels"
        style="width: 100%"
      >
        <el-table-column
          prop="name"
          :label="$t('common.name')"
          min-width="140"
        />
        <el-table-column
          :label="$t('alerts.channelType')"
          width="100"
        >
          <template #default="{ row }">
            {{ row.type === 'slack' ? 'Slack' : 'Webhook' }}
          </template>
        </el-table-column>
        <el-table-column
          prop="url"
          label="URL"
          min-width="280"
        >
          <template #default="{ row }">
            <span class="mono-text">{{ row.url }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('alerts.signatureColumn')"
          width="110"
        >
          <template #default="{ row }">
            <span
              v-if="row.type === 'slack'"
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
          width="110"
        >
          <template #default="{ row }">
            <span
              v-if="row.type !== 'slack'"
              class="field-muted"
            >{{ $t('alerts.notApplicable') }}</span>
            <template v-else>
              {{ channelLanguageLabel(row.language) }}
            </template>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('alerts.channelPushColumn')"
          width="130"
        >
          <template #default="{ row }">
            <span :class="isNarrowedMinSeverity(row.min_severity) ? 'push-narrowed' : 'field-muted'">
              {{ channelMinSeverityLabel(row.min_severity) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.enabled')"
          width="90"
        >
          <template #default="{ row }">
            <el-switch
              :model-value="row.enabled"
              :aria-label="$t('alerts.channelEnabledToggle', { name: row.name })"
              @change="(val) => handleChannelToggle(row, val)"
            />
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('common.actions')"
          width="220"
          fixed="right"
        >
          <template #default="{ row }">
            <el-button
              size="small"
              link
              type="primary"
              @click="handleTestChannel(row)"
            >
              {{ $t('alerts.testSend') }}
            </el-button>
            <el-button
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
              type="danger"
              @click="handleDeleteChannel(row)"
            >
              {{ $t('common.delete') }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
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
          >
            <el-option
              :label="$t('alerts.channelTypeWebhook')"
              value="webhook"
            />
            <el-option
              :label="$t('alerts.channelTypeSlack')"
              value="slack"
            />
          </el-select>
        </el-form-item>
        <el-form-item
          label="URL"
          prop="url"
          :required="!editingChannelId"
        >
          <div
            v-if="editingChannelId"
            class="secret-status"
          >
            {{ $t('alerts.currentUrlMasked') }}
            <span class="mono-text">{{ channelForm.maskedUrl }}</span>
          </div>
          <el-input
            v-model="channelForm.url"
            :placeholder="editingChannelId
              ? $t('alerts.urlKeepPlaceholder')
              : (channelForm.type === 'slack'
                ? 'https://hooks.slack.com/services/...'
                : 'https://hooks.example.com/...')"
          />
        </el-form-item>
        <!-- 改網址：舊與新兩個目的地都會收到「通道已變更」通知 -->
        <el-alert
          v-if="editingChannelId && channelForm.url"
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
        <el-form-item
          v-if="channelForm.type === 'slack'"
          :label="$t('alerts.signingSecret')"
        >
          <div class="field-hint">
            {{ $t('alerts.slackNoSecretHint') }}
          </div>
        </el-form-item>
        <el-form-item
          v-else
          :label="$t('alerts.signingSecret')"
        >
          <div
            v-if="editingChannelId"
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
            :disabled="channelForm.clearSecret"
            :placeholder="editingChannelId
              ? (channelForm.hasSecret ? $t('alerts.secretKeepPlaceholder') : $t('alerts.secretFillPlaceholder'))
              : $t('alerts.secretNewPlaceholder')"
          />
          <el-checkbox
            v-if="editingChannelId && channelForm.hasSecret"
            v-model="channelForm.clearSecret"
            class="clear-secret-check"
          >
            {{ $t('alerts.clearSecretLabel') }}
          </el-checkbox>
          <!-- 提示帶 <code> 標記：走 i18n-t 具名插槽插值，三語各自掌控語序 -->
          <i18n-t
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
        <el-form-item :label="$t('common.enabled')">
          <el-switch v-model="channelForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="channelDialogVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="channelSaving"
          @click="handleSaveChannel"
        >
          {{ $t('common.save') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  getChannels,
  createChannel,
  updateChannel,
  deleteChannel,
  testChannel,
} from '@/api/alerts'
import EmptyState from '@/components/EmptyState.vue'
import { t } from '@/i18n'
import { riskLabel } from '@/utils/transportDisplay'
import { resolveApiError } from '@/api/error'
import {
  CHANNEL_LANGUAGE_VALUES,
  CHANNEL_LANGUAGE_DEFAULT,
  channelLanguageLabel,
  CHANNEL_MIN_SEVERITY_VALUES,
  CHANNEL_MIN_SEVERITY_DEFAULT,
} from '@/constants/notification-channels'

// 通道推送門檻：缺值（後端尚未回此欄）視同預設「全部告警」；未知值原樣顯示
const channelMinSeverityLabel = (level) => {
  const v = level || CHANNEL_MIN_SEVERITY_DEFAULT
  return CHANNEL_MIN_SEVERITY_VALUES.includes(v) ? t(`alerts.channelMinSeverity.${v}`) : v
}
// 限縮（中、高等級／只有高等級）以警示色提示此通道會略過部分告警
const isNarrowedMinSeverity = (level) => !!level && level !== CHANNEL_MIN_SEVERITY_DEFAULT

// ---- 通知通道（頁籤三，admin） ----
const channels = ref([])
const channelsLoading = ref(false)
const channelDialogVisible = ref(false)
const channelSaving = ref(false)
const editingChannelId = ref(null)
const channelFormRef = ref(null)
const channelForm = ref({ name: '', type: 'webhook', url: '', secret: '', clearSecret: false, hasSecret: false, enabled: true, language: CHANNEL_LANGUAGE_DEFAULT, minSeverity: CHANNEL_MIN_SEVERITY_DEFAULT })

// 編輯時 URL 留空＝沿用既有值，僅建立時必填
const channelFormRules = computed(() => ({
  name: [
    { required: true, message: t('alerts.channelNameRequired'), trigger: 'blur' },
  ],
  type: [
    { required: true, message: t('alerts.channelTypeRequired'), trigger: 'change' },
  ],
  url: [
    {
      validator: (rule, value, callback) => {
        if (!editingChannelId.value && !value) {
          callback(new Error(t('alerts.channelUrlRequired')))
        } else {
          callback()
        }
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
  // 編輯時 secret 與 url 皆留空＝沿用既有（後端回應的 url 已遮罩，
  // 回填會把遮罩字串存成真 URL）；maskedUrl 僅供顯示
  channelForm.value = row
    ? { name: row.name, type: row.type || 'webhook', url: '', maskedUrl: row.url, secret: '', clearSecret: false, hasSecret: !!row.has_secret, enabled: row.enabled, language: row.language || CHANNEL_LANGUAGE_DEFAULT, minSeverity: row.min_severity || CHANNEL_MIN_SEVERITY_DEFAULT }
    : { name: '', type: 'webhook', url: '', maskedUrl: '', secret: '', clearSecret: false, hasSecret: false, enabled: true, language: CHANNEL_LANGUAGE_DEFAULT, minSeverity: CHANNEL_MIN_SEVERITY_DEFAULT }
  channelDialogVisible.value = true
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
    return // 驗證未過，紅字就近提示
  }
  channelSaving.value = true
  try {
    // clearSecret（表單）→ clear_secret（API）；secret/url 留空＝後端沿用既有值。
    // 僅送後端欄位：hasSecret/maskedUrl/clearSecret 為表單顯示狀態不外送
    const f = channelForm.value
    const payload = {
      name: f.name,
      type: f.type,
      url: f.url,
      secret: f.secret,
      enabled: f.enabled,
      clear_secret: f.clearSecret,
      // 通道語系：Create 未給＝後端預設 zh-TW、Update 省略＝保留，
      // 表單恆有值故一律送出（白名單外由後端 VALIDATION 碼擋）
      language: f.language,
      // 推送門檻：表單恆有值故一律送出；列表的啟用開關刻意不送（後端省略＝保留）
      min_severity: f.minSeverity,
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
        // 其他錯誤：skipErrorToast 已關掉全域 toast，此處補回呈現
        ElMessage.error(resolveApiError(resp?.data, resp?.status, t('alerts.channelSaveFailed')))
        throw error
      }
    }
    ElMessage.success(editingChannelId.value ? t('alerts.channelUpdated') : t('alerts.channelCreated'))
    channelDialogVisible.value = false
    fetchChannels()
  } catch (error) {
    // 使用者取消同意（cancel）或錯誤已呈現；對話框保持開啟供修正
    console.error('儲存通道失敗:', error)
  } finally {
    channelSaving.value = false
  }
}

const handleChannelToggle = async (row, val) => {
  try {
    // 不送 url：row.url 是遮罩值，送出會把遮罩存成真 URL；空值＝後端沿用既有
    await updateChannel(row.id, { name: row.name, type: row.type, enabled: val })
    row.enabled = val
  } catch (error) {
    console.error('切換通道狀態失敗:', error)
    fetchChannels()
  }
}

const handleTestChannel = async (row) => {
  try {
    const result = await testChannel(row.id)
    if (result.success) {
      ElMessage.success(t('alerts.testSent', { status: result.status_code }))
    } else {
      ElMessage.error(t('alerts.testFailed', { status: result.status_code }))
    }
  } catch (error) {
    console.error('測試通知送出失敗:', error)
  }
}

const handleDeleteChannel = async (row) => {
  try {
    await ElMessageBox.confirm(
      `${t('alerts.deleteChannelConfirm', { name: row.name })}\n${t('alerts.channelDeleteNotice')}`,
      t('common.deleteConfirmTitle'),
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
    await deleteChannel(row.id)
    ElMessage.success(t('alerts.channelDeleted'))
    fetchChannels()
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

.push-narrowed {
  color: var(--ot-warning);
  font-weight: 600;
}

.url-change-notice {
  margin-bottom: var(--ot-space-md);
}
</style>
