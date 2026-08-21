<template>
  <!-- syslog 轉發設定卡（audit-log-compliance D9）：獨立 API，儲存/測試不走
       政策整頁提交流；表單欄位樣式沿通知通道表單模式
       （settings-domain-restructure D7 自 SecurityPolicies.vue 抽取，行為不變） -->
  <div
    v-loading="syslogLoading"
    class="policy-card syslog-card"
  >
    <div class="card-header">
      <span class="card-title">{{ $t('syslogCard.title') }}</span>
      <span class="card-hint">
        {{ $t('syslogCard.hint') }}
      </span>
      <el-tag
        v-if="syslogDropped > 0"
        class="syslog-dropped"
        type="warning"
        size="small"
      >
        <el-icon><Warning /></el-icon>
        {{ $t('syslogCard.dropped', { n: syslogDropped }) }}
      </el-tag>
    </div>

    <el-form
      :model="syslogForm"
      label-width="90px"
      class="syslog-form"
      @submit.prevent
    >
      <el-form-item :label="$t('syslogCard.enableLabel')">
        <el-switch
          v-model="syslogForm.enabled"
          :aria-label="$t('syslogCard.enableAria')"
        />
      </el-form-item>
      <el-form-item :label="$t('sessionDetail.host')">
        <el-input
          v-model="syslogForm.host"
          :placeholder="$t('syslogCard.hostPlaceholder')"
          :aria-label="$t('syslogCard.hostAria')"
        />
      </el-form-item>
      <el-form-item :label="$t('syslogCard.portLabel')">
        <el-input-number
          v-model="syslogForm.port"
          :min="1"
          :max="65535"
          :step="1"
          step-strictly
          :aria-label="$t('syslogCard.portAria')"
        />
      </el-form-item>
      <el-form-item :label="$t('common.protocol')">
        <el-select
          v-model="syslogForm.protocol"
          :aria-label="$t('syslogCard.protocolAria')"
          style="width: 100%"
        >
          <el-option
            label="UDP"
            value="udp"
          />
          <el-option
            label="TCP"
            value="tcp"
          />
          <el-option
            label="TCP + TLS"
            value="tcp+tls"
          />
        </el-select>
      </el-form-item>
      <el-form-item
        v-if="syslogForm.protocol === 'tcp+tls'"
        label="TLS CA"
      >
        <el-input
          v-model="syslogForm.tls_ca"
          type="textarea"
          :rows="4"
          :placeholder="$t('syslogCard.tlsCaPlaceholder')"
          :aria-label="$t('syslogCard.tlsCaAria')"
        />
      </el-form-item>
    </el-form>

    <el-alert
      v-if="syslogTestResult"
      class="syslog-test-result"
      :type="syslogTestResult.success ? 'success' : 'error'"
      :closable="false"
      show-icon
    >
      {{ syslogTestResult.success
        ? $t('syslogCard.testSent')
        : $t('syslogCard.testFailed', { error: syslogTestResult.error }) }}
    </el-alert>

    <div class="syslog-actions">
      <el-button
        :loading="syslogTesting"
        :disabled="syslogSaving"
        @click="handleTestSyslog"
      >
        {{ $t('syslogCard.sendTest') }}
      </el-button>
      <el-button
        type="primary"
        :loading="syslogSaving"
        :disabled="syslogTesting"
        @click="handleSaveSyslog"
      >
        {{ $t('common.save') }}
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Warning } from '@element-plus/icons-vue'
import {
  getSyslogSettings,
  testSyslogSettings,
  updateSyslogSettings,
} from '@/api/syslogSettings'
import { t } from '@/i18n'
import { resolveApiError } from '@/api/error'
import { riskLabel } from '@/utils/transportDisplay'

const syslogLoading = ref(false)
const syslogSaving = ref(false)
const syslogTesting = ref(false)
const syslogDropped = ref(0)
// { success: boolean, error?: string }；null = 尚未測試
const syslogTestResult = ref(null)
const syslogForm = ref({
  enabled: false,
  host: '',
  port: 514,
  protocol: 'udp',
  tls_ca: '',
})

const applySyslogSetting = (setting) => {
  syslogForm.value = {
    enabled: setting.enabled,
    host: setting.host,
    port: setting.port,
    protocol: setting.protocol,
    tls_ca: setting.tls_ca,
  }
}

// 送出目前表單值（協議非 tcp+tls 時 tls_ca 照送，後端忽略；切回時不丟使用者輸入）
const syslogPayload = () => ({
  enabled: syslogForm.value.enabled,
  host: syslogForm.value.host.trim(),
  port: Number(syslogForm.value.port),
  protocol: syslogForm.value.protocol,
  tls_ca: syslogForm.value.tls_ca,
})

const loadSyslogSettings = async () => {
  syslogLoading.value = true
  try {
    const response = await getSyslogSettings()
    syslogDropped.value = response.data.dropped
    applySyslogSetting(response.data.setting)
  } catch (error) {
    console.error('載入 syslog 設定失敗:', error)
  } finally {
    syslogLoading.value = false
  }
}

const handleSaveSyslog = async () => {
  syslogSaving.value = true
  try {
    // 傳輸政策 warn 檔存非 TLS 轉發（transmission-security-policy D6）：
    // 後端回 400＋code=VALIDATION_TRANSMISSION_ACK_REQUIRED＋risks，確認後帶 risk_acknowledged 重送
    let acknowledged = false
    let response
    for (;;) {
      try {
        response = await updateSyslogSettings(
          { ...syslogPayload(), risk_acknowledged: acknowledged },
          { skipErrorToast: true }
        )
        break
      } catch (error) {
        const resp = error?.response
        if (resp?.status === 400 && resp.data?.code === 'VALIDATION_TRANSMISSION_ACK_REQUIRED' && !acknowledged) {
          const risks = Array.isArray(resp.data.risks) ? resp.data.risks : []
          await ElMessageBox.confirm(
            t('syslogCard.saveRiskConfirm', {
              risks: risks.map((r) => riskLabel(r, { protocol: syslogForm.value.protocol })).join(t('common.listSeparator')),
            }),
            t('connect.risksTitle'),
            {
              confirmButtonText: t('connect.risksConfirm'),
              cancelButtonText: t('common.cancel'),
              type: 'warning',
            }
          )
          acknowledged = true
          continue
        }
        ElMessage.error(resolveApiError(resp?.data, resp?.status, t('syslogCard.saveFailed')))
        throw error
      }
    }
    if (response?.data) applySyslogSetting(response.data)
    syslogTestResult.value = null
    ElMessage.success(t('syslogCard.saved'))
  } catch (error) {
    // 使用者取消同意或錯誤已呈現
    console.error('儲存 syslog 設定失敗:', error)
  } finally {
    syslogSaving.value = false
  }
}

const handleTestSyslog = async () => {
  syslogTesting.value = true
  syslogTestResult.value = null
  try {
    // 測試即實送，與存檔同受傳輸政策閘（warn 檔非 TLS 須確認後重送）
    let acknowledged = false
    for (;;) {
      try {
        await testSyslogSettings(
          { ...syslogPayload(), risk_acknowledged: acknowledged },
          { skipErrorToast: true }
        )
        // 成功由 HTTP 2xx 表達（asset-syslog-debt-cleanup D1）：不再依賴
        // 回應 body 的 success 旗標形狀
        syslogTestResult.value = { success: true }
        break
      } catch (error) {
        const resp = error?.response
        // 確認要求判定必須在送達失敗之前：兩者狀態碼不重疊（400 vs 502），
        // 但若改以「非 2xx 即失敗」判定會吃掉風險確認迴圈，使 warn 檔非 TLS
        // 目的地永遠無法完成同意流程
        if (resp?.status === 400 && resp.data?.code === 'VALIDATION_TRANSMISSION_ACK_REQUIRED' && !acknowledged) {
          const risks = Array.isArray(resp.data.risks) ? resp.data.risks : []
          await ElMessageBox.confirm(
            t('syslogCard.testRiskConfirm', {
              risks: risks.map((r) => riskLabel(r, { protocol: syslogForm.value.protocol })).join(t('common.listSeparator')),
            }),
            t('connect.risksTitle'),
            {
              confirmButtonText: t('connect.risksConfirm'),
              cancelButtonText: t('common.cancel'),
              type: 'warning',
            }
          )
          acknowledged = true
          continue
        }
        // 送達失敗（502＋registered code）：alert 與 toast 同源查譯，避免
        // 一處顯示譯文、一處顯示後端 zh fallback
        const message = resolveApiError(resp?.data, resp?.status)
        syslogTestResult.value = { success: false, error: message }
        ElMessage.error(message)
        throw error
      }
    }
  } catch (error) {
    // 使用者取消同意或錯誤已呈現
    console.error('syslog 測試失敗:', error)
  } finally {
    syslogTesting.value = false
  }
}

onMounted(() => {
  loadSyslogSettings()
})
</script>

<style scoped>
.policy-card {
  padding: var(--ot-space-md);
  margin-bottom: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}

.card-header {
  display: flex;
  align-items: baseline;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
  padding-bottom: var(--ot-space-sm);
  border-bottom: 1px solid var(--ot-border-subtle);
}

.card-title {
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.card-hint {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}

.syslog-card .card-header {
  flex-wrap: wrap;
}

.syslog-dropped {
  margin-left: auto;
}

.syslog-form {
  max-width: 560px;
}

.syslog-test-result {
  max-width: 560px;
  margin-bottom: var(--ot-space-sm);
}

/* 按鈕與表單欄位對齊（el-button 相鄰間距沿 Element Plus 預設 margin） */
.syslog-actions {
  display: flex;
  justify-content: flex-start;
  max-width: 560px;
  padding-left: 90px;
}

@media (max-width: 900px) {
  .syslog-actions {
    padding-left: 0;
  }
}
</style>
