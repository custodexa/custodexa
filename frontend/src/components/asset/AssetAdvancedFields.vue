<!--
  AssetAdvancedFields：資產的進階欄位，預設收合。

  收合的判準是「多數情況下不用碰」，不是「不重要」：收合區內任一欄位已經有值、
  或伺服端把驗證錯誤指到收合區內的欄位時，本元件自動展開並在標題上標示，
  免得使用者對著一個看不見的欄位找錯。

  新增資產對話框與編輯抽屜共用本元件（抽屜內標題為「其他」）。
-->
<template>
  <el-collapse
    v-model="activeNames"
    class="advanced-collapse"
  >
    <el-collapse-item
      name="advanced"
      data-test="asset-advanced"
    >
      <template #title>
        <span class="advanced-title">{{ title || t('assets.credentialSection.advanced') }}</span>
        <el-tag
          v-if="markState"
          size="small"
          :type="markState === 'error' ? 'danger' : 'info'"
          data-test="asset-advanced-mark"
        >
          {{ markState === 'error'
            ? t('assets.credentialSection.advancedError')
            : t('assets.credentialSection.advancedFilled') }}
        </el-tag>
        <!-- 摘要各自報各自的欄位：新增資產與編輯抽屜的收合區內容本來就不同
             （狀態只在編輯態、SFTP 只在 vnc），共用一句會讓摘要指向不存在的欄位 -->
        <span
          v-else
          class="advanced-summary"
          data-test="asset-advanced-summary"
        >{{ isEdit
          ? t('assets.credentialSection.advancedSummaryEdit')
          : t('assets.credentialSection.advancedSummary') }}</span>
      </template>

      <el-form-item :label="t('common.description')">
        <el-input
          v-model="form.description"
          type="textarea"
          :rows="3"
          :placeholder="t('assets.descPlaceholder')"
        />
      </el-form-item>
      <!-- 標籤輸入輔助：既有標籤自動完成（大小寫不敏感）＋自由建立 -->
      <el-form-item :label="t('common.tags')">
        <el-select
          v-model="form.tagList"
          multiple
          filterable
          allow-create
          default-first-option
          clearable
          :placeholder="t('assets.tagPlaceholder')"
          class="full"
          :filter-method="(q) => emit('tag-filter', q)"
          @change="(vals) => emit('tag-change', vals)"
          @visible-change="() => emit('tag-visible-change')"
        >
          <el-option
            v-for="name in tagNames"
            :key="name"
            :label="name"
            :value="name"
          />
        </el-select>
      </el-form-item>
      <!-- 掛載節點（多歸屬）：樹狀多選、全路徑顯示；空＝未分組。節點 CRUD 在資產頁左樹 -->
      <el-form-item :label="t('assets.mountNodes')">
        <el-tree-select
          v-model="form.node_ids"
          :data="nodeOptions"
          :props="{ label: 'name', children: 'children' }"
          node-key="id"
          multiple
          check-strictly
          show-checkbox
          clearable
          :placeholder="t('assets.mountNodesPlaceholder')"
          class="full"
        />
      </el-form-item>
      <!-- 連線政策：政策掛資產本身，主要設定入口 -->
      <el-form-item :label="t('assets.accessPolicy')">
        <!-- empty-values 排除 ''：繼承選項 value 為空字串，
             預設會被 el-select 當空值而顯示 placeholder -->
        <el-select
          v-model="form.access_policy"
          :empty-values="[null, undefined]"
          class="full"
        >
          <el-option
            :label="inheritPolicyLabel"
            value=""
          />
          <el-option
            v-for="(label, value) in accessPolicyEnumLabels"
            :key="value"
            :label="label"
            :value="value"
          />
        </el-select>
      </el-form-item>
      <el-form-item
        v-if="isEdit"
        :label="t('common.status')"
      >
        <el-switch
          v-model="form.active"
          :active-text="t('common.enabled')"
          :inactive-text="t('common.disabled')"
        />
      </el-form-item>

      <el-form-item
        v-if="isDatabaseProtocol(form.protocol)"
        :label="t('assets.dbName')"
      >
        <el-input
          v-model="form.db_name"
          :placeholder="t('assets.dbNamePlaceholder')"
        />
      </el-form-item>
      <el-form-item
        v-if="isDatabaseProtocol(form.protocol)"
        :label="t('assets.tlsMode')"
      >
        <el-select
          v-model="form.db_tls_mode"
          class="full"
        >
          <el-option
            :label="t('assets.tlsDefault')"
            value=""
          />
          <el-option
            :label="t('assets.tlsDisable')"
            value="disable"
          />
          <el-option
            :label="t('assets.tlsRequire')"
            value="require"
          />
          <el-option
            :label="t('assets.tlsVerifyCa')"
            value="verify-ca"
          />
          <el-option
            :label="t('assets.tlsVerifyFull')"
            value="verify-full"
          />
        </el-select>
      </el-form-item>
      <el-form-item
        v-if="isDatabaseProtocol(form.protocol) && ['verify-ca', 'verify-full'].includes(form.db_tls_mode)"
        :label="t('assets.caCert')"
      >
        <!-- mssql 的語義是「伺服器憑證釘選」（收單張伺服器憑證），
             不是 CA bundle，故說明文字與其他三協議不共用 -->
        <el-input
          v-model="form.db_ca_cert"
          type="textarea"
          :rows="3"
          :placeholder="form.protocol === 'mssql' ? t('assets.mssqlCaCertHint') : t('assets.dbCaPlaceholder')"
        />
      </el-form-item>
      <!-- 查詢主控台的執行目標限制。射程只到主控台，命令列會話不受影響——
           helper 必須把這件事寫出來，否則管理者會以為填了就等於資料庫級存取控制 -->
      <el-form-item
        v-if="isDBConsoleProtocol(form.protocol)"
        :label="t('assets.allowedDatabases')"
      >
        <el-select
          v-model="form.allowed_databases"
          multiple
          filterable
          allow-create
          default-first-option
          class="full"
          :reserve-keyword="false"
          :placeholder="t('assets.allowedDatabasesPlaceholder')"
          data-test="allowed-databases"
        />
        <div class="form-tip">
          {{ t('assets.allowedDatabasesScopeHint') }}
        </div>
        <div class="form-tip">
          {{ t(`assets.allowedDatabasesCaseHint.${form.protocol}`) }}
        </div>
      </el-form-item>

      <!-- RDP 傳輸安全：預設沿現狀，strict 檔的修復路徑＝調 NLA＋開啟憑證驗證 -->
      <template v-if="form.protocol === 'rdp'">
        <el-form-item :label="t('assets.rdpSecurity')">
          <el-select
            v-model="form.rdp_security"
            class="full"
          >
            <el-option
              :label="t('assets.rdpAuto')"
              value=""
            />
            <el-option
              :label="t('assets.rdpNla')"
              value="nla"
            />
            <el-option
              label="TLS"
              value="tls"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('assets.rdpVerifyCert')">
          <el-switch v-model="form.rdp_verify_cert" />
          <span
            v-if="!form.rdp_verify_cert"
            class="form-tip form-tip--inline form-tip--warning"
          >{{ t('assets.rdpVerifyWarning') }}</span>
        </el-form-item>
        <!-- 改密通道側車：通道與連線路徑無關，這裡設定的只有改密計劃會用到 -->
        <el-form-item
          :label="t('assets.rotationChannel')"
          data-test="rotation-channel-item"
        >
          <el-select
            v-model="form.rotation_channel"
            class="full"
            data-test="rotation-channel"
            @change="() => emit('rotation-channel-change')"
          >
            <el-option
              :label="t('assets.rotationChannelNone')"
              value="none"
            />
            <el-option
              :label="t('assets.rotationChannelWinrm')"
              value="windows_winrm"
            />
            <el-option
              :label="t('assets.rotationChannelWindowsSsh')"
              value="windows_ssh"
            />
          </el-select>
          <div class="form-tip">
            {{ t('assets.rotationChannelHint') }}
          </div>
        </el-form-item>
        <template v-if="form.rotation_channel === 'windows_winrm'">
          <el-form-item
            :label="t('assets.winrmScheme')"
            data-test="winrm-scheme-item"
          >
            <el-radio-group
              v-model="form.winrm_scheme"
              data-test="winrm-scheme"
              @change="(scheme) => emit('winrm-scheme-change', scheme)"
            >
              <el-radio-button
                v-for="scheme in WINRM_SCHEME_VALUES"
                :key="scheme"
                :value="scheme"
              >
                {{ t(`enum.winrmScheme.${scheme}`) }} {{ WINRM_DEFAULT_PORTS[scheme] }}
              </el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item :label="t('assets.winrmPort')">
            <el-input-number
              v-model="form.winrm_port"
              :min="0"
              :max="65535"
              data-test="winrm-port"
            />
            <span class="form-tip form-tip--inline">{{ t('assets.winrmPortHint') }}</span>
          </el-form-item>
          <el-form-item
            v-if="form.winrm_scheme === 'https'"
            :label="t('assets.winrmTlsMode')"
            data-test="winrm-tls-mode-item"
          >
            <el-radio-group
              v-model="form.winrm_tls_mode"
              data-test="winrm-tls-mode"
            >
              <el-radio-button
                v-for="mode in WINRM_TLS_MODE_VALUES"
                :key="mode"
                :value="mode"
              >
                {{ t(`enum.winrmTlsMode.${mode}`) }}
              </el-radio-button>
            </el-radio-group>
            <div class="form-tip">
              {{ t('assets.winrmTlsHint') }}
            </div>
          </el-form-item>
          <el-form-item
            v-if="form.winrm_scheme === 'https' && form.winrm_tls_mode === 'ca'"
            :label="t('assets.winrmCaCert')"
            prop="winrm_ca_cert"
            data-test="winrm-ca-cert-item"
          >
            <el-input
              v-model="form.winrm_ca_cert"
              type="textarea"
              :rows="3"
              :placeholder="t('assets.winrmCaCertPlaceholder')"
              data-test="winrm-ca-cert"
            />
            <div class="form-tip">
              {{ isEdit && form.has_winrm_ca_cert ? t('assets.winrmCaCertKeep') : t('assets.winrmCaCertHint') }}
            </div>
          </el-form-item>
          <el-form-item>
            <div
              class="form-tip"
              data-test="winrm-target-requirements"
            >
              {{ t('assets.winrmTargetRequirements') }}
            </div>
          </el-form-item>
        </template>
        <el-form-item
          v-if="form.rotation_channel === 'windows_ssh'"
          :label="t('assets.rotationSshPort')"
          data-test="rotation-ssh-port-item"
        >
          <el-input-number
            v-model="form.rotation_ssh_port"
            :min="1"
            :max="65535"
            data-test="rotation-ssh-port"
          />
          <span class="form-tip form-tip--inline">{{ t('assets.rotationSshPortHint') }}</span>
        </el-form-item>
      </template>

      <template v-if="form.protocol === 'k8s'">
        <el-form-item
          label="Namespace"
          prop="k8s_namespace"
        >
          <el-input
            v-model="form.k8s_namespace"
            :placeholder="t('assets.k8sNamespacePlaceholder')"
          />
        </el-form-item>
        <el-form-item :label="t('assets.caCert')">
          <el-input
            v-model="form.k8s_ca_cert"
            type="textarea"
            :rows="3"
            :placeholder="t('assets.k8sCaPlaceholder')"
          />
        </el-form-item>
        <el-form-item :label="t('assets.k8sSkipTls')">
          <el-switch v-model="form.k8s_insecure_skip_tls" />
          <span
            v-if="form.k8s_insecure_skip_tls"
            class="form-tip form-tip--inline form-tip--danger"
          >{{ t('assets.k8sSkipTlsWarning') }}</span>
        </el-form-item>
      </template>

      <!-- ssh 資產的 Windows 開關＝通道 windows_ssh；關閉即回到依協議推導的 POSIX 通道 -->
      <el-form-item
        v-if="form.protocol === 'ssh'"
        :label="t('assets.windowsSsh')"
        data-test="windows-ssh-item"
      >
        <el-switch
          :model-value="form.rotation_channel === 'windows_ssh'"
          data-test="windows-ssh-switch"
          @update:model-value="(on) => (form.rotation_channel = on ? 'windows_ssh' : '')"
        />
        <span class="form-tip form-tip--inline">{{ t('assets.windowsSshNote') }}</span>
      </el-form-item>

      <template v-if="form.protocol === 'vnc'">
        <el-form-item :label="t('assets.sftpTransfer')">
          <el-switch v-model="form.sftp_enabled" />
          <span class="form-tip form-tip--inline">{{ t('assets.sftpNote') }}</span>
        </el-form-item>
        <template v-if="form.sftp_enabled">
          <el-form-item :label="t('assets.sftpPort')">
            <el-input-number
              v-model="form.sftp_port"
              :min="1"
              :max="65535"
            />
          </el-form-item>
          <el-form-item
            :label="t('assets.sftpUsername')"
            prop="sftp_username"
          >
            <el-input
              v-model="form.sftp_username"
              :placeholder="t('assets.sftpUsernamePlaceholder')"
            />
          </el-form-item>
          <el-form-item :label="t('assets.sftpPassword')">
            <el-input
              v-model="form.sftp_password"
              type="password"
              show-password
              :placeholder="isEdit && form.has_sftp_password ? t('assets.sftpPasswordKeep') : t('assets.sftpPasswordPlaceholder')"
            />
          </el-form-item>
        </template>
      </template>
    </el-collapse-item>
  </el-collapse>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { accessPolicyEnumLabels } from '@/utils/policyFormat'
import { isDatabaseProtocol, isDBConsoleProtocol } from '@/utils/protocol'
import {
  WINRM_SCHEME_VALUES,
  WINRM_TLS_MODE_VALUES,
  WINRM_DEFAULT_PORTS,
} from '@/constants/rotationChannel'

const form = defineModel('form', { type: Object, required: true })

const props = defineProps({
  isEdit: { type: Boolean, default: false },
  nodeOptions: { type: Array, default: () => [] },
  tagNames: { type: Array, default: () => [] },
  inheritPolicyLabel: { type: String, default: '' },
  title: { type: String, default: '' },
})

const emit = defineEmits([
  'tag-change',
  'tag-filter',
  'tag-visible-change',
  'rotation-channel-change',
  'winrm-scheme-change',
])

const { t } = useI18n()

const activeNames = ref([])
const serverError = ref(false)

// 「已經有值」的判準逐欄列出而非比對整份表單：出廠值本身也是值，
// 拿「與初始狀態不同」當判準會在編輯既有資產時恆為真，收合就永遠不會發生
const hasValue = computed(() => {
  const f = form.value
  const filled = [
    f.description,
    f.access_policy,
    f.db_name,
    f.db_tls_mode,
    f.db_ca_cert,
    f.rdp_security,
    f.k8s_namespace,
    f.k8s_ca_cert,
  ].some((value) => !!value)
  const flags =
    f.rdp_verify_cert ||
    f.k8s_insecure_skip_tls ||
    f.sftp_enabled ||
    f.has_winrm_ca_cert ||
    (props.isEdit && f.active === false)
  const lists =
    (f.tagList || []).length > 0 ||
    (f.node_ids || []).length > 0 ||
    (f.allowed_databases || []).length > 0
  const channel = !!f.rotation_channel && f.rotation_channel !== 'none'
  return filled || flags || lists || channel
})

// k8s 的 namespace 是必填且住在收合區：協議一選就展開，
// 否則使用者會對著一個看不見的必填欄位卡住
const hasRequiredField = computed(() => form.value.protocol === 'k8s')

const markState = computed(() => {
  if (serverError.value) return 'error'
  return hasValue.value ? 'filled' : ''
})

const expanded = computed(() => activeNames.value.includes('advanced'))

function expand() {
  if (!expanded.value) activeNames.value = ['advanced']
}

// 伺服端把錯誤指到收合區內：展開並標示，讓紅字所在的欄位真的看得到
function markServerError() {
  serverError.value = true
  expand()
}

function clearServerError() {
  serverError.value = false
}

watch(
  () => [hasValue.value, hasRequiredField.value],
  ([filled, required]) => {
    if (filled || required) expand()
  }
)

onMounted(() => {
  if (hasValue.value || hasRequiredField.value) expand()
})

defineExpose({ activeNames, expand, markServerError, clearServerError, hasValue, expanded })
</script>

<style scoped>
.advanced-collapse {
  width: 100%;
  border-top: none;
}

.advanced-title {
  margin-right: var(--ot-space-sm);
  font-weight: 600;
}

.advanced-summary {
  color: var(--el-text-color-secondary);
  font-size: var(--ot-font-size-xs);
}

.full {
  width: 100%;
}

.form-tip {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
  line-height: 1.6;
}

.form-tip--inline {
  margin-left: var(--ot-space-sm);
}

.form-tip--warning {
  color: var(--el-color-warning);
}

.form-tip--danger {
  color: var(--el-color-danger);
}
</style>
