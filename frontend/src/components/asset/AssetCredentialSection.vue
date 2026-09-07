<!--
  AssetCredentialSection：登入憑證的二擇一區塊。

  一個畫面上只有一個憑證入口：要嘛挑一筆共用憑證（這台跟著那組秘密一起改密），
  要嘛這台自己一組（建立後成為一筆專用憑證）。兩者互斥，送出的載荷也是二擇一
  ——同時給兩種來源會被伺服端擋下。

  新增資產與抽屜內的新增帳號共用本元件：同一個問題只該有一種問法。
-->
<template>
  <div class="credential-section">
    <div
      v-if="!compact"
      class="section-title"
    >
      {{ t('assets.credentialSection.title') }}
    </div>

    <el-radio-group
      v-model="model.credential_mode"
      class="mode-group"
      data-test="credential-mode"
      @change="onModeChange"
    >
      <el-radio-button value="shared">
        {{ t('assets.credentialSection.modeShared') }}
      </el-radio-button>
      <el-radio-button value="dedicated">
        {{ t('assets.credentialSection.modeDedicated') }}
      </el-radio-button>
    </el-radio-group>

    <template v-if="model.credential_mode === 'shared'">
      <el-form-item
        :label="t('assets.credentialSection.sharedLabel')"
        prop="credential_id"
      >
        <CredentialPicker
          v-model="model.credential_id"
          :protocol="protocol"
          :windows-openssh="windowsOpenssh"
          :exclude-ids="excludeIds"
          @loaded="onPickerLoaded"
        />
        <!-- 列內使用時由呼叫端給更貼近該情境的說明，兩句同時出現只是噪音 -->
        <div
          v-if="!compact"
          class="form-tip"
          data-test="credential-shared-hint"
        >
          {{ sharedHint }}
        </div>
      </el-form-item>
    </template>

    <template v-else>
      <el-form-item
        v-if="!isPasswordOnlyProtocol(protocol)"
        :label="t('assets.credentialSection.usernameLabel')"
        prop="username"
      >
        <el-input
          v-model="model.username"
          :placeholder="t('assets.usernamePlaceholder')"
          data-test="credential-username"
        />
      </el-form-item>
      <el-form-item
        :label="protocol === 'k8s' ? 'Token' : t('common.password')"
        prop="password"
      >
        <el-input
          v-model="model.password"
          type="password"
          show-password
          autocomplete="new-password"
          :placeholder="protocol === 'k8s' ? t('assets.tokenPlaceholder') : t('assets.passwordPlaceholder')"
          data-test="credential-password"
        />
      </el-form-item>
      <el-form-item
        v-if="protocol === 'ssh'"
        :label="t('assets.privateKey')"
        prop="private_key"
      >
        <el-input
          v-model="model.private_key"
          type="textarea"
          :rows="compact ? 2 : 4"
          :placeholder="t('assets.credentialSection.privateKeyPlaceholder')"
          data-test="credential-private-key"
        />
      </el-form-item>
      <el-form-item
        v-if="isDatabaseProtocol(protocol)"
        :label="t('assets.authMethod')"
      >
        <el-select
          v-model="model.auth_method"
          class="auth-select"
        >
          <el-option
            :label="t('assets.authMethodSql')"
            value="sql"
          />
          <el-option
            :label="t('assets.authMethodDomain')"
            value="domain"
            disabled
          />
        </el-select>
      </el-form-item>
      <el-form-item
        v-if="showPrivileged"
        :label="t('assetAccounts.colPrivileged')"
      >
        <el-switch
          v-model="model.privileged"
          data-test="credential-privileged"
        />
        <span class="form-tip form-tip--inline">{{ t('assetAccounts.privilegedHint') }}</span>
      </el-form-item>
      <div
        class="dedicated-note"
        data-test="credential-dedicated-note"
      >
        <el-icon><Info /></el-icon>
        <span>{{ dedicatedNote }}</span>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { Info } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import CredentialPicker from '@/components/credential/CredentialPicker.vue'
import { credentialDisplayName } from '@/constants/credentials'
import { isDatabaseProtocol, isPasswordOnlyProtocol } from '@/utils/protocol'

// model 由呼叫端持有（新增資產走表單本體、新增帳號走列內表單），
// 形狀：{ credential_mode, credential_id, username, password, private_key, privileged, auth_method }
const model = defineModel('model', { type: Object, required: true })

const props = defineProps({
  protocol: { type: String, default: '' },
  windowsOpenssh: { type: Boolean, default: false },
  excludeIds: { type: Array, default: () => [] },
  // 建立資產的端點不接受特權旗標，故只有新增帳號時顯示這個開關
  showPrivileged: { type: Boolean, default: false },
  assetName: { type: String, default: '' },
  compact: { type: Boolean, default: false },
})

const { t } = useI18n()

// 選中憑證的掛載數只有清單答得出來，故留下 picker 回報的那一份原樣使用，不在此推導
const pickerOptions = ref([])

function onPickerLoaded(options) {
  pickerOptions.value = options || []
}

const selectedCredential = computed(() => {
  const id = model.value.credential_id
  if (!id) return null
  return pickerOptions.value.find((item) => String(item.id) === String(id)) || null
})

// 掛上去等於多一台跟著這組秘密走：選定憑證後把「這台會是第幾台」當場說出來，
// 使用者才看得到自己正在擴大哪一組秘密的影響面。查不到掛載數就退回不帶數字那句
const sharedHint = computed(() => {
  const cred = selectedCredential.value
  const bound = Number(cred?.binding_count)
  if (!cred || !Number.isFinite(bound)) return t('assets.credentialSection.sharedHint')
  return t('assets.credentialSection.sharedHintCount', {
    name: credentialDisplayName(cred),
    count: bound + 1,
  })
})

// 專用憑證的名字是計算值：現在就把它算給操作者看，免得建完在憑證庫裡找不到自己剛建的東西
const dedicatedNote = computed(() => {
  const username = model.value.username || t('assets.credentialSection.usernamePlaceholderShort')
  if (!props.assetName) {
    return t('assets.credentialSection.dedicatedNoteNoName')
  }
  return t('assets.credentialSection.dedicatedNote', {
    name: `${props.assetName} / ${username}`,
  })
})

// 切換來源即清掉另一側的殘值：兩種來源同時帶值會被伺服端判為意圖不明
function onModeChange(mode) {
  if (mode === 'shared') {
    model.value.username = ''
    model.value.password = ''
    model.value.private_key = ''
  } else {
    model.value.credential_id = null
  }
}

defineExpose({ dedicatedNote, sharedHint, onModeChange, onPickerLoaded })
</script>

<style scoped>
.credential-section {
  width: 100%;
}

.section-title {
  margin-bottom: var(--ot-space-sm);
  padding-bottom: var(--ot-space-xs);
  border-bottom: 1px solid var(--el-border-color);
  font-weight: 600;
}

.mode-group {
  margin-bottom: var(--ot-space-md);
}

.auth-select {
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

.dedicated-note {
  display: flex;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--el-color-primary-light-5);
  border-radius: var(--ot-radius-md, 6px);
  background: var(--el-color-primary-light-9);
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}
</style>
