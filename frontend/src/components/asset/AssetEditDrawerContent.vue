<!--
  AssetEditDrawerContent：編輯資產抽屜的內容。

  抽屜本身（開關、標題列）留在資產頁；內容獨立成元件，單測直接掛這一支即可，
  不必穿過會被搬到 body 的浮層。

  版面順序即使用順序：先確認這台是誰（基本資料），再處理登入身分（帳號），
  然後是主機金鑰，最後才是不常動的其他設定。
-->
<template>
  <div class="drawer-content">
    <el-form
      ref="formRef"
      :model="form"
      :rules="rules"
      label-position="top"
      @submit.prevent
    >
      <div class="section-head">
        <h3 class="section-title">
          {{ t('assets.editDrawer.basicSection') }}
        </h3>
      </div>
      <AssetBasicFields
        v-model:form="form"
        @protocol-change="(value) => emit('protocol-change', value)"
      />

      <AssetAccountRows
        :asset-id="form.id"
        :asset-name="form.name"
        :protocol="form.protocol"
        :windows-openssh="form.rotation_channel === 'windows_ssh'"
        @changed="emit('changed')"
      />

      <!-- 主機金鑰：TOFU 指紋檢視與重置，僅 SSH 資產。
           class 是終端拒線引導的落點（?edit=<id> 深連結捲到這裡），勿更名 -->
      <div
        v-if="form.protocol === 'ssh'"
        class="host-key-item"
      >
        <div class="section-head">
          <h3 class="section-title">
            {{ t('assets.hostKey') }}
          </h3>
          <el-button
            v-if="hostKey"
            size="small"
            type="danger"
            link
            data-test="host-key-reset"
            @click="resetKey"
          >
            {{ t('assets.resetKey') }}
          </el-button>
        </div>
        <div
          v-if="hostKey"
          class="host-key-box"
        >
          <div class="host-key-line">
            <span class="host-key-algo">{{ hostKey.algorithm }}</span>
            <code class="host-key-fp">{{ hostKey.fingerprint }}</code>
            <el-button
              size="small"
              link
              @click="copyFingerprint"
            >
              {{ t('common.copy') }}
            </el-button>
          </div>
          <div class="host-key-meta">
            {{ t('assets.hostKeyMeta', { time: formatDateTime(hostKey.created_at) }) }}
          </div>
        </div>
        <span
          v-else
          class="host-key-empty"
        >{{ t('assets.hostKeyEmpty') }}</span>
      </div>

      <AssetAdvancedFields
        ref="advancedRef"
        v-model:form="form"
        is-edit
        :node-options="nodeOptions"
        :tag-names="tagNames"
        :inherit-policy-label="inheritPolicyLabel"
        :title="t('assets.editDrawer.otherSection')"
        @tag-change="(vals) => emit('tag-change', vals)"
        @tag-filter="(query) => emit('tag-filter', query)"
        @tag-visible-change="() => emit('tag-visible-change')"
        @rotation-channel-change="() => emit('rotation-channel-change')"
        @winrm-scheme-change="(scheme) => emit('winrm-scheme-change', scheme)"
      />
    </el-form>

    <div class="drawer-footer">
      <el-button @click="emit('cancel')">
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        data-test="drawer-save"
        @click="emit('submit')"
      >
        {{ t('common.save') }}
      </el-button>
    </div>
  </div>
</template>

<script setup>
import { ref, watch, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { getAssetHostKey, resetAssetHostKey } from '@/api/assets'
import { formatDateTime } from '@/utils/format'
import AssetBasicFields from '@/components/asset/AssetBasicFields.vue'
import AssetAccountRows from '@/components/asset/AssetAccountRows.vue'
import AssetAdvancedFields from '@/components/asset/AssetAdvancedFields.vue'

const form = defineModel('form', { type: Object, required: true })

defineProps({
  rules: { type: Object, default: () => ({}) },
  submitting: { type: Boolean, default: false },
  nodeOptions: { type: Array, default: () => [] },
  tagNames: { type: Array, default: () => [] },
  inheritPolicyLabel: { type: String, default: '' },
})

const emit = defineEmits([
  'submit',
  'cancel',
  'changed',
  'protocol-change',
  'tag-change',
  'tag-filter',
  'tag-visible-change',
  'rotation-channel-change',
  'winrm-scheme-change',
])

const { t } = useI18n()

const formRef = ref(null)
const advancedRef = ref(null)
const hostKey = ref(null)

async function loadHostKey() {
  hostKey.value = null
  if (!form.value.id || form.value.protocol !== 'ssh') return
  try {
    hostKey.value = await getAssetHostKey(form.value.id)
  } catch {
    // 404＝尚無記錄，顯示空態即可
  }
}

watch(() => [form.value.id, form.value.protocol], loadHostKey)
onMounted(loadHostKey)

async function copyFingerprint() {
  try {
    await navigator.clipboard.writeText(hostKey.value.fingerprint)
    ElMessage.success(t('assets.fingerprintCopied'))
  } catch {
    ElMessage.error(t('common.copyFailed'))
  }
}

async function resetKey() {
  try {
    await ElMessageBox.confirm(
      t('assets.hostKeyResetConfirm'),
      t('assets.hostKeyResetTitle'),
      { type: 'warning', confirmButtonText: t('assets.hostKeyResetButton') }
    )
  } catch {
    return // 使用者取消
  }
  try {
    await resetAssetHostKey(form.value.id)
    hostKey.value = null
    ElMessage.success(t('assets.hostKeyResetDone'))
  } catch (error) {
    console.error('[AssetEditDrawer] 重置主機金鑰失敗:', error)
  }
}

defineExpose({ formRef, advancedRef, hostKey, loadHostKey })
</script>

<style scoped>
.drawer-content {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-lg);
  height: 100%;
}

.section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-bottom: var(--ot-space-xs);
  border-bottom: 1px solid var(--el-border-color);
  margin-bottom: var(--ot-space-sm);
}

.section-title {
  margin: 0;
  font-size: var(--ot-font-size-md);
  font-weight: 600;
}

.host-key-item {
  margin: var(--ot-space-md) 0;
}

.host-key-box {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.host-key-line {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
}

.host-key-algo {
  color: var(--el-text-color-secondary);
  font-size: var(--ot-font-size-sm);
}

.host-key-fp {
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-xs);
  word-break: break-all;
}

.host-key-meta {
  font-size: var(--ot-font-size-xs);
  color: var(--el-text-color-secondary);
}

.host-key-empty {
  color: var(--el-text-color-secondary);
  font-size: var(--ot-font-size-sm);
}

.drawer-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--ot-space-sm);
  padding-top: var(--ot-space-md);
  border-top: 1px solid var(--el-border-color);
}
</style>
