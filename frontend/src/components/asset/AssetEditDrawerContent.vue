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

      <el-alert
        v-if="securityChangeFields.length"
        class="security-change-notice"
        data-test="security-change-notice"
        type="warning"
        :closable="false"
        show-icon
        :title="t('assets.securityChangeNotice', { fields: securityChangeFields.join(', ') })"
      />

      <el-alert
        v-if="accountsDenied"
        type="info"
        :closable="false"
        show-icon
        data-test="accounts-denied-hint"
        :title="accountsDeniedText"
      />
      <!-- 帳號管理不在範圍內：整塊唯讀（inert 擋互動與焦點），不另寫第二套判斷 -->
      <AssetAccountRows
        :inert="accountsDenied || undefined"
        :class="{ 'accounts-locked': accountsDenied }"
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
            :disabled="!canResetHostKey"
            @click="resetKey"
          >
            {{ t('assets.resetKey') }}
          </el-button>
        </div>
        <div
          v-if="hostKey && !canResetHostKey"
          class="host-key-meta"
          data-test="host-key-reset-note"
        >
          {{ t('assets.hostKeyResetSuperAdminOnly') }}
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
          <div
            v-if="hostKey.inherited"
            class="host-key-meta"
            data-test="host-key-inherited"
          >
            {{ t('assets.hostKeyInherited') }}
          </div>
          <div
            v-else
            class="host-key-meta"
          >
            {{ t('assets.hostKeyMeta', { time: formatDateTime(hostKey.created_at) }) }}
          </div>
        </div>
        <span
          v-else
          class="host-key-empty"
        >{{ t('assets.hostKeyEmpty') }}</span>

        <!-- 待確認的指紋：連線時出現過、與記錄不同的指紋（最近的在前，最多 5 筆）。
             每筆附「採用這個指紋」：超管直接把已核對的觀察指紋寫成記錄，重置保留為備用 -->
        <div
          v-if="hostKeyMismatches.length"
          class="host-key-mismatches"
          data-test="host-key-mismatches"
        >
          <div class="host-key-mismatch-head">
            <span class="host-key-mismatch-title">
              {{ t('assets.hostKeyMismatchTitle', { count: hostKeyMismatches.length }) }}
            </span>
            <span class="host-key-meta">{{ t('assets.hostKeyMismatchHint') }}</span>
          </div>
          <div
            v-if="!canResetHostKey"
            class="host-key-meta"
            data-test="host-key-adopt-note"
          >
            {{ t('assets.hostKeyAdoptSuperAdminOnly') }}
          </div>
          <div
            v-for="row in hostKeyMismatches"
            :key="row.fingerprint"
            class="host-key-mismatch-row"
            data-test="host-key-mismatch-row"
          >
            <div class="host-key-line">
              <span class="host-key-algo">{{ row.algorithm }}</span>
              <code class="host-key-fp">{{ row.fingerprint }}</code>
              <el-button
                size="small"
                type="warning"
                link
                data-test="host-key-adopt"
                :disabled="!canResetHostKey"
                @click="adoptKey(row)"
              >
                {{ t('assets.hostKeyAdopt') }}
              </el-button>
            </div>
            <div class="host-key-meta">
              {{ t('assets.hostKeyMismatchRow', {
                first: formatDateTime(row.first_seen_at),
                last: formatDateTime(row.last_seen_at),
                count: row.seen_count,
              }) }}
            </div>
          </div>
        </div>
      </div>

      <AssetAdvancedFields
        ref="advancedRef"
        v-model:form="form"
        is-edit
        :node-options="nodeOptions"
        :scoped="scoped"
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
import { ref, computed, watch, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { useI18n } from 'vue-i18n'
import { getAssetHostKey, resetAssetHostKey, adoptAssetHostKey } from '@/api/assets'
import { resolveApiError } from '@/api/error'
import { formatDateTime } from '@/utils/format'
import { actionDenial, denialText } from '@/utils/scopedAssets'
import AssetBasicFields from '@/components/asset/AssetBasicFields.vue'
import AssetAccountRows from '@/components/asset/AssetAccountRows.vue'
import AssetAdvancedFields from '@/components/asset/AssetAdvancedFields.vue'

const form = defineModel('form', { type: Object, required: true })

const props = defineProps({
  scoped: { type: Object, default: null },
  securityChangeFields: { type: Array, default: () => [] },
  canResetHostKey: { type: Boolean, default: false },
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

const accountsDenial = computed(() =>
  props.scoped?.actions ? actionDenial({ actions: props.scoped.actions }, 'manage_accounts') : null
)
const accountsDenied = computed(() => !!accountsDenial.value)
const accountsDeniedText = computed(() => denialText(t, accountsDenial.value))

const formRef = ref(null)
const advancedRef = ref(null)
const hostKey = ref(null)
// 待確認的指紋（檢視回應的 mismatches；無觀察紀錄時後端不帶此欄）
const hostKeyMismatches = ref([])

async function loadHostKey() {
  hostKey.value = null
  hostKeyMismatches.value = []
  if (!form.value.id || form.value.protocol !== 'ssh') return
  try {
    const view = await getAssetHostKey(form.value.id)
    hostKey.value = view
    hostKeyMismatches.value = Array.isArray(view?.mismatches) ? view.mismatches : []
  } catch {
    // 404＝尚無記錄，顯示空態即可
  }
}

// 採用觀察到的指紋：先確認（提示向主機管理者核對、會記錄並通知安全人員），成功後重新載入主機金鑰區塊。
// 後端回 NOTFOUND_HOST_KEY_OBSERVATION（清單已變）時以當前語言顯示並重新取檢視
async function adoptKey(row) {
  try {
    await ElMessageBox.confirm(
      t('assets.hostKeyAdoptConfirm'),
      t('assets.hostKeyAdopt'),
      { type: 'warning', confirmButtonText: t('assets.hostKeyAdoptButton') }
    )
  } catch {
    return // 使用者取消
  }
  try {
    await adoptAssetHostKey(form.value.id, row.fingerprint)
    ElMessage.success(t('assets.hostKeyAdoptSuccess'))
  } catch (error) {
    console.error('[AssetEditDrawer] 採用主機金鑰指紋失敗:', error?.response?.status, error?.response?.data?.code)
    ElMessage.error(resolveApiError(error?.response?.data, undefined, t('common.unknownError')))
  }
  await loadHostKey()
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

defineExpose({ formRef, advancedRef, hostKey, hostKeyMismatches, loadHostKey })
</script>

<style scoped>
.accounts-locked {
  opacity: 0.6;
}

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

.host-key-mismatches {
  margin-top: var(--ot-space-sm);
  padding: var(--ot-space-sm);
  border: 1px solid var(--el-color-danger-light-5);
  border-radius: var(--ot-radius-sm, 6px);
  background: var(--el-color-danger-light-9);
}

.host-key-mismatch-head {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-xs);
}

.host-key-mismatch-title {
  font-weight: 600;
  color: var(--el-color-danger);
}

.host-key-mismatch-row + .host-key-mismatch-row {
  margin-top: var(--ot-space-xs);
  padding-top: var(--ot-space-xs);
  border-top: 1px dashed var(--el-border-color);
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
