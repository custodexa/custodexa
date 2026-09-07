<template>
  <div
    class="detail-panel"
    data-test="credential-detail"
  >
    <template v-if="credential">
      <div class="panel-head">
        <div class="head-text">
          <div class="title-row">
            <span
              class="title"
              data-test="detail-name"
            >{{ displayName }}</span>
            <el-tag
              size="small"
              :type="isShared ? 'primary' : 'info'"
              data-test="detail-scope"
            >
              {{ t(`enum.credentialScope.${credential.scope}`) }}
            </el-tag>
          </div>
          <span class="meta">{{ t('credentials.createdAt', { date: createdAt }) }}</span>
        </div>
        <div class="head-actions">
          <el-button
            link
            type="primary"
            data-test="detail-edit"
            @click="emit('edit', credential)"
          >
            {{ t('common.edit') }}
          </el-button>
          <el-button
            link
            type="danger"
            :disabled="!!deleteBlockedReason"
            data-test="detail-delete"
            @click="removeCredential"
          >
            {{ t('common.delete') }}
          </el-button>
        </div>
      </div>

      <dl class="kv">
        <dt>{{ t('credentials.detailUsername') }}</dt>
        <dd class="mono">
          {{ credential.username }}
        </dd>
        <dt>{{ t('credentials.detailSecretType') }}</dt>
        <dd>{{ secretTypeLabel }}</dd>
        <dt>{{ t('credentials.detailProtocol') }}</dt>
        <dd>{{ t(`enum.credentialProtocolFamily.${credential.protocol_family}`) }}</dd>
        <dt>{{ t('credentials.detailVersion') }}</dt>
        <dd data-test="detail-version">
          {{ credential.current_version_no
            ? t('credentials.versionNo', { no: credential.current_version_no })
            : t('credentials.versionNone') }}
        </dd>
        <dt>{{ t('credentials.detailRotation') }}</dt>
        <dd>
          <el-tag
            size="small"
            :type="aggregateTagType"
            data-test="detail-aggregate"
          >
            {{ aggregateLabel }}
          </el-tag>
        </dd>
        <dt>{{ t('credentials.detailNote') }}</dt>
        <dd>{{ credential.note || t('credentials.empty') }}</dd>
      </dl>

      <div class="actions">
        <el-button
          type="primary"
          :disabled="!!rotateBlockedReason"
          data-test="action-rotate"
          @click="rotateVisible = true"
        >
          {{ t('credentials.rotate') }}
        </el-button>
        <el-button
          :disabled="!!bindBlockedReason"
          data-test="action-bind"
          @click="bindVisible = true"
        >
          {{ t('credentials.bind') }}
        </el-button>
        <el-button
          v-if="isShared"
          :disabled="!!toDedicatedBlockedReason"
          data-test="action-to-dedicated"
          @click="convertToDedicated"
        >
          {{ t('credentials.toDedicated') }}
        </el-button>
        <!-- 專用轉共用是「別台也要用同一組」的唯一入口：新增資產時的說明句就指到這裡，
             沒有這顆按鈕那句話等於指向一個做不到那件事的畫面 -->
        <el-button
          v-else
          :disabled="!!toSharedBlockedReason"
          data-test="action-to-shared"
          @click="openToShared"
        >
          {{ t('credentials.toShared') }}
        </el-button>
      </div>

      <div class="reasons">
        <p
          v-for="reason in blockedReasons"
          :key="reason.key"
          class="reason"
          :data-test="`blocked-${reason.key}`"
          :data-actions="reason.actions.join(' ')"
        >
          {{ reason.text }}
        </p>
      </div>

      <CredentialRotationProgress
        v-if="activeRotationId"
        :key="activeRotationId"
        :credential-id="credential.id"
        :rotation-id="activeRotationId"
        :current-version-no="credential.current_version_no"
        :bindings="bindings"
        @changed="emit('changed')"
        @finished="onRotationFinished"
      />

      <CredentialBindingList
        :bindings="bindings"
        :scope="credential.scope"
        :rotation-active="rotationActive"
        @detach="openDetach"
        @unbind="unbind"
      />

      <CredentialRotateDialog
        v-model="rotateVisible"
        :credential-id="credential.id"
        :credential-name="displayName"
        :binding-count="bindings.length"
        @submitted="onRotationStarted"
      />

      <CredentialBindDialog
        v-model="bindVisible"
        :credential-id="credential.id"
        :protocol-family="credential.protocol_family"
        @bound="emit('changed')"
      />

      <!-- 轉共用時名稱必填（伺服端同判準）：共用憑證在清單上要認得出來，
           沿用專用的計算名「資產名 / 帳號名」會讓它掛到第二台之後就對不上 -->
      <el-dialog
        v-model="toSharedVisible"
        :title="t('credentials.toSharedTitle')"
        width="480px"
        :close-on-click-modal="false"
        data-test="to-shared-dialog"
      >
        <p class="to-shared-hint">
          {{ t('credentials.toSharedHint') }}
        </p>
        <el-form label-position="top">
          <el-form-item :label="t('credentials.form.name')">
            <el-input
              v-model="toSharedName"
              :placeholder="t('credentials.form.namePlaceholder')"
              data-test="to-shared-name"
            />
          </el-form-item>
        </el-form>
        <p
          v-if="toSharedError"
          class="to-shared-error"
          data-test="to-shared-error"
        >
          {{ toSharedError }}
        </p>
        <template #footer>
          <el-button
            data-test="to-shared-cancel"
            @click="toSharedVisible = false"
          >
            {{ t('common.cancel') }}
          </el-button>
          <el-button
            type="primary"
            :loading="toSharedSubmitting"
            data-test="to-shared-submit"
            @click="convertToShared"
          >
            {{ t('common.confirm') }}
          </el-button>
        </template>
      </el-dialog>

      <CredentialDetachDialog
        v-model="detachVisible"
        :credential-id="credential.id"
        :credential-name="displayName"
        :binding-count="bindings.length"
        :account-id="detachTarget?.account_id || 0"
        :asset-name="detachTarget?.asset_name || ''"
        :username="credential.username"
        :secret-type="credential.secret_type"
        @detached="emit('changed')"
      />
    </template>

    <EmptyState
      v-else
      :title="t('credentials.pickTitle')"
      :hint="t('credentials.pickHint')"
      data-test="detail-placeholder"
    />
  </div>
</template>

<script setup>
/**
 * 憑證詳情（設計稿 01 右半）。
 *
 * 動作區的每一顆按鈕都可能因為憑證當下的狀態而不能按。**不靜默禁用**：
 * 不可執行時在按鈕下方寫出原因與下一步（先卸載、等這一輪跑完、到資產上處理），
 * 否則使用者面對的是一排灰掉的按鈕與零個線索。
 */
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import EmptyState from '@/components/EmptyState.vue'
import CredentialBindingList from './CredentialBindingList.vue'
import CredentialRotationProgress from './CredentialRotationProgress.vue'
import CredentialRotateDialog from './CredentialRotateDialog.vue'
import CredentialDetachDialog from './CredentialDetachDialog.vue'
import CredentialBindDialog from './CredentialBindDialog.vue'
import {
  deleteCredential,
  unbindCredential,
  convertCredentialScope,
} from '@/api/credentials'
import { confirmDestructive } from '@/utils/confirm'
import { formatDateTime } from '@/utils/format'
import { AGGREGATE_STATE_TAG_TYPE, credentialDisplayName } from '@/constants/credentials'

const props = defineProps({
  credential: { type: Object, default: null },
  aggregateState: { type: String, default: '' },
})

const emit = defineEmits(['edit', 'changed', 'deleted'])

const { t } = useI18n()

const rotateVisible = ref(false)
const bindVisible = ref(false)
const detachVisible = ref(false)
const detachTarget = ref(null)
const toSharedVisible = ref(false)
const toSharedName = ref('')
const toSharedError = ref('')
const toSharedSubmitting = ref(false)
// 本次操作發起的輪替識別：詳情端點回的是聚合態，不含輪替識別
const startedRotationId = ref(null)

const bindings = computed(() => props.credential?.bindings || [])
const isShared = computed(() => props.credential?.scope === 'shared')
const rotationActive = computed(() => !!props.credential?.rotation_active)
const createdAt = computed(() => formatDateTime(props.credential?.created_at))
const displayName = computed(() => credentialDisplayName(props.credential))

const activeRotationId = computed(() =>
  props.credential?.active_rotation_id || startedRotationId.value || null)

const aggregateLabel = computed(() => (props.aggregateState
  ? t(`enum.credentialAggregateState.${props.aggregateState}`)
  : t('credentials.stateIdle')))
const aggregateTagType = computed(() =>
  AGGREGATE_STATE_TAG_TYPE[props.aggregateState] || 'info')

const secretTypeLabel = computed(() => {
  const cred = props.credential
  if (!cred) return ''
  if (!cred.secret_type) return t('credentials.empty')
  if (cred.protocol_family === 'k8s' && cred.secret_type === 'password') {
    return t('credentials.secretTypeToken')
  }
  return t(`enum.credentialSecretType.${cred.secret_type}`)
})

const rotateBlockedReason = computed(() => {
  if (rotationActive.value) return t('credentials.blockedRotationActive')
  if (!isShared.value) return t('credentials.blockedNotShared')
  if (!bindings.value.length) return t('credentials.blockedNoBinding')
  return ''
})

const bindBlockedReason = computed(() => {
  if (rotationActive.value) return t('credentials.blockedRotationActive')
  if (!isShared.value) return t('credentials.blockedDedicatedScope')
  return ''
})

const toDedicatedBlockedReason = computed(() => {
  if (!isShared.value) return ''
  if (rotationActive.value) return t('credentials.blockedRotationActive')
  if (bindings.value.length !== 1) return t('credentials.blockedToDedicatedMulti')
  return ''
})

// 轉共用與轉專用同一支端點、同一道輪替閘門（ConvertScope 內 assertNoActiveRotation）
const toSharedBlockedReason = computed(() => {
  if (isShared.value) return ''
  if (rotationActive.value) return t('credentials.blockedRotationActive')
  return ''
})

const deleteBlockedReason = computed(() => {
  if (rotationActive.value) return t('credentials.blockedRotationActive')
  if (!isShared.value) return t('credentials.blockedDedicatedScope')
  if (bindings.value.length) {
    return t('credentials.blockedInUse', { count: bindings.value.length })
  }
  return ''
})

// 同一句話不重複四遍：輪替進行中時四個動作被同一個理由擋住，寫四行只是噪音。
// 每一句仍記得自己涵蓋哪些動作（data-actions），所以「哪個動作為什麼不能按」
// 仍然答得出來，只是答案共用一行
const blockedReasons = computed(() => {
  const entries = [
    { key: 'rotate', text: rotateBlockedReason.value },
    { key: 'bind', text: bindBlockedReason.value },
    { key: 'to-dedicated', text: toDedicatedBlockedReason.value },
    { key: 'to-shared', text: toSharedBlockedReason.value },
    { key: 'delete', text: deleteBlockedReason.value },
  ].filter((r) => r.text)
  const grouped = []
  for (const entry of entries) {
    const same = grouped.find((g) => g.text === entry.text)
    if (same) same.actions.push(entry.key)
    else grouped.push({ key: entry.key, text: entry.text, actions: [entry.key] })
  }
  return grouped
})

// 換一筆憑證即丟掉上一筆的輪替識別：那個號碼只對它自己的憑證有意義
watch(() => props.credential?.id, () => {
  startedRotationId.value = null
})

function onRotationStarted(rotation) {
  if (rotation?.id) startedRotationId.value = rotation.id
  emit('changed')
}

function onRotationFinished() {
  startedRotationId.value = null
  emit('changed')
}

function openDetach(binding) {
  detachTarget.value = binding
  detachVisible.value = true
}

async function unbind(binding) {
  try {
    await confirmDestructive(
      t('credentials.unbindMessage', {
        asset: binding.asset_name || t('common.assetRef', { id: binding.asset_id }),
      }),
      t('credentials.unbindTitle'),
      { confirmButtonText: t('credentials.unbindConfirm') },
    )
  } catch {
    return
  }
  try {
    await unbindCredential(props.credential.id, binding.account_id)
    ElMessage.success(t('credentials.unbindDone'))
    emit('changed')
  } catch (err) {
    console.error('[CredentialDetail] 卸載失敗:', err)
  }
}

async function removeCredential() {
  try {
    await confirmDestructive(
      t('credentials.deleteMessage', { name: displayName.value }),
      t('common.deleteConfirmTitle'),
      { confirmButtonText: t('common.deleteConfirmButton') },
    )
  } catch {
    return
  }
  try {
    await deleteCredential(props.credential.id)
    ElMessage.success(t('credentials.deleteDone'))
    emit('deleted', props.credential.id)
  } catch (err) {
    console.error('[CredentialDetail] 刪除憑證失敗:', err)
  }
}

async function convertToDedicated() {
  const [binding] = bindings.value
  try {
    await confirmDestructive(
      t('credentials.toDedicatedMessage', {
        name: displayName.value,
        asset: binding?.asset_name || t('common.assetRef', { id: binding?.asset_id }),
      }),
      t('credentials.toDedicatedTitle'),
      { confirmButtonText: t('credentials.toDedicated') },
    )
  } catch {
    return
  }
  try {
    await convertCredentialScope(props.credential.id, { scope: 'dedicated', name: '' })
    ElMessage.success(t('credentials.toDedicatedDone'))
    emit('changed')
  } catch (err) {
    console.error('[CredentialDetail] 轉為專用失敗:', err)
  }
}

function openToShared() {
  toSharedName.value = ''
  toSharedError.value = ''
  toSharedVisible.value = true
}

// 名稱必填由前端先擋一次：伺服端會回 RULE_CREDENTIAL_SHARED_REQUIRES_NAME，
// 但那是一次來回之後才看得到，而這裡當場說得出來
async function convertToShared() {
  const name = toSharedName.value.trim()
  if (!name) {
    toSharedError.value = t('credentials.form.nameRequired')
    return
  }
  toSharedError.value = ''
  toSharedSubmitting.value = true
  try {
    await convertCredentialScope(props.credential.id, { scope: 'shared', name })
    ElMessage.success(t('credentials.toSharedDone'))
    toSharedVisible.value = false
    emit('changed')
  } catch (err) {
    console.error('[CredentialDetail] 轉為共用失敗:', err?.response?.status, err?.response?.data?.code)
  } finally {
    toSharedSubmitting.value = false
  }
}

defineExpose({
  rotateVisible, bindVisible, detachVisible, detachTarget, displayName,
  unbind, removeCredential, convertToDedicated, blockedReasons,
  toSharedVisible, toSharedName, toSharedError, openToShared, convertToShared,
})
</script>

<style scoped>
.detail-panel {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
  min-height: 0;
  overflow-y: auto;
}

.panel-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--ot-space-sm);
}

.head-text {
  min-width: 0;
}

.title-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}

.title {
  font-size: var(--ot-font-size-lg);
  font-weight: 600;
  color: var(--ot-text-primary);
}

.meta {
  display: block;
  margin-top: var(--ot-space-xs);
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}

.head-actions {
  display: flex;
  gap: var(--ot-space-sm);
  flex-shrink: 0;
}

.kv {
  display: grid;
  grid-template-columns: 88px minmax(0, 1fr);
  gap: var(--ot-space-sm) var(--ot-space-md);
  margin: 0;
  font-size: var(--ot-font-size-sm);
}

.kv dt {
  color: var(--ot-text-secondary);
}

.kv dd {
  margin: 0;
  color: var(--ot-text-primary);
  overflow-wrap: anywhere;
}

.mono {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
}

.actions {
  display: flex;
  gap: var(--ot-space-sm);
}

.actions .el-button {
  flex: 1;
}

.reasons {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}

.reason {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
  line-height: 1.5;
}

.to-shared-hint {
  margin: 0 0 var(--ot-space-md);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}

.to-shared-error {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--el-color-danger);
}
</style>
