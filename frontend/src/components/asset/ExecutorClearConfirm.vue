<!--
  ExecutorClearConfirm：清除堡壘機專用帳號的確認框，錨定在「清除」鈕下方。

  焦點起點在「取消」，Enter 不會直接清除；取消或 Esc 關閉後焦點回到「清除」鈕，
  Esc 只關確認框、不連外層抽屜一起關。送出結果交給區塊：成功 emit cleared(account)，
  改密中 emit rotation-blocked，狀態已變（409 或已被清除的 404）emit state-changed；
  其他錯誤就地顯示在確認框內。
-->
<template>
  <el-popover
    :visible="visible"
    :virtual-ref="anchor || undefined"
    virtual-triggering
    placement="bottom-end"
    :width="380"
    :teleported="false"
    @after-leave="onAfterLeave"
  >
    <div
      class="clear-confirm"
      data-test="executor-clear-confirm"
    >
      <strong
        class="confirm-title"
        data-test="executor-clear-title"
      >
        <TriangleAlert
          :size="14"
          aria-hidden="true"
          class="warn-icon"
        />
        {{ t('assetExecutor.clearConfirm.title') }}
      </strong>
      <p data-test="executor-clear-body">
        {{ body }}
      </p>
      <p
        v-if="error"
        class="err"
        data-test="executor-clear-error"
      >
        {{ error }}
      </p>
      <div class="confirm-actions">
        <el-button
          ref="cancelRef"
          size="small"
          data-test="executor-clear-cancel"
          @click="cancel"
        >
          {{ t('assetExecutor.clearConfirm.cancel') }}
        </el-button>
        <el-button
          v-preview-write
          size="small"
          type="danger"
          plain
          :loading="clearing"
          data-test="executor-clear-confirm-btn"
          @click="confirm"
        >
          {{ t('assetExecutor.clearConfirm.confirm') }}
        </el-button>
      </div>
    </div>
  </el-popover>
</template>

<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { TriangleAlert } from 'lucide-vue-next'
import { deleteAssetExecutor } from '@/api/assetExecutor'
import { resolveApiError } from '@/api/error'
import { executorSourceKey } from '@/constants/assetExecutor'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import { useEscapeToClose } from '@/composables/useEscapeToClose'

const props = defineProps({
  visible: { type: Boolean, default: false },
  anchor: { type: Object, default: null },
  assetId: { type: [Number, String], required: true },
  executor: { type: Object, default: () => ({}) },
  expectedAccountId: { type: Number, default: 0 },
})
const emit = defineEmits(['update:visible', 'cleared', 'rotation-blocked', 'state-changed'])

const { t } = useI18n()
const clearing = ref(false)
const error = ref('')
const cancelRef = ref(null)

const body = computed(() => {
  const account = props.executor?.username || ''
  const base = t('assetExecutor.clearConfirm.body', { account })
  const key = executorSourceKey(props.executor)
  const count = props.executor?.credential?.binding_count || 1
  let end
  if (key === 'sharedOutOfScope') end = t('assetExecutor.clearConfirm.endSharedOutOfScope')
  else if (key === 'shared') end = t('assetExecutor.clearConfirm.endShared', { count: Math.max(count - 1, 0) })
  else if (key === 'generate') end = t('assetExecutor.clearConfirm.endGenerate')
  else end = t('assetExecutor.clearConfirm.endSecret')
  return `${base}${end}`
})

// 打開時焦點起點在「取消」，Enter 不會直接確認清除
watch(() => props.visible, async (open) => {
  if (!open) return
  error.value = ''
  await nextTick()
  cancelRef.value?.$el?.focus?.()
})

// 取消或 Esc：焦點回到「清除」鈕。彈出框收起時元件庫會把焦點還給打開前的元素，
// 若那是 body（例如以觸控打開），收起後再補一次
let returnFocus = false
function cancel() {
  returnFocus = true
  emit('update:visible', false)
  props.anchor?.focus?.()
}
function onAfterLeave() {
  const active = document.activeElement
  if (returnFocus && (!active || active === document.body)) props.anchor?.focus?.()
  returnFocus = false
}
useEscapeToClose(() => props.visible, cancel)

async function confirm() {
  clearing.value = true
  error.value = ''
  const account = props.executor?.username || ''
  try {
    await deleteAssetExecutor(props.assetId, props.expectedAccountId)
    emit('update:visible', false)
    emit('cleared', account)
  } catch (err) {
    const code = err?.response?.data?.code
    if (code === 'RULE_CREDENTIAL_ROTATION_ACTIVE') {
      emit('update:visible', false)
      emit('rotation-blocked')
    } else if (code === 'RULE_EXECUTOR_STATE_CHANGED' || err?.response?.status === 404) {
      emit('update:visible', false)
      emit('state-changed')
    } else {
      error.value = resolveApiError(err?.response?.data, err?.response?.status, t('common.unknownError'))
    }
  } finally {
    clearing.value = false
  }
}
</script>

<style scoped>
.clear-confirm p {
  margin: var(--ot-space-xs) 0;
  font-size: var(--ot-font-size-sm);
}

.err {
  color: var(--ot-danger);
}

.confirm-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.warn-icon {
  flex: none;
  color: var(--ot-warning);
}

.confirm-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--ot-space-xs);
}
</style>
