<template>
  <el-popover
    v-model:visible="visible"
    trigger="click"
    placement="bottom-end"
    :width="320"
    :teleported="false"
    :show-arrow="false"
    :offset="6"
    popper-class="inv-confirm-popper"
  >
    <template #reference>
      <el-button
        ref="startBtn"
        v-preview-write
        type="primary"
        :disabled="disabled"
        :loading="loading"
        data-test="inv-start"
      >
        {{ label }}
      </el-button>
    </template>
    <div
      ref="panel"
      class="inv-confirm"
      role="dialog"
      tabindex="-1"
      :aria-labelledby="titleId"
      data-test="inv-confirm"
      @keydown.esc.stop.prevent="cancel"
    >
      <h4
        :id="titleId"
        class="inv-confirm-title"
        data-test="inv-confirm-title"
      >
        <Info
          :size="14"
          aria-hidden="true"
          class="inv-confirm-icon"
          data-test="inv-confirm-title-icon"
        />
        <span>{{ title }}</span>
      </h4>
      <p data-test="inv-confirm-body">
        {{ $t('hostInventory.confirm.body') }}
      </p>
      <p
        v-if="noExecutor"
        class="inv-confirm-warn"
        data-test="inv-confirm-no-executor"
      >
        <Info
          :size="14"
          aria-hidden="true"
          class="inv-confirm-warn-icon"
          data-test="inv-confirm-warn-icon"
        />
        <span>{{ $t('hostInventory.confirm.noExecutor') }}</span>
      </p>
      <p
        v-if="fingerprint === 'none'"
        class="inv-confirm-note"
        data-test="inv-fingerprint-line"
      >
        {{ $t('hostInventory.confirm.fingerprint') }}
      </p>
      <p
        v-else-if="fingerprint === 'unknown'"
        class="inv-confirm-note"
        data-test="inv-fingerprint-unknown"
      >
        {{ $t('hostInventory.confirm.fingerprintUnknown') }}
      </p>
      <div class="inv-confirm-actions">
        <el-button
          size="small"
          data-test="inv-confirm-cancel"
          @click="cancel"
        >
          {{ $t('hostInventory.confirm.cancel') }}
        </el-button>
        <el-button
          size="small"
          type="primary"
          data-test="inv-confirm-ok"
          @click="ok"
        >
          {{ $t('hostInventory.confirm.ok') }}
        </el-button>
      </div>
    </div>
  </el-popover>
</template>

<script setup>
import { Info } from 'lucide-vue-next'
import { nextTick, ref, watch } from 'vue'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'

// 盤點發起前的確認框：錨定在發起鈕下方，內文與提醒由這裡自繪
// （Element Plus 的 popconfirm 不渲染預設插槽，內文會整段消失）
defineProps({
  title: { type: String, default: '' },
  label: { type: String, default: '' },
  disabled: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
  // 這台沒有堡壘機專用帳號時多一句提醒
  noExecutor: { type: Boolean, default: false },
  // 主機金鑰記錄狀態：'none' 首次登入會記下指紋；'unknown' 讀不到記錄；其他不顯示
  fingerprint: { type: String, default: '' },
})
const emit = defineEmits(['confirm'])

let seq = 0
const titleId = `inv-confirm-title-${++seq}-${Math.random().toString(36).slice(2, 7)}`
const visible = ref(false)
const startBtn = ref(null)
const panel = ref(null)

// 開啟後焦點先進確認框；關閉（取消、Esc、點外面）後回到原按鈕
watch(visible, async (open, was) => {
  await nextTick()
  if (open) panel.value?.focus()
  else if (was) (startBtn.value?.ref || startBtn.value?.$el)?.focus?.()
})

function cancel() {
  visible.value = false
}
function ok() {
  visible.value = false
  emit('confirm')
}
</script>

<style scoped>
.inv-confirm {
  outline: none;
}

.inv-confirm-title {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 0 0 8px;
  font-size: 14px;
  font-weight: 600;
  color: var(--ot-text-primary);
}

.inv-confirm p {
  margin: 0 0 6px;
  font-size: 13px;
  line-height: 1.6;
  text-align: left;
}

.inv-confirm .inv-confirm-note {
  color: var(--ot-text-secondary);
}

.inv-confirm .inv-confirm-warn {
  color: var(--ot-warning);
}

.inv-confirm-icon {
  flex: none;
  color: var(--ot-primary);
}

.inv-confirm .inv-confirm-warn {
  display: flex;
  align-items: flex-start;
  gap: 6px;
}

.inv-confirm-warn-icon {
  flex: none;
  margin-top: 4px;
}

.inv-confirm-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 10px;
}
</style>
