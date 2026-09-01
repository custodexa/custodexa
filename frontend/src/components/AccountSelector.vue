<!--
  AccountSelector：連線時選資產帳號。
  沿 K8sPodSelector 的 openTab→selector→createTab 流程；帳號清單由呼叫端傳入
  （Workspace 為了判斷「是否需要打擾」本就得先取清單，元件內再取一次等於雙倍請求）。
  清單已由後端依有效授權帳號範圍過濾——前端不再自行推斷可見性。
-->
<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('accountSelector.title', { name: assetName })"
    width="560px"
    @update:model-value="(v) => emit('update:modelValue', v)"
    @open="onOpen"
  >
    <p class="acct-sel__hint-top">
      {{ $t('accountSelector.hint') }}
    </p>
    <el-table
      ref="tableRef"
      :data="accounts"
      height="280"
      size="small"
      highlight-current-row
      @current-change="onSelect"
      @row-dblclick="onRowDblClick"
    >
      <el-table-column
        :label="$t('assetAccounts.colUsername')"
        min-width="180"
        show-overflow-tooltip
      >
        <template #default="{ row }">
          <el-icon
            v-if="row.is_default"
            class="acct-sel__star"
          >
            <Star fill="currentColor" />
          </el-icon>
          <span class="acct-sel__name">{{ row.username }}</span>
          <el-tag
            v-if="row.privileged"
            size="small"
            type="danger"
            class="acct-sel__tag"
          >
            {{ $t('assetAccounts.privileged') }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('assetAccounts.colCredential')"
        width="120"
      >
        <template #default="{ row }">
          <el-tag
            :type="accountCredentialTagType(row)"
            size="small"
          >
            {{ accountCredentialLabel(row) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        prop="note"
        :label="$t('assetAccounts.colNote')"
        min-width="140"
        show-overflow-tooltip
      />
      <template #empty>
        <span class="acct-sel__empty">{{ $t('accountSelector.empty') }}</span>
      </template>
    </el-table>

    <template #footer>
      <span class="acct-sel__hint">
        {{ selected ? $t('accountSelector.willConnect', { username: selected.username }) : $t('accountSelector.pleaseSelect') }}
      </span>
      <el-button @click="emit('update:modelValue', false)">
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :disabled="!selected"
        @click="confirm"
      >
        {{ $t('common.connect') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, watch, nextTick } from 'vue'
import { Star } from 'lucide-vue-next'
import { accountCredentialLabel, accountCredentialTagType } from '@/constants/assetAccounts'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  assetName: { type: String, default: '' },
  // 已依有效授權帳號範圍過濾的帳號清單（後端 GET /assets/:id/accounts）
  accounts: { type: Array, default: () => [] },
})
const emit = defineEmits(['update:modelValue', 'confirm'])

const selected = ref(null)
const tableRef = ref(null)

// 預選預設帳號（無預設則取首筆）。@open 在 el-dialog stub 環境不必然觸發，
// 故 modelValue 轉真時也走同一條預選路徑。
// **同步套用 current-row**（UI 走查）：只設 selected 而不設 current-row，
// 表格看起來一列都沒選中，使用者只能靠頁尾「將以 X 連線」文字推斷——
// 預選是否生效必須在主視覺上看得見
async function preselect() {
  const row = props.accounts.find((a) => a.is_default) || props.accounts[0] || null
  selected.value = row
  await nextTick()
  tableRef.value?.setCurrentRow?.(row)
}

function onOpen() {
  preselect()
}

watch(
  () => props.modelValue,
  (visible) => {
    if (visible) preselect()
  },
  { immediate: true }
)

function onSelect(row) {
  // el-table 的 current-change 在清空選取時給 null——保留既有選取避免按鈕跳成 disabled
  if (row) selected.value = row
}

function onRowDblClick(row) {
  onSelect(row)
  confirm()
}

function confirm() {
  if (!selected.value) return
  emit('confirm', { id: selected.value.id, username: selected.value.username })
  emit('update:modelValue', false)
}
</script>

<style scoped>
.acct-sel__hint-top {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
.acct-sel__star {
  color: var(--ot-warning, #d9a93e);
  margin-right: 4px;
  vertical-align: -2px;
}
.acct-sel__name {
  font-family: var(--ot-font-mono, monospace);
}
.acct-sel__tag {
  margin-left: 6px;
}
.acct-sel__empty {
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.acct-sel__hint {
  margin-right: auto;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}
:deep(.el-dialog__footer) {
  display: flex;
  align-items: center;
}
</style>
