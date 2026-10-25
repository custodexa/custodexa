<template>
  <div
    v-if="selected.length || failure"
    class="batch-actions"
  >
    <!-- 整批沒有執行：沿用整批拒絕的呈現（說明句＋重新整理），不列出任何資產名稱 -->
    <el-alert
      v-if="failure"
      class="batch-failure"
      type="warning"
      show-icon
      :closable="false"
      data-test="batch-error"
    >
      <template #title>
        <span>{{ $t('assets.batchOps.unavailableTitle') }}</span>
      </template>
      <p
        class="batch-failure-body"
        data-test="batch-error-body"
      >
        {{ failureBody }}
      </p>
      <el-button
        size="small"
        data-test="batch-error-refresh"
        @click="onRefresh"
      >
        {{ $t('common.refresh') }}
      </el-button>
    </el-alert>

    <div
      v-if="selected.length"
      class="batch-bar"
      data-test="batch-bar"
    >
      <span
        class="batch-count"
        data-test="batch-count"
      >{{ $t('assets.batchOps.selectedCount', { n: selected.length }) }}</span>
      <el-button
        size="small"
        data-test="batch-move"
        :disabled="!canEdit"
        @click="openMove"
      >
        {{ $t('assets.batchOps.move') }}
      </el-button>
      <el-button
        size="small"
        data-test="batch-tags"
        :disabled="!canEdit"
        @click="openTags"
      >
        {{ $t('assets.batchOps.addTags') }}
      </el-button>
      <el-button
        size="small"
        type="danger"
        plain
        data-test="batch-delete"
        :disabled="!canDelete"
        @click="onDelete"
      >
        {{ $t('assets.batchOps.delete') }}
      </el-button>
      <el-button
        size="small"
        text
        data-test="batch-clear"
        @click="emit('clear')"
      >
        {{ $t('assets.batchOps.clearSelection') }}
      </el-button>
    </div>

    <!-- 搬移：目的節點只列伺服器標示可選者 -->
    <el-dialog
      v-model="moveVisible"
      :title="$t('assets.batchOps.moveTitle', { n: selected.length })"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('assets.batchOps.moveTarget')">
          <el-tree-select
            v-model="moveTarget"
            :data="moveOptions"
            :props="{ label: 'name', children: 'children', disabled: 'disabled' }"
            node-key="id"
            check-strictly
            default-expand-all
            clearable
            :loading="moveLoading"
            :placeholder="$t('assets.batchOps.moveTargetPlaceholder')"
            class="batch-full"
            data-test="move-target"
          />
        </el-form-item>
        <p
          v-if="moveNoTarget"
          class="batch-tip"
          data-test="move-no-target"
        >
          {{ $t('assets.batchOps.moveNoTarget') }}
        </p>
        <p
          v-if="scopedViewer"
          class="batch-tip"
          data-test="move-keeps-out-of-scope"
        >
          {{ $t('assets.batchOps.moveKeepsOutOfScope') }}
        </p>
      </el-form>
      <template #footer>
        <el-button @click="moveVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          :disabled="moveNoTarget || !moveTarget"
          data-test="move-submit"
          @click="submitMove"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 加標籤：沿用資產表單的標籤輸入；範圍化檢視者的候選只含看得到的資產上的標籤 -->
    <el-dialog
      v-model="tagsVisible"
      :title="$t('assets.batchOps.addTagsTitle', { n: selected.length })"
      width="480px"
      :close-on-click-modal="false"
    >
      <el-form
        label-position="top"
        @submit.prevent
      >
        <el-form-item :label="$t('common.tags')">
          <el-select
            v-model="tagList"
            multiple
            filterable
            allow-create
            default-first-option
            clearable
            :placeholder="$t('assets.tagPlaceholder')"
            class="batch-full"
            data-test="batch-tag-select"
            @change="onTagChange"
          >
            <el-option
              v-for="name in tagNames"
              :key="name"
              :label="name"
              :value="name"
            />
            <template
              v-if="scopedViewer"
              #footer
            >
              <div
                class="batch-tip"
                data-test="tag-visible-hint"
              >
                {{ $t('assets.tagVisibleOnlyHint') }}
              </div>
            </template>
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="tagsVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="submitting"
          :disabled="!tagList.length"
          data-test="tags-submit"
          @click="submitTags"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage } from 'element-plus'
import { getAssetGroups, batchMoveAssets, batchAddAssetTags, batchDeleteAssets } from '@/api/assets'
import { buildNodeOptions, selectableIdSet } from '@/utils/scopedAssets'
import { confirmDestructive } from '@/utils/confirm'
import { t } from '@/i18n'

// 批次動作的對話框與結果呈現。可勾選與否、可選的目的節點一律取自伺服器標示，
// 這裡不以節點樹或權限集合計算範圍；提交時伺服器仍自行裁決。
const props = defineProps({
  // 已勾選的資產列
  selected: { type: Array, default: () => [] },
  canEdit: { type: Boolean, default: false },
  canDelete: { type: Boolean, default: false },
  // 範圍化檢視者：顯示範圍外保留說明與標籤候選範圍提示
  scopedViewer: { type: Boolean, default: false },
  // 標籤候選（已是伺服器投影後的字典）
  tagNames: { type: Array, default: () => [] },
})

const emit = defineEmits([
  'clear', // 取消選取
  'refresh', // 只重載列表
  'done', // 成功：重載列表與標籤字典
])

const ids = () => props.selected.map((r) => r.id)
const submitting = ref(false)

// 整批拒絕：{ code, count }
const failure = ref(null)
const failureBody = computed(() => {
  if (!failure.value) return ''
  const { code, count } = failure.value
  return code === 'NOTFOUND_BATCH_ITEMS_UNAVAILABLE'
    ? t('assets.batchOps.unavailableBody', { count })
    : t('assets.batchOps.blockedBody', { count })
})

const BATCH_FAILURE_CODES = [
  'NOTFOUND_BATCH_ITEMS_UNAVAILABLE',
  'RULE_ASSET_BATCH_HAS_OUT_OF_SCOPE_NODES',
]

// 回 true 代表已就地呈現（整批拒絕）；其餘錯誤已由全域 toast 處理
function showFailure(error) {
  const data = error?.response?.data
  if (!data || !BATCH_FAILURE_CODES.includes(data.code)) return false
  failure.value = { code: data.code, count: Number(data.params?.count) || 0 }
  return true
}

function onRefresh() {
  failure.value = null
  emit('refresh')
}

async function run(call, successKey, size, closeDialog) {
  submitting.value = true
  failure.value = null
  try {
    const res = await call()
    ElMessage.success(t(successKey, { n: res?.data?.affected ?? size }))
    closeDialog?.()
    emit('done')
  } catch (error) {
    closeDialog?.()
    if (!showFailure(error)) console.error('批次操作失敗:', error)
  } finally {
    submitting.value = false
  }
}

// 搬移
const moveVisible = ref(false)
const moveLoading = ref(false)
const moveTarget = ref(null)
const moveNodes = ref([])
const moveOptions = computed(() => buildNodeOptions(moveNodes.value))
const moveNoTarget = computed(
  () => !moveLoading.value && selectableIdSet(moveOptions.value).size === 0
)

async function openMove() {
  failure.value = null
  moveTarget.value = null
  moveNodes.value = []
  moveVisible.value = true
  moveLoading.value = true
  try {
    const res = await getAssetGroups({ purpose: 'asset_update' })
    moveNodes.value = res?.data || []
  } catch (error) {
    console.error('載入可搬入節點失敗:', error)
  } finally {
    moveLoading.value = false
  }
}

function submitMove() {
  const n = props.selected.length
  return run(
    () => batchMoveAssets({ asset_ids: ids(), target_node_id: moveTarget.value }),
    'assets.batchOps.moveSuccess',
    n,
    () => {
      moveVisible.value = false
    }
  )
}

// 加標籤
const tagsVisible = ref(false)
const tagList = ref([])

function openTags() {
  failure.value = null
  tagList.value = []
  tagsVisible.value = true
}

// 與資產表單相同：標籤不得含半形逗號
function onTagChange(vals) {
  const last = vals[vals.length - 1]
  if (last && last.includes(',')) {
    tagList.value = vals.filter((v) => v !== last)
    ElMessage.warning(t('assets.tagNoComma'))
  }
}

function submitTags() {
  const n = props.selected.length
  return run(
    () => batchAddAssetTags({ asset_ids: ids(), tags: [...tagList.value] }),
    'assets.batchOps.addTagsSuccess',
    n,
    () => {
      tagsVisible.value = false
    }
  )
}

// 刪除：顯示台數並二次確認
async function onDelete() {
  failure.value = null
  const n = props.selected.length
  try {
    await confirmDestructive(
      t('assets.batchOps.deleteConfirm', { n }),
      t('assets.batchOps.deleteTitle', { n }),
      { confirmButtonText: t('common.deleteConfirmButton'), cancelButtonText: t('common.cancel') }
    )
  } catch {
    return // 使用者取消
  }
  await run(() => batchDeleteAssets({ asset_ids: ids() }), 'assets.batchOps.deleteSuccess', n)
}
</script>

<style scoped>
.batch-actions {
  margin-bottom: 12px;
}
.batch-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border: 1px solid var(--ot-border);
  border-radius: 6px;
  background: var(--ot-bg-elevated);
}
.batch-count {
  margin-right: 8px;
  font-weight: 600;
}
.batch-failure {
  margin-bottom: 8px;
}
.batch-failure-body {
  margin: 4px 0 8px;
}
.batch-full {
  width: 100%;
}
.batch-tip {
  margin: 4px 0 0;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
</style>
