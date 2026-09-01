<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('assets.tagManager')"
    width="580px"
    @update:model-value="$emit('update:modelValue', $event)"
  >
    <p class="tag-manager-hint">
      {{ $t('tagManager.hint') }}
    </p>
    <el-input
      v-model="search"
      :placeholder="$t('tagManager.searchPlaceholder')"
      clearable
      size="small"
      class="tag-search"
    >
      <template #prefix>
        <el-icon><Search /></el-icon>
      </template>
    </el-input>
    <el-table
      :data="filteredTags"
      size="small"
      max-height="360"
    >
      <el-table-column
        prop="name"
        :label="$t('common.tags')"
        min-width="200"
      />
      <el-table-column
        prop="count"
        :label="$t('tagManager.assetCountColumn')"
        width="110"
      />
      <el-table-column
        :label="$t('common.actions')"
        width="140"
        fixed="right"
      >
        <template #default="{ row }">
          <el-button
            size="small"
            text
            type="primary"
            @click="openRename(row)"
          >
            {{ $t('common.rename') }}
          </el-button>
          <el-button
            size="small"
            text
            type="danger"
            @click="handleDelete(row)"
          >
            {{ $t('common.delete') }}
          </el-button>
        </template>
      </el-table-column>
      <template #empty>
        <el-empty
          :description="$t('tagManager.empty')"
          :image-size="60"
        />
      </template>
    </el-table>

    <!-- 改名/合併內層 dialog：受影響數前置顯示＋二次確認 -->
    <el-dialog
      v-model="renameVisible"
      :title="$t('tagManager.renameTitle')"
      width="420px"
      append-to-body
    >
      <p>{{ $t('tagManager.renamePrompt', { name: renameFrom?.name || '' }) }}</p>
      <el-input
        v-model="renameTo"
        :placeholder="$t('tagManager.newNamePlaceholder')"
        maxlength="64"
      />
      <p class="affect-hint">
        {{ $t('tagManager.affectedCount', { n: renameFrom?.count ?? '' }) }}
        <!-- 合併提示帶 <strong> 標記：走 i18n-t 具名插槽插值，三語各自掌控語序 -->
        <i18n-t
          v-if="mergeTarget"
          scope="global"
          keypath="tagManager.mergeNotice"
          tag="span"
        >
          <template #name>
            {{ mergeTarget }}
          </template>
          <template #merge>
            <strong>{{ $t('tagManager.mergeWord') }}</strong>
          </template>
        </i18n-t>
      </p>
      <template #footer>
        <el-button @click="renameVisible = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :loading="working"
          @click="confirmRename"
        >
          {{ mergeTarget ? $t('tagManager.confirmMerge') : $t('tagManager.confirmRename') }}
        </el-button>
      </template>
    </el-dialog>
  </el-dialog>
</template>

<script setup>
import { ref, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from 'lucide-vue-next'
import { renameAssetTag, deleteAssetTag } from '@/api/assets'
import { t } from '@/i18n'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // [{ name, count }]，來源為標籤清單端點（父層載入共用）
  tags: { type: Array, default: () => [] },
})
const emit = defineEmits(['update:modelValue', 'changed'])

const search = ref('')
const working = ref(false)
const renameVisible = ref(false)
const renameFrom = ref(null)
const renameTo = ref('')

const filteredTags = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return props.tags
  return props.tags.filter((t) => t.name.toLowerCase().includes(q))
})

// 目標 canonical 相等於既有標籤（且非自身）＝合併
const mergeTarget = computed(() => {
  const to = renameTo.value.trim()
  if (!to || !renameFrom.value) return ''
  const hit = props.tags.find(
    (t) =>
      t.name.toLowerCase() === to.toLowerCase() &&
      t.name.toLowerCase() !== renameFrom.value.name.toLowerCase()
  )
  return hit ? hit.name : ''
})

const openRename = (row) => {
  renameFrom.value = row
  renameTo.value = ''
  renameVisible.value = true
}

const confirmRename = async () => {
  const to = renameTo.value.trim()
  if (!to) {
    ElMessage.warning(t('tagManager.newNameRequired'))
    return
  }
  if (to.includes(',')) {
    ElMessage.warning(t('assets.tagNoComma'))
    return
  }
  working.value = true
  try {
    const res = await renameAssetTag(renameFrom.value.name, to)
    ElMessage.success(t('tagManager.renamed', { n: res.affected }))
    renameVisible.value = false
    emit('changed')
  } catch (error) {
    console.error('標籤改名失敗:', error)
  } finally {
    working.value = false
  }
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(
      t('tagManager.deleteConfirm', { count: row.count, name: row.name }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
        type: 'warning',
      }
    )
  } catch {
    return
  }
  try {
    const res = await deleteAssetTag(row.name)
    ElMessage.success(t('tagManager.deleted', { n: res.affected }))
    emit('changed')
  } catch (error) {
    console.error('標籤刪除失敗:', error)
  }
}

defineExpose({ filteredTags, mergeTarget, openRename, confirmRename, handleDelete, renameVisible, renameTo, renameFrom, search })
</script>

<style scoped>
.tag-manager-hint {
  margin: 0 0 12px;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}

.tag-search {
  margin-bottom: 12px;
}

.affect-hint {
  margin-top: 12px;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
</style>
