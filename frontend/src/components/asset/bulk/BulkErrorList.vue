<template>
  <div
    class="error-list"
    data-test="bulk-error-list"
  >
    <div class="head">
      <el-button
        link
        class="toggle"
        data-test="bulk-error-list-toggle"
        @click="open = !open"
      >
        {{ t('assets.bulk.errorList') }}
        <el-icon class="caret">
          <ChevronDown v-if="open" />
          <ChevronRight v-else />
        </el-icon>
      </el-button>
      <el-button
        link
        type="primary"
        data-test="bulk-download-errors"
        @click="emit('download')"
      >
        {{ t('assets.bulk.downloadErrors') }}
      </el-button>
    </div>
    <el-table
      v-if="open"
      :data="items"
      size="small"
      max-height="220"
    >
      <el-table-column
        :label="t('assets.bulk.colLine')"
        width="80"
      >
        <template #default="{ row }">
          <el-button
            link
            type="primary"
            data-test="bulk-error-jump"
            @click="emit('jump', row)"
          >
            {{ row.line }}
          </el-button>
        </template>
      </el-table-column>
      <el-table-column
        :label="t('assets.bulk.colField')"
        prop="fieldLabel"
        width="140"
      />
      <el-table-column
        :label="t('assets.bulk.colValue')"
        width="220"
        show-overflow-tooltip
      >
        <template #default="{ row }">
          <span class="mono">{{ row.value }}</span>
        </template>
      </el-table-column>
      <el-table-column
        :label="t('assets.bulk.colProblem')"
        prop="problem"
        min-width="240"
      />
    </el-table>
  </div>
</template>

<script setup>
/**
 * 錯誤清單（預設展開）：列｜欄位｜填寫內容｜問題。點列號跳到表格中的那一格
 */
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'

defineProps({
  items: { type: Array, default: () => [] },
})

const emit = defineEmits(['jump', 'download'])

const { t } = useI18n()
const open = ref(true)
</script>

<style scoped>
.error-list {
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}

.head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--ot-space-xs);
}

.toggle {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.caret {
  margin-left: 2px;
}

.mono {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
}
</style>
