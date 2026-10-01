<template>
  <el-table
    :data="rows"
    size="small"
    class="field-help"
    data-test="bulk-field-help"
  >
    <el-table-column
      :label="t('assets.bulk.helpColumn')"
      width="140"
    >
      <template #default="{ row }">
        <span class="mono">{{ row.field }}</span>
      </template>
    </el-table-column>
    <el-table-column
      :label="t('assets.bulk.helpRequired')"
      width="96"
    >
      <template #default="{ row }">
        {{ row.required }}
      </template>
    </el-table-column>
    <el-table-column
      :label="t('assets.bulk.helpDesc')"
      min-width="320"
    >
      <template #default="{ row }">
        {{ t(`assets.bulk.fields.${row.field}.desc`) }}
      </template>
    </el-table-column>
    <el-table-column
      :label="t('assets.bulk.helpExample')"
      width="150"
    >
      <template #default="{ row }">
        <span class="mono">{{ t(`assets.bulk.fields.${row.field}.example`) }}</span>
      </template>
    </el-table-column>
  </el-table>
</template>

<script setup>
/**
 * 批次新增的欄位說明表（13 欄；內容即 design §2.2）。
 * 上傳 CSV 模式展開於範本說明下方，線上填寫模式由右上「欄位說明」以浮層開啟
 */
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { BULK_FIELDS, REQUIRED_FIELDS } from '@/utils/assetBulk'

const { t } = useI18n()

const requiredText = (field) => {
  if (REQUIRED_FIELDS.includes(field)) return t('assets.bulk.requiredYes')
  if (field === 'k8s_namespace') return t('assets.bulk.requiredK8s')
  return t('assets.bulk.requiredNo')
}

const rows = computed(() => BULK_FIELDS.map((field) => ({ field, required: requiredText(field) })))
</script>

<style scoped>
.mono {
  font-family: var(--ot-font-mono);
  font-size: var(--ot-font-size-xs);
}
</style>
