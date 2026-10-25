<!--
  ScopedNodeCell：資產列表「所屬節點」欄的內容。

  範圍內歸屬照原樣列出路徑；範圍外歸屬只顯示計數（「＋N 範圍外」），
  伺服器不回範圍外節點的名稱、路徑或識別碼，這裡也不推算。
-->
<template>
  <span class="scoped-node-cell">
    <el-tooltip
      v-if="paths.length"
      :content="joined"
      placement="top"
    >
      <span
        class="node-paths"
        data-test="scoped-node-paths"
      >{{ joined }}</span>
    </el-tooltip>
    <span
      v-else-if="!count"
      class="node-paths-empty"
    >{{ t('assets.ungrouped') }}</span>
    <el-tag
      v-if="count"
      size="small"
      class="ot-tag-neutral out-of-scope-badge"
      data-test="out-of-scope-badge"
    >
      {{ t('assets.scopedOutOfScopeBadge', { n: count }) }}
    </el-tag>
  </span>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { outOfScopeCount } from '@/utils/scopedAssets'

const props = defineProps({
  row: { type: Object, required: true },
})

const { t } = useI18n()
const paths = computed(() => props.row.node_paths || [])
const joined = computed(() => paths.value.join(t('common.listSeparator')))
const count = computed(() => outOfScopeCount(props.row))
</script>

<style scoped>
.scoped-node-cell {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: var(--ot-space-xs);
}
.node-paths {
  color: var(--ot-text-primary);
}
.node-paths-empty {
  color: var(--ot-text-secondary);
}
</style>
