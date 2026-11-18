<template>
  <el-tag
    size="small"
    :type="isWrite ? 'warning' : 'info'"
    :class="['atlv', isWrite ? 'is-write' : 'ot-tag-neutral']"
    :data-level="normalized"
    data-test="level-tag"
  >
    <component
      :is="isWrite ? PenLine : Eye"
      :size="11"
      aria-hidden="true"
      class="atlv__icon"
    />{{ levelLabel(normalized) }}
  </el-tag>
</template>

<script setup>
import { computed } from 'vue'
import { Eye, PenLine } from 'lucide-vue-next'
import { LEVEL_READ_WRITE, levelLabel, normalizeLevel } from '@/constants/apiTokens'

/**
 * 單一授權角色在這把 API token 上的層級小標：唯讀為中性灰、讀寫為琥珀。
 * 顏色不是唯一線索，圖示（看／寫）與文字一起出現。
 */
const props = defineProps({
  level: { type: String, default: '' },
})
const normalized = computed(() => normalizeLevel(props.level))
const isWrite = computed(() => normalized.value === LEVEL_READ_WRITE)
</script>

<style scoped>
.atlv {
  gap: 3px;
}
.atlv__icon {
  margin-right: 3px;
  vertical-align: -1px;
}
</style>
