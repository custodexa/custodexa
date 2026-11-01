<template>
  <!-- 下拉選單項目的預覽停用包裝：el-dropdown-item 不是單一根節點，指令掛在它身上不會生效。
       預覽中以 disabled 讓項目點不到，內層填滿整列的 span 帶指令，滑過時顯示同一張說明卡 -->
  <el-dropdown-item
    v-bind="$attrs"
    :disabled="disabled || previewActive"
  >
    <span
      v-preview-write:[kind]
      class="preview-menu-fill"
    >
      <slot />
    </span>
  </el-dropdown-item>
</template>

<script setup>
import { previewActive } from '@/utils/previewOverlay'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'

defineOptions({ inheritAttrs: false })
defineProps({
  disabled: { type: Boolean, default: false },
  kind: { type: String, default: undefined },
})
</script>

<style scoped>
.preview-menu-fill {
  display: block;
  flex: 1;
  min-width: 0;
  margin: -5px -16px;
  padding: 5px 16px;
}
</style>
