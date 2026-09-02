<template>
  <!-- 給連線者的使用前說明：只列會影響他這次操作的事（結果上限、成功不等於已提交、
       取消與切庫、允許清單、留痕）。稽核與管理視角的邊界不列在這裡，那些留在規格、
       API 文件與管理者可見的面。折疊呈現＝不擋日常操作，但任何時候點得開。
       慣例沿存取管控頁的邊界說明面板 -->
  <el-collapse class="console-boundary">
    <el-collapse-item :title="t('dbConsole.boundary.title')">
      <ol class="boundary-list">
        <li
          v-for="i in BOUNDARY_ITEM_COUNT"
          :key="i"
        >
          {{ t(`dbConsole.boundary.item${i}`) }}
        </li>
      </ol>
    </el-collapse-item>
  </el-collapse>
</template>

<script setup>
import { t } from '@/i18n'

// 連線者版五條；增刪條目時三語 key 必須同步
const BOUNDARY_ITEM_COUNT = 5
</script>

<style scoped>
.console-boundary {
  flex: none;
  border-top: none;
  border-bottom: 1px solid var(--el-border-color-lighter);
}

.boundary-list {
  margin: 0;
  padding-left: var(--ot-space-lg);
  font-size: var(--ot-font-size-sm);
  line-height: 1.7;
  color: var(--ot-text-secondary);
}

.boundary-list li + li {
  margin-top: var(--ot-space-xs);
}
</style>
