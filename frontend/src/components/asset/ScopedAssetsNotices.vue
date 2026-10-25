<!--
  ScopedAssetsNotices：範圍化資產頁頂部的狀態提示（依 management_scope 與列表 total）。

  - 連線授權資產仍在、管理範圍沒有有效節點：提示管理範圍為空，列表照常；
  - 部分管理節點已不存在：只提示個數，不顯示名稱，其餘照常。
  無有效節點且無資產的空態由表格的空狀態呈現（見 Assets.vue），這裡不重複。
-->
<template>
  <div
    v-if="connectionOnly || inactive"
    class="scoped-notices"
  >
    <el-alert
      v-if="connectionOnly"
      type="info"
      :closable="false"
      show-icon
      data-test="scoped-connection-only"
      :title="t('assets.scopedConnectionOnlyNotice')"
    />
    <el-alert
      v-if="inactive"
      type="warning"
      :closable="false"
      show-icon
      data-test="scoped-inactive"
      :title="t('assets.scopedInactiveNotice', { n: inactive })"
    />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { scopeState, inactiveNodeCount } from '@/utils/scopedAssets'

const props = defineProps({
  scope: { type: Object, default: null },
  total: { type: Number, default: 0 },
})

const { t } = useI18n()
const connectionOnly = computed(() => scopeState(props.scope, props.total) === 'connection_only')
const inactive = computed(() => inactiveNodeCount(props.scope))
</script>

<style scoped>
.scoped-notices {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-md);
}
</style>
