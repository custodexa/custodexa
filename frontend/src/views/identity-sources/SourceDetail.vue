<template>
  <!-- 型別分派：兩型別共用同一套骨架（`SourceDetailLayout`），但各自持有自己的
       表單與端點。共用一份表單狀態會讓兩邊的欄位差異變成一串條件判斷 -->
  <component
    :is="isDirectory ? LDAPSourceDetail : OIDCSourceDetail"
    v-if="known"
    :key="routeKey"
  />
  <el-alert
    v-else
    type="error"
    :title="$t('identitySources.unknownType')"
    :description="$t('identitySources.unknownTypeHint')"
    :closable="false"
    show-icon
  />
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import OIDCSourceDetail from './OIDCSourceDetail.vue'
import LDAPSourceDetail from './LDAPSourceDetail.vue'

const route = useRoute()

const sourceType = computed(() => String(route.params.type || ''))
const isDirectory = computed(() => sourceType.value === 'ldap')
const known = computed(() => sourceType.value === 'ldap' || sourceType.value === 'oidc')

// 由「新增」導向「已建立」時路徑改變但元件相同：換 key 才會重新初始化
const routeKey = computed(() => `${sourceType.value}:${route.params.id || 'new'}`)
</script>
