<template>
  <el-select
    :model-value="null"
    filterable
    remote
    reserve-keyword
    :remote-method="search"
    :loading="loading"
    :placeholder="$t('permissionOverview.switchUser')"
    class="po-switch"
    data-test="po-user-switch"
    @visible-change="(open) => open && !options.length && search('')"
    @change="(id) => emit('switch', id)"
  >
    <el-option
      v-for="u in options"
      :key="u.id"
      :label="u.username"
      :value="u.id"
    />
  </el-select>
</template>

<script setup>
import { ref } from 'vue'
import { getUserList } from '@/api/user'

/** 權限一覽右上的使用者切換：建議清單取自既有使用者列表，選定後由上層換網址。 */
const emit = defineEmits(['switch'])

const options = ref([])
const loading = ref(false)

const search = async (keyword) => {
  loading.value = true
  try {
    const res = await getUserList({ search: keyword || undefined, page: 1, page_size: 20 })
    options.value = Array.isArray(res?.data) ? res.data : []
  } catch {
    options.value = []
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.po-switch {
  width: 220px;
}
</style>
