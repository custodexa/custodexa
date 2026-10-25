<template>
  <div
    class="user-detail"
    data-test="user-detail"
  >
    <el-alert
      v-if="loadFailed"
      type="error"
      :closable="false"
      show-icon
      :title="$t('userDetail.loadFailed')"
      data-test="user-load-failed"
    />
    <template v-else-if="user">
      <PageHeader :title="user.username">
        <template #actions>
          <el-tag
            v-if="holder === 'super'"
            type="danger"
            data-test="protected-super"
          >
            {{ $t('userDetail.header.protectedSuper') }}
          </el-tag>
          <el-tag
            v-else-if="holder === 'security'"
            type="warning"
            data-test="protected-security"
          >
            {{ $t('userDetail.header.protectedSecurity') }}
          </el-tag>
        </template>
      </PageHeader>
      <el-alert
        v-if="holder"
        :type="holder === 'super' ? 'error' : 'warning'"
        :closable="false"
        show-icon
        :title="holder === 'super' ? $t('userDetail.banner.super') : $t('userDetail.banner.security')"
        data-test="protected-banner"
      />
      <el-tabs
        :model-value="tab"
        @update:model-value="changeTab"
      >
        <el-tab-pane
          :label="$t('userDetail.tabs.basic')"
          name="basic"
        >
          <UserAccountForm
            inline
            :user="user"
            @saved="load"
          />
          <UserAccountActions
            layout="panel"
            :row="user"
            :account-ops="accountOps"
            @open-password="openPassword"
            @open-identities="openIdentities"
            @changed="load"
            @deleted="goList"
          />
        </el-tab-pane>
        <el-tab-pane
          :label="$t('userDetail.tabs.roles')"
          name="roles"
          lazy
        >
          <UserRoleScopeTab
            :user-id="user.id"
            :username="user.username"
            :role-sets="roleSets"
            :snapshot="snapshot"
            @changed="load"
          />
        </el-tab-pane>
      </el-tabs>
      <UserAccountDialogs
        ref="dialogsRef"
        :refresh-user="refreshUser"
      />
    </template>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHeader from '@/components/PageHeader.vue'
import { getUserDetail } from '@/api/user'
import { apiErrorSummary } from '@/api/redact'
import { clearDetailSubject, setDetailSubject } from '@/utils/detailTitle'
import UserAccountForm from './users/components/UserAccountForm.vue'
import UserAccountActions from './users/components/UserAccountActions.vue'
import UserAccountDialogs from './users/components/UserAccountDialogs.vue'
import UserRoleScopeTab from './users/components/UserRoleScopeTab.vue'
import { protectedIdentity } from './users/accountActionStates'

/**
 * 使用者詳情頁：基本資料（共用列表頁的編輯表單與帳號動作，另疊加伺服器下發的保護分類）
 * 與角色與範圍兩個分頁。進入資格與使用者列表相同，由路由的入口規則把關。
 */
const route = useRoute()
const router = useRouter()

const user = ref(null)
const roleSets = ref({ manual: [], mapped: [] })
const snapshot = ref(null)
const accountOps = ref(null)
const loadFailed = ref(false)
const dialogsRef = ref(null)

const userId = computed(() => Number(route.params.id))
const tab = computed(() => (route.query.tab === 'roles' ? 'roles' : 'basic'))
const holder = computed(() => protectedIdentity(accountOps.value))

const parseSnapshotGroups = (raw) => {
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed.map((v) => String(v)) : [String(raw)]
  } catch {
    return [String(raw)]
  }
}

const apply = (res) => {
  const data = res?.data || {}
  user.value = data
  setDetailSubject(data.username)
  roleSets.value = res?.role_sets || { manual: [], mapped: [] }
  accountOps.value = res?.account_ops || null
  snapshot.value = data.group_snapshot_at
    ? {
        channel: data.group_snapshot_channel || '',
        groups: parseSnapshotGroups(data.group_snapshot_groups),
        at: data.group_snapshot_at,
      }
    : null
}

const load = async () => {
  try {
    apply(await getUserDetail(userId.value))
    loadFailed.value = false
    return true
  } catch (error) {
    console.error(...apiErrorSummary('user_detail_failed', error))
    if (!user.value) loadFailed.value = true
    return false
  }
}

const refreshUser = async (id) => {
  const ok = await load()
  return { ok, user: ok && user.value?.id === id ? { ...user.value } : null }
}

const changeTab = (name) => {
  router?.replace({ query: { ...route.query, tab: name } })
}
const openPassword = (row) => dialogsRef.value?.openPassword(row)
const openIdentities = (row) => dialogsRef.value?.openIdentities(row)
const goList = () => router?.push('/users')

watch(userId, () => {
  user.value = null
  load()
})
onMounted(load)
onBeforeUnmount(clearDetailSubject)
</script>

<style scoped>
.user-detail {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}
</style>
