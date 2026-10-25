<template>
  <div
    class="group-detail"
    data-test="group-detail"
  >
    <el-alert
      v-if="loadFailed"
      type="error"
      :closable="false"
      show-icon
      :title="$t('userGroups.detail.loadFailed')"
      data-test="group-load-failed"
    />
    <template v-else-if="group">
      <PageHeader
        :title="group.name"
        :description="group.description"
      >
        <template #actions>
          <el-tag
            size="small"
            data-test="member-count"
          >
            {{ $t('userGroups.detail.memberCount', { n: (group.users || []).length }) }}
          </el-tag>
        </template>
      </PageHeader>

      <div
        v-if="mappingState === 'named'"
        class="mapping-header"
        data-test="mapping-header"
      >
        <span data-test="mapping-sentence">{{ mappingSentence }}</span>
        <el-popover
          v-if="mappings.total > 3"
          placement="bottom"
          trigger="click"
          :width="360"
          :teleported="false"
        >
          <template #reference>
            <el-button
              link
              type="primary"
              size="small"
              data-test="mapping-more"
            >
              <el-icon><Info /></el-icon>
            </el-button>
          </template>
          <strong>{{ $t('userGroups.detail.mapping.popoverTitle', { n: mappings.total }) }}</strong>
          <ul class="popover-list">
            <li
              v-for="row in mappings.rows"
              :key="row.rule_id"
            >
              {{ itemText(row) }}
            </li>
          </ul>
          <p class="hint">
            {{ $t('userGroups.detail.mapping.popoverNote') }}
          </p>
        </el-popover>
      </div>
      <div
        v-else-if="mappingState === 'fallback'"
        class="mapping-header"
        data-test="mapping-fallback"
      >
        <strong>{{ $t('userGroups.detail.mapping.fallbackTitle') }}</strong>
        <p>{{ $t('userGroups.detail.mapping.fallbackBody') }}</p>
        <p class="hint">
          {{ $t('userGroups.detail.mapping.fallbackHint') }}
        </p>
      </div>

      <el-tabs
        :model-value="tab"
        @update:model-value="changeTab"
      >
        <el-tab-pane
          :label="$t('userGroups.detail.tabs.members')"
          name="members"
        >
          <GroupMembersTab
            :group="group"
            :users="users"
            :protected-role="protectedRole"
            :bindings="bindings"
            :definitions="definitions"
            @changed="reload"
          />
        </el-tab-pane>
        <el-tab-pane
          :label="$t('userGroups.detail.tabs.roles')"
          name="roles"
          lazy
        >
          <GroupRolesTab
            :group="group"
            :bindings="bindings"
            :definitions="definitions"
            @changed="reload"
          />
        </el-tab-pane>
      </el-tabs>
    </template>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Info } from 'lucide-vue-next'
import { t } from '@/i18n'
import PageHeader from '@/components/PageHeader.vue'
import { getUserGroups, getUserGroupRoleBindings, getUserGroupExternalMappings } from '@/api/userGroups'
import { listRoleDefinitions } from '@/api/roleDefinitions'
import { getUsers } from '@/api/auth'
import { apiErrorSummary } from '@/api/redact'
import { clearDetailSubject, setDetailSubject } from '@/utils/detailTitle'
import GroupMembersTab from './usergroups/components/GroupMembersTab.vue'
import GroupRolesTab from './usergroups/components/GroupRolesTab.vue'
import { protectedRoleOf } from './usergroups/groupProtection'

/**
 * 使用者群組詳情頁：標頭依設定寫出映射來源，成員與角色與範圍兩個分頁。
 * 進入資格與群組列表相同，由路由的入口規則把關。
 */
const route = useRoute()
const router = useRouter()

const group = ref(null)
const users = ref([])
const bindings = ref([])
const definitions = ref([])
const mappings = ref({ rows: [], total: 0 })
const mappingsFailed = ref(false)
const loadFailed = ref(false)

const groupId = computed(() => Number(route.params.id))
const tab = computed(() => (route.query.tab === 'roles' ? 'roles' : 'members'))
const protectedRole = computed(() => protectedRoleOf(bindings.value, definitions.value))

const changeTab = (name) => {
  router?.replace({ query: { ...route.query, tab: name } })
}

// —— 標頭映射設定（依設定，不代表每位成員都來自這些群組）——
const hasMappedMembers = computed(() => (group.value?.member_sources || []).some((m) => m.mapped))
const mappingState = computed(() => {
  if (mappings.value.rows.length > 0 && !mappingsFailed.value) return 'named'
  if (mappingsFailed.value || hasMappedMembers.value) return 'fallback'
  return 'none'
})
const itemText = (row) => {
  const base = t('userGroups.detail.mapping.item', { source: row.source_name, group: row.external_group_label })
  return row.source_enabled === false ? `${base}（${t('userGroups.detail.mapping.sourceDisabled')}）` : base
}
const mappingSentence = computed(() => {
  const { rows, total } = mappings.value
  if (rows.length === 1 && total <= 1) {
    const r = rows[0]
    const sentence = t('userGroups.detail.mapping.one', { source: r.source_name, group: r.external_group_label })
    return r.source_enabled === false ? `${sentence}（${t('userGroups.detail.mapping.sourceDisabled')}）` : sentence
  }
  const items = rows.slice(0, 3).map(itemText).join('、')
  return total > 3
    ? t('userGroups.detail.mapping.manyMore', { items, n: total - 3 })
    : t('userGroups.detail.mapping.many', { items })
})

const loadGroup = async () => {
  const res = await getUserGroups()
  const found = (res.data || []).find((g) => g.id === groupId.value)
  if (!found) throw new Error('group not found')
  group.value = found
  setDetailSubject(found.name)
}
const loadBindings = async () => {
  try {
    const res = await getUserGroupRoleBindings(groupId.value, { quiet: true })
    bindings.value = res.data || []
  } catch (error) {
    bindings.value = []
    console.error(...apiErrorSummary('user_group_bindings_failed', error))
  }
}
const loadMappings = async () => {
  mappingsFailed.value = false
  try {
    const res = await getUserGroupExternalMappings(groupId.value)
    const rows = res.data || []
    mappings.value = { rows, total: Number.isInteger(res.total) ? res.total : rows.length }
  } catch (error) {
    mappings.value = { rows: [], total: 0 }
    mappingsFailed.value = true
    console.error(...apiErrorSummary('user_group_mappings_failed', error))
  }
}
const loadSupport = async () => {
  try {
    const res = await listRoleDefinitions()
    definitions.value = res?.data || []
  } catch (error) {
    console.error(...apiErrorSummary('role_definitions_failed', error))
  }
  try {
    const res = await getUsers()
    users.value = res.data || []
  } catch (error) {
    console.error(...apiErrorSummary('users_failed', error))
  }
}

const reload = async () => {
  try {
    await loadGroup()
  } catch (error) {
    console.error(...apiErrorSummary('user_group_detail_failed', error))
    if (!group.value) loadFailed.value = true
    return
  }
  loadFailed.value = false
  await Promise.all([loadBindings(), loadMappings()])
}

const init = async () => {
  group.value = null
  await reload()
  if (group.value) loadSupport()
}
watch(groupId, init)
onMounted(init)
onBeforeUnmount(clearDetailSubject)
</script>

<style scoped>
.group-detail {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}
.mapping-header {
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}
.mapping-header p {
  margin: var(--ot-space-xs) 0 0;
}
.popover-list {
  margin: var(--ot-space-xs) 0;
  padding-left: var(--ot-space-lg);
}
.hint {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
</style>
