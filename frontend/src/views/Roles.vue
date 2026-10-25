<template>
  <div class="roles">
    <PageHeader
      :title="$t('menu.roles')"
      :description="$t('roles.headerDesc')"
    >
      <template #actions>
        <el-button
          data-test="roles-refresh"
          @click="load"
        >
          {{ $t('common.refresh') }}
        </el-button>
        <el-button
          v-if="canDefine"
          type="primary"
          data-test="roles-create"
          @click="openCreate()"
        >
          {{ $t('roles.list.create') }}
        </el-button>
      </template>
    </PageHeader>

    <p
      v-if="loaded && !canDefine"
      class="view-only"
      data-test="roles-view-only"
    >
      {{ $t('roles.list.viewOnlyNote') }}
    </p>
    <el-alert
      v-if="loadFailed"
      type="warning"
      :closable="false"
      :title="$t('roles.list.unavailable')"
      data-test="roles-unavailable"
    />

    <section
      v-for="sec in sections"
      :key="sec.key"
      class="list-card"
      :data-test="`roles-section-${sec.key}`"
    >
      <h2 class="section-title">
        {{ sec.title }}
      </h2>
      <el-table
        v-loading="loading"
        :data="sec.rows"
        style="width: 100%"
        stripe
      >
        <el-table-column
          :label="$t('roles.nameColumn')"
          min-width="200"
        >
          <template #default="{ row }">
            <div class="role-name">
              <strong>{{ displayName(row) }}</strong>
              <el-tag
                v-if="row.builtin_key"
                size="small"
                type="info"
              >
                {{ $t('roles.list.builtinLocked') }}
              </el-tag>
            </div>
            <div
              v-if="!row.builtin_key"
              class="muted"
            >
              {{ templateLine(row) }}
            </div>
            <div
              v-if="row.description"
              class="muted"
            >
              {{ row.description }}
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('roles.list.colFeatures')"
          min-width="280"
        >
          <template #default="{ row }">
            <div
              class="summary"
              :data-test="`role-summary-${row.id}`"
            >
              <p
                v-for="line in summaryLines(row)"
                :key="line.kind"
                class="summary-line"
              >
                <strong>{{ line.label }}</strong>{{ line.text }}
              </p>
            </div>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('roles.list.colScope')"
          width="130"
        >
          <template #default="{ row }">
            <span :data-test="`role-scope-${row.id}`">{{ scopeText(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('roles.list.colUsers')"
          width="90"
        >
          <template #default="{ row }">
            <span :data-test="`role-users-${row.id}`">{{ row.user_count }}</span>
          </template>
        </el-table-column>
        <el-table-column
          :label="$t('roles.list.colActions')"
          min-width="260"
        >
          <template #default="{ row }">
            <div class="actions">
              <el-button
                v-if="!canEditRow(row)"
                link
                type="primary"
                :data-test="`role-view-${row.id}`"
                @click="goDetail(row)"
              >
                {{ $t('roles.list.actionView') }}
              </el-button>
              <el-button
                v-if="row.builtin_key && canDefine && row.builtin_key !== SUPER_KEY"
                link
                type="primary"
                :data-test="`role-template-${row.id}`"
                @click="openCreate(row)"
              >
                {{ $t('roles.list.actionUseAsTemplate') }}
              </el-button>
              <template v-if="canEditRow(row)">
                <el-button
                  link
                  type="primary"
                  :data-test="`role-edit-${row.id}`"
                  @click="goDetail(row)"
                >
                  {{ $t('roles.list.actionEdit') }}
                </el-button>
                <el-button
                  link
                  type="primary"
                  :data-test="`role-copy-${row.id}`"
                  @click="openCopy(row)"
                >
                  {{ $t('roles.list.actionCopy') }}
                </el-button>
                <el-button
                  link
                  type="danger"
                  :disabled="inUse(row)"
                  :data-test="`role-delete-${row.id}`"
                  @click="removeRole(row)"
                >
                  {{ $t('roles.list.actionDelete') }}
                </el-button>
              </template>
            </div>
            <div
              v-if="canEditRow(row) && inUse(row)"
              class="in-use"
              :data-test="`role-in-use-${row.id}`"
            >
              <strong>{{ $t('roles.list.inUse.title') }}</strong>
              <div>{{ $t('roles.list.inUse.direct', { n: refs(row).direct }) }}</div>
              <div>{{ $t('roles.list.inUse.groups', { n: refs(row).group_bindings }) }}</div>
              <div>{{ $t('roles.list.inUse.mappings', { n: refs(row).mapping_rules }) }}</div>
              <div class="muted">
                {{ inUseHint(row) }}
              </div>
            </div>
          </template>
        </el-table-column>
        <template #empty>
          <EmptyState
            :title="$t('roles.emptyTitle')"
            :hint="$t('roles.emptyHint')"
          />
        </template>
      </el-table>
    </section>

    <el-alert
      :title="$t('roles.tipTitle')"
      type="info"
      :closable="false"
      style="margin-top: var(--ot-space-md)"
    >
      {{ $t('roles.tipBody') }}
    </el-alert>

    <!-- 新增角色：選範本 -->
    <el-dialog
      v-model="createOpen"
      :title="$t('roles.create.title')"
      width="520px"
      :append-to-body="false"
      data-test="role-create-dialog"
    >
      <el-form label-position="top">
        <el-form-item :label="$t('roles.create.fromTemplate')">
          <el-select
            v-model="createDraft.template"
            style="width: 100%"
            data-test="role-create-template"
          >
            <el-option
              :value="0"
              :label="$t('roles.create.blank')"
            />
            <el-option
              v-for="opt in templateOptions"
              :key="opt.id"
              :value="opt.id"
              :label="displayName(opt)"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="$t('roles.create.name')">
          <el-input
            v-model="createDraft.name"
            maxlength="64"
            data-test="role-create-name"
          />
        </el-form-item>
        <el-form-item :label="$t('roles.create.description')">
          <el-input
            v-model="createDraft.description"
            type="textarea"
            :rows="2"
            :placeholder="$t('roles.create.descriptionPlaceholder')"
            data-test="role-create-description"
          />
        </el-form-item>
        <p class="muted">
          {{ $t('roles.create.adjustLater') }}
        </p>
      </el-form>
      <template #footer>
        <el-button @click="createOpen = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :disabled="!createDraft.name.trim()"
          data-test="role-create-next"
          @click="createNext"
        >
          {{ $t('roles.create.next') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 複製 -->
    <el-dialog
      v-model="copyOpen"
      :title="$t('roles.create.copyTitle')"
      width="440px"
      :append-to-body="false"
      data-test="role-copy-dialog"
    >
      <el-form label-position="top">
        <el-form-item :label="$t('roles.create.copyName')">
          <el-input
            v-model="copyName"
            maxlength="64"
            data-test="role-copy-name"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="copyOpen = false">
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          type="primary"
          :disabled="!copyName.trim() || copying"
          data-test="role-copy-submit"
          @click="submitCopy"
        >
          {{ $t('common.confirm') }}
        </el-button>
      </template>
    </el-dialog>

    <!-- 刪除當下發現已被使用 -->
    <el-dialog
      v-model="conflictOpen"
      :title="$t('roles.list.inUse.conflictTitle', { name: conflictName })"
      width="440px"
      :append-to-body="false"
      data-test="role-in-use-conflict"
    >
      <p>{{ $t('roles.list.inUse.conflictBody') }}</p>
      <p class="muted">
        {{ $t('roles.list.inUse.reloaded') }}
      </p>
      <template #footer>
        <el-button
          type="primary"
          data-test="role-in-use-ack"
          @click="conflictOpen = false"
        >
          {{ $t('roles.list.inUse.ack') }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import { t, te } from '@/i18n'
import { roleLabel } from '@/constants/roles'
import { confirmDestructive } from '@/utils/confirm'
import {
  listRoleDefinitions,
  copyRoleDefinition,
  deleteRoleDefinition,
  roleErrorCode,
  ROLE_ERROR_IN_USE,
} from '@/api/roleDefinitions'

const SUPER_KEY = 'super_admin'
const router = useRouter()

const loading = ref(false)
const loaded = ref(false)
const loadFailed = ref(false)
const rows = ref([])
const canDefine = ref(false)

const builtinRows = computed(() => rows.value.filter((r) => r.builtin_key))
const customRows = computed(() => rows.value.filter((r) => !r.builtin_key))
const sections = computed(() => [
  { key: 'builtin', title: t('roles.list.builtinTitle', { n: builtinRows.value.length }), rows: builtinRows.value },
  { key: 'custom', title: t('roles.list.customTitle', { n: customRows.value.length }), rows: customRows.value },
])
const templateOptions = computed(() => builtinRows.value.filter((r) => r.builtin_key !== SUPER_KEY))

const displayName = (row) => (row.builtin_key ? roleLabel(row.name) : row.name)

const canEditRow = (row) => canDefine.value && !row.builtin_key && !row.locked
const refs = (row) => ({
  direct: row.references?.direct || 0,
  group_bindings: row.references?.group_bindings || 0,
  mapping_rules: row.references?.mapping_rules || 0,
})
const inUse = (row) => {
  const r = refs(row)
  return r.direct > 0 || r.group_bindings > 0 || r.mapping_rules > 0
}
const inUseHint = (row) => {
  const r = refs(row)
  const people = r.direct > 0
  const groups = r.group_bindings > 0
  const maps = r.mapping_rules > 0
  const parts = []
  if (people && groups) parts.push(t('roles.list.inUse.hint.usersAndGroups'))
  else if (people) parts.push(t('roles.list.inUse.hint.users'))
  else if (groups) parts.push(t('roles.list.inUse.hint.groups'))
  if (maps) parts.push(t(people || groups ? 'roles.list.inUse.hint.mappingsToo' : 'roles.list.inUse.hint.mappings'))
  return parts.join('')
}

// 顯示表只做呈現，不做授權判斷
const scopeText = (row) => {
  if (row.builtin_key === 'approver') return t('roles.list.scopeByReviewer')
  if (row.builtin_key === 'user') return t('roles.list.scopeNotApplicable')
  // 可限定節點且範圍會生效才標「指派時選節點」；判定只取伺服器欄位，不由權限集合推算
  if (row.scopable === true && row.node_range_no_effect !== true) return t('roles.list.scopeAtAssignment')
  return t('roles.list.scopeGlobal')
}

const entryLabel = (id) => (te(`roles.editor.entry.${id}`) ? t(`roles.editor.entry.${id}`) : id)
const summaryLines = (row) => {
  const s = row.summary || {}
  const lines = []
  for (const kind of ['manage', 'partial', 'read', 'available']) {
    const ids = s[kind] || []
    if (ids.length) {
      lines.push({ kind, label: `${t(`roles.summary.${kind}`)}：`, text: ids.map(entryLabel).join('、') })
    }
  }
  // 審核人員的能力來自固定入口（審核中心），不在可勾選的入口摘要裡
  if (!lines.length && row.builtin_key === 'approver') {
    lines.push({ kind: 'fixed', label: '', text: t('roles.list.approverAbility') })
  }
  if (!lines.length) lines.push({ kind: 'hidden', label: '', text: t('roles.summary.hidden') })
  return lines
}

const templateLine = (row) => {
  const tpl = row.template_role_id ? rows.value.find((r) => r.id === row.template_role_id) : null
  return tpl ? t('roles.list.templateFrom', { name: displayName(tpl) }) : t('roles.list.blankStart')
}

const load = async () => {
  loading.value = true
  loadFailed.value = false
  try {
    const res = await listRoleDefinitions()
    rows.value = res?.data || []
    canDefine.value = res?.can_define === true
    loaded.value = true
  } catch (error) {
    loadFailed.value = true
    console.error('取得角色列表失敗:', error)
  } finally {
    loading.value = false
  }
}

const goDetail = (row) => router.push(`/roles/${row.id}`)

// 新增：先選範本與名稱，儲存在編輯頁才送出
const createOpen = ref(false)
const createDraft = ref({ template: 0, name: '', description: '' })
const openCreate = (row) => {
  const tpl = row && row.id && row.builtin_key ? row.id : 0
  createDraft.value = { template: tpl, name: '', description: '' }
  createOpen.value = true
}
const createNext = () => {
  const d = createDraft.value
  const query = { name: d.name.trim() }
  if (d.description.trim()) query.description = d.description.trim()
  if (d.template) query.template = String(d.template)
  createOpen.value = false
  router.push({ path: '/roles/new', query })
}

const copyOpen = ref(false)
const copyName = ref('')
const copyTarget = ref(null)
const copying = ref(false)
const openCopy = (row) => {
  copyTarget.value = row
  copyName.value = ''
  copyOpen.value = true
}
const submitCopy = async () => {
  if (!copyTarget.value) return
  copying.value = true
  try {
    await copyRoleDefinition(copyTarget.value.id, copyName.value.trim())
    ElMessage.success(t('roles.create.copied'))
    copyOpen.value = false
    await load()
  } catch (error) {
    console.error('複製角色失敗:', error)
  } finally {
    copying.value = false
  }
}

const conflictOpen = ref(false)
const conflictName = ref('')
const removeRole = async (row) => {
  if (inUse(row)) return
  try {
    await confirmDestructive(t('roles.list.deleteConfirm', { name: row.name }), t('roles.list.actionDelete'))
  } catch {
    return
  }
  try {
    await deleteRoleDefinition(row.id, row.definition_version)
    ElMessage.success(t('roles.list.deleted'))
    await load()
  } catch (error) {
    if (roleErrorCode(error) === ROLE_ERROR_IN_USE) {
      conflictName.value = row.name
      conflictOpen.value = true
      await load()
    } else {
      console.error('刪除角色失敗:', error)
    }
  }
}

onMounted(load)
</script>

<style scoped>
.list-card {
  margin-top: var(--ot-space-md);
  padding: var(--ot-space-md);
  background-color: var(--ot-bg-surface);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-lg);
}
.section-title {
  margin: 0 0 var(--ot-space-sm);
  font-size: var(--ot-font-size-md);
  font-weight: 600;
  color: var(--ot-text-primary);
}
.role-name {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
}
.muted {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}
.view-only {
  margin: 0 0 var(--ot-space-sm);
  color: var(--ot-text-secondary);
}
.summary-line {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
}
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
}
.in-use {
  margin-top: var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
</style>
