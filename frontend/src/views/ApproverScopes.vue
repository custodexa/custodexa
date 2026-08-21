<template>
  <div class="approver-scopes">
    <PageHeader
      :title="$t('menu.approverScopes')"
      :description="$t('approverScopes.headerDesc')"
    >
      <template #actions>
        <el-button
          type="primary"
          :icon="Plus"
          @click="openAdd()"
        >
          {{ $t('approverScopes.addScope') }}
        </el-button>
        <el-button
          :icon="Refresh"
          @click="fetchAll"
        >
          {{ $t('common.refresh') }}
        </el-button>
      </template>
    </PageHeader>

    <el-alert
      type="info"
      :closable="false"
      class="semantics-alert"
    >
      <ul class="semantics-list">
        <li
          v-for="line in SCOPE_SEMANTICS_LINES"
          :key="line"
        >
          {{ line }}
        </li>
      </ul>
    </el-alert>

    <el-tabs
      v-model="activeView"
      class="view-tabs"
    >
      <!-- 按資產/節點（客體中心，預設）：這個節點/資產誰審、湊不湊得到門檻 -->
      <el-tab-pane
        :label="$t('approverScopes.tabObjects')"
        name="objects"
      >
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="nodeTreeRows"
            row-key="key"
            default-expand-all
            style="width: 100%"
          >
            <el-table-column
              :label="$t('common.node')"
              min-width="220"
            >
              <template #default="{ row }">
                {{ row.name }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approverScopes.colActorNode')"
              min-width="240"
            >
              <template #default="{ row }">
                <el-tag
                  v-for="scope in row.scopes"
                  :key="scope.id"
                  :type="ACTOR_TYPES[actorType(scope)].tagType"
                  size="small"
                  closable
                  class="scope-tag"
                  @close="handleRemove(scope)"
                >
                  {{ actorLabel(scope) }}
                </el-tag>
                <span
                  v-if="!row.scopes.length"
                  class="cell-empty"
                >—</span>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approverScopes.colPoolCount')"
              width="140"
            >
              <template #default="{ row }">
                <el-tooltip
                  :content="row.poolNames.length ? $t('approverScopes.poolTooltip', { names: row.poolNames.join($t('common.listSeparator')) }) : $t('approverScopes.noPool')"
                  placement="top"
                >
                  <el-tag
                    size="small"
                    :type="row.poolCount < quorumThreshold ? 'danger' : 'success'"
                  >
                    {{ row.poolCount < quorumThreshold ? '⚠ ' : '' }}{{ row.poolCount }}{{ quorumThreshold > 1 ? $t('approverScopes.thresholdSuffix', { n: quorumThreshold }) : '' }}
                  </el-tag>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('common.actions')"
              width="110"
              fixed="right"
            >
              <template #default="{ row }">
                <el-button
                  link
                  type="primary"
                  size="small"
                  @click="openAdd(null, 'asset_group', row.id)"
                >
                  {{ $t('approverScopes.addActor') }}
                </el-button>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState
                :title="$t('approverScopes.emptyNodesTitle')"
                :hint="$t('approverScopes.emptyNodesHint')"
              />
            </template>
          </el-table>
        </div>

        <h3 class="section-title">
          {{ $t('approverScopes.sectionDirectAssets') }}
        </h3>
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="assetScopeRows"
            style="width: 100%"
            stripe
          >
            <el-table-column
              :label="$t('common.asset')"
              min-width="200"
            >
              <template #default="{ row }">
                {{ row.assetName }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approverScopes.colActorDirect')"
              min-width="260"
            >
              <template #default="{ row }">
                <el-tag
                  v-for="scope in row.scopes"
                  :key="scope.id"
                  :type="ACTOR_TYPES[actorType(scope)].tagType"
                  size="small"
                  closable
                  class="scope-tag"
                  @close="handleRemove(scope)"
                >
                  {{ actorLabel(scope) }}
                </el-tag>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState
                :title="$t('approverScopes.emptyDirectTitle')"
                :hint="$t('approverScopes.emptyDirectHint')"
              />
            </template>
          </el-table>
        </div>

        <h3 class="section-title">
          {{ $t('approverScopes.sectionSubjectRouting') }}
        </h3>
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="subjectScopeRows"
            style="width: 100%"
            stripe
          >
            <el-table-column
              :label="$t('approverScopes.colSubject')"
              min-width="200"
            >
              <template #default="{ row }">
                <el-tag
                  :type="SCOPE_TYPES[scopeType(row)].tagType"
                  size="small"
                  effect="plain"
                  class="scope-tag"
                >
                  {{ SCOPE_TYPES[scopeType(row)].label }}
                </el-tag>
                {{ scopeTargetLabel(row, groupPaths) }}
              </template>
            </el-table-column>
            <el-table-column
              :label="$t('approverScopes.colRouteTo')"
              min-width="200"
            >
              <template #default="{ row }">
                <el-tag
                  :type="ACTOR_TYPES[actorType(row)].tagType"
                  size="small"
                  closable
                  class="scope-tag"
                  @close="handleRemove(row)"
                >
                  {{ actorLabel(row) }}
                </el-tag>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState
                :title="$t('approverScopes.emptySubjectTitle')"
                :hint="$t('approverScopes.emptySubjectHint')"
              />
            </template>
          </el-table>
        </div>
      </el-tab-pane>

      <!-- 按審核人員（審核方中心）：這個人/群組管多寬 -->
      <el-tab-pane
        :label="$t('approverScopes.tabActors')"
        name="actors"
      >
        <div class="list-panel">
          <el-table
            v-loading="loading"
            :data="actorRows"
            style="width: 100%"
            stripe
          >
            <el-table-column
              :label="$t('approverScopes.colActor')"
              width="200"
            >
              <template #default="{ row }">
                <div>
                  {{ row.name }}
                  <el-tag
                    v-if="row.type === 'group'"
                    type="warning"
                    size="small"
                    effect="plain"
                  >
                    {{ $t('common.group') }}
                  </el-tag>
                </div>
                <div
                  v-if="row.fullName"
                  class="sub-text"
                >
                  {{ row.fullName }}
                </div>
                <div
                  v-if="!row.scopes.length"
                  class="sub-text"
                >
                  {{ $t('approverScopes.noScopeAssigned') }}
                </div>
              </template>
            </el-table-column>
            <el-table-column
              v-for="(meta, key) in SCOPE_TYPES"
              :key="key"
              :label="meta.label"
              min-width="170"
            >
              <template #default="{ row }">
                <el-tag
                  v-for="scope in row.byType[key]"
                  :key="scope.id"
                  :type="meta.tagType"
                  size="small"
                  closable
                  class="scope-tag"
                  @close="handleRemove(scope)"
                >
                  {{ scopeTargetLabel(scope, groupPaths) }}
                </el-tag>
                <el-button
                  link
                  type="primary"
                  size="small"
                  class="cell-add"
                  @click="openAdd({ type: row.type, id: row.id }, key)"
                >
                  ＋
                </el-button>
              </template>
            </el-table-column>
            <template #empty>
              <EmptyState
                :title="$t('approverScopes.emptyActorsTitle')"
                :hint="$t('approverScopes.emptyActorsHint')"
              />
            </template>
          </el-table>
        </div>
      </el-tab-pane>
    </el-tabs>

    <el-dialog
      v-model="addVisible"
      :title="addDialogTitle"
      width="560px"
      :close-on-click-modal="false"
    >
      <ApproverScopeForm
        v-if="addVisible"
        :key="addFormKey"
        :preset-actor="addPreset.actor"
        :preset-type="addPreset.type"
        :preset-target-id="addPreset.targetId"
        :show-help="false"
        @created="handleCreated"
      />
    </el-dialog>
  </div>
</template>

<script setup>
// 審核範圍雙視角總覽（approval-routing-quorum D-5/D-7）：admin only 獨立頁。
// 預設客體中心（這個節點/資產誰審、可審人數 vs 門檻——涵蓋缺口與卡單風險可視）；
// 「按審核人員」矩陣（個人與群組皆成列）。一站式新增（個人代配角色/群組零代配）
import { ref, reactive, computed, onMounted } from 'vue'
import { Refresh, Plus } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import PageHeader from '@/components/PageHeader.vue'
import EmptyState from '@/components/EmptyState.vue'
import ApproverScopeForm from '@/components/ApproverScopeForm.vue'
import { getApproverScopes, deleteApproverScope } from '@/api/accessRequests'
import { getUserList } from '@/api/user'
import { getUserGroups } from '@/api/userGroups'
import { getAssetGroups } from '@/api/assets'
import { getSecurityPolicies } from '@/api/securityPolicies'
import { hasRole } from '@/composables/useRoles'
import { t } from '@/i18n'
import {
  SCOPE_TYPES,
  ACTOR_TYPES,
  SCOPE_SEMANTICS_LINES,
  scopeType,
  actorType,
  actorLabel,
  scopeTargetLabel,
  buildGroupPaths,
} from '@/utils/approver-scope'

const activeView = ref('objects')
const loading = ref(false)
const scopes = ref([])
const users = ref([])
const userGroups = ref([])
const assetGroups = ref([])
const groupPaths = ref({})
const quorumThreshold = ref(1)

// —— 資料載入 ——
const fetchAll = async () => {
  loading.value = true
  try {
    const [scopeRes, userRes, ugroupRes, agroupRes, policyRes] = await Promise.all([
      getApproverScopes(),
      getUserList({ page: 1, page_size: 1000 }),
      getUserGroups(),
      getAssetGroups(),
      getSecurityPolicies(),
    ])
    scopes.value = scopeRes.data || []
    users.value = userRes.data || []
    userGroups.value = ugroupRes.data || []
    assetGroups.value = agroupRes.data || []
    groupPaths.value = buildGroupPaths(assetGroups.value)
    const policy = (policyRes.data || []).find((p) => p.key === 'access_request_min_approvals')
    quorumThreshold.value = parseInt(policy?.value, 10) || 1
  } catch (error) {
    console.error('載入審核範圍失敗:', error)
  } finally {
    loading.value = false
  }
}

// —— 審核方成員展開（可審人數計算用）——
const groupMemberIds = (groupId) => {
  const g = userGroups.value.find((x) => x.id === groupId)
  return (g?.users || []).map((u) => u.id)
}
const actorUserIds = (scope) =>
  scope.approver_group_id ? groupMemberIds(scope.approver_group_id) : [scope.approver_id]
const userNameById = (id) => {
  const u = users.value.find((x) => x.id === id)
  return u?.username || `#${id}`
}

// —— 按資產/節點視角 ——
// 節點樹列：own scopes＝直配本節點；pool＝本節點＋全部祖先的範圍展開成員去重
const nodeTreeRows = computed(() => {
  const byId = new Map(assetGroups.value.map((g) => [g.id, g]))
  const scopesByNode = new Map()
  scopes.value.forEach((s) => {
    if (s.asset_group_id) {
      const list = scopesByNode.get(s.asset_group_id) || []
      list.push(s)
      scopesByNode.set(s.asset_group_id, list)
    }
  })
  const effectivePool = (nodeId) => {
    const ids = new Set()
    let cur = byId.get(nodeId)
    let depth = 0
    while (cur && depth < 20) {
      (scopesByNode.get(cur.id) || []).forEach((s) =>
        actorUserIds(s).forEach((uid) => uid && ids.add(uid))
      )
      cur = cur.parent_id ? byId.get(cur.parent_id) : null
      depth++
    }
    return [...ids]
  }
  const build = (parentId) =>
    assetGroups.value
      .filter((g) => (g.parent_id ?? null) === parentId)
      .map((g) => {
        const pool = effectivePool(g.id)
        return {
          key: `node-${g.id}`,
          id: g.id,
          name: g.name,
          scopes: scopesByNode.get(g.id) || [],
          poolCount: pool.length,
          poolNames: pool.map(userNameById),
          children: build(g.id),
        }
      })
  return build(null)
})

// 直配資產列：有 asset_id 範圍的資產聚合
const assetScopeRows = computed(() => {
  const byAsset = new Map()
  scopes.value.forEach((s) => {
    if (!s.asset_id) return
    const row = byAsset.get(s.asset_id) || {
      assetId: s.asset_id,
      assetName: s.asset?.name || `#${s.asset_id}`,
      scopes: [],
    }
    row.scopes.push(s)
    byAsset.set(s.asset_id, row)
  })
  return [...byAsset.values()]
})

// 申請人側路由列
const subjectScopeRows = computed(() =>
  scopes.value.filter((s) => s.subject_user_id || s.subject_group_id)
)

// —— 按審核人員視角 ——
// 列＝個人審核方（具 approver 角色的使用者，含零範圍者——涵蓋缺口可視）
// ＋群組審核方（出現在任一範圍的群組）
const actorRows = computed(() => {
  const rows = users.value
    .filter((u) => hasRole(u.roles, 'approver'))
    .map((u) => ({
      type: 'user',
      id: u.id,
      name: u.username,
      fullName: u.full_name || '',
      scopes: scopes.value.filter((s) => s.approver_id === u.id),
    }))
  const groupIds = [...new Set(scopes.value.filter((s) => s.approver_group_id).map((s) => s.approver_group_id))]
  groupIds.forEach((gid) => {
    const g = userGroups.value.find((x) => x.id === gid)
    rows.push({
      type: 'group',
      id: gid,
      name: g?.name || `#${gid}`,
      fullName: '',
      scopes: scopes.value.filter((s) => s.approver_group_id === gid),
    })
  })
  return rows.map((r) => {
    const byType = { asset: [], asset_group: [], subject_user: [], subject_group: [] }
    r.scopes.forEach((s) => byType[scopeType(s)].push(s))
    return { ...r, byType }
  })
})

// —— 新增對話框（共用 ApproverScopeForm；成功即關窗——結果在矩陣上可見）——
const addVisible = ref(false)
const addPreset = reactive({ actor: null, type: '', targetId: null })
const addFormKey = ref(0)

const addDialogTitle = computed(() => {
  if (!addPreset.actor) return t('approverScopes.addScope')
  const name =
    addPreset.actor.type === 'group'
      ? userGroups.value.find((g) => g.id === addPreset.actor.id)?.name
      : userNameById(addPreset.actor.id)
  return t('approverScopes.addScopeFor', { name: name || '' })
})

const openAdd = (actor = null, type = '', targetId = null) => {
  addPreset.actor = actor
  addPreset.type = type
  addPreset.targetId = targetId
  addFormKey.value++
  addVisible.value = true
}

const handleCreated = () => {
  addVisible.value = false
  fetchAll()
}

const handleRemove = async (scope) => {
  try {
    await ElMessageBox.confirm(
      t('approverScopes.removeConfirm', {
        actor: actorLabel(scope),
        target: scopeTargetLabel(scope, groupPaths.value),
      }),
      t('approverScopes.removeTitle'),
      { confirmButtonText: t('approverScopes.removeButton'), cancelButtonText: t('common.cancel'), type: 'warning' }
    )
  } catch {
    return
  }
  try {
    await deleteApproverScope(scope.id)
    ElMessage.success(t('approverScopes.removed'))
    fetchAll()
  } catch (error) {
    console.error('移除審核範圍失敗:', error)
  }
}

onMounted(fetchAll)
</script>

<style scoped>
.approver-scopes {
  padding: 0;
}

.semantics-alert {
  margin-bottom: 16px;
}

.semantics-list {
  margin: 0;
  padding-left: 18px;
  line-height: 1.8;
}

.section-title {
  margin: 20px 0 12px;
  font-size: 15px;
  color: var(--ot-text-primary, #e6edf7);
}

.scope-tag {
  margin: 2px 4px 2px 0;
}

.cell-add {
  padding: 0 2px;
}

.cell-empty {
  color: var(--ot-text-disabled, #6b7a90);
}

.sub-text {
  font-size: 12px;
  color: var(--ot-text-secondary, #93a4bd);
}
</style>
