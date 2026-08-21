<template>
  <el-dialog
    :model-value="modelValue"
    :title="$t('authorizations.batchAuthorize')"
    width="800px"
    :close-on-click-modal="false"
    @update:model-value="$emit('update:modelValue', $event)"
    @closed="handleClosed"
  >
    <el-steps
      :active="currentStep"
      align-center
      finish-status="success"
    >
      <el-step :title="$t('authzWizard.stepSubject')" />
      <el-step :title="$t('authzWizard.stepAsset')" />
      <el-step :title="$t('authzWizard.stepPermission')" />
      <el-step :title="$t('authzWizard.stepConfirm')" />
    </el-steps>

    <div class="step-content">
      <!-- Step 1: 選擇主體（使用者或使用者群組，user-group-authorization） -->
      <div v-show="currentStep === 0">
        <el-radio-group
          v-model="subjectMode"
          style="margin-bottom: 15px"
        >
          <el-radio-button value="users">
            {{ $t('authzWizard.subjectIndividual') }}
          </el-radio-button>
          <el-radio-button value="userGroups">
            {{ $t('authzWizard.subjectGroup') }}
          </el-radio-button>
        </el-radio-group>

        <el-table
          v-if="subjectMode === 'userGroups'"
          :data="userGroupList"
          height="350"
          @selection-change="handleUserGroupSelectionChange"
        >
          <el-table-column
            type="selection"
            width="55"
          />
          <el-table-column
            prop="name"
            :label="$t('authzWizard.colGroupName')"
            min-width="160"
          />
          <el-table-column
            :label="$t('authzWizard.colMemberCount')"
            width="100"
          >
            <template #default="{ row }">
              {{ (row.users || []).length }}
            </template>
          </el-table-column>
          <el-table-column
            prop="description"
            :label="$t('common.description')"
            min-width="180"
          />
        </el-table>

        <el-input
          v-if="subjectMode === 'users'"
          v-model="userSearchText"
          :placeholder="$t('authzWizard.searchUserPlaceholder')"
          clearable
          style="margin-bottom: 15px"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
        <el-table
          v-if="subjectMode === 'users'"
          ref="userTableRef"
          :data="filteredUserList"
          height="350"
          @selection-change="handleUserSelectionChange"
        >
          <el-table-column
            type="selection"
            width="55"
          />
          <el-table-column
            prop="id"
            label="ID"
            width="80"
          />
          <el-table-column
            prop="username"
            :label="$t('common.username')"
            min-width="150"
          />
          <el-table-column
            prop="email"
            label="Email"
            min-width="200"
          />
          <el-table-column
            :label="$t('common.role')"
            width="150"
          >
            <template #default="{ row }">
              <!-- 角色取 role.name（原噴整包 role 物件 JSON，authorization-page-redesign 修錯） -->
              <el-tag
                v-for="role in row.roles || []"
                :key="role.id"
                size="small"
                style="margin-right: 5px"
              >
                {{ role.name }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('common.status')"
            width="80"
          >
            <template #default="{ row }">
              <!-- API 欄位為 active（原讀不存在的 is_active 致全員誤標停用） -->
              <el-tag
                :type="row.active ? 'success' : 'info'"
                size="small"
              >
                {{ row.active ? $t('common.enabled') : $t('common.disabled') }}
              </el-tag>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <!-- Step 2: 選擇資產（逐資產或節點含子樹，asset-node-tree D5） -->
      <div v-show="currentStep === 1">
        <el-radio-group
          v-model="targetMode"
          style="margin-bottom: 15px"
        >
          <el-radio-button value="assets">
            {{ $t('authzWizard.targetIndividual') }}
          </el-radio-button>
          <el-radio-button value="groups">
            {{ $t('authzWizard.targetNode') }}
          </el-radio-button>
        </el-radio-group>

        <template v-if="targetMode === 'groups'">
          <el-alert
            type="info"
            :closable="false"
            show-icon
            style="margin-bottom: 10px"
            :title="$t('authzWizard.nodeScopeAlert')"
          />
          <el-tree
            ref="nodeCheckTreeRef"
            :data="nodeTreeOptions"
            :props="{ label: 'label', children: 'children' }"
            node-key="id"
            show-checkbox
            check-strictly
            default-expand-all
            class="node-check-tree"
            @check="handleNodeCheck"
          />
        </template>

        <!-- 挑選輔助（authz-tag-node-filters D6）：搜尋/節點/標籤伺服端過濾疊加，
             reserve-selection 跨篩選保勾選 -->
        <div
          v-if="targetMode === 'assets'"
          class="asset-filter-row"
        >
          <el-input
            v-model="assetSearchText"
            :placeholder="$t('authzWizard.searchAssetPlaceholder')"
            clearable
            class="asset-search-input"
            @input="scheduleAssetReload"
            @clear="reloadAssetList"
          >
            <template #prefix>
              <el-icon><Search /></el-icon>
            </template>
          </el-input>
          <el-tree-select
            v-model="assetNodeFilter"
            :data="nodeTreeOptions"
            :props="{ label: 'label', children: 'children' }"
            node-key="id"
            check-strictly
            clearable
            :placeholder="$t('authzWizard.filterByNodePlaceholder')"
            class="asset-node-filter"
            @change="reloadAssetList"
          />
          <el-select
            v-model="assetTagFilter"
            multiple
            filterable
            collapse-tags
            clearable
            :placeholder="$t('authzWizard.filterByTagPlaceholder')"
            class="asset-tag-filter"
            @change="reloadAssetList"
          >
            <el-option
              v-for="tag in tagOptions"
              :key="tag.name"
              :label="tag.name"
              :value="tag.name"
            />
          </el-select>
        </div>
        <!-- 誠實截斷（不得靜默）：total 超過已載入數即警示 -->
        <el-alert
          v-if="targetMode === 'assets' && assetListTruncated"
          type="warning"
          :closable="false"
          show-icon
          :title="$t('authzWizard.assetTruncated', { loaded: assetList.length, total: assetListTotal })"
          style="margin-bottom: 10px"
        />
        <div
          v-if="targetMode === 'assets' && selectedAssets.length"
          class="selected-count-hint"
        >
          {{ $t('authzWizard.selectedAssetsHint', { n: selectedAssets.length }) }}
        </div>
        <el-table
          v-if="targetMode === 'assets'"
          ref="assetTableRef"
          v-loading="assetListLoading"
          row-key="id"
          :data="assetList"
          height="350"
          @selection-change="handleAssetSelectionChange"
        >
          <el-table-column
            type="selection"
            reserve-selection
            width="55"
          />
          <el-table-column
            prop="id"
            label="ID"
            width="80"
          />
          <el-table-column
            prop="name"
            :label="$t('common.assetName')"
            min-width="150"
          />
          <el-table-column
            :label="$t('common.protocol')"
            width="110"
          >
            <template #default="{ row }">
              <el-tag
                :type="protocolTagType(row.protocol)"
                size="small"
              >
                {{ row.protocol.toUpperCase() }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column
            :label="$t('assets.host')"
            min-width="180"
          >
            <template #default="{ row }">
              {{ row.host }}:{{ row.port }}
            </template>
          </el-table-column>
        </el-table>
      </div>

      <!-- Step 3: 選擇權限 -->
      <div
        v-show="currentStep === 2"
        class="permission-step"
      >
        <el-radio-group
          v-model="selectedPermission"
          size="large"
        >
          <el-radio-button label="view">
            <el-icon><View /></el-icon>
            {{ $t('assets.permission.view') }}
          </el-radio-button>
          <el-radio-button label="connect">
            <el-icon><Connection /></el-icon>
            {{ $t('assets.permission.connect') }}
          </el-radio-button>
        </el-radio-group>
        <div class="permission-description">
          <el-alert
            :title="getPermissionDescription(selectedPermission)"
            type="info"
            :closable="false"
          />
        </div>
      </div>

      <!-- Step 4: 確認摘要 -->
      <div
        v-show="currentStep === 3"
        class="summary-step"
      >
        <el-descriptions
          border
          :column="1"
        >
          <el-descriptions-item :label="$t('authorizations.colSubject')">
            <div v-if="selectedUsers.length">
              {{ $t('authzWizard.summaryUsers', { n: selectedUsers.length }) }}
              <el-text type="info">
                {{ selectedUsers.map(u => u.username).join(', ') }}
              </el-text>
            </div>
            <div v-if="selectedUserGroups.length">
              {{ $t('authzWizard.summaryUserGroups', { n: selectedUserGroups.length }) }}
              <el-text type="info">
                {{ $t('authzWizard.groupSummaryEffect', { names: selectedUserGroups.map(g => g.name).join(', ') }) }}
              </el-text>
            </div>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('authzWizard.summaryObject')">
            <div v-if="selectedAssets.length">
              {{ $t('authzWizard.summaryAssets', { n: selectedAssets.length }) }}
              <el-text type="info">
                {{ selectedAssets.map(a => a.name).join(', ') }}
              </el-text>
            </div>
            <div v-if="selectedGroups.length">
              {{ $t('authzWizard.summaryNodes', { n: selectedGroups.length }) }}
              <el-text type="info">
                {{ $t('authzWizard.nodeSummaryEffect', { names: selectedGroups.map(g => g.path || g.name).join(', ') }) }}
              </el-text>
            </div>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('authzWizard.summaryPermissionType')">
            <el-tag :type="getPermissionTagType(selectedPermission)">
              {{ getPermissionText(selectedPermission) }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item :label="$t('authzWizard.summaryWillCreate')">
            <el-text
              type="danger"
              size="large"
            >
              {{ $t('authzWizard.maxRecords', { n: (selectedUsers.length + selectedUserGroups.length) * (selectedAssets.length + selectedGroups.length) }) }}
            </el-text>
          </el-descriptions-item>
        </el-descriptions>

        <!-- 進度顯示 -->
        <div
          v-if="batchProcessing"
          class="batch-progress"
        >
          <el-progress
            :percentage="batchProgress"
            :status="batchProgressStatus"
          />
          <p class="batch-progress-text">
            {{ $t('authzWizard.processing', { done: batchProcessedCount, total: batchTotalCount }) }}
          </p>
        </div>
      </div>
    </div>

    <template #footer>
      <el-button
        :disabled="batchProcessing"
        @click="$emit('update:modelValue', false)"
      >
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        v-if="currentStep > 0"
        :disabled="batchProcessing"
        @click="handlePreviousStep"
      >
        {{ $t('authzWizard.prevStep') }}
      </el-button>
      <el-button
        v-if="currentStep < 3"
        type="primary"
        :disabled="!canProceedToNextStep"
        @click="handleNextStep"
      >
        {{ $t('authzWizard.nextStep') }}
      </el-button>
      <el-button
        v-if="currentStep === 3"
        type="primary"
        :loading="batchProcessing"
        @click="handleBatchSubmit"
      >
        {{ $t('authzWizard.stepConfirm') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { ref, computed, watch, nextTick } from 'vue'
import { protocolTagType } from '@/utils/protocol'
import { ElMessage } from 'element-plus'
import { Search, View, Connection } from '@element-plus/icons-vue'
import { batchCreateAuthorizations } from '@/api/authorizations'
import { getAssetGroups, getAssetList, getAssetTags } from '@/api/assets'
import { getUserGroups } from '@/api/userGroups'
import { getUsers } from '@/api/auth'
import { t } from '@/i18n'

// 批次授權精靈（authorization-page-redesign D6：自 Authorizations.vue 拆出，
// 流程零改動；prefillNodeId 承接資產樹「授權此節點」深連結預填契約）
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // 資產頁「授權此節點」?node_id 深連結預填：開啟時切節點模式並預勾該節點
  prefillNodeId: { type: Number, default: null },
})
const emit = defineEmits(['update:modelValue', 'completed'])

const currentStep = ref(0)
const subjectMode = ref('users')
const targetMode = ref('assets')
const selectedUsers = ref([])
const selectedUserGroups = ref([])
const selectedAssets = ref([])
const selectedGroups = ref([])
const selectedPermission = ref('view')
const userSearchText = ref('')
const assetSearchText = ref('')
const batchProcessing = ref(false)
const batchProgress = ref(0)
const batchProgressStatus = ref('')
const batchProcessedCount = ref(0)
const batchTotalCount = ref(0)

const userList = ref([])
const userGroupList = ref([])
const assetList = ref([])
const groupList = ref([])

// 挑選輔助（authz-tag-node-filters D6）：伺服端過濾狀態
const assetNodeFilter = ref(null)
const assetTagFilter = ref([])
const tagOptions = ref([])
const assetListTotal = ref(0)
const assetListLoading = ref(false)
// latest-request-wins：debounce 只降頻不防亂序，舊回應晚到不得覆蓋新結果
let assetRequestSeq = 0
let assetReloadTimer = null

const assetListTruncated = computed(
  () => assetListTotal.value > assetList.value.length
)

const assetListParams = () => {
  const params = { page_size: 1000 }
  if (assetSearchText.value) params.search = assetSearchText.value
  // include_subtree 預設含子樹（後端 D5 契約）
  if (assetNodeFilter.value) params.node_id = assetNodeFilter.value
  if (assetTagFilter.value.length) params.tags = assetTagFilter.value.join(',')
  return params
}

async function reloadAssetList() {
  const seq = ++assetRequestSeq
  assetListLoading.value = true
  try {
    const res = await getAssetList(assetListParams())
    if (seq !== assetRequestSeq) return
    assetList.value = res.data || []
    assetListTotal.value = res.total ?? (res.data || []).length
  } catch (err) {
    if (seq === assetRequestSeq) console.error('載入資產清單失敗:', err)
  } finally {
    if (seq === assetRequestSeq) assetListLoading.value = false
  }
}

const scheduleAssetReload = () => {
  clearTimeout(assetReloadTimer)
  assetReloadTimer = setTimeout(reloadAssetList, 300)
}

const userTableRef = ref(null)
const assetTableRef = ref(null)
const nodeCheckTreeRef = ref(null)

const filteredUserList = computed(() => {
  if (!userSearchText.value) return userList.value
  const q = userSearchText.value.toLowerCase()
  return userList.value.filter(
    u => u.username.toLowerCase().includes(q) || (u.email && u.email.toLowerCase().includes(q))
  )
})

const canProceedToNextStep = computed(() => {
  if (currentStep.value === 0) {
    return selectedUsers.value.length + selectedUserGroups.value.length > 0
  } else if (currentStep.value === 1) {
    return selectedAssets.value.length + selectedGroups.value.length > 0
  } else if (currentStep.value === 2) {
    return selectedPermission.value !== ''
  }
  return true
})

// 平面節點列表組樹（label 帶全路徑，供 checkbox 樹與確認步驟）
const nodeTreeOptions = computed(() => {
  const byId = new Map()
  groupList.value.forEach((n) => {
    byId.set(n.id, { id: n.id, name: n.name, path: n.path, label: n.name, parent_id: n.parent_id, children: [] })
  })
  const roots = []
  byId.forEach((n) => {
    if (n.parent_id && byId.has(n.parent_id)) {
      byId.get(n.parent_id).children.push(n)
    } else {
      roots.push(n)
    }
  })
  return roots
})

// 節點樹 checkbox（asset-node-tree D5）：check-strictly 各自獨立勾——
// 授節點語義已含子樹，父子連動勾選反而造成重複授權
const handleNodeCheck = () => {
  const checked = nodeCheckTreeRef.value?.getCheckedNodes() || []
  selectedGroups.value = checked
}

// 模式切換清殘留（codex 對抗審查 P1）：切到另一模式時隱藏面板的選擇
// 仍在 state，提交會靜默同時授權兩者——切換即清空對面模式的選擇
watch(targetMode, (mode) => {
  if (mode === 'assets') {
    selectedGroups.value = []
    nodeCheckTreeRef.value?.setCheckedKeys([])
  } else {
    selectedAssets.value = []
    assetTableRef.value?.clearSelection?.()
  }
})
watch(subjectMode, (mode) => {
  if (mode === 'users') {
    selectedUserGroups.value = []
  } else {
    selectedUsers.value = []
  }
})

const handleUserSelectionChange = (selection) => {
  selectedUsers.value = selection
}
const handleUserGroupSelectionChange = (selection) => {
  selectedUserGroups.value = selection
}
const handleAssetSelectionChange = (selection) => {
  selectedAssets.value = selection
}

async function loadLists() {
  try {
    const [users, userGroups, groups, tags] = await Promise.all([
      getUsers(),
      getUserGroups(),
      getAssetGroups(),
      getAssetTags(),
    ])
    userList.value = users.data || []
    userGroupList.value = userGroups.data || []
    groupList.value = groups.data || []
    tagOptions.value = tags.data || []
  } catch (err) {
    console.error('載入精靈選項失敗:', err)
  }
  // 資產清單走伺服端過濾（D6），與上列選項獨立載入
  await reloadAssetList()
}

// 開啟時載清單＋處理 node_id 預填（深連結契約：清單落地後預勾）。
// immediate：掛載時已 visible（如主頁帶 ?node_id 直開）也要載入
watch(
  () => props.modelValue,
  async (visible) => {
    if (!visible) return
    resetState()
    await loadLists()
    if (props.prefillNodeId) {
      targetMode.value = 'groups'
      await nextTick()
      const node = groupList.value.find((n) => n.id === props.prefillNodeId)
      selectedGroups.value = node ? [node] : []
      if (node && nodeCheckTreeRef.value) {
        nodeCheckTreeRef.value.setCheckedKeys([props.prefillNodeId])
      }
    }
  },
  { immediate: true }
)

const handlePreviousStep = () => {
  if (currentStep.value > 0) {
    currentStep.value--
  }
}
const handleNextStep = () => {
  if (currentStep.value < 3) {
    currentStep.value++
  }
}

// 批次提交：伺服端交易內展開（user-group-authorization D6），
// 主體集 users∪user_groups × 客體集 assets∪asset_groups，既有組合跳過
const handleBatchSubmit = async () => {
  batchProcessing.value = true
  batchProgress.value = 0
  batchProgressStatus.value = ''

  const payload = {
    user_ids: selectedUsers.value.map(u => u.id),
    user_group_ids: selectedUserGroups.value.map(g => g.id),
    asset_ids: selectedAssets.value.map(a => a.id),
    asset_group_ids: selectedGroups.value.map(g => g.id),
    permission: selectedPermission.value,
  }
  batchTotalCount.value =
    (payload.user_ids.length + payload.user_group_ids.length) *
    (payload.asset_ids.length + payload.asset_group_ids.length)
  batchProcessedCount.value = 0

  try {
    const res = await batchCreateAuthorizations(payload)

    batchProcessedCount.value = batchTotalCount.value
    batchProgress.value = 100
    batchProgressStatus.value = 'success'
    if (res.skipped > 0) {
      ElMessage.success(t('authzWizard.batchDoneWithSkipped', { created: res.created, skipped: res.skipped }))
    } else {
      ElMessage.success(t('authzWizard.batchDone', { created: res.created }))
    }

    setTimeout(() => {
      emit('update:modelValue', false)
      emit('completed', res)
    }, 1200)
  } catch (error) {
    batchProgressStatus.value = 'exception'
    console.error('批次授權失敗:', error)
  } finally {
    batchProcessing.value = false
  }
}

function resetState() {
  currentStep.value = 0
  selectedUsers.value = []
  selectedUserGroups.value = []
  selectedAssets.value = []
  selectedGroups.value = []
  subjectMode.value = 'users'
  targetMode.value = 'assets'
  selectedPermission.value = 'view'
  userSearchText.value = ''
  assetSearchText.value = ''
  batchProcessing.value = false
  batchProgress.value = 0
  batchProcessedCount.value = 0
  batchTotalCount.value = 0
  // 挑選輔助歸零＋顯式清空表格選擇（對抗驗證 M2：reserve-selection 跨資料
  // 替換保留，重開精靈殘留上次勾選＝溢授；廢棄在途請求防舊回應落地）
  assetNodeFilter.value = null
  assetTagFilter.value = []
  assetListTotal.value = 0
  assetRequestSeq++
  clearTimeout(assetReloadTimer)
  assetTableRef.value?.clearSelection?.()
  userTableRef.value?.clearSelection?.()
}

const handleClosed = () => {
  resetState()
}

const getPermissionTagType = (permission) => {
  const typeMap = { view: 'info', connect: 'success' }
  return typeMap[permission] || 'info'
}
const getPermissionText = (permission) =>
  t(permission === 'connect' ? 'assets.permission.connect' : 'assets.permission.view')
const getPermissionDescription = (permission) =>
  t(permission === 'connect' ? 'authzWizard.permDescConnect' : 'authzWizard.permDescView')

defineExpose({
  // 供單測驗證預填契約與內部狀態（拆檔後既有測試遷移點）
  currentStep,
  subjectMode,
  targetMode,
  selectedUsers,
  selectedUserGroups,
  selectedAssets,
  selectedGroups,
  selectedPermission,
  canProceedToNextStep,
  nodeTreeOptions,
  handleBatchSubmit,
  handleNodeCheck,
  // 挑選輔助（authz-tag-node-filters D6）
  assetList,
  assetListTotal,
  assetListTruncated,
  assetNodeFilter,
  assetTagFilter,
  tagOptions,
  reloadAssetList,
  scheduleAssetReload,
  resetState,
})
</script>

<style scoped>
.step-content {
  margin-top: 30px;
  min-height: 400px;
}

.asset-filter-row {
  display: flex;
  gap: 10px;
  margin-bottom: 15px;
}

.asset-search-input {
  flex: 1;
  min-width: 180px;
}

.asset-node-filter,
.asset-tag-filter {
  width: 220px;
}

.selected-count-hint {
  margin-bottom: 8px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

.permission-step {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 0;
}

.permission-step .el-radio-group {
  margin-bottom: 30px;
}

.permission-step .el-radio-button {
  margin: 0 10px;
}

.permission-description {
  width: 100%;
  max-width: 600px;
}

.summary-step {
  padding: var(--ot-space-md);
}

.batch-progress {
  margin-top: var(--ot-space-lg);
  text-align: center;
}

.batch-progress-text {
  margin-top: var(--ot-space-sm);
  color: var(--ot-text-secondary);
}
</style>
