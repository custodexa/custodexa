<template>
  <div class="mapping">
    <slot name="attr" />

    <!-- 來源尚未建立：規則以來源為軸，沒有來源就沒有可掛的地方 -->
    <el-alert
      v-if="!sourceId"
      class="mapping__notice"
      type="info"
      :title="$t('identitySources.mapping.needSaveFirst')"
      :closable="false"
      show-icon
    />
    <!-- 端點尚未提供：說出「這一塊現在讀不到」，不要留白畫面 -->
    <el-alert
      v-else-if="unavailable"
      class="mapping__notice"
      type="info"
      :title="$t('identitySources.backendPending')"
      :description="$t('identitySources.mapping.backendPendingDesc')"
      :closable="false"
      show-icon
    />
    <el-alert
      v-else-if="loadFailed"
      class="mapping__notice"
      type="error"
      :title="$t('identitySources.mapping.loadFailed')"
      :closable="false"
      show-icon
    />

    <!-- 依目標角色篩選：稽核者要回答「哪些外部群組取得了管理員角色」時，
         規則多的來源上逐列目視不可行。純前端過濾——規則以來源為軸，一個來源的
         規則數量本來就在一次讀取的範圍內，再走一次查詢只是多一列稽核記錄 -->
    <div class="mapping__toolbar">
      <span class="mapping__toolbar-label">{{ $t('identitySources.mapping.filterRole') }}</span>
      <el-select
        v-model="roleFilter"
        class="mapping__toolbar-select"
        size="small"
        data-test="mapping-role-filter"
        :placeholder="$t('identitySources.mapping.filterRoleAll')"
      >
        <el-option
          :label="$t('identitySources.mapping.filterRoleAll')"
          value=""
        />
        <el-option
          v-for="r in filterRoleOptions"
          :key="r"
          :label="roleLabel(r)"
          :value="r"
        />
      </el-select>
    </div>

    <el-table
      v-loading="loading"
      :data="visibleRules"
      size="small"
      style="width: 100%"
    >
      <el-table-column
        :label="matchLabel"
        min-width="280"
      >
        <template #default="{ row }">
          <el-input
            v-if="editingId === row.id"
            v-model="editDraft.match_value"
            size="small"
          />
          <span
            v-else
            class="mapping__value"
          >{{ row.match_value }}</span>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('identitySources.mapping.role')"
        width="150"
      >
        <template #default="{ row }">
          <el-select
            v-if="editingId === row.id"
            v-model="editDraft.role"
            size="small"
          >
            <el-option
              v-for="r in roleOptions"
              :key="r"
              :label="roleLabel(r)"
              :value="r"
            />
          </el-select>
          <el-tag
            v-else
            size="small"
            :type="roleTagType(row.role)"
            effect="plain"
          >
            {{ roleLabel(row.role) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('common.status')"
        width="90"
      >
        <template #default="{ row }">
          <el-switch
            v-if="editingId === row.id"
            v-model="editDraft.enabled"
            size="small"
          />
          <el-switch
            v-else
            :model-value="row.enabled"
            size="small"
            :disabled="busy"
            @change="toggleRule(row, $event)"
          />
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('identitySources.mapping.createdBy')"
        width="160"
      >
        <template #default="{ row }">
          <span class="mapping__meta">{{ row.created_by }}</span>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('common.actions')"
        width="130"
        align="right"
      >
        <template #default="{ row }">
          <template v-if="editingId === row.id">
            <el-button
              type="primary"
              size="small"
              link
              :loading="busy"
              @click="saveEdit(row)"
            >
              {{ $t('common.save') }}
            </el-button>
            <el-button
              size="small"
              link
              @click="editingId = null"
            >
              {{ $t('common.cancel') }}
            </el-button>
          </template>
          <template v-else>
            <el-button
              type="primary"
              size="small"
              link
              @click="startEdit(row)"
            >
              {{ $t('common.edit') }}
            </el-button>
            <el-button
              type="danger"
              size="small"
              link
              @click="removeRule(row)"
            >
              {{ $t('common.delete') }}
            </el-button>
          </template>
        </template>
      </el-table-column>
      <template #empty>
        <span class="mapping__empty">{{
          roleFilter ? $t('identitySources.mapping.emptyFiltered') : $t('identitySources.mapping.empty')
        }}</span>
      </template>
    </el-table>

    <!-- 行內新增：不另開對話框——建立一條規則只有三個值，開框反而多兩次點擊。
         端點暫時讀不到時**不停用輸入**：正在打的內容不該因為一次伺服端狀況被清空，
         失敗由送出時的訊息與上方聲明承擔（來源尚未建立才是真的無處可掛） -->
    <div class="mapping__new">
      <el-input
        v-model="draft.match_value"
        class="mapping__new-value"
        size="small"
        :disabled="!sourceId"
        :placeholder="matchPlaceholder"
      />
      <el-select
        v-model="draft.role"
        class="mapping__new-role"
        size="small"
        :disabled="!sourceId"
        :placeholder="$t('identitySources.mapping.rolePlaceholder')"
      >
        <el-option
          v-for="r in roleOptions"
          :key="r"
          :label="roleLabel(r)"
          :value="r"
        />
      </el-select>
      <el-switch
        v-model="draft.enabled"
        size="small"
        :disabled="!sourceId"
      />
      <el-button
        type="primary"
        size="small"
        :loading="busy"
        :disabled="!sourceId || !draft.match_value || !draft.role"
        @click="addRule"
      >
        {{ $t('identitySources.mapping.add') }}
      </el-button>
    </div>

    <div class="mapping__hint">
      {{ matchHint }}
    </div>
    <div class="mapping__hint">
      {{ $t('identitySources.mapping.adminNote') }}
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { t } from '@/i18n'
import { roleLabel, roleTagType } from '@/constants/roles'
import { confirmDestructive } from '@/utils/confirm'
import { confirmWarnings, withRiskGate } from '@/utils/mappingRiskGate'
import { apiErrorSummary } from '@/api/redact'
import { getRoleList } from '@/api/user'
import {
  getSourceMappings,
  createSourceMapping,
  updateSourceMapping,
  deleteSourceMapping,
  isNotImplemented,
} from '@/api/identitySources'

const props = defineProps({
  type: { type: String, required: true },
  // 來源尚未儲存時為 null：此時只顯示提示，不呼叫任何端點
  sourceId: { type: [Number, String], default: null },
  // 群組屬性名或群組宣告名是否已設定：未設定時新增規則要先確認
  attrSet: { type: Boolean, default: true },
})

const emit = defineEmits(['count-change'])

const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const loading = ref(false)
const busy = ref(false)
const loadFailed = ref(false)
const unavailable = ref(false)
const rules = ref([])
const roleOptions = ref(['admin', 'auditor', 'approver', 'user'])
const editingId = ref(null)
const editDraft = ref({ match_value: '', role: '', enabled: true })
const draft = ref({ match_value: '', role: '', enabled: true })
// 空字串＝全部。篩選只影響顯示，不影響回報給來源列表的規則條數
const roleFilter = ref('')

// 可篩的角色＝可指派角色 ∪ 現存規則實際用到的角色。後者不可省——角色被停用或
// 改名後，既有規則仍指著它，若只列前者那些規則會篩不出來
const filterRoleOptions = computed(() => {
  const names = new Set(roleOptions.value)
  rules.value.forEach((r) => { if (r?.role) names.add(r.role) })
  return [...names]
})

const visibleRules = computed(() =>
  roleFilter.value ? rules.value.filter((r) => r.role === roleFilter.value) : rules.value
)

const isDirectory = computed(() => props.type === 'ldap')

const matchLabel = computed(() =>
  isDirectory.value
    ? t('identitySources.mapping.matchDn')
    : t('identitySources.mapping.matchClaimValue')
)

const matchPlaceholder = computed(() =>
  isDirectory.value
    ? t('identitySources.mapping.matchDnPlaceholder')
    : t('identitySources.mapping.matchClaimValuePlaceholder')
)

// 比對規則的介面說明。目錄側走辨識名稱解析後比對——**屬性型別的大小寫不影響、
// 值的大小寫影響**，故最容易踩到的形態是把整串改成慣用的大寫排版；
// 提供者側兩家官方文件皆查無比對規則，取嚴為逐字相符
const matchHint = computed(() =>
  isDirectory.value
    ? t('identitySources.mapping.matchDnHint')
    : t('identitySources.mapping.matchClaimValueHint')
)

/**
 * 風險確認（規則側）：命中即先問，確認後帶 `risk_acknowledged` 重送。
 *
 * 兩層都要有——前端就近先問（省一次來回，也讓管理者在按下去之前讀到後果），
 * 伺服端回 422 時再問一次（前端不知道的判準以伺服端為準）。
 * **兩層都是警告加確認，不是阻擋**。確認流程本體與提供者儲存共用
 * `@/utils/mappingRiskGate`，兩處文案與語義不得分岔。
 */

// 前端可自行判定的兩種情形（與契約的警告碼同名）
const localWarnings = (role) => {
  const codes = []
  if (role === 'admin') codes.push('MAPPING_TARGETS_ADMIN_ROLE')
  if (!props.attrSet) codes.push('MAPPING_SOURCE_ATTR_UNSET')
  return codes
}

const fetchRules = async () => {
  if (!props.sourceId) {
    rules.value = []
    return
  }
  loading.value = true
  try {
    const res = await getSourceMappings(props.type, props.sourceId)
    rules.value = res?.data || []
    unavailable.value = false
    loadFailed.value = false
    emit('count-change', rules.value.length)
  } catch (error) {
    if (isNotImplemented(error)) {
      unavailable.value = true
      rules.value = []
    } else {
      loadFailed.value = true
      logFailure('identity_source_mappings_load_failed', error)
    }
  } finally {
    loading.value = false
  }
}

const fetchRoles = async () => {
  try {
    const res = await getRoleList()
    const names = (res?.data || res || []).map((r) => r.name).filter(Boolean)
    if (names.length) roleOptions.value = names
  } catch (error) {
    // 角色清單讀不到時沿用內建四角色：規則表不該因此完全不能用
    logFailure('identity_source_roles_load_failed', error)
  }
}

const addRule = async () => {
  const codes = localWarnings(draft.value.role)
  if (codes.length && !(await confirmWarnings(codes))) return
  busy.value = true
  try {
    const done = await withRiskGate((acknowledged) =>
      createSourceMapping(props.type, props.sourceId, {
        match_value: draft.value.match_value.trim(),
        role: draft.value.role,
        enabled: draft.value.enabled,
        risk_acknowledged: acknowledged || codes.length > 0,
      })
    )
    if (!done) return
    ElMessage.success(t('identitySources.mapping.added'))
    draft.value = { match_value: '', role: '', enabled: true }
    await fetchRules()
  } catch (error) {
    if (isNotImplemented(error)) {
      unavailable.value = true
      return
    }
    ElMessage.error(t('identitySources.mapping.saveFailed'))
    logFailure('identity_source_mapping_create_failed', error)
  } finally {
    busy.value = false
  }
}

const startEdit = (row) => {
  editingId.value = row.id
  editDraft.value = {
    match_value: row.match_value,
    role: row.role,
    enabled: row.enabled === true,
  }
}

const submitUpdate = async (row, patch) => {
  const codes = localWarnings(patch.role)
  if (codes.length && !(await confirmWarnings(codes))) return false
  busy.value = true
  try {
    const done = await withRiskGate((acknowledged) =>
      updateSourceMapping(props.type, props.sourceId, row.id, {
        ...patch,
        risk_acknowledged: acknowledged || codes.length > 0,
      })
    )
    if (!done) return false
    await fetchRules()
    return true
  } catch (error) {
    if (isNotImplemented(error)) {
      unavailable.value = true
      return false
    }
    ElMessage.error(t('identitySources.mapping.saveFailed'))
    logFailure('identity_source_mapping_update_failed', error)
    return false
  } finally {
    busy.value = false
  }
}

const saveEdit = async (row) => {
  const ok = await submitUpdate(row, {
    match_value: editDraft.value.match_value.trim(),
    role: editDraft.value.role,
    enabled: editDraft.value.enabled,
  })
  if (ok) {
    editingId.value = null
    ElMessage.success(t('identitySources.mapping.updated'))
  }
}

const toggleRule = async (row, next) => {
  const ok = await submitUpdate(row, {
    match_value: row.match_value,
    role: row.role,
    enabled: next === true,
  })
  // 失敗時把畫面切回實際狀態：開關留在使用者按下的位置等於謊報
  if (!ok) await fetchRules()
}

const removeRule = async (row) => {
  try {
    await confirmDestructive(
      t('identitySources.mapping.deleteConfirm', {
        value: row.match_value,
        role: roleLabel(row.role),
      }),
      t('common.deleteConfirmTitle'),
      {
        confirmButtonText: t('common.deleteConfirmButton'),
        cancelButtonText: t('common.cancel'),
      }
    )
  } catch {
    return
  }
  busy.value = true
  try {
    await deleteSourceMapping(props.type, props.sourceId, row.id)
    ElMessage.success(t('identitySources.mapping.deleted'))
    await fetchRules()
  } catch (error) {
    if (isNotImplemented(error)) {
      unavailable.value = true
      return
    }
    ElMessage.error(t('identitySources.mapping.deleteFailed'))
    logFailure('identity_source_mapping_delete_failed', error)
  } finally {
    busy.value = false
  }
}

watch(() => props.sourceId, fetchRules)

onMounted(() => {
  fetchRoles()
  fetchRules()
})

defineExpose({ refresh: fetchRules })
</script>

<style scoped>
.mapping__notice {
  margin-bottom: var(--ot-space-sm);
}

.mapping__value {
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-xs);
  word-break: break-all;
}

.mapping__meta {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.mapping__empty {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.mapping__toolbar {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
}

.mapping__toolbar-label {
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.mapping__toolbar-select {
  width: 150px;
}

.mapping__new {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-top: var(--ot-space-sm);
}

.mapping__new-value {
  flex: 1;
  min-width: 0;
}

.mapping__new-role {
  width: 150px;
  flex-shrink: 0;
}

.mapping__hint {
  margin-top: var(--ot-space-xs);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.7;
}
</style>
