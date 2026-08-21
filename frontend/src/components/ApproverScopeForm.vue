<template>
  <div class="scope-form">
    <el-alert
      v-if="showHelp"
      type="info"
      :closable="false"
      class="scope-help"
    >
      <ul class="scope-help-list">
        <li
          v-for="line in SCOPE_SEMANTICS_LINES"
          :key="line"
        >
          {{ line }}
        </li>
      </ul>
    </el-alert>
    <el-form
      label-position="top"
      @submit.prevent
    >
      <template v-if="!presetActor">
        <el-form-item :label="$t('approverScopes.colActor')">
          <el-radio-group v-model="form.actorType">
            <el-radio
              v-for="(meta, key) in ACTOR_TYPES"
              :key="key"
              :value="key"
            >
              {{ meta.label }}
            </el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="$t('approverScopeForm.selectActor', { actor: ACTOR_TYPES[form.actorType]?.label })">
          <el-select
            v-model="form.actorId"
            filterable
            clearable
            :placeholder="$t('approverScopeForm.searchByNamePlaceholder')"
            style="width: 100%"
          >
            <el-option
              v-for="opt in currentActorOptions"
              :key="opt.id"
              :label="opt.label"
              :value="opt.id"
            />
          </el-select>
        </el-form-item>
      </template>
      <el-form-item :label="$t('approverScopeForm.scopeTypeLabel')">
        <el-radio-group v-model="form.type">
          <el-radio
            v-for="(meta, key) in SCOPE_TYPES"
            :key="key"
            :value="key"
          >
            {{ meta.label }}
          </el-radio>
        </el-radio-group>
      </el-form-item>
      <el-form-item :label="$t('approverScopeForm.selectTarget', { type: SCOPE_TYPES[form.type]?.label || $t('approverScopeForm.targetFallback') })">
        <el-select
          v-model="form.targetId"
          filterable
          clearable
          :placeholder="$t('approverScopeForm.searchByNamePlaceholder')"
          style="width: 100%"
        >
          <el-option
            v-for="opt in currentOptions"
            :key="opt.id"
            :label="opt.label"
            :value="opt.id"
          />
        </el-select>
      </el-form-item>
      <el-button
        type="primary"
        :loading="submitting"
        :disabled="!canSubmit"
        @click="handleSubmit"
      >
        {{ $t('approverScopeForm.submit') }}
      </el-button>
    </el-form>
  </div>
</template>

<script setup>
// 審核範圍新增表單（approval-routing-quorum D-5/D-7）：矩陣頁與 Users 對話框
// 共用同一組件避免雙入口漂移；審核方（個人代配角色/群組零代配）與客體四維、
// 語義說明走 utils/approver-scope 事實源
import { ref, reactive, computed, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { getAssetGroups, getAssetList } from '@/api/assets'
import { getUserList, addUserRole } from '@/api/user'
import { getUserGroups } from '@/api/userGroups'
import { createApproverScope } from '@/api/accessRequests'
import { roleNames } from '@/composables/useRoles'
import { t } from '@/i18n'
import {
  SCOPE_TYPES,
  ACTOR_TYPES,
  SCOPE_SEMANTICS_LINES,
  buildGroupPaths,
} from '@/utils/approver-scope'

const props = defineProps({
  // 預選審核方（列內/格內捷徑）：{ type: 'user'|'group', id }；null＝表單內選擇
  presetActor: { type: Object, default: null },
  // 預選範圍類型（格內＋捷徑）
  presetType: { type: String, default: '' },
  // 預選客體（客體中心視角的節點列＋捷徑：類型與客體都預填，只選審核方）
  presetTargetId: { type: Number, default: null },
  showHelp: { type: Boolean, default: true },
})
const emit = defineEmits(['created'])

const form = reactive({
  actorType: 'user',
  actorId: null,
  type: props.presetType || 'asset',
  targetId: props.presetTargetId,
})
const submitting = ref(false)
const options = reactive({
  asset: [], asset_group: [], subject_user: [], subject_group: [],
  actor_user: [], actor_group: [],
})
const loaded = ref(false)

const currentOptions = computed(() => options[form.type] || [])
const currentActorOptions = computed(() =>
  form.actorType === 'user' ? options.actor_user : options.actor_group
)
const canSubmit = computed(() =>
  form.targetId && (props.presetActor || form.actorId)
)

watch(() => form.type, () => {
  form.targetId = null
})
watch(() => form.actorType, () => {
  form.actorId = null
})
watch(() => props.presetType, (v) => {
  if (v) form.type = v
})

const loadOptions = async () => {
  if (loaded.value) return
  try {
    const [assetRes, groupRes, userRes, ugroupRes] = await Promise.all([
      getAssetList({ page: 1, page_size: 1000 }),
      getAssetGroups(),
      getUserList({ page: 1, page_size: 1000 }),
      getUserGroups(),
    ])
    options.asset = (assetRes.data || []).map((a) => ({ id: a.id, label: a.name }))
    const groups = groupRes.data || []
    const paths = buildGroupPaths(groups)
    options.asset_group = groups.map((g) => ({ id: g.id, label: paths[g.id] || g.name }))
    const users = userRes.data || []
    options.subject_user = users.map((u) => ({ id: u.id, label: u.username }))
    const ugroups = (ugroupRes.data || []).map((g) => ({ id: g.id, label: g.name }))
    options.subject_group = ugroups
    options.actor_group = ugroups
    // 審核方個人：排除 admin（恆可核，配範圍無意義）與 auditor（稽核與審批職能衝突）；
    // 未具 approver 角色者標註代配（一站式，D-5）
    options.actor_user = users
      .filter((u) => {
        const names = roleNames(u.roles)
        return !names.includes('admin') && !names.includes('auditor')
      })
      .map((u) => ({
        id: u.id,
        label: roleNames(u.roles).includes('approver')
          ? u.username
          : t('approverScopeForm.actorNeedsRoleLabel', { username: u.username }),
        needsRole: !roleNames(u.roles).includes('approver'),
        username: u.username,
        roles: roleNames(u.roles),
      }))
    loaded.value = true
  } catch (error) {
    console.error('載入範圍選項失敗:', error)
  }
}
loadOptions()

const fieldByType = {
  asset: 'asset_id',
  asset_group: 'asset_group_id',
  subject_user: 'subject_user_id',
  subject_group: 'subject_group_id',
}

const handleSubmit = async () => {
  if (!canSubmit.value) return

  const actor = props.presetActor || { type: form.actorType, id: form.actorId }

  // 一站式代配（D-5）：表單內選到未具 approver 角色的個人 → 確認後先配角色。
  // 兩步各自入審計；第一步成功第二步失敗不回滾角色（誠實提示，重試只補第二步）
  let assignRoleFirst = null
  if (!props.presetActor && actor.type === 'user') {
    const opt = options.actor_user.find((o) => o.id === actor.id)
    if (opt?.needsRole) {
      try {
        await ElMessageBox.confirm(
          t('approverScopeForm.assignRoleConfirm', { username: opt.username }),
          t('approverScopeForm.assignRoleTitle'),
          { confirmButtonText: t('approverScopeForm.continue'), cancelButtonText: t('common.cancel'), type: 'warning' }
        )
      } catch {
        return
      }
      assignRoleFirst = opt
    }
  }

  submitting.value = true
  try {
    if (assignRoleFirst) {
      try {
        // 冪等追加端點（codex #1）：不整包覆蓋角色集，
        // 避免載入後他處改過角色時以過期快照蓋回
        await addUserRole(assignRoleFirst.id, 'approver')
        assignRoleFirst.needsRole = false
        assignRoleFirst.roles = [...assignRoleFirst.roles, 'approver']
        assignRoleFirst.label = assignRoleFirst.username
      } catch (error) {
        console.error('分配審核人員角色失敗:', error)
        return
      }
    }
    const payload = {}
    if (actor.type === 'group') payload.approver_group_id = actor.id
    else payload.approver_id = actor.id
    payload[fieldByType[form.type]] = form.targetId
    try {
      await createApproverScope(payload)
    } catch (error) {
      if (assignRoleFirst) {
        ElMessage.warning(t('approverScopeForm.roleAssignedScopeFailed'))
      }
      console.error('分配審核範圍失敗:', error)
      return
    }
    ElMessage.success(t('approverScopeForm.scopeAssigned'))
    form.targetId = null
    emit('created')
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.scope-help {
  margin-bottom: 16px;
}

.scope-help-list {
  margin: 0;
  padding-left: 18px;
  line-height: 1.8;
}
</style>
