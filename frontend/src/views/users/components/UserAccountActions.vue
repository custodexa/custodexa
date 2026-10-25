<template>
  <div
    v-if="layout === 'list'"
    class="account-actions-list"
  >
    <!-- 三顆按鈕不帶圖示：圖示在 en 下把本欄推到 280+，直接吃掉表格預算，
         而「編輯／外部身分」在文字之外沒有額外辨識價值 -->
    <el-button
      type="primary"
      size="small"
      link
      @click="$emit('edit', row)"
    >
      {{ $t('common.edit') }}
    </el-button>
    <!-- 外部身分管理：對每個帳號都開放——
         本地帳號亦可由 admin 綁定外部身分（UA-1「admin SHALL 可為既有帳號
         顯式綁定」），只對 oidc 來源開放會使該路徑無從進入。
         這是本 change 的主要入口，維持常駐可見，不收進選單 -->
    <el-button
      v-if="states.bind_identity.visible"
      type="primary"
      size="small"
      link
      @click="$emit('open-identities', row)"
    >
      {{ $t('users.externalIdentities') }}
    </el-button>
    <el-button
      v-if="row.kind === 'agent'"
      type="primary"
      size="small"
      link
      data-test="open-agent-tokens"
      @click="$emit('keys', row)"
    >
      {{ $t('agentPrincipals.keys') }}
    </el-button>
    <el-dropdown
      class="row-more"
      trigger="click"
      placement="bottom-end"
      :popper-options="menuPopperOptions"
      @command="handleRowCommand"
    >
      <el-button
        size="small"
        link
      >
        {{ $t('common.more') }}<el-icon class="more-caret">
          <ChevronDown />
        </el-icon>
      </el-button>
      <template #dropdown>
        <el-dropdown-menu>
          <!-- 變更密碼：外部身分帳號無本地密碼，保留項目但停用並
               就地說明原因（隱藏會讓人以為功能不存在）。停用項的 tooltip
               在 EP 下不會觸發（pointer-events: none），故原因寫成副行；
               用短句而非完整 tooltip 文案——長句會把選單撐到 217×297，
               在最後幾列會同時貼齊視窗右緣與下緣 -->
          <el-dropdown-item
            v-if="states.set_password.visible"
            command="changePassword"
            :disabled="states.set_password.disabled"
          >
            <!-- 包一層自有容器：`el-dropdown-item` 的根元素**不帶本元件的
                 scoped 屬性**（EP 內部以 collection item 重新渲染），
                 直接對它下 scoped 樣式不會生效；而該根是 flex row，
                 副行不包起來會被排到標題右側，把選單撐到 336px 寬 -->
            <div class="item-body">
              <span>{{ $t('common.changePassword') }}</span>
              <span
                v-if="states.set_password.disabled"
                class="item-note"
              >{{ $t('users.externalPasswordShort') }}</span>
            </div>
          </el-dropdown-item>
          <el-dropdown-item command="assignRoles">
            {{ $t('users.assignRoles') }}
          </el-dropdown-item>
          <el-dropdown-item
            v-if="hasApproverRole"
            command="scopes"
          >
            {{ $t('menu.approverScopes') }}
          </el-dropdown-item>
          <el-dropdown-item
            v-if="states.unlock.visible"
            command="unlock"
          >
            {{ $t('users.unlock') }}
          </el-dropdown-item>
          <el-dropdown-item
            v-if="states.disable_mfa.visible"
            command="disableMfa"
            divided
          >
            <span class="danger-item">{{ $t('common.disableMfa') }}</span>
          </el-dropdown-item>
          <el-dropdown-item
            command="delete"
            divided
          >
            <span class="danger-item">{{ $t('common.delete') }}</span>
          </el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
  <div
    v-else
    class="account-ops"
    data-test="account-ops"
  >
    <div class="account-ops__head">
      <h3>{{ $t('userDetail.accountOps.title') }}</h3>
      <span class="account-ops__same">{{ $t('userDetail.accountOps.sameAsList') }}</span>
    </div>
    <div
      v-for="key in panelKeys"
      :key="key"
    >
      <div
        v-if="states[key].visible"
        class="account-op"
        :data-test="`account-op-${key}`"
      >
        <div class="account-op__text">
          <div class="account-op__title">
            {{ opTitle(key) }}
            <el-tag
              v-if="states[key].notify"
              size="small"
              type="warning"
              effect="plain"
              :data-test="`account-op-notify-${key}`"
            >
              {{ $t('userDetail.accountOps.notify.badge') }}
            </el-tag>
          </div>
          <div class="account-op__desc">
            {{ opDesc(key) }}
          </div>
          <div
            v-if="states[key].disabled && states[key].reason"
            class="account-op__reason"
            :data-test="`account-op-reason-${key}`"
          >
            {{ $t(states[key].reason) }}
          </div>
        </div>
        <el-button
          :type="key === 'delete' || key === 'disable' ? 'danger' : 'default'"
          size="small"
          :disabled="states[key].disabled || busy"
          :data-test="`account-op-btn-${key}`"
          @click="runOp(key)"
        >
          {{ opTitle(key) }}
        </el-button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ChevronDown } from 'lucide-vue-next'
import { t } from '@/i18n'
import { confirmDestructive } from '@/utils/confirm'
import { hasRole } from '@/composables/useRoles'
import { accountActionStates } from '../accountActionStates'
import {
  handleStatusChange,
  unlockAccount,
  disableAccountMfa,
  deleteAccount,
} from '../accountActionHandlers'

/**
 * 帳號動作。列表頁（layout="list"）與詳情頁基本資料分頁（layout="panel"）共用：
 * 可見性與停用條件來自 accountActionStates，詳情頁另帶伺服器下發的保護分類。
 * 對話框與抽屜由頁面上的 UserAccountDialogs 承載，這裡只發出開啟事件。
 */
const props = defineProps({
  row: { type: Object, required: true },
  layout: { type: String, default: 'list' },
  // 保護分類（單筆讀取才有）；列表頁不帶
  accountOps: { type: Object, default: null },
})
const emit = defineEmits(['edit', 'keys', 'manage-scopes', 'open-password', 'open-identities', 'changed', 'deleted'])

const router = useRouter()
const busy = ref(false)
const states = computed(() => accountActionStates(props.row, props.accountOps))
const hasApproverRole = computed(() => hasRole(props.row.roles, 'approver'))

// 列上「更多」選單靠右對齊（bottom-end）：en-US 的長項目會把選單推到距視窗
// 右緣僅 1px。preventOverflow 的 padding 保底留白，保留 EP 預設的 computeStyles 設定
const menuPopperOptions = {
  modifiers: [
    { name: 'computeStyles', options: { gpuAcceleration: false } },
    { name: 'preventOverflow', options: { padding: 12 } },
  ],
}

const panelKeys = [
  'set_password',
  'disable_mfa',
  'bind_identity',
  'unbind_identity',
  'unbind_and_disable',
  'unlock',
  'disable',
  'enable',
  'delete',
]
const opTitle = (key) => (key === 'unlock' ? t('users.unlock') : t(`userDetail.accountOps.${key}.title`))
const opDesc = (key) => {
  if (key === 'unbind_identity') {
    const n = Array.isArray(props.row.auth_provider_names) ? props.row.auth_provider_names.length : 0
    return t('userDetail.accountOps.unbind_identity.desc', { n })
  }
  return t(`userDetail.accountOps.${key}.desc`)
}

// 會通知安全人員的操作：執行前先提示，確認後才送出
const confirmNotify = async (key) => {
  const body = key === 'set_password'
    ? t('userDetail.accountOps.notify.passwordDialog')
    : t('userDetail.accountOps.notify.dialogBody', { action: opTitle(key) })
  try {
    await confirmDestructive(body, t('userDetail.accountOps.notify.dialogTitle'), {
      confirmButtonText: t('common.confirm'),
      cancelButtonText: t('common.cancel'),
    })
    return true
  } catch {
    return false
  }
}

const dispatch = {
  set_password: () => emit('open-password', props.row),
  bind_identity: () => emit('open-identities', props.row),
  unbind_identity: () => emit('open-identities', props.row),
  unbind_and_disable: () => emit('open-identities', props.row),
  disable_mfa: async () => { if (await disableAccountMfa(props.row)) emit('changed') },
  unlock: async () => { if (await unlockAccount(props.row)) emit('changed') },
  delete: async () => { if (await deleteAccount(props.row)) emit('deleted') },
  disable: async () => { if (await setActive(false)) emit('changed') },
  enable: async () => { if (await setActive(true)) emit('changed') },
}
const setActive = (active) => handleStatusChange({ ...props.row, active })

const runOp = async (key) => {
  const state = states.value[key]
  if (!state?.visible || state.disabled || busy.value) return
  busy.value = true
  try {
    if (state.notify && !(await confirmNotify(key))) return
    await dispatch[key]()
  } finally {
    busy.value = false
  }
}

// 「更多」選單的命令分派：選單項不各自綁 handler，集中一處才看得出哪些操作
// 被收進選單（以及哪些是破壞性的）
const handleRowCommand = (command) => {
  const row = props.row
  const handlers = {
    changePassword: () => emit('open-password', row),
    assignRoles: () => router?.push({ path: `/users/${row.id}`, query: { tab: 'roles' } }),
    scopes: () => emit('manage-scopes', row),
    unlock: async () => { if (await unlockAccount(row)) emit('changed') },
    disableMfa: async () => { if (await disableAccountMfa(row)) emit('changed') },
    delete: async () => { if (await deleteAccount(row)) emit('deleted') },
  }
  handlers[command]?.()
}
</script>

<style scoped>
.more-caret {
  margin-left: 2px;
}

/* Element Plus 的按鈕間距靠相鄰選擇器 `.el-button + .el-button` 給，被
   `el-dropdown` 包住的按鈕不再是前一顆的相鄰兄弟，margin 直接失效——
   結果是「更多」觸發鈕與前一顆按鈕的點擊熱區貼在一起（gap 0px），
   且 el-dropdown 預設 vertical-align: top 使兩者基線差 4px */
.row-more {
  margin-left: 12px;
  vertical-align: middle;
}

/* 選單內的破壞性項目與一般項目分色（配合 divided 分隔線） */
.danger-item {
  color: var(--el-color-danger);
}

/* 停用選單項的原因就地說明（停用項不觸發 tooltip） */
.item-body {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  line-height: 1.4;
}

.item-note {
  display: block;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
  line-height: 1.4;
}

.account-ops {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-sm);
}
.account-ops__head {
  display: flex;
  align-items: baseline;
  gap: var(--ot-space-md);
}
.account-ops__head h3 {
  margin: 0;
  font-size: var(--ot-font-size-md);
  color: var(--ot-text-primary);
}
.account-ops__same {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.account-op {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--ot-space-md);
  padding: var(--ot-space-sm) var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.account-op__title {
  display: flex;
  align-items: center;
  gap: var(--ot-space-xs);
  font-weight: 600;
  color: var(--ot-text-primary);
}
.account-op__desc {
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
}
.account-op__reason {
  margin-top: 2px;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-warning);
}
</style>
