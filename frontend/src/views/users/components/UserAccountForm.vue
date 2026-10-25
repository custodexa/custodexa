<template>
  <component
    :is="shell"
    v-bind="shellProps"
  >
    <!-- 建立 agent 後的下一步：不直接關閉對話框，告訴管理者建好了、
         負責人是誰、下一步是發鑰匙。起因是建好 agent 後找不到發鑰匙的地方 -->
    <div
      v-if="createdAgent"
      class="agent-created"
      role="status"
      data-test="agent-created"
    >
      <div class="agent-created__head">
        <el-icon
          class="agent-created__icon"
          aria-hidden="true"
        >
          <CircleCheck />
        </el-icon>
        <div class="agent-created__summary">
          <div class="agent-created__title">
            {{ $t('agentPrincipals.createdTitle', { name: createdAgent.username }) }}
          </div>
          <div class="agent-created__owner">
            {{ $t('agentPrincipals.ownerValue', { owner: createdAgent.owner_username || $t('agentPrincipals.unavailable') }) }}
          </div>
        </div>
      </div>
      <div class="agent-created__next">
        <div class="agent-created__next-title">
          {{ $t('agentPrincipals.nextStepTitle') }}
        </div>
        <p class="agent-created__next-body">
          {{ $t('agentPrincipals.nextStepBody') }}
        </p>
        <p class="agent-created__next-hint">
          {{ $t('agentPrincipals.nextStepOwnerHint') }}
        </p>
      </div>
    </div>
    <template v-else>
      <div
        v-if="!isEdit"
        class="principal-kind-choice"
      >
        <span>{{ $t('agentPrincipals.kind') }}</span>
        <el-radio-group
          v-model="createKind"
          :aria-label="$t('agentPrincipals.kind')"
          data-test="create-kind"
        >
          <el-radio value="human">
            {{ $t('agentPrincipals.human') }}
          </el-radio>
          <el-radio value="agent">
            {{ $t('agentPrincipals.agent') }}
          </el-radio>
        </el-radio-group>
      </div>
      <AgentPrincipalForm
        v-if="dialogVisible && !isEdit && createKind === 'agent'"
        @created="agentCreated"
        @cancel="dialogVisible = false"
      />
      <el-form
        v-else
        ref="formRef"
        :model="form"
        :rules="formRules"
        label-position="top"
      >
        <el-form-item
          :label="$t('common.username')"
          prop="username"
        >
          <el-input
            v-model="form.username"
            :placeholder="$t('users.usernamePlaceholder')"
            :disabled="isEdit"
          />
        </el-form-item>
        <el-form-item
          v-if="!isEdit"
          :label="$t('common.password')"
          prop="password"
        >
          <el-input
            v-model="form.password"
            type="password"
            :placeholder="$t('users.passwordPlaceholder')"
            show-password
          />
        </el-form-item>
        <el-form-item
          label="Email"
          prop="email"
        >
          <el-input
            v-model="form.email"
            :placeholder="$t('users.emailPlaceholder')"
          />
        </el-form-item>
        <el-form-item
          :label="$t('users.fullName')"
          prop="full_name"
        >
          <el-input
            v-model="form.full_name"
            :placeholder="$t('users.fullNamePlaceholder')"
          />
        </el-form-item>
        <!-- 允許來源網段（來源限定功能）。
             前端只做**格式層**的就近提示；正規化、有效涵蓋狀態與「你進不進得來」
             一律由判定端點回覆——前端自己解析 CIDR 必與強制點分歧，而分歧的那一側
             正是自鎖警告會說錯話的地方。
             全部警示皆為 warning 級、**不阻擋送出**：管理者可能刻意設定一個
             尚未切換過去的網段 -->
        <el-form-item :label="$t('users.allowedCidrs')">
          <div class="cidr-field">
            <div
              v-if="form.allowed_cidrs.length"
              class="cidr-tags"
              data-test="cidr-tags"
            >
              <el-tag
                v-for="(item, index) in form.allowed_cidrs"
                :key="`${item}-${index}`"
                size="small"
                closable
                :type="itemErrorKey(item) ? 'danger' : 'info'"
                :aria-label="$t('users.allowedCidrsRemove', { value: item })"
                @close="removeCidr(index)"
              >
                {{ item }}
              </el-tag>
            </div>
            <el-input
              v-model="cidrDraft"
              :placeholder="$t('users.allowedCidrsPlaceholder')"
              data-test="cidr-input"
              @keyup.enter="addCidr"
              @blur="onCidrBlur"
            >
              <template #append>
                <el-button
                  data-test="cidr-add"
                  @click="addCidr"
                >
                  {{ $t('users.allowedCidrsAdd') }}
                </el-button>
              </template>
            </el-input>

            <p class="cidr-hint">
              {{ $t('users.allowedCidrsHint', { max: SOURCE_POLICY_MAX_ENTRIES }) }}
            </p>
            <!-- 「你目前的來源」是**管理者自己**的位址（`/auth/me`）。編輯別人的
                 帳號時它與那份清單毫無關係，卻緊挨在清單旁邊——累了的人會讀成
                 「這個帳號的來源」而照著它填。故只在編輯自己的帳號時出現，
                 那時「你」與被編輯的帳號是同一個人，句子才成立 -->
            <p
              v-if="currentSourceLine"
              class="cidr-hint"
              data-test="cidr-current-source"
            >
              {{ currentSourceLine }}
            </p>

            <!-- 就近紅字：格式層（本地）與端點層（逐項 error_code）分開呈現，
                 前者說「看起來不像」，後者說「後端解析不了」 -->
            <p
              v-if="cidrDraftError"
              class="cidr-error"
              data-test="cidr-format-error"
            >
              {{ cidrDraftError }}
            </p>
            <p
              v-for="err in itemErrors"
              :key="err.input"
              class="cidr-error"
              data-test="cidr-item-error"
            >
              {{ err.text }}
            </p>

            <p
              v-if="cidrChecking"
              class="cidr-hint"
              data-test="cidr-checking"
            >
              {{ $t('users.allowedCidrsChecking') }}
            </p>
            <p
              v-else-if="cidrCheckFailed"
              class="cidr-warning"
              data-test="cidr-check-failed"
            >
              {{ $t('users.allowedCidrsCheckFailed') }}
            </p>
            <template v-else>
              <p
                v-if="normalizedPreview"
                class="cidr-hint"
                data-test="cidr-normalized"
              >
                {{ $t('users.allowedCidrsNormalized', { list: normalizedPreview }) }}
              </p>
              <p
                v-if="effectiveUnrestrictedLine"
                class="cidr-warning"
                data-test="cidr-effective-warning"
              >
                {{ effectiveUnrestrictedLine }}
              </p>
              <template v-if="selfLockLine">
                <p
                  class="cidr-warning"
                  data-test="cidr-self-lock"
                >
                  {{ selfLockLine }}
                </p>
                <p class="cidr-hint">
                  {{ $t('users.allowedCidrsSelfLockRecovery') }}
                </p>
              </template>
            </template>
          </div>
        </el-form-item>
        <el-form-item
          v-if="!isEdit"
          :label="$t('common.role')"
          prop="roles"
        >
          <!-- 由 /roles API 生成（補遺）：勿硬編碼 -->
          <el-checkbox-group v-model="form.roles">
            <el-checkbox
              v-for="role in assignableRoles"
              :key="role.name"
              :label="role.name"
            >
              {{ roleLabel(role.name) }}
            </el-checkbox>
          </el-checkbox-group>
        </el-form-item>
      </el-form>
    </template>
    <!-- 頁尾按鈕一律 `mousedown.prevent`：**按下時不讓來源網段輸入框失焦**。
         失焦會就地觸發一次判定，「檢查中」那行插進對話框內容後把整個頁尾往下推
         一行；按下與放開之間按鈕已離開游標，瀏覽器不產生 click——使用者看到的是
         「按了沒反應」。不失焦即無重排。輸入框裡還沒收進清單的那一項改由
         handleSubmit 自己收攏，不倚賴失焦的副作用 -->
    <template
      v-if="createdAgent"
      #footer
    >
      <el-button
        data-test="agent-created-later"
        @click="dialogVisible = false"
      >
        {{ $t('agentPrincipals.issueLater') }}
      </el-button>
      <el-button
        type="primary"
        data-test="agent-created-issue"
        @click="issueKeyForCreated"
      >
        {{ $t('agentPrincipals.issueNow') }}
      </el-button>
    </template>
    <template
      v-else-if="inline"
      #footer
    >
      <el-button
        data-test="user-form-restore"
        :disabled="submitting"
        @click="restore"
      >
        {{ $t('userDetail.basic.restore') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        data-test="user-form-save"
        @click="handleSubmit"
      >
        {{ $t('userDetail.basic.saveChanges') }}
      </el-button>
    </template>
    <template
      v-else-if="isEdit || createKind === 'human'"
      #footer
    >
      <el-button
        data-test="user-dialog-cancel"
        @mousedown.prevent
        @click="dialogVisible = false"
      >
        {{ $t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        data-test="user-dialog-submit"
        @mousedown.prevent
        @click="handleSubmit"
      >
        {{ $t('common.confirm') }}
      </el-button>
    </template>
  </component>
</template>

<script setup>
import { ref, reactive, computed, watch, resolveComponent } from 'vue'
import { ElMessage } from 'element-plus'
import { CircleCheck } from 'lucide-vue-next'
import { getRoleList, createUser, updateUser, checkSourcePolicy } from '@/api/user'
import { getCurrentUser } from '@/api/auth'
import AgentPrincipalForm from '@/components/agent/AgentPrincipalForm.vue'
import { apiErrorSummary } from '@/api/redact'
import { t } from '@/i18n'
import { roleLabel } from '@/constants/roles'
import { useRoles } from '@/composables/useRoles'
import {
  SOURCE_POLICY_MAX_ENTRIES,
  looksLikeSourcePrefix,
} from '@/utils/sourcePolicy'
import InlineShell from './InlineShell'
import { effectiveUnrestrictedText } from '../sourcePolicyText'

/**
 * 帳號編輯表單。列表頁以對話框承載（建立與編輯），詳情頁以內嵌方式承載（只編輯）。
 * 兩處共用同一份欄位、驗證、來源網段判定與送出邏輯。
 */
const props = defineProps({
  // 內嵌模式：不包對話框，由 user 驅動表單內容
  inline: { type: Boolean, default: false },
  user: { type: Object, default: null },
})
const emit = defineEmits(['saved', 'opening', 'agent-created', 'issue-key'])

const logFailure = (event, error) => console.error(...apiErrorSummary(event, error))

const dialogShell = resolveComponent('el-dialog')
const shell = computed(() => (props.inline ? InlineShell : dialogShell))
const shellProps = computed(() =>
  props.inline
    ? {}
    : {
        modelValue: dialogVisible.value,
        'onUpdate:modelValue': (v) => { dialogVisible.value = v },
        title: dialogTitle.value,
        width: '560px',
        closeOnClickModal: false,
      }
)

const createKind = ref('human')
const dialogVisible = ref(false)
const isEdit = ref(false)
// 編輯中帳號的主體類型：agent 的 email 選填（管理端建立時不帶 email，存 NULL）
const editKind = ref('human')
const submitting = ref(false)
const formRef = ref(null)

const form = reactive({
  id: null,
  username: '',
  password: '',
  email: '',
  full_name: '',
  roles: [],
  allowed_cidrs: [],
})

const dialogTitle = computed(() => (isEdit.value ? t('users.editTitle') : t('users.create')))

// 建立 agent 後停在同一個對話框顯示下一步，而不是直接關掉
const createdAgent = ref(null)
watch(dialogVisible, (open) => { if (!open) createdAgent.value = null })

const { currentUserId } = useRoles()

const cidrDraft = ref('')
const cidrDraftError = ref('')
// **清單這次有沒有被動過**：更新請求對 `allowed_cidrs` 有 presence 語義
//（缺欄與 null＝保留現值、`[]`＝清除）。沒動過就不送這個欄位——
// 送 `[]` 會把既有限制靜默清空
const cidrTouched = ref(false)
const cidrCheck = ref(null)
const cidrChecking = ref(false)
const cidrCheckFailed = ref(false)
// 本人的來源位址（`GET /auth/me` 的 source_ip，僅供顯示、不參與判定）
const currentSourceIp = ref('')
let currentSourceLoaded = false
let checkTimer = null

const isEditingSelf = computed(
  () => isEdit.value && form.id != null && form.id === currentUserId.value
)

const resetCidrState = () => {
  cidrDraft.value = ''
  cidrDraftError.value = ''
  cidrTouched.value = false
  cidrCheck.value = null
  cidrChecking.value = false
  cidrCheckFailed.value = false
  if (checkTimer) {
    clearTimeout(checkTimer)
    checkTimer = null
  }
}

// 判定端點：清單變更後 debounce、失焦、以及儲存前各呼叫一次。
// 取不到結果時**不代替端點下判斷**——畫面只說「無法確認」，
// 不得把「查不到」渲染成「沒問題」
const runSourcePolicyCheck = async () => {
  cidrChecking.value = true
  cidrCheckFailed.value = false
  try {
    // address 省略＝以本請求的來源判定（自鎖預警走這條）
    cidrCheck.value = await checkSourcePolicy({
      allowed_cidrs: [...form.allowed_cidrs],
    })
  } catch (error) {
    cidrCheck.value = null
    cidrCheckFailed.value = true
    logFailure('source_policy_check_failed', error)
  } finally {
    cidrChecking.value = false
  }
}

const scheduleSourcePolicyCheck = () => {
  if (checkTimer) clearTimeout(checkTimer)
  checkTimer = setTimeout(runSourcePolicyCheck, 400)
}

// 立刻判定一次，並吃掉還在等的 debounce——否則同一份清單會被判兩次
const flushSourcePolicyCheck = () => {
  if (checkTimer) {
    clearTimeout(checkTimer)
    checkTimer = null
  }
  return runSourcePolicyCheck()
}

// 回傳「這次輸入有沒有被收下」：被格式／重複／上限擋下時回 false，
// 呼叫端據此決定要不要繼續（送出路徑靠它停在紅字上，而不是靜默丟掉那一項）
const addCidr = () => {
  const value = cidrDraft.value.trim()
  if (!value) return true
  if (form.allowed_cidrs.includes(value)) {
    cidrDraftError.value = t('users.allowedCidrsDuplicate', { value })
    return false
  }
  // 格式層寬鬆：只擋明顯不是位址的輸入。後端才拒的邊界（值域越界、
  // 前綴長度越界）刻意放行——重複判斷的兩套規則遲早分歧
  if (!looksLikeSourcePrefix(value)) {
    cidrDraftError.value = t('users.allowedCidrsFormat', { value })
    return false
  }
  if (form.allowed_cidrs.length >= SOURCE_POLICY_MAX_ENTRIES) {
    cidrDraftError.value = t('users.allowedCidrsTooMany', {
      value,
      max: SOURCE_POLICY_MAX_ENTRIES,
    })
    return false
  }
  form.allowed_cidrs.push(value)
  cidrDraft.value = ''
  cidrDraftError.value = ''
  cidrTouched.value = true
  scheduleSourcePolicyCheck()
  return true
}

const removeCidr = (index) => {
  form.allowed_cidrs.splice(index, 1)
  cidrDraftError.value = ''
  cidrTouched.value = true
  scheduleSourcePolicyCheck()
}

// 失焦：把還停在輸入框裡的那一項一併收進清單（打完字直接移開焦點是常態），
// 再重新判定一次。**按頁尾按鈕走不到這裡**（那條路刻意不失焦），送出路徑
// 另由 commitCidrDraft 收攏
const onCidrBlur = () => {
  if (cidrDraft.value.trim()) addCidr()
  else if (cidrTouched.value) flushSourcePolicyCheck()
}

// 送出前收攏還停在輸入框裡的那一項。回 false＝那一項被擋下（紅字已就地顯示），
// 送出停在原地讓使用者看見，不靜默把它丟掉
const commitCidrDraft = () => addCidr()

// 逐項錯誤：端點回的 error_code 就近顯示。`invalid`＝解析不了、
// `too_many`＝去重後超過上限；未知碼退回通用的「解析不了」而非吞掉
const ITEM_ERROR_KEYS = {
  invalid: 'users.allowedCidrsInvalid',
  too_many: 'users.allowedCidrsTooMany',
}

const itemErrorKey = (input) => {
  const item = (cidrCheck.value?.items || []).find((i) => i.input === input)
  if (!item?.error_code) return ''
  return ITEM_ERROR_KEYS[item.error_code] || ITEM_ERROR_KEYS.invalid
}

const itemErrors = computed(() =>
  (cidrCheck.value?.items || [])
    .filter((i) => i.error_code)
    .map((i) => ({
      input: i.input,
      text: t(ITEM_ERROR_KEYS[i.error_code] || ITEM_ERROR_KEYS.invalid, {
        value: i.input,
        max: SOURCE_POLICY_MAX_ENTRIES,
      }),
    }))
)

// 正規化預覽只在「存起來會跟你打的不一樣」時出現：一模一樣時多這一行是噪音
const normalizedPreview = computed(() => {
  const normalized = cidrCheck.value?.normalized
  if (!cidrCheck.value?.valid || !Array.isArray(normalized) || !normalized.length) return ''
  const same =
    normalized.length === form.allowed_cidrs.length &&
    normalized.every((v, i) => v === form.allowed_cidrs[i])
  return same ? '' : normalized.join('、')
})

// 「等同不限」：三句分寫（v4／v6／both），不以分隔符拼接家族名——
// 各語言的並列連接詞不同，拼接會在其中一語產出讀不通的句子
const effectiveUnrestrictedLine = computed(() => {
  if (cidrCheck.value?.status !== 'effectively_unrestricted') return ''
  return effectiveUnrestrictedText(cidrCheck.value?.families)
})

// 自鎖警告**只消費端點的 allowed**，不自行比對。編輯對象是本人、清單非空、
// 端點判定本次來源不放行時出現；後端不擋、本頁也不擋
const selfLockLine = computed(() => {
  if (!isEditingSelf.value) return ''
  if (!form.allowed_cidrs.length) return ''
  if (cidrCheck.value?.allowed !== false) return ''
  const address = cidrCheck.value?.source?.address
  return address
    ? t('users.allowedCidrsSelfLock', { address })
    : t('users.allowedCidrsSelfLockNoSource')
})

// 「你目前的來源」只供顯示（`/auth/me` 的 source_ip），不參與任何判定。
// 取不到時整行不出現——顯示「未知」會讓管理者以為那是判定結果。
//
// **只在編輯自己的帳號時出現**：它是管理者自己的位址，擺在別人的允許清單旁邊
// 會被讀成「這個帳號的來源」。與 selfLockLine 同一道把關（isEditingSelf）
const currentSourceLine = computed(() =>
  isEditingSelf.value && currentSourceIp.value
    ? t('users.allowedCidrsCurrentSource', { address: currentSourceIp.value })
    : ''
)

// 取一次即快取（同一次進站不重複問）；失敗只留前端失敗紀錄，不打斷開窗
const loadCurrentSource = async () => {
  if (currentSourceLoaded) return
  currentSourceLoaded = true
  try {
    const me = await getCurrentUser()
    currentSourceIp.value = me?.source_ip || ''
  } catch (error) {
    logFailure('current_source_load_failed', error)
  }
}

// 表單驗證規則（computed：切語言時錯誤訊息隨當下語言）
const formRules = computed(() => ({
  username: [
    { required: true, message: t('users.usernamePlaceholder'), trigger: 'blur' },
    { min: 3, max: 50, message: t('users.usernameLength'), trigger: 'blur' },
  ],
  password: [
    { required: true, message: t('users.passwordPlaceholder'), trigger: 'blur' },
  ],
  email: [
    // agent 不收信、不登入：email 選填，有填仍驗格式；human 必填
    { required: !(isEdit.value && editKind.value === 'agent'), message: t('users.emailPlaceholder'), trigger: 'blur' },
    { type: 'email', message: t('users.emailInvalid'), trigger: 'blur' },
  ],
}))


// 重置表單
const resetForm = () => {
  form.id = null
  form.username = ''
  form.password = ''
  form.email = ''
  form.full_name = ''
  form.roles = []
  form.allowed_cidrs = []
  resetCidrState()
  formRef.value?.clearValidate()
}

// 以一列使用者資料填入編輯表單（對話框與內嵌共用）
const fillFromUser = (row) => {
  resetForm()
  isEdit.value = true
  editKind.value = row.kind === 'agent' ? 'agent' : 'human'
  form.id = row.id
  form.username = row.username
  form.email = row.email || ''
  form.full_name = row.full_name || ''
  // 現值進表單但**不標記為已編輯**：沒動過就不送該欄（presence 語義）
  form.allowed_cidrs = [...(row.allowed_cidrs || [])]
  loadCurrentSource()
}

const openCreate = () => {
  emit('opening')
  createdAgent.value = null
  createKind.value = 'human'
  loadAssignableRoles()
  resetForm()
  isEdit.value = false
  dialogVisible.value = true
  loadCurrentSource()
}

const openEdit = (row) => {
  emit('opening')
  fillFromUser(row)
  dialogVisible.value = true
}

const restore = () => {
  if (props.user) fillFromUser(props.user)
}

watch(
  () => props.user,
  (row) => { if (props.inline && row) fillFromUser(row) },
  { immediate: true }
)

// 處理提交
const handleSubmit = async () => {
  try {
    // 打完字沒按 Enter 就直接送出是常態；那一項在這裡收進清單
    if (!commitCidrDraft()) return
    await formRef.value.validate()

    // 儲存前最後一次判定：警示是 warning 級、**不阻擋送出**（管理者可能刻意
    // 設定一個尚未切換過去的網段），但要讓他在按下去之前就看到
    if (cidrTouched.value) {
      await flushSourcePolicyCheck()
    }
    submitting.value = true

    if (isEdit.value) {
      // 更新用戶
      const data = {
        email: form.email,
        full_name: form.full_name,
      }
      // presence 語義：**沒動過清單就不帶這個欄位**（缺欄＝保留現值）。
      // 一律帶會在使用者只改了 Email 時把既有的來源限定靜默清空
      if (cidrTouched.value) data.allowed_cidrs = [...form.allowed_cidrs]
      await updateUser(form.id, data)
      ElMessage.success(t('users.updated'))
    } else {
      // 新增使用者
      const data = {
        username: form.username,
        password: form.password,
        email: form.email,
        full_name: form.full_name,
        roles: form.roles.length > 0 ? form.roles : ['user'],
      }
      // 建立時省略＝不限；空清單不必送出
      if (form.allowed_cidrs.length) data.allowed_cidrs = [...form.allowed_cidrs]
      await createUser(data)
      ElMessage.success(t('users.created'))
    }

    dialogVisible.value = false
    emit('saved')
  } catch (error) {
    if (error?.errors) {
      // 驗證錯誤，不需要處理
      return
    }
    logFailure('user_submit_failed', error)
  } finally {
    submitting.value = false
  }
}

// 可指派角色清單：/roles API 為事實源（開窗時惰性載入一次，失敗下次開窗重試）
const assignableRoles = ref([])
const loadAssignableRoles = async () => {
  if (assignableRoles.value.length) return
  try {
    const res = await getRoleList()
    assignableRoles.value = res.data || []
  } catch (error) {
    logFailure('role_list_failed', error)
  }
}

function agentCreated(agent) {
  createdAgent.value = agent?.id ? agent : null
  if (!createdAgent.value) dialogVisible.value = false
  emit('saved')
}
function issueKeyForCreated() {
  const agent = createdAgent.value
  if (!agent) return
  emit('issue-key', agent)
}
const close = () => { dialogVisible.value = false }

defineExpose({ openCreate, openEdit, close })
</script>

<style scoped>
.principal-kind-choice { display: flex; align-items: center; gap: var(--ot-space-md); margin-bottom: var(--ot-space-md); }
/* 建立 agent 後的下一步：主要資訊（名稱、下一步）用主要文字色，說明句至多一行次級色 */
.agent-created { display: flex; flex-direction: column; gap: var(--ot-space-lg); }
.agent-created__head { display: flex; gap: var(--ot-space-sm); align-items: flex-start; }
.agent-created__icon { color: var(--ot-success); font-size: 22px; flex-shrink: 0; margin-top: 1px; }
.agent-created__summary { display: flex; flex-direction: column; gap: var(--ot-space-xs); }
.agent-created__title { font-size: var(--ot-font-size-md); font-weight: 600; color: var(--ot-text-primary); }
.agent-created__owner { font-size: var(--ot-font-size-sm); color: var(--ot-text-secondary); }
.agent-created__next { background: var(--ot-bg-page); border: 1px solid var(--ot-border-subtle); border-radius: var(--ot-radius-md); padding: var(--ot-space-md); display: flex; flex-direction: column; gap: var(--ot-space-xs); }
.agent-created__next-title { font-weight: 600; color: var(--ot-text-primary); }
.agent-created__next-body { margin: 0; line-height: 1.6; color: var(--ot-text-primary); }
.agent-created__next-hint { margin: 0; font-size: var(--ot-font-size-sm); line-height: 1.6; color: var(--ot-text-secondary); }
/* 允許來源網段：tag 清單 + 輸入框 + 逐條就近提示。
   提示一律在欄位下方就近呈現（C6），不彈對話框、不擋送出 */
.cidr-field {
  width: 100%;
}

.cidr-tags {
  display: flex;
  flex-wrap: wrap;
  gap: var(--ot-space-xs);
  margin-bottom: var(--ot-space-xs);
}

.cidr-tags :deep(.el-tag) {
  font-family: var(--ot-font-mono);
}

.cidr-field :deep(.el-input__inner) {
  font-family: var(--ot-font-mono);
}

.cidr-hint,
.cidr-error,
.cidr-warning {
  margin: var(--ot-space-xs) 0 0;
  font-size: var(--ot-font-size-xs);
  line-height: 1.6;
}

.cidr-hint {
  color: var(--ot-text-secondary);
}

.cidr-error {
  color: var(--ot-danger);
}

/* 警示是 warning 級：它不阻擋儲存，色階也不該偽裝成阻擋 */
.cidr-warning {
  color: var(--ot-warning);
}

.inline-shell__footer { display: flex; justify-content: flex-end; gap: var(--ot-space-sm); margin-top: var(--ot-space-md); }
</style>
