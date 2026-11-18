<template>
  <el-dialog
    :model-value="modelValue"
    :title="step === 'reveal' ? $t('apiTokens.reveal.title') : $t('apiTokens.create')"
    width="min(600px, calc(100vw - 32px))"
    :show-close="step === 'form'"
    :close-on-click-modal="false"
    :close-on-press-escape="step === 'form'"
    append-to-body
    data-test="api-token-create-dialog"
    @update:model-value="onDialogToggle"
    @opened="focusName"
    @closed="clearSecret"
  >
    <ApiTokenRevealPanel
      v-if="step === 'reveal' && created"
      :created="created"
      :username="username"
    />

    <div
      v-else
      class="atc-form"
      data-test="create-form"
    >
      <el-alert
        v-if="serverError"
        type="error"
        :closable="false"
        show-icon
        :title="$t('apiTokens.form.err.serverTitle')"
        :description="serverError"
        data-test="create-server-error"
      />
      <el-alert
        v-if="privilege"
        type="warning"
        :closable="false"
        show-icon
        :title="privilegeTitle"
        :description="privilegeBody"
        :data-test="`create-privilege-${privilege}`"
      />

      <div class="atc-field">
        <label
          :for="nameId"
          class="atc-label"
        >{{ $t('apiTokens.form.name') }}</label>
        <el-input
          :id="nameId"
          ref="nameInput"
          v-model="name"
          maxlength="100"
          :placeholder="$t('apiTokens.form.namePlaceholder')"
          :class="{ 'atc-input-error': errors.name }"
          :disabled="submitting"
          data-test="create-name"
        />
        <p
          v-if="errors.name"
          class="atc-error"
          role="alert"
          data-test="err-name"
        >
          <CircleX
            :size="13"
            aria-hidden="true"
          />{{ errors.name }}
        </p>
        <p
          v-else
          class="atc-hint"
        >
          {{ $t('apiTokens.form.nameHint') }}
        </p>
      </div>

      <div
        class="atc-field"
        role="group"
        :aria-labelledby="rolesLabelId"
      >
        <span
          :id="rolesLabelId"
          class="atc-label"
        >{{ $t('apiTokens.form.roles') }}</span>
        <div
          v-if="grantable.length === 1"
          class="atc-roles is-single"
          data-test="roles-single"
        >
          <div class="atc-role-row">
            <el-tag
              size="small"
              :type="grantedRoleTagType(grantable[0])"
              :class="grantedRoleTagType(grantable[0]) === 'info' ? 'ot-tag-neutral' : ''"
            >
              {{ grantedRoleLabel(grantable[0]) }}
            </el-tag>
            <span
              v-if="scopeText(grantable[0].scope)"
              class="atc-role-scope"
            >{{ $t('apiTokens.form.scope', { scope: scopeText(grantable[0].scope) }) }}</span>
            <el-radio-group
              :model-value="levelOf(grantable[0].role_id)"
              size="small"
              class="atc-level"
              :class="{ 'is-write': levelOf(grantable[0].role_id) === LEVEL_READ_WRITE }"
              :disabled="submitting"
              :aria-label="levelGroupLabel(grantable[0])"
              :data-test="`level-${grantable[0].role_id}`"
              @update:model-value="(v) => setLevel(grantable[0].role_id, v)"
            >
              <el-radio-button
                v-for="lv in API_TOKEN_LEVELS"
                :key="lv"
                :value="lv"
                :data-test="`level-${grantable[0].role_id}-${lv}`"
              >
                <component
                  :is="lv === LEVEL_READ_WRITE ? PenLine : Eye"
                  :size="12"
                  aria-hidden="true"
                  class="atc-level__icon"
                />{{ $t(`apiTokens.level.${lv}`) }}
              </el-radio-button>
            </el-radio-group>
          </div>
          <div class="atc-role-row atc-role-note-row">
            <span class="atc-role-note">{{ $t('apiTokens.form.singleRole') }}</span>
          </div>
        </div>
        <div
          v-else
          class="atc-roles"
          :class="{ 'is-error': errors.roles }"
          data-test="roles-multi"
        >
          <div class="atc-role-row atc-role-all">
            <el-checkbox
              :model-value="allSelected"
              :indeterminate="someSelected"
              :disabled="submitting"
              data-test="roles-all"
              @change="toggleAll"
            >
              {{ $t('apiTokens.form.rolesAll', { n: grantable.length }) }}
            </el-checkbox>
            <span
              class="atc-role-count"
              data-test="roles-count"
            >{{ $t('apiTokens.form.rolesSelected', { n: selectedIds.length }) }}</span>
          </div>
          <div
            v-for="role in grantable"
            :key="role.role_id"
            class="atc-role-row"
          >
            <el-checkbox
              :model-value="selectedIds.includes(role.role_id)"
              :disabled="submitting"
              :data-test="`role-${role.role_id}`"
              @change="(v) => toggleRole(role.role_id, v)"
            >
              <el-tag
                size="small"
                :type="grantedRoleTagType(role)"
                :class="grantedRoleTagType(role) === 'info' ? 'ot-tag-neutral' : ''"
              >
                {{ grantedRoleLabel(role) }}
              </el-tag>
              <span
                v-if="scopeText(role.scope)"
                class="atc-role-scope"
              >{{ $t('apiTokens.form.scope', { scope: scopeText(role.scope) }) }}</span>
            </el-checkbox>
            <!-- 未勾選的角色保留切換的位置但整組變灰，勾選時版面不跳動 -->
            <el-radio-group
              :model-value="levelOf(role.role_id)"
              size="small"
              class="atc-level"
              :class="{ 'is-write': selectedIds.includes(role.role_id) && levelOf(role.role_id) === LEVEL_READ_WRITE }"
              :disabled="submitting || !selectedIds.includes(role.role_id)"
              :aria-label="levelGroupLabel(role)"
              :data-test="`level-${role.role_id}`"
              @update:model-value="(v) => setLevel(role.role_id, v)"
            >
              <el-radio-button
                v-for="lv in API_TOKEN_LEVELS"
                :key="lv"
                :value="lv"
                :data-test="`level-${role.role_id}-${lv}`"
              >
                <component
                  :is="lv === LEVEL_READ_WRITE ? PenLine : Eye"
                  :size="12"
                  aria-hidden="true"
                  class="atc-level__icon"
                />{{ $t(`apiTokens.level.${lv}`) }}
              </el-radio-button>
            </el-radio-group>
          </div>
          <div
            class="atc-role-row atc-set-all"
            data-test="level-set-all"
          >
            <span class="atc-set-all__label">{{ $t('apiTokens.form.setAll') }}</span>
            <template
              v-for="(lv, i) in API_TOKEN_LEVELS"
              :key="lv"
            >
              <span
                v-if="i > 0"
                class="atc-set-all__sep"
                aria-hidden="true"
              >|</span>
              <el-button
                link
                type="primary"
                :disabled="submitting || !selectedIds.length"
                :data-test="`level-set-all-${lv}`"
                @click="setAllLevels(lv)"
              >
                {{ $t(`apiTokens.level.${lv}`) }}
              </el-button>
            </template>
          </div>
        </div>
        <p
          v-if="errors.roles"
          class="atc-error"
          role="alert"
          data-test="err-roles"
        >
          <CircleX
            :size="13"
            aria-hidden="true"
          />{{ errors.roles }}
        </p>
        <p
          class="atc-hint"
          data-test="roles-hint"
        >
          {{ rolesHintText }}
        </p>
        <button
          type="button"
          class="atc-help-link"
          :aria-expanded="explainOpen ? 'true' : 'false'"
          data-test="level-help"
          @click="explainOpen = !explainOpen"
        >
          <CircleHelp
            :size="13"
            aria-hidden="true"
          />{{ $t('apiTokens.form.levelHelp') }}
        </button>
        <ApiTokenLevelExplain
          v-if="explainOpen"
          closable
          @close="explainOpen = false"
        />
      </div>

      <div class="atc-field">
        <span
          :id="expiryLabelId"
          class="atc-label"
        >{{ $t('apiTokens.form.expiry') }}</span>
        <el-radio-group
          v-model="expiry"
          class="atc-expiry"
          :class="{ 'is-error': errors.expiry }"
          :aria-labelledby="expiryLabelId"
          :disabled="submitting"
          data-test="expiry-options"
        >
          <el-radio-button
            v-for="opt in EXPIRY_OPTIONS"
            :key="opt"
            :value="opt"
            :data-test="`expiry-${opt}`"
          >
            {{ $t(`apiTokens.form.expiryOption.${opt}`) }}
          </el-radio-button>
        </el-radio-group>
        <div
          v-if="expiry === 'custom'"
          class="atc-custom-date"
          data-test="expiry-custom"
        >
          <el-date-picker
            v-model="customDate"
            type="date"
            :placeholder="$t('apiTokens.form.datePlaceholder')"
            :disabled-date="isPastDate"
            :aria-label="$t('apiTokens.form.expiryOption.custom')"
            :disabled="submitting"
          />
          <span class="atc-hint">{{ $t('apiTokens.form.customDateHint') }}</span>
        </div>
        <p
          v-if="errors.expiry"
          class="atc-error"
          role="alert"
          data-test="err-expiry"
        >
          <CircleX
            :size="13"
            aria-hidden="true"
          />{{ errors.expiry }}
        </p>
        <p
          v-else-if="expiry === 'never'"
          class="atc-expiry-line"
          data-test="expiry-never-line"
        >
          {{ $t('apiTokens.form.neverHint') }}
        </p>
        <p
          v-else-if="expiryDate"
          class="atc-expiry-line"
          data-test="expiry-line"
        >
          {{ $t('apiTokens.form.expiresOn', { time: formatDateTime(expiryDate), rel: relativeExpiry(expiryDate) }) }}
        </p>
        <p
          v-else
          class="atc-hint"
          data-test="expiry-hint"
        >
          {{ $t('apiTokens.form.expiryHint') }}
        </p>
      </div>

      <section
        class="atc-summary"
        data-test="create-summary"
      >
        <h4>{{ $t('apiTokens.form.summaryTitle') }}</h4>
        <div
          class="atc-summary__roles"
          data-test="summary-roles"
        >
          <p
            v-if="!selectedRoles.length"
            class="is-none"
            data-test="summary-none"
          >
            {{ $t('apiTokens.form.summaryNone') }}
          </p>
          <template v-else-if="superOnlySummary">
            <p data-test="summary-super">
              <span
                v-if="superLine.label"
                class="is-write"
              >{{ superLine.label }}</span>{{ superLine.rest }}
            </p>
          </template>
          <template v-else>
            <p
              v-if="writeRoles.length"
              data-test="summary-write"
            >
              <span class="is-write">{{ $t('apiTokens.form.summaryWriteLabel') }}</span>{{ writeLineRest }}
            </p>
            <p
              v-if="readRoles.length"
              data-test="summary-read"
            >
              {{ readLine }}
            </p>
          </template>
          <p data-test="summary-sync">
            {{ $t('apiTokens.form.summarySync') }}
          </p>
        </div>
        <p>{{ $t('apiTokens.form.summaryScope') }}</p>
        <p data-test="summary-cidr">
          {{ cidrs.length ? $t('apiTokens.form.summaryCidr', { cidrs: cidrs.join(listSeparator) }) : $t('apiTokens.form.summaryNoCidr') }}
        </p>
        <p>{{ $t('apiTokens.form.summaryAudit') }}</p>
      </section>
    </div>

    <template #footer>
      <el-button
        v-if="step === 'reveal'"
        type="primary"
        data-test="reveal-close"
        @click="closeDialog"
      >
        {{ $t('apiTokens.reveal.close') }}
      </el-button>
      <template v-else>
        <el-button
          :disabled="submitting"
          data-test="create-cancel"
          @click="closeDialog"
        >
          {{ $t('common.cancel') }}
        </el-button>
        <el-button
          v-preview-write:create
          type="primary"
          :loading="submitting"
          data-test="create-submit"
          @click="submit"
        >
          {{ $t('apiTokens.create') }}
        </el-button>
      </template>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, onBeforeUnmount, ref, useId, watch } from 'vue'
import { CircleHelp, CircleX, Eye, PenLine } from 'lucide-vue-next'
import { t, te, currentLocale } from '@/i18n'
import { formatDateTime } from '@/utils/format'
import { resolveApiError } from '@/api/error'
import { createMyApiToken } from '@/api/apiTokens'
import { previewWrite as vPreviewWrite } from '@/directives/previewWrite'
import {
  API_TOKEN_LEVELS,
  EXPIRY_OPTIONS,
  LEVEL_READ,
  LEVEL_READ_WRITE,
  SECURITY_ROLE_KEY,
  SUPER_ROLE_KEY,
  endOfDay,
  grantedRoleLabel,
  grantedRoleTagType,
  presetExpiry,
  privilegeLevel,
  relativeExpiry,
  rolesText,
  rolesWithScopeText,
  scopeText,
} from '@/constants/apiTokens'
import ApiTokenRevealPanel from './ApiTokenRevealPanel.vue'
import ApiTokenLevelExplain from './ApiTokenLevelExplain.vue'

/**
 * 建立 API token 的對話框。送出成功後同一個對話框換成一次性明文顯示；
 * 明文只存在本元件的區域狀態，關閉時清掉，不交給父層、不寫入任何儲存。
 */
const props = defineProps({
  modelValue: { type: Boolean, default: false },
  // GET /my/api-tokens 的 eligibility
  eligibility: { type: Object, default: () => ({}) },
  username: { type: String, default: '' },
})
const emit = defineEmits(['update:modelValue', 'created', 'ineligible', 'stale-roles'])

const nameId = useId()
// 對話框開啟動畫結束後把焦點放到名稱欄（第一個要填的欄位）；明文面板階段不動焦點
const nameInput = ref(null)
const focusName = () => {
  if (step.value === 'form') nameInput.value?.focus?.()
}
const rolesLabelId = useId()
const expiryLabelId = useId()
const listSeparator = computed(() => t('common.listSeparator'))

const grantable = computed(() => props.eligibility?.grantable_roles || [])
const cidrs = computed(() => props.eligibility?.allowed_cidrs || [])
const nonGrantableText = computed(() => rolesText(props.eligibility?.non_grantable_roles || []))
// 兩句接在同一段時的分隔：中文與日文句號後不留空白，英文要一個空白。
// 不能靠模板換行產生空白——編譯時會被壓掉或多出一格，三語結果不同
const sentenceSeparator = computed(() => (currentLocale().startsWith('en') ? ' ' : ''))
// 標籤（「只能讀取：」）與後面的角色清單之間：英文冒號後留一個空白，中日文全形冒號不留
const labelSeparator = computed(() => (currentLocale().startsWith('en') ? ' ' : ''))
const rolesHintText = computed(() =>
  [
    t('apiTokens.form.levelHint'),
    t('apiTokens.form.rolesHint'),
    ...(nonGrantableText.value ? [t('apiTokens.form.rolesHintNonGrantable', { roles: nonGrantableText.value })] : []),
  ].join(sentenceSeparator.value)
)

const step = ref('form')
const name = ref('')
const selectedIds = ref([])
// 每個角色的層級：預設唯讀；取消勾選即回到唯讀，再勾回時不記得先前選的讀寫
const levels = ref({})
const explainOpen = ref(false)
const expiry = ref('')
const customDate = ref(null)
const errors = ref({ name: '', roles: '', expiry: '' })
const serverError = ref('')
const submitting = ref(false)
// 建立回應（含一次性明文）：只在明文顯示期間存在
const created = ref(null)

const selectedRoles = computed(() => grantable.value.filter((r) => selectedIds.value.includes(r.role_id)))
const allSelected = computed(() => grantable.value.length > 0 && selectedIds.value.length === grantable.value.length)
const someSelected = computed(() => selectedIds.value.length > 0 && !allSelected.value)
const levelOf = (id) => (levels.value[id] === LEVEL_READ_WRITE ? LEVEL_READ_WRITE : LEVEL_READ)
const setLevel = (id, level) => {
  levels.value = { ...levels.value, [id]: level === LEVEL_READ_WRITE ? LEVEL_READ_WRITE : LEVEL_READ }
}
// 「全部設為」只改已勾選的角色，不會順便勾選未勾的
const setAllLevels = (level) => {
  const next = { ...levels.value }
  for (const id of selectedIds.value) next[id] = level
  levels.value = next
}
const resetLevel = (ids) => {
  const next = { ...levels.value }
  for (const id of ids) delete next[id]
  levels.value = next
}
const levelGroupLabel = (role) => `${grantedRoleLabel(role)} ${t('apiTokens.col.access')}`

const writeRoles = computed(() => selectedRoles.value.filter((r) => levelOf(r.role_id) === LEVEL_READ_WRITE))
const readRoles = computed(() => selectedRoles.value.filter((r) => levelOf(r.role_id) !== LEVEL_READ_WRITE))
const roleListText = (roles) => t('apiTokens.form.summaryRoleList', { roles: rolesWithScopeText(roles) })
const writeLineRest = computed(() => `${labelSeparator.value}${roleListText(writeRoles.value)}`)
const readLine = computed(() => {
  const line = `${t('apiTokens.form.summaryReadLabel')}${labelSeparator.value}${roleListText(readRoles.value)}`
  return writeRoles.value.length ? line : `${line}${sentenceSeparator.value}${t('apiTokens.form.summaryAllReadTail')}`
})

const privilege = computed(() => privilegeLevel(selectedRoles.value))
const levelOfKey = (key) => {
  const role = selectedRoles.value.find((r) => r.builtin_key === key)
  return role ? levelOf(role.role_id) : ''
}
// 勾選了超級管理者時，摘要只寫它（它涵蓋全部），並依它的層級擇句
const superLevel = computed(() => levelOfKey(SUPER_ROLE_KEY))
// 只寫超級管理者那一句的條件：它是讀寫（涵蓋全部），或它是唯讀且沒有其他讀寫角色。
// 它是唯讀而另有角色設為讀寫時，改用逐角色的兩行，摘要才不會說成不能修改資料。
const superOnlySummary = computed(() =>
  superLevel.value === LEVEL_READ_WRITE || (superLevel.value && !writeRoles.value.length))
// 讀寫時句首的「可以讀取，也可以修改：」以琥珀色標出，與一般角色的摘要同一種寫法
const superLine = computed(() => {
  if (superLevel.value !== LEVEL_READ_WRITE) return { label: '', rest: t('apiTokens.form.summarySuperRead') }
  const text = t('apiTokens.form.summarySuperWrite')
  const label = t('apiTokens.form.summaryWriteLabel')
  return text.startsWith(label) ? { label, rest: text.slice(label.length) } : { label: '', rest: text }
})
// 高權限提示不因唯讀而取消（告警照發），只依該角色的層級換標題與內文
const privilegeLevelValue = computed(() =>
  privilege.value === 'super' ? superLevel.value : levelOfKey(SECURITY_ROLE_KEY)
)
const privilegeTitle = computed(() => {
  const base = privilege.value === 'super' ? 'privSuper' : 'privSec'
  return t(`apiTokens.form.${base}.${privilegeLevelValue.value === LEVEL_READ_WRITE ? 'titleWrite' : 'titleRead'}`)
})
const privilegeBody = computed(() => {
  const base = privilege.value === 'super' ? 'privSuper' : 'privSec'
  return t(`apiTokens.form.${base}.${privilegeLevelValue.value === LEVEL_READ_WRITE ? 'body' : 'bodyRead'}`)
})

const startOfToday = () => {
  const d = new Date()
  d.setHours(0, 0, 0, 0)
  return d
}
const isPastDate = (date) => date.getTime() < startOfToday().getTime()

const expiryDate = computed(() => {
  if (expiry.value === 'custom') return customDate.value ? endOfDay(customDate.value) : null
  return presetExpiry(expiry.value)
})

const resetForm = () => {
  step.value = 'form'
  name.value = ''
  selectedIds.value = grantable.value.map((r) => r.role_id)
  levels.value = {}
  explainOpen.value = false
  expiry.value = ''
  customDate.value = null
  errors.value = { name: '', roles: '', expiry: '' }
  serverError.value = ''
  submitting.value = false
  created.value = null
}

const clearSecret = () => {
  created.value = null
  if (!props.modelValue) step.value = 'form'
}

watch(
  () => props.modelValue,
  (open) => {
    if (open) resetForm()
    else created.value = null
  },
  { immediate: true }
)

// 可授權角色重新載入後（例如角色剛被收回），只保留仍在清單裡的勾選
watch(grantable, (roles) => {
  const ids = new Set(roles.map((r) => r.role_id))
  selectedIds.value = selectedIds.value.filter((id) => ids.has(id))
  if (roles.length === 1) selectedIds.value = [roles[0].role_id]
})

watch(name, () => { errors.value.name = '' })
watch(selectedIds, () => { errors.value.roles = '' })
watch([expiry, customDate], () => { errors.value.expiry = '' })

const toggleAll = (checked) => {
  if (!checked) resetLevel(selectedIds.value)
  selectedIds.value = checked ? grantable.value.map((r) => r.role_id) : []
}
const toggleRole = (id, checked) => {
  if (!checked) resetLevel([id])
  selectedIds.value = checked
    ? [...selectedIds.value.filter((v) => v !== id), id]
    : selectedIds.value.filter((v) => v !== id)
}

const onDialogToggle = (value) => {
  // 明文顯示期間只能用「我已保存，關閉」離開
  if (!value && step.value === 'reveal') return
  emit('update:modelValue', value)
}
const closeDialog = () => {
  created.value = null
  emit('update:modelValue', false)
}

const validate = () => {
  const next = { name: '', roles: '', expiry: '' }
  if (!name.value.trim()) next.name = t('apiTokens.form.err.name')
  if (!selectedIds.value.length) next.roles = t('apiTokens.form.err.roles')
  if (!expiry.value) next.expiry = t('apiTokens.form.err.expiry')
  else if (expiry.value === 'custom' && !customDate.value) next.expiry = t('apiTokens.form.err.expiry')
  else if (expiryDate.value && expiryDate.value.getTime() <= Date.now()) next.expiry = t('apiTokens.form.err.customDate')
  errors.value = next
  return !next.name && !next.roles && !next.expiry
}

const knownMessage = (data, status) =>
  data?.code && te(`apiError.${data.code}`) ? resolveApiError(data, status) : ''

const handleError = (error) => {
  const data = error?.response?.data
  const status = error?.response?.status
  const code = data?.code
  // 沒帶錯誤碼的 409 仍視為同名；帶了其他錯誤碼的 409 交給下面的通用處理顯示實際原因
  if (code === 'CONFLICT_API_TOKEN_NAME' || (status === 409 && !code)) {
    errors.value = { ...errors.value, name: t('apiTokens.form.err.duplicate') }
    return
  }
  if (code === 'API_TOKEN_NAME_INVALID') {
    errors.value = { ...errors.value, name: knownMessage(data, status) || t('apiTokens.form.err.name') }
    return
  }
  if (code === 'API_TOKEN_ROLE_REQUIRED') {
    errors.value = { ...errors.value, roles: knownMessage(data, status) || t('apiTokens.form.err.roles') }
    return
  }
  if (code === 'API_TOKEN_EXPIRY_REQUIRED' || code === 'API_TOKEN_EXPIRY_INVALID') {
    errors.value = { ...errors.value, expiry: knownMessage(data, status) || t('apiTokens.form.err.expiry') }
    return
  }
  if (code === 'API_TOKEN_NOT_ELIGIBLE') {
    // 建立資格在送出時才失去：關閉對話框，由區塊重新載入成說明狀態
    emit('ineligible')
    emit('update:modelValue', false)
    return
  }
  if (code === 'API_TOKEN_ROLE_NOT_GRANTABLE') emit('stale-roles')
  serverError.value = knownMessage(data, status) || t('apiTokens.form.err.server')
}

const submit = async () => {
  if (submitting.value) return
  serverError.value = ''
  if (!validate()) return
  // 每個勾選的角色各帶一個層級；不再送只列角色識別的舊寫法（那等同全部讀寫）
  const payload = {
    name: name.value.trim(),
    roles: selectedIds.value.map((id) => ({ role_id: id, level: levelOf(id) })),
  }
  if (expiry.value === 'never') payload.never_expires = true
  else payload.expires_at = expiryDate.value.toISOString()
  submitting.value = true
  try {
    const res = await createMyApiToken(payload)
    created.value = res || {}
    step.value = 'reveal'
    // 交給父層的是不含明文的呈現物件
    const view = { ...(res || {}) }
    delete view.token
    emit('created', view)
  } catch (error) {
    handleError(error)
  } finally {
    submitting.value = false
  }
}

onBeforeUnmount(() => {
  created.value = null
})

defineExpose({ submit, step })
</script>

<style scoped>
.atc-form {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-md);
}
.atc-field {
  display: flex;
  flex-direction: column;
  gap: var(--ot-space-xs);
}
.atc-label {
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  color: var(--ot-text-primary);
}
.atc-label::before {
  content: '*';
  margin-right: 4px;
  color: var(--ot-danger);
}
.atc-hint {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
  line-height: 1.5;
}
.atc-error {
  display: flex;
  align-items: center;
  gap: 4px;
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-danger);
}
.atc-input-error :deep(.el-input__wrapper) {
  box-shadow: 0 0 0 1px var(--ot-danger) inset;
}
.atc-roles {
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
}
.atc-roles.is-error {
  border-color: var(--ot-danger);
}
.atc-role-row {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  padding: var(--ot-space-xs) 12px;
  border-bottom: 1px solid var(--ot-border-subtle);
  flex-wrap: wrap;
}
.atc-role-row:last-child {
  border-bottom: none;
}
.atc-role-all {
  justify-content: space-between;
  background: var(--ot-bg-elevated);
}
.atc-role-count,
.atc-role-scope,
.atc-role-note {
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-secondary);
}
.atc-role-scope {
  margin-left: var(--ot-space-sm);
}
.atc-level {
  margin-left: auto;
  flex-wrap: nowrap;
}
.atc-level__icon {
  margin-right: 4px;
  vertical-align: -2px;
}
/* 讀寫選中時整段轉琥珀色，與唯讀的品牌色一眼可分 */
.atc-level.is-write :deep(.el-radio-button) {
  --el-radio-button-checked-bg-color: var(--ot-warning);
  --el-radio-button-checked-border-color: var(--ot-warning);
  --el-radio-button-checked-text-color: var(--ot-text-inverse);
}
.atc-roles.is-single .atc-role-row {
  border-bottom: none;
}
.atc-role-note-row {
  padding-top: 0;
}
.atc-set-all {
  gap: var(--ot-space-xs);
  font-size: var(--ot-font-size-xs);
}
.atc-set-all__label {
  color: var(--ot-text-secondary);
  margin-right: var(--ot-space-xs);
}
.atc-set-all__sep {
  color: var(--ot-text-secondary);
}
.atc-help-link {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  align-self: flex-start;
  padding: 0;
  border: none;
  background: none;
  font: inherit;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-primary);
  cursor: pointer;
}
.atc-help-link:focus-visible {
  outline: 2px solid var(--ot-primary);
  outline-offset: 2px;
}
.atc-expiry {
  flex-wrap: wrap;
}
.atc-expiry.is-error :deep(.el-radio-button__inner) {
  border-color: var(--ot-danger);
}
.atc-custom-date {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  flex-wrap: wrap;
  margin-top: var(--ot-space-xs);
}
.atc-expiry-line {
  margin: 0;
  font-size: var(--ot-font-size-sm);
  font-weight: 600;
  color: var(--ot-text-primary);
}
.atc-summary {
  padding: var(--ot-space-md);
  border: 1px solid var(--ot-border-subtle);
  border-radius: var(--ot-radius-md);
  background: var(--ot-bg-page);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-secondary);
  line-height: 1.6;
}
.atc-summary h4 {
  margin: 0 0 var(--ot-space-xs);
  font-size: var(--ot-font-size-sm);
  color: var(--ot-text-primary);
}
.atc-summary p {
  margin: 0;
}
.atc-summary__roles {
  font-weight: 600;
  color: var(--ot-text-primary);
}
.atc-summary__roles .is-none,
.atc-summary__roles .is-write {
  color: var(--ot-warning);
}
</style>
