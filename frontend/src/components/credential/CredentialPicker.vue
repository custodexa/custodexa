<!--
  CredentialPicker：共用憑證下拉選擇器。

  相容性過濾一律由伺服端回答：本元件把「表單當下的協定」與「Windows 開關」
  原樣送給端點，不在前端把協定推導成協定族——推導出來的那份會在改密通道設定
  改變的那一刻開始說謊，而畫面上看不出來。

  底部的「新增共用憑證…」就地開建立對話框，建完直接選用；呼叫端的其他欄位
  不受影響（本元件只回報選中的識別，不碰表單）。
-->
<template>
  <div class="credential-picker">
    <el-select
      :model-value="modelValue || undefined"
      :placeholder="t('assets.credentialSection.picker.placeholder')"
      :loading="loading"
      :disabled="disabled"
      :empty-values="[null, undefined]"
      filterable
      class="picker-select"
      data-test="credential-picker"
      @update:model-value="onSelect"
    >
      <!-- 專用帳號模式：選定值也帶「帳號 · 型別」，與選項同格式 -->
      <template
        v-if="executorMode"
        #label="{ value }"
      >
        <span class="opt-name">{{ selectedLabel(value) }}</span>
        <span
          class="opt-meta"
          data-test="picker-selected-meta"
        >{{ selectedMeta(value) }}</span>
      </template>
      <el-option
        v-for="item in options"
        :key="item.id"
        :label="credentialDisplayName(item)"
        :value="item.id"
        :disabled="optionDisabledReason(item) !== ''"
      >
        <span class="opt-name">{{ credentialDisplayName(item) }}</span>
        <span
          class="opt-meta"
          :data-test="optionDisabledReason(item) ? `picker-disabled-${item.id}` : `picker-meta-${item.id}`"
        >{{ optionMeta(item) }}</span>
      </el-option>
      <template #empty>
        <div class="picker-empty">
          <div>{{ t('assets.credentialSection.picker.empty') }}</div>
          <div class="picker-empty__hint">
            {{ t('assets.credentialSection.picker.emptyHint') }}
          </div>
        </div>
      </template>
      <template #footer>
        <el-button
          link
          type="primary"
          data-test="credential-picker-create"
          @click="openCreate"
        >
          <el-icon><Plus /></el-icon>
          {{ t('assets.credentialSection.picker.create') }}
        </el-button>
      </template>
    </el-select>

    <!-- 伺服器對範圍化檢視者的列附了 actions：清單只含歸屬在其可管理節點的共用憑證 -->
    <p
      v-if="scopedList"
      class="scoped-note"
      data-test="credential-picker-scoped-note"
    >
      {{ t('credentials.pickerScopedNote') }}
    </p>

    <CredentialFormDialog
      v-model="createVisible"
      @saved="onCreated"
    />
  </div>
</template>

<script setup>
import { computed, ref, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { listCredentials } from '@/api/credentials'
import { credentialDisplayName } from '@/constants/credentials'
import { hasActionFlags } from '@/utils/credentialActions'
import CredentialFormDialog from '@/components/credential/CredentialFormDialog.vue'

const props = defineProps({
  modelValue: { type: [Number, String], default: null },
  // protocol／windowsOpenssh 原樣轉給端點，不在此推導協定族
  protocol: { type: String, default: '' },
  windowsOpenssh: { type: Boolean, default: false },
  // 已掛在本資產上的憑證：同一台不會掛兩次同一筆
  excludeIds: { type: Array, default: () => [] },
  disabled: { type: Boolean, default: false },
  // 堡壘機專用帳號的選擇模式：用途為人員連線的憑證停用；Windows 族資產上金鑰型停用；
  // 已是專用帳號的憑證在選項後綴寫台數
  executorMode: { type: Boolean, default: false },
  windowsFamily: { type: Boolean, default: false },
})

const emit = defineEmits(['update:modelValue', 'loaded'])

const { t } = useI18n()

const options = ref([])
const scopedList = computed(() => options.value.some(hasActionFlags))
const loading = ref(false)
const createVisible = ref(false)

// latest-request-wins：連續切協定時，先發後到的回應不得覆寫成上一個協定的清單
let seq = 0

async function load() {
  const current = ++seq
  loading.value = true
  try {
    // windows_openssh 只在 ssh 資產上有意義：其他協定帶著它是不相容的組合，
    // 端點會直接拒絕（那是刻意的，不是可以順手忽略的參數）
    const params = { scope: 'shared' }
    if (props.protocol) params.protocol = props.protocol
    if (props.protocol === 'ssh' && props.windowsOpenssh) params.windows_openssh = true
    const res = await listCredentials(params)
    if (current !== seq) return
    const excluded = new Set((props.excludeIds || []).map((id) => String(id)))
    options.value = (res?.data || []).filter((item) => !excluded.has(String(item.id)))
    emit('loaded', options.value)
  } catch (err) {
    if (current === seq) options.value = []
    console.error('[CredentialPicker] 載入共用憑證失敗:', err)
  } finally {
    if (current === seq) loading.value = false
  }
}

// 協定或 Windows 開關一變就重問伺服端：清單的相容性判準在那一端
watch(
  () => [props.protocol, props.windowsOpenssh],
  () => {
    if (props.modelValue) emit('update:modelValue', null)
    void load()
  }
)

watch(() => props.excludeIds, load, { deep: true })

onMounted(load)

function onSelect(value) {
  emit('update:modelValue', value ?? null)
}

// 專用帳號模式下選項停用的原因（空字串＝可選）；伺服器的 409 仍是最後防線
const optionDisabledReason = (item) => {
  if (!props.executorMode) return ''
  if (item.purpose === 'login') return t('assetExecutor.dialog.disabledLoginUse')
  if (props.windowsFamily && item.secret_type === 'ssh_key') return t('assetExecutor.dialog.disabledWindowsKey')
  return ''
}

// 專用帳號模式的選項後綴（一行、以「 · 」分段）：
// 可選＝「帳號 {名} · 型別」，已是專用帳號再加「已是 N 台的專用帳號」；
// 停用＝人員連線用的只寫原因，Windows 上的金鑰型寫「型別 · 原因」
const executorAccountMeta = (item) => [
  t('assetExecutor.dialog.optionAccount', { account: item.username || t('credentials.usernameUnset') }),
  t(`enum.credentialSecretType.${item.secret_type}`),
]
const executorOptionMeta = (item) => {
  const reason = optionDisabledReason(item)
  if (item.purpose === 'login') return reason
  if (reason) return [t(`enum.credentialSecretType.${item.secret_type}`), reason].join(' · ')
  const parts = executorAccountMeta(item)
  if (item.purpose === 'executor') parts.push(t('assetExecutor.dialog.executorUse', { count: item.binding_count || 0 }))
  return parts.join(' · ')
}

const optionMeta = (item) =>
  props.executorMode
    ? executorOptionMeta(item)
    : t('assets.credentialSection.picker.meta', {
      username: item.username || t('credentials.usernameUnset'),
      type: t(`enum.credentialSecretType.${item.secret_type}`),
      count: item.binding_count || 0,
    })

const findOption = (value) => options.value.find((item) => item.id === value) || null
const selectedLabel = (value) => {
  const item = findOption(value)
  return item ? credentialDisplayName(item) : ''
}
const selectedMeta = (value) => {
  const item = findOption(value)
  return item ? executorAccountMeta(item).join(' · ') : ''
}

function openCreate() {
  createVisible.value = true
}

// 建立對話框只回報「存好了」，不回報建了哪一筆。故以清單差集認人：
// 重載後新出現的識別即本次建立的那筆。新憑證的協定與本資產不符時它不會出現在
// 清單裡（相容性由伺服端過濾），此時就地說明，不靜默什麼都沒發生
async function onCreated() {
  const before = new Set(options.value.map((item) => String(item.id)))
  await load()
  const created = options.value.filter((item) => !before.has(String(item.id)))
  if (!created.length) {
    ElMessage.warning(t('assets.credentialSection.picker.createdNotListed'))
    return
  }
  const picked = created.reduce((a, b) => (Number(b.id) > Number(a.id) ? b : a))
  emit('update:modelValue', picked.id)
}

defineExpose({ options, load, openCreate, onCreated, createVisible, optionDisabledReason, optionMeta, selectedMeta })
</script>

<style scoped>
.credential-picker {
  width: 100%;
}

.picker-select {
  width: 100%;
}

.scoped-note {
  margin: var(--ot-space-xs) 0 0;
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-sm);
}

.opt-name {
  margin-right: var(--ot-space-sm);
}

.opt-meta {
  color: var(--el-text-color-secondary);
  font-family: var(--ot-font-mono, monospace);
  font-size: var(--ot-font-size-xs);
}

.picker-empty {
  padding: var(--ot-space-sm) var(--ot-space-md);
  color: var(--el-text-color-secondary);
  font-size: var(--ot-font-size-sm);
  line-height: 1.6;
}

.picker-empty__hint {
  font-size: var(--ot-font-size-xs);
}
</style>
