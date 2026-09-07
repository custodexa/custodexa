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
      <el-option
        v-for="item in options"
        :key="item.id"
        :label="credentialDisplayName(item)"
        :value="item.id"
      >
        <span class="opt-name">{{ credentialDisplayName(item) }}</span>
        <span class="opt-meta">{{ optionMeta(item) }}</span>
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

    <CredentialFormDialog
      v-model="createVisible"
      @saved="onCreated"
    />
  </div>
</template>

<script setup>
import { ref, watch, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Plus } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { listCredentials } from '@/api/credentials'
import { credentialDisplayName } from '@/constants/credentials'
import CredentialFormDialog from '@/components/credential/CredentialFormDialog.vue'

const props = defineProps({
  modelValue: { type: [Number, String], default: null },
  // protocol／windowsOpenssh 原樣轉給端點，不在此推導協定族
  protocol: { type: String, default: '' },
  windowsOpenssh: { type: Boolean, default: false },
  // 已掛在本資產上的憑證：同一台不會掛兩次同一筆
  excludeIds: { type: Array, default: () => [] },
  disabled: { type: Boolean, default: false },
})

const emit = defineEmits(['update:modelValue', 'loaded'])

const { t } = useI18n()

const options = ref([])
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
    load()
  }
)

watch(() => props.excludeIds, load, { deep: true })

onMounted(load)

function onSelect(value) {
  emit('update:modelValue', value ?? null)
}

const optionMeta = (item) =>
  t('assets.credentialSection.picker.meta', {
    username: item.username || t('credentials.usernameUnset'),
    type: t(`enum.credentialSecretType.${item.secret_type}`),
    count: item.binding_count || 0,
  })

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

defineExpose({ options, load, openCreate, onCreated, createVisible })
</script>

<style scoped>
.credential-picker {
  width: 100%;
}

.picker-select {
  width: 100%;
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
