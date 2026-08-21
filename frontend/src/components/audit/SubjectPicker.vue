<template>
  <el-select
    :model-value="modelValue"
    class="subject-picker"
    filterable
    remote
    clearable
    reserve-keyword
    data-test="subject-picker"
    :remote-method="search"
    :loading="loading"
    :placeholder="placeholder"
    :no-data-text="$t('auditorWorkbench.subject.empty')"
    @update:model-value="onSelect"
    @visible-change="onVisible"
  >
    <el-option
      v-for="item in options"
      :key="item.id"
      :value="item.id"
      :label="optionLabel(item)"
    >
      <span class="opt-name">{{ item.name || `#${item.id}` }}</span>
      <span
        v-if="item.display_name && item.display_name !== item.name"
        class="opt-sub"
      >{{ item.display_name }}</span>
      <!--
        已停用／已軟刪的主體照樣可選，但**必須標記**：查得到卻不標，
        稽核員會以為自己在查一個仍在線的帳號或資產
      -->
      <el-tag
        v-if="item.active === false"
        size="small"
        type="info"
        class="opt-tag"
      >
        {{ $t('auditorWorkbench.subject.inactive') }}
      </el-tag>
      <el-tag
        v-if="item.deleted"
        size="small"
        type="danger"
        class="opt-tag"
      >
        {{ $t('auditorWorkbench.subject.deleted') }}
      </el-tag>
    </el-option>
  </el-select>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { getAuditSubjects } from '@/api/auditTimeline'

const { t } = useI18n()

const props = defineProps({
  modelValue: { type: Number, default: null },
  subjectType: { type: String, required: true },
})
const emit = defineEmits(['update:modelValue', 'change'])

const options = ref([])
const loading = ref(false)

const placeholder = computed(() =>
  props.subjectType === 'asset'
    ? t('auditorWorkbench.subject.assetPlaceholder')
    : t('auditorWorkbench.subject.userPlaceholder')
)

const optionLabel = (item) =>
  item.display_name && item.display_name !== item.name
    ? `${item.name || `#${item.id}`}（${item.display_name}）`
    : item.name || `#${item.id}`

const search = async (keyword = '') => {
  loading.value = true
  try {
    const res = await getAuditSubjects({
      type: props.subjectType,
      q: keyword,
      limit: 50,
    })
    const list = res?.data || []
    // 已選但不在本次結果內者釘在最前，否則搜尋一次就把選中項的名字弄丟
    const selected = options.value.find((o) => o.id === props.modelValue)
    if (selected && !list.some((o) => o.id === selected.id)) {
      options.value = [selected, ...list]
    } else {
      options.value = list
    }
  } catch (_e) {
    options.value = []
  } finally {
    loading.value = false
  }
}

const onSelect = (value) => {
  emit('update:modelValue', value ?? null)
  emit('change', options.value.find((o) => o.id === value) || null)
}

const onVisible = (visible) => {
  if (visible && options.value.length === 0) search('')
}

watch(
  () => props.subjectType,
  () => {
    options.value = []
    search('')
  }
)

onMounted(() => {
  search('').then(() => {
    // 深連結帶入的 id 可能不在預設清單裡（大量主體時）：補一個佔位項，
    // 讓選擇器至少顯示得出 id 而不是空白
    if (props.modelValue && !options.value.some((o) => o.id === props.modelValue)) {
      options.value = [{ id: props.modelValue, name: `#${props.modelValue}` }, ...options.value]
    }
  })
})
</script>

<style scoped>
.subject-picker {
  width: 240px;
}

.opt-name {
  color: var(--ot-text-primary);
}

.opt-sub {
  margin-left: var(--ot-space-sm);
  color: var(--ot-text-secondary);
  font-size: var(--ot-font-size-xs);
}

.opt-tag {
  margin-left: var(--ot-space-sm);
}
</style>
