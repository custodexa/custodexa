<template>
  <el-select
    :model-value="modelValue"
    class="subject-picker"
    :class="{ 'is-ip': isIP }"
    filterable
    remote
    clearable
    reserve-keyword
    :allow-create="isIP"
    :default-first-option="isIP"
    data-test="subject-picker"
    :remote-method="search"
    :loading="loading"
    :placeholder="placeholder"
    :no-data-text="noDataText"
    @update:model-value="onSelect"
    @visible-change="onVisible"
  >
    <!--
      位址型是另一種形狀（`{ip, last_seen_at}`，無 id／狀態欄），且**可自由輸入**：
      候選只含成功登入或建線過的位址，只出現在拒絕紀錄裡的位址查不到候選，
      但那正是最需要查的一種。allow-create 讓任一位址都送得出去
    -->
    <template v-if="isIP">
      <el-option
        v-for="item in options"
        :key="item.ip"
        :value="item.ip"
        :label="item.ip"
      >
        <span class="opt-name opt-ip">{{ item.ip }}</span>
        <span
          v-if="item.last_seen_at"
          class="opt-sub"
        >{{ $t('auditorWorkbench.subject.ipLastSeen', {
          time: formatDateTime(item.last_seen_at),
        }) }}</span>
      </el-option>
    </template>
    <template v-else>
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
    </template>
  </el-select>
</template>

<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { getAuditSubjects } from '@/api/auditTimeline'
import { formatDateTime } from '@/utils/format'

const { t } = useI18n()

const props = defineProps({
  // 位址樞紐的主體鍵是**字串**（位址）；人／資產樞紐是整數 id
  modelValue: { type: [Number, String], default: null },
  subjectType: { type: String, required: true },
})
const emit = defineEmits(['update:modelValue', 'change'])

const options = ref([])
const loading = ref(false)

const isIP = computed(() => props.subjectType === 'ip')

const placeholder = computed(() => {
  if (isIP.value) return t('auditorWorkbench.subject.ipPlaceholder')
  return props.subjectType === 'asset'
    ? t('auditorWorkbench.subject.assetPlaceholder')
    : t('auditorWorkbench.subject.userPlaceholder')
})

// 位址型的「查無候選」不是死路：候選是便利而非範圍限制，空提示要說出下一步
const noDataText = computed(() =>
  isIP.value
    ? t('auditorWorkbench.subject.ipEmpty')
    : t('auditorWorkbench.subject.empty')
)

const optionLabel = (item) =>
  item.display_name && item.display_name !== item.name
    ? `${item.name || `#${item.id}`}（${item.display_name}）`
    : item.name || `#${item.id}`

const keyOf = (item) => (isIP.value ? item?.ip : item?.id)

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
    const selected = options.value.find((o) => keyOf(o) === props.modelValue)
    if (selected && !list.some((o) => keyOf(o) === keyOf(selected))) {
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
  // 位址型：allow-create 產出的值是字串，原樣送出（正規化與合法性判定在後端）；
  // 人／資產型維持整數（null＝清空）
  const next = isIP.value ? (value ? String(value).trim() : '') : (value ?? null)
  emit('update:modelValue', next)
  emit('change', options.value.find((o) => keyOf(o) === next) || null)
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
    // 深連結帶入的主體可能不在預設清單裡（大量主體、或位址只出現在拒絕紀錄）：
    // 補一個佔位項，讓選擇器至少顯示得出它而不是空白
    if (!props.modelValue) return
    if (options.value.some((o) => keyOf(o) === props.modelValue)) return
    options.value = [
      isIP.value
        ? { ip: String(props.modelValue) }
        : { id: props.modelValue, name: `#${props.modelValue}` },
      ...options.value,
    ]
  })
})
</script>

<style scoped>
.subject-picker {
  width: 240px;
}

/* 位址比帳號名長，且要等寬字才對得齊 */
.subject-picker.is-ip {
  width: 280px;
}

.opt-name {
  color: var(--ot-text-primary);
}

.opt-ip {
  font-family: var(--ot-font-mono);
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
