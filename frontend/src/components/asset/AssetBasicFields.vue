<!--
  AssetBasicFields：資產的基本資料欄位（名稱、協議、主機、埠號）。
  新增資產對話框與編輯抽屜共用同一份欄位定義——兩邊各寫一份，遲早會分歧。
-->
<template>
  <div class="basic-fields">
    <el-form-item
      :label="t('common.name')"
      prop="name"
    >
      <el-input
        v-model="form.name"
        :placeholder="t('assets.namePlaceholder')"
        data-test="asset-name"
      />
    </el-form-item>
    <el-form-item
      :label="t('common.protocol')"
      prop="protocol"
    >
      <el-select
        v-model="form.protocol"
        :placeholder="t('assets.protocolPlaceholder')"
        class="full"
        data-test="asset-protocol"
        @change="(value) => emit('protocol-change', value)"
      >
        <el-option
          v-for="option in PROTOCOL_OPTIONS"
          :key="option.value"
          :label="option.label"
          :value="option.value"
        />
      </el-select>
    </el-form-item>
    <el-form-item
      :label="t('assets.host')"
      prop="host"
    >
      <el-input
        v-model="form.host"
        :placeholder="t('assets.hostPlaceholder')"
        data-test="asset-host"
      />
    </el-form-item>
    <el-form-item
      :label="t('assets.port')"
      prop="port"
    >
      <el-input-number
        v-model="form.port"
        :min="1"
        :max="65535"
        class="full"
        data-test="asset-port"
      />
    </el-form-item>
  </div>
</template>

<script setup>
import { useI18n } from 'vue-i18n'

// 協議標籤是技術識別字，不進 locale（C14）
const PROTOCOL_OPTIONS = [
  { value: 'ssh', label: 'SSH' },
  { value: 'rdp', label: 'RDP' },
  { value: 'vnc', label: 'VNC' },
  { value: 'mysql', label: 'MySQL' },
  { value: 'postgres', label: 'PostgreSQL' },
  { value: 'redis', label: 'Redis' },
  { value: 'mssql', label: 'SQL Server' },
  { value: 'k8s', label: 'K8s' },
]

// form 由呼叫端持有：同一份表單被基本欄位、憑證區塊與進階欄位共同編輯，
// 逐欄回傳只會把一份狀態拆成四份
const form = defineModel('form', { type: Object, required: true })

const emit = defineEmits(['protocol-change'])

const { t } = useI18n()
</script>

<style scoped>
.full {
  width: 100%;
}
</style>
