<template>
  <!-- 資產政策覆寫表格：僅列已覆寫資產
      （access_policy 非空），資產表單為主要設定入口、本表為總覽；
       列內即存＋寫入互斥＋讀取序號守衛沿覆寫表格既有語義 -->
  <div
    v-loading="loading"
    class="asset-policy-table"
  >
    <div class="table-header">
      <span class="table-title">{{ $t('assetPolicyTable.title') }}</span>
      <el-tag
        type="info"
        size="small"
        effect="plain"
      >
        {{ $t('assetPolicyTable.liveEffect') }}
      </el-tag>
    </div>

    <!-- 加入覆寫：選未覆寫資產＋段位 -->
    <div class="add-override">
      <el-select
        v-model="addAssetId"
        :placeholder="$t('assetPolicyTable.addOverridePlaceholder')"
        filterable
        clearable
        style="width: 260px"
      >
        <el-option
          v-for="a in nonOverridden"
          :key="a.id"
          :label="$t('assetPolicyTable.assetOption', { name: a.name, protocol: a.protocol.toUpperCase() })"
          :value="a.id"
        />
      </el-select>
      <el-select
        v-model="addPolicy"
        style="width: 180px"
      >
        <el-option
          v-for="(label, value) in accessPolicyEnumLabels"
          :key="value"
          :label="label"
          :value="value"
        />
      </el-select>
      <el-button
        :disabled="!addAssetId || savingId !== null"
        @click="addOverride"
      >
        {{ $t('assetPolicyTable.addOverride') }}
      </el-button>
    </div>

    <el-table
      v-if="overridden.length > 0"
      :data="overridden"
      size="default"
    >
      <el-table-column
        prop="name"
        :label="$t('common.asset')"
        min-width="180"
      />
      <el-table-column
        :label="$t('common.protocol')"
        width="90"
      >
        <template #default="{ row }">
          {{ row.protocol.toUpperCase() }}
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('assets.accessPolicy')"
        min-width="240"
      >
        <template #default="{ row }">
          <el-select
            :model-value="row.access_policy"
            :aria-label="$t('assetPolicyTable.policyAria', { name: row.name })"
            :disabled="savingId !== null"
            style="width: 220px"
            @change="(value) => changePolicy(row, value)"
          >
            <el-option
              :label="$t('assetPolicyTable.clearOverrideWithGlobal', { value: globalPolicyLabel })"
              value=""
            />
            <el-option
              v-for="(label, value) in accessPolicyEnumLabels"
              :key="value"
              :label="label"
              :value="value"
            />
          </el-select>
        </template>
      </el-table-column>
      <el-table-column
        :label="$t('common.actions')"
        width="110"
      >
        <template #default="{ row }">
          <!-- 顯式清除鈕：與下拉「清除覆寫」選項同路徑——移除一列是刪除
               動作，不該只藏在修改控件裡 -->
          <el-button
            text
            type="danger"
            size="small"
            :disabled="savingId !== null"
            @click="changePolicy(row, '')"
          >
            {{ $t('assetPolicyTable.clearOverride') }}
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-empty
      v-else-if="!loading"
      :description="$t('assetPolicyTable.empty')"
      :image-size="48"
    />
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getAssetList, updateAsset } from '@/api/assets'
import { accessPolicyEnumLabels } from '@/utils/policyFormat'
import { t } from '@/i18n'

const props = defineProps({
  // 全域預設段位的已儲存值（未儲存編輯不改變此文案——生效值才是事實）
  globalPolicy: { type: String, default: 'open' },
})

const loading = ref(false)
const assets = ref([])
// 寫入互斥：任一列儲存中即全表禁改，杜絕並發 PUT 亂序留舊值
const savingId = ref(null)
// 讀取序號：只套用最新一次載入回應
let loadSeq = 0

const addAssetId = ref(null)
const addPolicy = ref('approval')

const overridden = computed(() => assets.value.filter((a) => a.access_policy))
const nonOverridden = computed(() => assets.value.filter((a) => !a.access_policy))

const globalPolicyLabel = computed(
  () => accessPolicyEnumLabels[props.globalPolicy] || props.globalPolicy
)

const loadAssets = async () => {
  const seq = ++loadSeq
  loading.value = true
  try {
    const res = await getAssetList({ page: 1, page_size: 1000 })
    if (seq !== loadSeq) return
    assets.value = res.data || []
  } catch (error) {
    console.error('載入資產失敗:', error)
  } finally {
    if (seq === loadSeq) loading.value = false
  }
}

// 列內即存（PUT 部分更新僅送 access_policy）；失敗以重載回滾顯示值
const changePolicy = async (asset, value) => {
  if (savingId.value !== null) return
  savingId.value = asset.id
  try {
    await updateAsset(asset.id, { access_policy: value })
    ElMessage.success(value ? t('assetPolicyTable.updated') : t('assetPolicyTable.cleared'))
  } catch (error) {
    console.error('更新資產政策失敗:', error)
  } finally {
    savingId.value = null
    loadAssets()
  }
}

const addOverride = async () => {
  if (!addAssetId.value) return
  const target = assets.value.find((a) => a.id === addAssetId.value)
  if (!target) return
  await changePolicy(target, addPolicy.value)
  addAssetId.value = null
}

onMounted(loadAssets)
</script>

<style scoped>
.asset-policy-table {
  margin-top: var(--ot-space-sm);
  padding-top: var(--ot-space-sm);
  border-top: 1px solid var(--ot-border-subtle);
}

.table-header {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
}

.table-title {
  font-weight: 600;
  color: var(--ot-text-primary);
}

.add-override {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
}
</style>
