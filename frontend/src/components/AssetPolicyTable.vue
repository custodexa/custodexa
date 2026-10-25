<template>
  <!-- 資產政策覆寫表格：資料來自覆寫清單查詢（伺服器依存取政策權限點的範圍投影），
       只列已覆寫資產，資產表單為主要設定入口、本表為總覽；
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

    <p
      class="default-banner"
      data-test="policy-default-banner"
    >
      {{ $t('assetPolicyTable.defaultBanner', { policy: globalPolicyLabel }) }}
    </p>

    <!-- 加入覆寫：遠端搜尋未覆寫資產＋段位 -->
    <div class="add-override">
      <el-select
        v-model="addAssetId"
        :placeholder="$t('assetPolicyTable.addOverridePlaceholder')"
        filterable
        remote
        clearable
        :remote-method="searchCandidates"
        :loading="searching"
        style="width: 260px"
      >
        <el-option
          v-for="a in candidates"
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
      <span
        v-if="scoped"
        class="scoped-hint"
        data-test="policy-scoped-hint"
      >
        {{ $t('assetPolicyTable.scopedHint') }}
      </span>
    </div>

    <el-table
      v-if="overridden.length > 0"
      :key="tableKey"
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
        :label="$t('assetPolicyTable.colNodes')"
        min-width="200"
      >
        <template #default="{ row }">
          <div
            v-for="(path, i) in row.node_paths || []"
            :key="i"
          >
            {{ path }}
          </div>
          <el-text
            v-if="outOfScopeCount(row)"
            size="small"
            type="info"
            data-test="policy-out-of-scope"
          >
            {{ $t('assets.scopedOutOfScopeNodes', { n: outOfScopeCount(row) }) }}
          </el-text>
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
import { getAccessPolicyOverrides, updateAsset } from '@/api/assets'
import { outOfScopeCount } from '@/utils/scopedAssets'
import { accessPolicyEnumLabels } from '@/utils/policyFormat'
import { classifyOverrideChange } from '@/utils/accessPolicyTier'
import { confirmAccessPolicyDowngrade } from '@/utils/accessPolicyDowngradeConfirm'
import { t } from '@/i18n'

const props = defineProps({
  // 全域預設段位的已儲存值（未儲存編輯不改變此文案——生效值才是事實）；
  // 未傳入時用覆寫清單回應的 meta.global_default
  globalPolicy: { type: String, default: null },
})

const loading = ref(false)
const overridden = ref([])
const candidates = ref([])
const searching = ref(false)
const metaGlobalDefault = ref('')
const scoped = ref(false)
let searchSeq = 0
// 寫入互斥：任一列儲存中即全表禁改，杜絕並發 PUT 亂序留舊值
const savingId = ref(null)
// 讀取序號：只套用最新一次載入回應
let loadSeq = 0

// 取消降級確認時遞增：重掛表格，讓下拉的顯示值回到原值
const tableKey = ref(0)

const addAssetId = ref(null)
const addPolicy = ref('approval')

const effectiveGlobalPolicy = computed(() => props.globalPolicy ?? metaGlobalDefault.value)
const globalPolicyLabel = computed(
  () => accessPolicyEnumLabels[effectiveGlobalPolicy.value] || effectiveGlobalPolicy.value
)

const loadAssets = async () => {
  const seq = ++loadSeq
  loading.value = true
  try {
    const res = await getAccessPolicyOverrides({ overridden: true, page: 1, page_size: 1000 })
    if (seq !== loadSeq) return
    overridden.value = res.data || []
    metaGlobalDefault.value = res.meta?.global_default || ''
    scoped.value = res.meta?.scoped === true
  } catch (error) {
    console.error('載入資產失敗:', error)
  } finally {
    if (seq === loadSeq) loading.value = false
  }
}

// 候選資產：未輸入關鍵字不查（伺服器對空搜尋也回空集合）；只套用最新一次回應
const searchCandidates = async (keyword) => {
  const query = (keyword || '').trim()
  const seq = ++searchSeq
  if (!query) {
    candidates.value = []
    searching.value = false
    return
  }
  searching.value = true
  try {
    const res = await getAccessPolicyOverrides({ overridden: false, search: query, page: 1, page_size: 50 })
    if (seq !== searchSeq) return
    candidates.value = res.data || []
  } catch (error) {
    console.error('搜尋資產失敗:', error)
  } finally {
    if (seq === searchSeq) searching.value = false
  }
}

// 列內即存（PUT 部分更新僅送 access_policy）；失敗以重載回滾顯示值
const changePolicy = async (asset, value) => {
  if (savingId.value !== null) return
  // 降級（調低或清除回落到較低預設）先確認；取消則不送出、顯示值回原值
  const change = classifyOverrideChange(asset.access_policy || '', value, effectiveGlobalPolicy.value)
  if (change.downgrade) {
    try {
      await confirmAccessPolicyDowngrade({ assetName: asset.name, change })
    } catch {
      tableKey.value += 1
      return
    }
  }
  savingId.value = asset.id
  try {
    await updateAsset(asset.id, { access_policy: value })
    ElMessage.success(value ? t('assetPolicyTable.updated') : t('assetPolicyTable.cleared'))
  } catch (error) {
    console.error('更新資產政策失敗:', error)
  } finally {
    savingId.value = null
    loadAssets()
    candidates.value = candidates.value.filter((a) => a.id !== asset.id)
  }
}

const addOverride = async () => {
  if (!addAssetId.value) return
  const target = candidates.value.find((a) => a.id === addAssetId.value)
  if (!target) return
  await changePolicy(target, addPolicy.value)
  addAssetId.value = null
}

// 資產授權頁換分頁或按重新整理時重載
defineExpose({ reload: loadAssets })

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

.default-banner {
  margin: 0 0 var(--ot-space-sm);
  color: var(--ot-text-secondary);
}

.scoped-hint {
  color: var(--ot-text-secondary);
  font-size: 12px;
}

.add-override {
  display: flex;
  align-items: center;
  gap: var(--ot-space-sm);
  margin-bottom: var(--ot-space-sm);
}
</style>
