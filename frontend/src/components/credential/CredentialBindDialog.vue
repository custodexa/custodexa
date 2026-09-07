<template>
  <el-dialog
    :model-value="modelValue"
    :title="t('credentials.bindDialog.title')"
    width="480px"
    :close-on-click-modal="false"
    @update:model-value="close"
  >
    <el-form
      ref="formRef"
      :model="form"
      :rules="rules"
      label-position="top"
      @submit.prevent
    >
      <el-form-item
        prop="asset_id"
        :label="t('credentials.bindDialog.asset')"
      >
        <el-select
          v-model="form.asset_id"
          filterable
          :loading="assetsLoading"
          :empty-values="[null, undefined]"
          :placeholder="t('credentials.bindDialog.assetPlaceholder')"
          class="full"
          data-test="bind-asset"
        >
          <el-option
            v-for="asset in assets"
            :key="asset.id"
            :label="asset.name"
            :value="asset.id"
          />
        </el-select>
      </el-form-item>

      <el-form-item>
        <el-checkbox
          v-model="form.is_default"
          data-test="bind-default"
        >
          {{ t('credentials.bindDialog.isDefault') }}
        </el-checkbox>
        <el-checkbox
          v-model="form.privileged"
          data-test="bind-privileged"
        >
          {{ t('credentials.bindDialog.privileged') }}
        </el-checkbox>
      </el-form-item>

      <el-form-item :label="t('credentials.bindDialog.note')">
        <el-input
          v-model="form.note"
          maxlength="255"
          data-test="bind-note"
        />
      </el-form-item>
    </el-form>

    <p class="hint">
      {{ t('credentials.bindDialog.hint') }}
    </p>

    <template #footer>
      <el-button
        data-test="bind-cancel"
        @click="close(false)"
      >
        {{ t('common.cancel') }}
      </el-button>
      <el-button
        type="primary"
        :loading="submitting"
        data-test="bind-submit"
        @click="submit"
      >
        {{ t('credentials.bindDialog.submit') }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup>
/**
 * 把共用憑證掛到一台資產上。
 *
 * 掛載對目標主機零寫入——這件事寫在對話框裡而不是只寫在文件上，因為「掛上去」
 * 聽起來很像「把密碼推過去」，而兩者的後果差很多。
 *
 * 清單不在前端過濾協定相容性：那個判定在後端由資產的協定與改密通道共同推導，
 * 在畫面上複製一份會在通道設定改變時開始說謊。不相容時後端以機器碼拒絕。
 */
import { reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { bindCredential } from '@/api/credentials'
import { getAssetList } from '@/api/assets'

const props = defineProps({
  modelValue: { type: Boolean, default: false },
  credentialId: { type: [Number, String], default: 0 },
  protocolFamily: { type: String, default: '' },
})

const emit = defineEmits(['update:modelValue', 'bound'])

const { t } = useI18n()

const formRef = ref(null)
const assets = ref([])
const assetsLoading = ref(false)
const submitting = ref(false)
const form = reactive({
  asset_id: null,
  is_default: false,
  privileged: false,
  note: '',
})

const rules = {
  asset_id: [{ required: true, message: () => t('credentials.bindDialog.assetRequired') }],
}

async function loadAssets() {
  assetsLoading.value = true
  try {
    const res = await getAssetList({ page: 1, page_size: 200 })
    assets.value = res?.data || []
  } catch (err) {
    console.error('[CredentialBind] 載入資產失敗:', err)
  } finally {
    assetsLoading.value = false
  }
}

watch(() => props.modelValue, (open) => {
  if (!open) return
  form.asset_id = null
  form.is_default = false
  form.privileged = false
  form.note = ''
  formRef.value?.clearValidate?.()
  loadAssets()
})

function close(visible = false) {
  emit('update:modelValue', visible === true)
}

async function submit() {
  if (!form.asset_id) {
    await formRef.value?.validate?.().catch(() => {})
    return
  }
  submitting.value = true
  try {
    await bindCredential(props.credentialId, {
      asset_id: form.asset_id,
      is_default: form.is_default,
      privileged: form.privileged,
      note: form.note,
    })
    close(false)
    ElMessage.success(t('credentials.bindDialog.done'))
    emit('bound')
  } catch (err) {
    console.error('[CredentialBind] 掛載失敗:', err)
  } finally {
    submitting.value = false
  }
}

defineExpose({ form, assets, submit, loadAssets })
</script>

<style scoped>
.full {
  width: 100%;
}

.hint {
  margin: 0;
  font-size: var(--ot-font-size-xs);
  color: var(--ot-text-disabled);
  line-height: 1.6;
}
</style>
