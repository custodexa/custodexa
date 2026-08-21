// 資料傳輸有效能力的取用與呈現（data-transfer-control 6.2）。
//
// **呈現面與強制面的失敗方向刻意相反，這不是筆誤**：
// - 強制面（後端 SFTP／K8s 閘、tunnel 攔截）解析失敗一律拒絕（fail-close），
//   因為它是控制。
// - 呈現面（本 composable）查詢失敗時**視為可用**（fail-open），因為它不是控制。
//   查不到能力就把按鈕全部鎖死，等於讓一次網路抖動變成「產品看起來壞了」，而
//   使用者實際上有權限；真的沒權限時伺服端仍會擋並回 RULE_TRANSFER_DENIED。
//   查詢失敗會以 `stale` 旗標外露，呼叫端可據此提示呈現可能不準。

import { ref, computed } from 'vue'
import { getTransferCapabilities } from '@/api/files'

// 五項能力的動作鍵（與後端 policy.TransferAction* 同名，JSON 欄位即此組）
export const TRANSFER_ACTIONS = [
  'clipboard_send',
  'clipboard_recv',
  'file_upload',
  'file_download',
  'file_delete',
]

export function useTransferCapabilities() {
  // null＝尚未取得（載入中或查詢失敗）；物件＝伺服端解析結果
  const capabilities = ref(null)
  const loading = ref(false)
  // 上一次查詢失敗（呈現可能不反映現行政策）
  const stale = ref(false)
  // 剪貼簿邊界事實由伺服端下發，前端不硬編（D11-1／D4）
  const clipboardProtocols = ref([])
  const clipboardRequiresReconnect = ref(true)

  /**
   * 取得能力集。
   * @param {number|string} assetId
   * @returns {Promise<Object|null>} 解析到的能力集；失敗回 null
   */
  async function load(assetId) {
    if (!assetId) return null
    loading.value = true
    try {
      const res = await getTransferCapabilities(assetId)
      capabilities.value = res?.capabilities || null
      clipboardProtocols.value = res?.clipboard_enforced_protocols || []
      clipboardRequiresReconnect.value = res?.clipboard_requires_reconnect !== false
      stale.value = capabilities.value === null
      return capabilities.value
    } catch (err) {
      // 呈現面 fail-open：保留上一次已知值，只標記 stale
      console.error('[transferCapabilities] 能力查詢失敗:', err?.response?.status, err?.response?.data?.code)
      stale.value = true
      return null
    } finally {
      loading.value = false
    }
  }

  /**
   * 某動作是否可用。未取得能力集時回 true（fail-open，見檔頭）。
   * @param {string} action - TRANSFER_ACTIONS 之一
   */
  function allows(action) {
    const caps = capabilities.value
    if (!caps) return true
    return caps[action] !== false
  }

  // 目前被禁止的動作清單（供區塊層提示「哪些被擋」用）
  const deniedActions = computed(() =>
    capabilities.value ? TRANSFER_ACTIONS.filter((a) => capabilities.value[a] === false) : []
  )

  function reset() {
    capabilities.value = null
    stale.value = false
  }

  return {
    capabilities,
    loading,
    stale,
    clipboardProtocols,
    clipboardRequiresReconnect,
    deniedActions,
    load,
    allows,
    reset,
  }
}
