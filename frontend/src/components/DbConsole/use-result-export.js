// 匯出鈕的可用性與動作。
//
// 停用有三個彼此獨立的成因，各自要有自己的說法：沒有結果、看的不是最近一次
// 送出（伺服端只快取那一批）、連線已結束（快取隨會話釋放）；再加上傳輸政策的
// 能力投影。三態都不發請求——讓使用者收到一個「找不到」的回應，等於要他去猜。
//
// 投影會過期，所以視窗重獲焦點時重抓一次；它**永遠不是授權真相**，
// 匯出端點每次都重驗政策，這裡只決定按鈕長什麼樣子。

import { ref, computed } from 'vue'
import { downloadResultCsv, exportFilename, fetchExportCapability } from '@/api/dbConsole'
import { downloadBlob } from '@/utils/download'
import { resolveApiError } from '@/api/error'
import { t } from '@/i18n'

/**
 * @param {object} deps
 * @param {import('vue').Ref} deps.activeUnit 目前檢視的執行單位
 * @param {import('vue').Ref} deps.setIndex 目前檢視的結果集索引
 * @param {object} deps.socket useDbConsoleSocket 的回傳
 * @param {() => (number|string)} deps.assetId
 * @param {() => string} deps.assetName
 */
export function useResultExport({ activeUnit, setIndex, socket, assetId, assetName }) {
  const exporting = ref(false)
  const exportError = ref('')

  const disabledReason = computed(() => {
    const unit = activeUnit.value
    if (!unit || !(unit.sets || []).length) return 'noResult'
    if (socket.sessionEnded.value) return 'sessionEnded'
    if (unit.submission !== socket.submissionSeq.value) return 'notLatest'
    if (!socket.exportAllowed.value) return 'policy'
    return ''
  })

  // 可匯出時一併說明公式注入轉義：使用者拿到的 CSV 會與畫面上的值不同
  // （前置單引號），不先講清楚就會被讀成資料被改過
  const tooltip = computed(() =>
    disabledReason.value
      ? t(`dbConsole.exportDisabled.${disabledReason.value}`)
      : `${t('dbConsole.exportTip')} ${t('dbConsole.exportEscapeNote')}`
  )

  async function run() {
    if (disabledReason.value) return
    exporting.value = true
    exportError.value = ''
    try {
      const blob = await downloadResultCsv(
        socket.sessionId.value,
        activeUnit.value.eventId,
        setIndex.value
      )
      downloadBlob(
        blob,
        exportFilename({
          assetName: assetName(),
          seq: activeUnit.value.seq,
          setIndex: setIndex.value,
        })
      )
    } catch (err) {
      // 就近誠實呈現：這一次的請求已關掉全域提示，成因只在這裡說
      exportError.value = resolveApiError(
        err?.response?.data,
        err?.response?.status,
        t('dbConsole.exportFailed')
      )
    } finally {
      exporting.value = false
    }
  }

  // 政策中途放寬（false→true）時毋須重連即可解除停用
  async function refreshCapability() {
    if (document.visibilityState !== 'visible') return
    socket.setExportCapability(await fetchExportCapability(assetId()))
  }

  return { exporting, exportError, disabledReason, tooltip, run, refreshCapability }
}
