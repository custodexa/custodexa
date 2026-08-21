import { h } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import request from './request'
import { createAccessRequest } from './accessRequests'
import { t } from '@/i18n'
import { resolveApiError } from './error'
import { riskLabel } from '@/utils/transportDisplay'

/**
 * 換取一次性連線 token（connect-token）：授權檢查在簽發時完成。
 * options.accountId（asset-multi-account D3）為所選資產帳號——**憑證選擇器而非
 * 授權快照**，簽發與兌換兩點都以 DB 現查驗客體綁定與帳號授權；省略＝預設帳號。
 * K8s 資產固定單一預設帳號，帶 account_id 會被後端擋（RULE_ACCOUNT_K8S_DEFAULT_ONLY）
 */
export function createConnectToken(assetId, options = {}) {
  const data = { asset_id: Number(assetId) }
  if (options.accountId) data.account_id = Number(options.accountId)
  return request({
    url: '/connect-tokens',
    method: 'post',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/** 傳輸風險同意立據（transmission-security-policy D3）：risk_keys＝使用者看到的風險項 */
export function createTransmissionConsent(assetId, riskKeys) {
  return request({
    url: '/transmission-consents',
    method: 'post',
    data: { asset_id: Number(assetId), risk_keys: riskKeys },
  })
}

/**
 * 連線前風險同意對話框（5.2）：列風險項＋「我了解風險並繼續」。
 * 拒絕即 reject（呼叫端中止連線）
 */
export function confirmTransmissionRisks(risks) {
  return ElMessageBox.confirm(
    h('div', null, [
      h('p', null, t('connect.risksIntro')),
      h(
        'ul',
        { style: 'margin: 8px 0 8px 20px' },
        // 風險項文案以 risk.key 查譯（i18n-backend-labels）；AssetRisks 無 params
        risks.map((r) => h('li', { key: r.key }, riskLabel(r)))
      ),
      h('p', null, t('connect.risksConfirmNote')),
    ]),
    t('connect.risksTitle'),
    {
      confirmButtonText: t('connect.risksConfirm'),
      cancelButtonText: t('connect.risksCancel'),
      type: 'warning',
    }
  )
}

/**
 * 帶同意流程的簽發（transmission-security-policy 5.2）：
 * 428（需同意）→對話框→立據→自動重試一次；拒絕即中止。
 * 後端閘才是強制點，本流程僅為呈現層——繞過它直呼簽發同樣被擋
 */
export async function createConnectTokenWithConsent(assetId, accountId = null) {
  try {
    // 428（傳輸同意）與 403（存取政策）屬預期流程，不走全域錯誤 toast
    return await createConnectToken(assetId, { skipErrorToast: true, accountId })
  } catch (error) {
    const resp = error?.response

    // 存取政策閘 403 分流（access-policy-approval D7 補充二）：行為以後端
    // 回應為準——列表按鈕態過時（核准後/到期後未刷新）在此自癒
    if (resp?.status === 403 && resp.data?.reason === 'reason_required') {
      // 填理由段：就地補一張理由單（後端自動核准）後重試連線
      const { value } = await ElMessageBox.prompt(
        t('connect.reasonPromptMessage'),
        t('connect.reasonPromptTitle'),
        {
          confirmButtonText: t('connect.reasonSubmit'),
          cancelButtonText: t('connect.risksCancel'),
          inputType: 'textarea',
          inputPlaceholder: t('connect.reasonPlaceholder'),
          inputValidator: (v) => (v && v.trim() ? true : t('connect.reasonRequired')),
        }
      )
      const maxMinutes = Number(resp.data?.max_duration_minutes) || 60
      await createAccessRequest({
        asset_id: Number(assetId),
        reason: value.trim(),
        duration_minutes: Math.min(60, maxMinutes),
      })
      return await createConnectToken(assetId, { accountId })
    }
    if (resp?.status === 403 && resp.data?.reason === 'recording_unavailable') {
      // 錄影 fail-close（recording-failure-handling D2）：reason 顯式分流，
      // 不依賴後端文案經 generic toast 轉述——阻斷性狀態用對話框明確告知
      await ElMessageBox.alert(
        t('connect.recordingUnavailableMessage'),
        t('connect.recordingUnavailableTitle'),
        { confirmButtonText: t('connect.ok'), type: 'error' }
      ).catch(() => {})
      throw error
    }
    if (resp?.status === 403 && resp.data?.reason === 'approval_required') {
      const pendingId = resp.data?.pending_request_id
      await ElMessageBox.alert(
        pendingId
          ? t('connect.approvalPendingMessage', { id: pendingId })
          : t('connect.approvalNeededMessage'),
        t('connect.approvalTitle'),
        { confirmButtonText: t('connect.ok'), type: 'warning' }
      ).catch(() => {})
      throw error
    }

    if (resp?.status !== 428) {
      // 非同意語義的失敗：skipErrorToast 關掉了全域 toast，此處補回同等呈現
      ElMessage.error(resolveApiError(resp?.data, resp?.status, t('connect.tokenFailed')))
      throw error
    }
    const risks = Array.isArray(resp.data?.risks) ? resp.data.risks : []
    // 使用者取消 → reject，呼叫端中止連線
    await confirmTransmissionRisks(risks)
    await createTransmissionConsent(
      assetId,
      risks.map((r) => r.key)
    )
    // 重試一次；仍失敗（政策競態改 strict 等）由全域 toast 呈現
    return await createConnectToken(assetId, { accountId })
  }
}
