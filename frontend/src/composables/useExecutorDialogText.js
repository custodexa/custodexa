import { computed } from 'vue'

// 堡壘機專用帳號設定對話框的文字：更換說明，以及共用來源的台數確認框。
// props 為對話框的 props（mode、current）；credentialOptions、credentialId、ackCount 為對話框的 ref。
export function useExecutorDialogText({ props, t, credentialOptions, credentialId, ackCount }) {
  // 更換說明：依目前來源選全文；{來源} 與區塊資訊列同字樣
  const replaceDesc = computed(() => {
    const cur = props.current || {}
    const c = cur.credential || {}
    let key
    if (c.credential_out_of_scope) key = 'sharedOutOfScope'
    else if (c.shared_credential || cur.source === 'shared') key = 'shared'
    else key = cur.source === 'generate' || cur.has_public_key ? 'generate' : 'secret'

    let labelKey
    if (cur.source === 'convert') labelKey = 'convert'
    else if (cur.source === 'inline') labelKey = cur.secret_type === 'ssh_key' ? 'inlineKey' : 'inline'
    else if (c.credential_out_of_scope) labelKey = 'sharedOutOfScope'
    else if (c.shared_credential) labelKey = 'shared'
    else labelKey = cur.has_public_key ? 'generate' : 'dedicated'

    const params = {
      account: cur.username || '',
      source: t(`assetExecutor.sourceLabel.${labelKey}`, { name: c.credential_name || '' }),
    }
    if (key === 'shared' || key === 'sharedOutOfScope') return t('assetExecutor.dialog.replaceDescShared', params)
    return t(key === 'generate' ? 'assetExecutor.dialog.replaceDescKeep' : 'assetExecutor.dialog.replaceDescSecret', params)
  })

  // 共用來源：預填台數＝選定憑證目前台數，加上本台（更換為同一把時不加）
  const selectedCredential = computed(() => credentialOptions.value.find((c) => c.id === credentialId.value) || null)
  const sharedIsKey = computed(() => selectedCredential.value?.secret_type === 'ssh_key')
  const sameAsCurrent = computed(
    () => props.mode === 'replace' && props.current?.credential?.credential_id === credentialId.value,
  )
  const prefillCount = computed(() => {
    const n = selectedCredential.value?.binding_count || 0
    return sameAsCurrent.value ? n : n + 1
  })
  const shownCount = computed(() => ackCount.value || prefillCount.value)
  const secretWord = computed(() =>
    t(sharedIsKey.value ? 'assetExecutor.sharedConfirm.secretKey' : 'assetExecutor.sharedConfirm.secretPassword'))
  const sharedTitle = computed(() =>
    t(sharedIsKey.value ? 'assetExecutor.sharedConfirm.titleKey' : 'assetExecutor.sharedConfirm.titlePassword', { count: shownCount.value }))
  const sharedBody = computed(() => {
    const count = shownCount.value
    const parts = [t('assetExecutor.sharedConfirm.leak', { count })]
    if (!sharedIsKey.value) parts.push(t('assetExecutor.sharedConfirm.rotateSend', { count }))
    return parts.join('')
  })
  // 建議句另起一行，與揭露內文分開；金鑰型共用不給此建議
  const sharedAdvice = computed(() => (sharedIsKey.value ? '' : t('assetExecutor.sharedConfirm.adviceKey')))
  const sharedCheckText = computed(() =>
    t(sharedIsKey.value ? 'assetExecutor.sharedConfirm.checkKey' : 'assetExecutor.sharedConfirm.checkPassword', { count: shownCount.value }))

  return { replaceDesc, selectedCredential, shownCount, secretWord, sharedTitle, sharedBody, sharedAdvice, sharedCheckText }
}
