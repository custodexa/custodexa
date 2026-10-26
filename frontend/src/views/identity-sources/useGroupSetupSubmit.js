import { computed, reactive } from 'vue'
import { ElMessageBox } from 'element-plus'
import { t } from '@/i18n'
import {
  createUserGroup,
  getUserGroups,
  getUserGroupRoleBindings,
  replaceUserGroupRoleBindings,
} from '@/api/userGroups'
import { createUserGroupMapping, getUserGroupMappings } from '@/api/identitySources'
import { useAssignmentPreview } from '@/composables/useAssignmentPreview'
import { needsDangerConfirm } from '@/utils/dangerCombo'
import { confirmWarnings } from '@/utils/mappingRiskGate'
import { useRuleChangeGate } from './useRuleChangeGate'
import {
  WRITE_GROUP,
  WRITE_ROLES,
  WRITE_RULE,
  apiErrorText,
  classifyWriteFailure,
  errorInfo,
  sameAssignment,
} from './groupSetupOutcome'

export const newRow = () => ({ state: 'notRun', code: '', reason: '' })
export const newRunState = () => ({ groupId: null, groupName: '', doubtGroup: false, readBack: [], rows: [newRow(), newRow(), newRow()] })

/**
 * 「建立群組並設定角色與範圍」抽屜的送出序列：建立群組、寫入群組的角色指派、建立映射規則，
 * 以及每一步寫入結果的判讀、核對讀取、重試與部分完成狀態。
 * ctx 由抽屜元件提供表單與畫面狀態，這裡只讀寫它們，不持有畫面。
 */
export function useGroupSetupSubmit(ctx) {
  const {
    props, form, roleDraft, matchTrimmed, dictEntry, managementNames, canAssign,
    nameError, phase, step, running, gateBusy, editorBindings,
  } = ctx
  const run = reactive(newRunState())
  const rolesPreview = useAssignmentPreview()

  const canSubmit = computed(() => Boolean(form.name.trim() && roleDraft.value.roleIds.length && matchTrimmed.value) && !running.value)

  const resultTitle = computed(() => {
    if (phase.value === 'done') return t('groupSetup.doneTitle')
    if (run.rows.some((r) => r.state === 'unconfirmed')) return t('groupSetup.unconfirmedTitle')
    return running.value ? t('groupSetup.runningTitle') : t('groupSetup.partialTitle')
  })
  const firstOpenIndex = computed(() => run.rows.findIndex((r) => r.state !== 'done'))
  const recheckStep = computed(() => {
    const i = firstOpenIndex.value
    return i !== -1 && run.rows[i].state === 'unconfirmed' && run.rows[i].reason === 'readFailed' ? i : -1
  })
  const retryKind = computed(() => {
    const i = firstOpenIndex.value
    if (i === -1) return ''
    const row = run.rows[i]
    if (row.state === 'unconfirmed') return ''
    if (row.state === 'differs') return 'edit'
    return ['group', 'roles', 'rule'][i]
  })
  const canEditRolesAfterReject = computed(() => {
    const i = firstOpenIndex.value
    return i === 1 && run.rows[1].state === 'rejected'
  })
  const showNoImpact = computed(() => {
    const r = run.rows
    return r[0].state === 'done' && !['done', 'unconfirmed'].includes(r[2].state)
  })

  // —— 寫入結果的設定 ——
  const setRow = (index, state, extra = {}) => {
    Object.assign(run.rows[index], { state, code: '', reason: '', ...extra })
  }

  // 群組角色確認框：與群組頁相同的元件與判讀
  const rolesConfirm = reactive({ open: false, preview: null, unavailable: false, resolver: null, settle: null })
  rolesConfirm.settle = (value) => {
    rolesConfirm.open = false
    const done = rolesConfirm.resolver
    rolesConfirm.resolver = null
    done?.(value)
  }
  const rolesConfirmNotify = computed(() => {
    const p = rolesConfirm.preview
    if (!p) return ''
    const op = p.operation || {}
    if (['increase', 'decrease'].includes(op.self_direction) || (p.subjects || []).some((s) => s.self)) {
      return t('dangerConfirm.notify.selfChange')
    }
    if ((op.marks || []).includes('management_grant')) {
      const roles = managementNames.value.join('、')
      return (p.total ?? 0) === 0
        ? t('dangerConfirm.notify.groupEmpty', { group: run.groupName, role: roles })
        : t('dangerConfirm.notify.groupRoles', { role: roles })
    }
    return ''
  })
  const askRolesConfirm = (preview, unavailable) =>
    new Promise((resolve) => {
      rolesConfirm.preview = preview
      rolesConfirm.unavailable = unavailable
      rolesConfirm.resolver = resolve
      rolesConfirm.open = true
    })

  // 映射規則確認框：沿用映射頁的規則異動閘門
  const { confirmOpen, confirmPreview, confirmUnavailable, confirmNotify, confirmFootnote, gate, proceedConfirm, cancelConfirm } = useRuleChangeGate(gateBusy)

  // —— 步驟 1：建立群組 ——
  const reconcileGroup = async () => {
    run.doubtGroup = true
    setRow(0, 'checking')
    try {
      const res = await getUserGroups({ quiet: true })
      const exists = (res?.data || []).some((g) => g.name === run.groupName)
      if (exists) setRow(0, 'unconfirmed', { reason: 'sameName' })
      else setRow(0, 'notWritten')
    } catch {
      setRow(0, 'unconfirmed', { reason: 'readFailed' })
    }
    return false
  }
  const backToStep1 = (code) => {
    nameError.value = apiErrorText(code, t) || t('groupSetup.failureGeneric')
    setRow(0, 'notRun')
    phase.value = 'form'
    step.value = 1
    return false
  }
  const stepGroup = async () => {
    run.groupName = form.name.trim()
    try {
      const res = await createUserGroup({ name: run.groupName, description: form.description.trim() })
      const id = res?.id ?? res?.data?.id
      if (id == null) return await reconcileGroup()
      run.groupId = id
      setRow(0, 'done')
      return true
    } catch (error) {
      const verdict = classifyWriteFailure(WRITE_GROUP, error)
      if (verdict.kind === 'rejected') {
        // 前一次結果未確認時，名稱已存在可能正是那次稍晚提交的結果：不當作被拒絕
        if (verdict.code === 'CONFLICT_USER_GROUP_NAME_EXISTS' && run.doubtGroup) {
          setRow(0, 'unconfirmed', { reason: 'sameName' })
          return false
        }
        return backToStep1(verdict.code)
      }
      return await reconcileGroup()
    }
  }

  // —— 步驟 2：群組的角色指派 ——
  const reconcileRoles = async () => {
    setRow(1, 'checking')
    try {
      const res = await getUserGroupRoleBindings(run.groupId, { quiet: true })
      const list = res?.data || []
      if (!list.length) {
        setRow(1, 'notWritten')
        return false
      }
      if (sameAssignment(list, roleDraft.value.roleIds, roleDraft.value.roleNodes, editorBindings?.value)) {
        setRow(1, 'done')
        return true
      }
      run.readBack = list
      setRow(1, 'differs')
    } catch {
      setRow(1, 'unconfirmed', { reason: 'readFailed' })
    }
    return false
  }
  const stepRoles = async () => {
    const ids = [...roleDraft.value.roleIds]
    const nodes = { ...roleDraft.value.roleNodes }
    const body = { kind: 'group_roles', group_id: run.groupId, role_ids: ids }
    if (canAssign.value) {
      body.include_managed_asset_counts = true
      if (Object.keys(nodes).length) body.role_nodes = nodes
    }
    const outcome = await rolesPreview.run(body)
    if (!outcome.ok || needsDangerConfirm(outcome.data)) {
      const go = await askRolesConfirm(outcome.ok ? outcome.data : null, !outcome.ok)
      if (!go) {
        setRow(1, 'notRun')
        setRow(2, 'notRun')
        return false
      }
    }
    try {
      await replaceUserGroupRoleBindings(run.groupId, ids, nodes)
      setRow(1, 'done')
      return true
    } catch (error) {
      const verdict = classifyWriteFailure(WRITE_ROLES, error)
      if (verdict.kind === 'rejected') {
        setRow(1, 'rejected', { code: verdict.code })
        return false
      }
      return await reconcileRoles()
    }
  }

  // —— 步驟 3：建立映射規則 ——
  const reconcileRule = async () => {
    setRow(2, 'checking')
    try {
      const res = await getUserGroupMappings(props.sourceType, props.sourceId)
      const found = (res?.data || []).some(
        (r) => r.match_value === matchTrimmed.value && r.user_group_id === run.groupId
      )
      if (found) {
        setRow(2, 'done')
        return true
      }
      setRow(2, 'notWritten')
    } catch {
      setRow(2, 'unconfirmed', { reason: 'readFailed' })
    }
    return false
  }
  const confirmUsageAck = async (usage) => {
    const text = `${t('identityGroupMappings.currentUsage', {
      asset_authorizations: usage?.asset_authorizations || 0,
      approver_scopes: usage?.approver_scopes || 0,
      requester_scopes: usage?.requester_scopes || 0,
    })} ${t('identityGroupMappings.confirmUsage')}`
    try {
      await ElMessageBox.confirm(text, t('identityGroupMappings.confirmTitle'), { type: 'warning' })
      return true
    } catch {
      return false
    }
  }
  const stepRule = async () => {
    const match = matchTrimmed.value
    const body = {
      kind: 'mapping_rule_change',
      rule_type: 'user_group',
      source_type: props.sourceType,
      source_id: Number(props.sourceId),
      match_value: match,
      group_id: run.groupId,
      enabled: true,
    }
    const ctx = { newTarget: run.groupName, managementRoles: managementNames.value, oldTarget: '' }
    if (!(await gate(body, ctx))) {
      setRow(2, 'notRun')
      return false
    }
    let acknowledged = false
    let sourceConfigAcknowledged = false
    for (let attempt = 0; attempt < 3; attempt++) {
      const payload = {
        match_value: match,
        user_group_id: run.groupId,
        enabled: true,
        risk_acknowledged: acknowledged,
        source_config_acknowledged: sourceConfigAcknowledged,
      }
      // 外部群組已在字典時不帶顯示名稱（那是共用值，要在原處修改）
      if (!dictEntry.value) payload.note = form.note
      try {
        await createUserGroupMapping(props.sourceType, props.sourceId, payload)
        setRow(2, 'done')
        return true
      } catch (error) {
        const { code, meta } = errorInfo(error)
        if (code === 'MAPPING_ACK_REQUIRED' && !sourceConfigAcknowledged) {
          const warnings = (meta.warnings || []).map((item) => item.code)
          if (!(await confirmWarnings(warnings))) {
            setRow(2, 'notRun')
            return false
          }
          sourceConfigAcknowledged = true
          continue
        }
        if (code === 'MAPPING_USAGE_ACK_REQUIRED' && !acknowledged) {
          if (!(await confirmUsageAck(meta.usage))) {
            setRow(2, 'notRun')
            return false
          }
          acknowledged = true
          continue
        }
        const verdict = classifyWriteFailure(WRITE_RULE, error)
        if (verdict.kind === 'rejected') {
          setRow(2, 'rejected', { code: verdict.code })
          return false
        }
        return await reconcileRule()
      }
    }
    setRow(2, 'unconfirmed', { reason: 'readFailed' })
    return false
  }

  // —— 序列 ——
  const proceed = async () => {
    running.value = true
    try {
      if (run.rows[0].state !== 'done' && !(await stepGroup())) return
      if (run.rows[1].state !== 'done' && !(await stepRoles())) return
      if (run.rows[2].state !== 'done' && !(await stepRule())) return
      phase.value = 'done'
    } finally {
      running.value = false
    }
  }
  const submit = async () => {
    if (!canSubmit.value) return
    nameError.value = ''
    phase.value = 'run'
    await proceed()
  }
  const retry = async () => {
    phase.value = 'run'
    await proceed()
  }
  const recheck = async () => {
    const i = recheckStep.value
    if (i === -1 || running.value) return
    running.value = true
    try {
      const ok = i === 0 ? await reconcileGroup() : i === 1 ? await reconcileRoles() : await reconcileRule()
      if (ok) {
        running.value = false
        await proceed()
      }
    } finally {
      running.value = false
    }
  }

  return {
    run, rolesPreview, canSubmit, resultTitle, recheckStep, retryKind, canEditRolesAfterReject, showNoImpact,
    setRow, rolesConfirm, rolesConfirmNotify, confirmOpen, confirmPreview, confirmUnavailable, confirmNotify,
    confirmFootnote, proceedConfirm, cancelConfirm, submit, retry, recheck,
  }
}
