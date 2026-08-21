import request from './request'

/**
 * 連線申請與審核 API（access-policy-approval）
 * 申請人側：提出/我的申請/撤回；審核側：待審/歷史/核准/拒絕（approver 或 admin）；
 * 審核範圍管理 admin only
 */

/**
 * 提出連線申請
 * @param {Object} data - { asset_id, reason, duration_minutes, date_start? }
 */
export function createAccessRequest(data, options = {}) {
  return request({
    url: '/access-requests',
    method: 'post',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/** 我的申請（僅本人；伺服端以 JWT 身分過濾） */
export function getMyAccessRequests() {
  return request({
    url: '/access-requests/mine',
    method: 'get',
  })
}

/** 我的有效限時連線（核准後的時窗） */
export function getMyActiveTickets() {
  return request({
    url: '/access-requests/mine/tickets',
    method: 'get',
  })
}

/** 撤回自己的待審申請 */
export function cancelAccessRequest(id) {
  return request({
    url: `/access-requests/${id}/cancel`,
    method: 'post',
  })
}

/** 待審列表（approver 依審核範圍、admin 全部） */
export function getPendingAccessRequests() {
  return request({
    url: '/access-requests/pending',
    method: 'get',
  })
}

/** 待審件數（導覽 badge；options.skipErrorToast 供輪詢靜默失敗） */
export function getPendingAccessRequestCount(options = {}) {
  return request({
    url: '/access-requests/pending/count',
    method: 'get',
    skipErrorToast: options.skipErrorToast === true,
  })
}

/** 申請歷史（已決定的單） */
export function getAccessRequestHistory(params) {
  return request({
    url: '/access-requests/history',
    method: 'get',
    params,
  })
}

/** 有效限時連線清冊（審核中心視圖） */
export function getActiveTickets() {
  return request({
    url: '/access-requests/tickets',
    method: 'get',
  })
}

/**
 * 核准申請（可縮短時長/延後開始，不可放寬）
 * @param {number} id
 * @param {Object} data - { duration_minutes?, date_start?, note? }
 */
export function approveAccessRequest(id, data = {}) {
  return request({
    url: `/access-requests/${id}/approve`,
    method: 'post',
    data,
  })
}

/**
 * 拒絕申請（必須填理由）
 * @param {number} id
 * @param {string} note
 */
export function rejectAccessRequest(id, note) {
  return request({
    url: `/access-requests/${id}/reject`,
    method: 'post',
    data: { note },
  })
}

/** 審核範圍列表（admin only） */
export function getApproverScopes() {
  return request({
    url: '/approver-scopes',
    method: 'get',
  })
}

/**
 * 分配審核範圍（admin only）
 * @param {Object} data - { approver_id, asset_id? XOR asset_group_id? }
 */
export function createApproverScope(data) {
  return request({
    url: '/approver-scopes',
    method: 'post',
    data,
  })
}

/** 移除審核範圍（admin only） */
export function deleteApproverScope(id) {
  return request({
    url: `/approver-scopes/${id}`,
    method: 'delete',
  })
}

/**
 * 破窗緊急連線（break-glass-revocation）：立即取得短窗連線、事後補審。
 * 時長固定由政策決定，不接受自填。開關關閉時回 403 code=RULE_BREAK_GLASS_DISABLED
 * @param {Object} data - { asset_id, reason }
 */
export function breakGlassConnect(data, options = {}) {
  return request({
    url: '/access-requests/break-glass',
    method: 'post',
    data,
    skipErrorToast: options.skipErrorToast === true,
  })
}

/**
 * 提前撤銷限時連線（admin 或原核准人；auto/破窗單為範圍內審核人）
 * @param {number} id
 * @param {string} note - 撤銷事由（必填）
 */
export function revokeAccessRequest(id, note) {
  return request({
    url: `/access-requests/${id}/revoke`,
    method: 'post',
    data: { note },
  })
}

/**
 * 破窗事後補審（範圍內審核人或 admin；破窗人不得自審）
 * @param {number} id
 * @param {string} disposition - confirmed | violation
 * @param {string} note
 */
export function reviewBreakGlass(id, disposition, note) {
  return request({
    url: `/access-requests/${id}/review`,
    method: 'post',
    data: { disposition, note },
  })
}

/** 待補審破窗單清單（審核中心） */
export function getPendingReviews() {
  return request({
    url: '/access-requests/reviews/pending',
    method: 'get',
  })
}
