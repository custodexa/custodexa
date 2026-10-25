// 角色定義預覽的共用回應形狀。
// 來源：後端經真實路由預覽「沒有持有者、只被一條停用映射規則指向的自訂角色加入 asset:update」的實際回應。
export const previewDisabledMapping = {
  matched: 0,
  operation: {
    entries_gained: [],
    entries_lost: [],
    evaluated: 0,
    management_granted: true,
    marks: ['management_grant'],
    routes_gained: [],
    routes_lost: [],
    self_direction: '',
  },
  subjects: [],
  total: 0,
  truncated: false,
}

// 直接指派預覽（kind=direct_roles）的回應：鍵集合與上面實際回應相同，
// 頁面入口取自路由鏡像表（backend/internal/api/testdata/route-entry-rules.json）的 /credentials。
// entries_* 故意放不同於 routes_* 的值，用來證明畫面只讀 routes_*。
export const previewDirectCredentials = {
  matched: 1,
  operation: {
    entries_gained: ['credentials.secret'],
    entries_lost: ['assets'],
    evaluated: 1,
    management_granted: false,
    marks: [],
    routes_gained: ['/credentials'],
    routes_lost: ['/sessions'],
    self_direction: '',
  },
  subjects: [],
  total: 1,
  truncated: false,
}
