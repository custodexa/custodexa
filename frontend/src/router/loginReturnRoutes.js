// 登入後可回到的路由。導向登入頁時，目的路由的名稱在這份清單內才帶 next；
// 清單只決定「要不要帶」，登入後的目的地一律由伺服端判定（只採用回應的 redirect_next）。
// 後端測試讀這個檔案，核對每個 sample 都被伺服端的判準原樣接受、且涵蓋伺服端的每一個路徑樣式；
// 增刪路由時兩邊一起改。sample 是該路由的一個合法網址樣本，不是路由宣告。
export const LOGIN_RETURN_ROUTES = Object.freeze([
  Object.freeze({ name: 'Approvals', sample: '/approvals?tab=pending&request=42' }),
  Object.freeze({ name: 'AuditLogs', sample: '/audit-logs?tab=reviews' }),
  Object.freeze({ name: 'AgentTaskDetail', sample: '/audit/agent-tasks/42' }),
  Object.freeze({ name: 'AgentBreakers', sample: '/agent-breakers?user_id=9' }),
  Object.freeze({ name: 'Alerts', sample: '/alerts' }),
  Object.freeze({ name: 'SessionDetail', sample: '/sessions/42' }),
  Object.freeze({ name: 'NotificationChannels', sample: '/notification-channels' }),
])

export const LOGIN_RETURN_ROUTE_NAMES = Object.freeze(
  new Set(LOGIN_RETURN_ROUTES.map((route) => route.name))
)

export function isLoginReturnRoute(name) {
  return typeof name === 'string' && LOGIN_RETURN_ROUTE_NAMES.has(name)
}
