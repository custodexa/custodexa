package middleware

import (
	"net/http"
	"sort"
)

// API token 的路由範圍登錄：以「方法 樣板路徑」為鍵，每一條路由記三項具名分類。
//
//   - 開放（RouteAccess*）：是否對 API token 開放。
//   - 性質（RouteNature*）：請求會改變系統保存的資料為寫；稽核留痕、最近使用時間不算；不改變資料的預覽與
//     試算為讀。判定不依 HTTP 方法：方法與性質不符的路由逐條列在 apiTokenMethodNatureMismatch。
//   - 對外連線（RouteOutbound*）：請求處理中平台就連出去為 immediate；請求改變了平台日後會連去的位址、
//     送往某個目的地的是哪一筆保存的秘密，或會讓平台主動對外連線的排程或觸發條件（新增、修改、刪除皆算）
//     為 deferred。系統告警經管理者設定的通道外送，屬平台既有的通報，不因此把會觸發告警的路由算成對外連線。
//
// 封閉清單、預設拒絕：未登錄、查無路由（樣板路徑為空）、登錄為不開放、或三項任一不是認得的已分類值，
// 一律不開放。開放而為 immediate 的路由只有列在 apiTokenImmediateOutboundExceptions 時才開放。
// 每一條已註冊的路由都必須在此登錄（守衛以路由清冊雙向比對）；新增路由時預設登錄為不開放、兩項分類為
// unclassified，要開放就必須先分類。只有程式化管理所需、且不會讓平台以保存的秘密對外連線、不改動外部
// 服務目的地以致秘密或證據外流、不回傳機敏內容的管理與設定端點才登錄為開放。
// 內容另以 testdata/api-token-route-scope.tsv 逐條對照。
//
// 性質決定以 API token 認證的請求計入哪些授權角色：性質恰為讀時計入全部授權角色，其他一律只計入層級為
// 讀寫的角色。性質填錯的後果是唯讀的 token 可以寫入，新增或修改任何一列都要以這個後果審視。

// APITokenRouteAccess 路由是否對 API token 開放。
type APITokenRouteAccess string

// APITokenRouteNature 路由的性質（讀或寫）。
type APITokenRouteNature string

// APITokenRouteOutbound 路由是否讓平台對外連線。
type APITokenRouteOutbound string

const (
	RouteAccessOpen   APITokenRouteAccess = "open"
	RouteAccessClosed APITokenRouteAccess = "closed"

	RouteNatureRead         APITokenRouteNature = "read"
	RouteNatureWrite        APITokenRouteNature = "write"
	RouteNatureUnclassified APITokenRouteNature = "unclassified"

	RouteOutboundNone         APITokenRouteOutbound = "none"
	RouteOutboundImmediate    APITokenRouteOutbound = "immediate"
	RouteOutboundDeferred     APITokenRouteOutbound = "deferred"
	RouteOutboundUnclassified APITokenRouteOutbound = "unclassified"
)

// APITokenRouteClass 一條路由的三項分類。
type APITokenRouteClass struct {
	Access   APITokenRouteAccess
	Nature   APITokenRouteNature
	Outbound APITokenRouteOutbound
}

// Known 三項是否都是列舉內的值（unclassified 也算列舉內）。
func (c APITokenRouteClass) Known() bool {
	switch c.Access {
	case RouteAccessOpen, RouteAccessClosed:
	default:
		return false
	}
	switch c.Nature {
	case RouteNatureRead, RouteNatureWrite, RouteNatureUnclassified:
	default:
		return false
	}
	switch c.Outbound {
	case RouteOutboundNone, RouteOutboundImmediate, RouteOutboundDeferred, RouteOutboundUnclassified:
	default:
		return false
	}
	return true
}

// Classified 性質與對外連線是否都是認得的已分類值（不是 unclassified、不是空值、不是不認得的值）。
func (c APITokenRouteClass) Classified() bool {
	switch c.Nature {
	case RouteNatureRead, RouteNatureWrite:
	default:
		return false
	}
	switch c.Outbound {
	case RouteOutboundNone, RouteOutboundImmediate, RouteOutboundDeferred:
	default:
		return false
	}
	return true
}

var apiTokenRouteRegistry = map[string]APITokenRouteClass{
	"POST /api/v1/access-requests":                                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/access-requests/:id/approve":                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/access-requests/:id/cancel":                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/access-requests/:id/reject":                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-requests/:id/reports":                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/access-requests/:id/reports":                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/access-requests/:id/review":                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/access-requests/:id/revoke":                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/access-requests/break-glass":                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-requests/history":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-requests/mine":                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-requests/mine/tickets":                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-requests/pending":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-requests/pending/count":                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-requests/reviews/pending":                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-requests/tickets":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-reviews":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/access-reviews":                                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-reviews/:id":                                                {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/access-reviews/matrix":                                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/account-inventory/findings":                                        {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/agent-tasks":                                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/agent-tasks/:requestId":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/agent-tool-calls":                                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/agent-tool-calls/:id/arguments":                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/api-tokens/verify":                                                 {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/alert-rules":                                                       {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/alert-rules":                                                      {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"DELETE /api/v1/alert-rules/:id":                                                {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"PUT /api/v1/alert-rules/:id":                                                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"GET /api/v1/approver-scopes":                                                   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/approver-scopes":                                                  {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/approver-scopes/:id":                                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/approver-scopes/approver-options":                                  {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/approver-scopes/target-options":                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/asset-groups":                                                      {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/asset-groups":                                                     {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/asset-groups/:id":                                               {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/asset-groups/:id":                                                  {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/asset-groups/:id/move":                                             {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/asset-groups/tree":                                                 {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/asset-groups/:id":                                                  {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/assets":                                                            {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/assets":                                                           {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"DELETE /api/v1/assets/:id":                                                     {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"GET /api/v1/assets/:id":                                                        {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/assets/:id":                                                        {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"GET /api/v1/assets/:id/account-inventory":                                      {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/assets/:id/account-inventory/findings/:findingId/ignore":          {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/assets/:id/account-inventory/findings/:findingId/reopen":          {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/assets/:id/account-inventory/scans":                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/:id/accounts":                                               {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/assets/:id/accounts/:accountId":                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/assets/:id/accounts":                                              {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"DELETE /api/v1/assets/:id/accounts/:accountId":                                 {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"PUT /api/v1/assets/:id/accounts/:accountId":                                    {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"PUT /api/v1/assets/:id/accounts/:accountId/credential":                         {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/assets/:id/accounts/:accountId/set-default":                       {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"DELETE /api/v1/assets/:id/executor":                                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"GET /api/v1/assets/:id/executor":                                               {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/assets/:id/executor":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/:id/executor/login-check":                                   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/assets/:id/executor/login-check":                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/:id/executor/public-key":                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"DELETE /api/v1/assets/:id/files":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/:id/files":                                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/:id/files/download":                                         {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/assets/:id/files/mkdir":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/assets/:id/files/upload":                                          {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/assets/:id/host-key":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/:id/host-key":                                               {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/assets/:id/host-key/adopt":                                        {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/:id/k8s/download":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/:id/k8s/pods":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/assets/:id/k8s/upload":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/assets/:id/test-connection":                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/:id/transfer-capabilities":                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/assets/access-policy-overrides":                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/assets/batch/delete":                                              {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/assets/batch/move":                                                {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/assets/batch/tags":                                                {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/assets/import":                                                    {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/assets/import/preview":                                            {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/assets/tags":                                                       {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/assets/tags/delete":                                               {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/assets/tags/rename":                                               {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/audit-checkpoints":                                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-checkpoints/public-key":                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-checkpoints/verify":                                          {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-export":                                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-export/jobs":                                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/audit-export/jobs":                                                {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-export/jobs/:id/download":                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-export/public-key":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-failures":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/audit-failures/permission-state/accept":                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-integrity/verify":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-logs":                                                        {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-logs/:id":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit-logs/resource/:resource/:id":                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit/subjects":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/audit/timeline":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/auth/banner":                                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/change-password":                                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/login":                                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/logout":                                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/auth/me":                                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"PATCH /api/v1/auth/me":                                                         {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/auth/me/release-guidance/:version":                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"PUT /api/v1/auth/me/release-guidance/:version":                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/auth/methods":                                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/mfa/disable":                                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/mfa/enable":                                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/mfa/enroll/confirm":                                          {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/mfa/enroll/setup":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/mfa/setup":                                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/mfa/verify":                                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/auth/oidc/:id/begin":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/auth/oidc/callback":                                                {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/oidc/exchange":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/auth/refresh":                                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/authorizations":                                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/authorizations":                                                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/authorizations/:id":                                             {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/authorizations/:id":                                                {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/authorizations/:id/accounts":                                       {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/authorizations/batch":                                             {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/authorizations/effective-assets":                                   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/authorizations/effective-users":                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/authorizations/self-subjects":                                      {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/authorizations/subject-options":                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/authorizations/target-options":                                     {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/change-secret-batches":                                             {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/change-secret-batches":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/change-secret-batches/:id":                                         {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/change-secret-batches/targets":                                     {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/change-secret-batches/usernames":                                   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/change-secret-candidates":                                          {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"DELETE /api/v1/change-secret-candidates/:id":                                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/change-secret-candidates/:id/retry":                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/change-secret-plans":                                               {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/change-secret-plans":                                              {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"DELETE /api/v1/change-secret-plans/:id":                                        {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"PUT /api/v1/change-secret-plans/:id":                                           {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"GET /api/v1/change-secret-plans/:id/records":                                   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/change-secret-plans/:id/run":                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/change-secret-plans/reauthorize":                                  {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"GET /api/v1/command-alerts":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/command-alerts/:id/review":                                        {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/command-alerts/:id/system-detail":                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/commands":                                                          {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/compliance/report-jobs":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/compliance/snapshot":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/connect":                                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/connect-tokens":                                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/credentials":                                                       {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/credentials":                                                      {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/credentials/:id":                                                {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"GET /api/v1/credentials/:id":                                                   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/credentials/:id":                                                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/credentials/:id/bindings":                                         {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"DELETE /api/v1/credentials/:id/bindings/:accountId":                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/credentials/:id/bindings/:accountId/detach":                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/credentials/:id/impact-confirmations":                             {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/credentials/:id/rotations":                                        {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/credentials/:id/rotations/:rid":                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/credentials/:id/rotations/:rid/abandon":                           {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/credentials/:id/rotations/:rid/members/:mid/retry":                {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/credentials/:id/scope":                                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/credentials/:id/secret":                                           {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/credentials/ownership":                                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/daily-reviews":                                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/daily-reviews":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/daily-reviews/days/:date":                                          {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/daily-reviews/pending":                                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/daily-reviews/pending/count":                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/daily-reviews/stats":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/daily-reviews/status":                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/dashboard/cards/:key":                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/dashboard/retention-adjustments":                                   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/db-console":                                                        {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/db-console/sessions/:id/results/:event_id/export":                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/identity-sources":                                                  {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/identity-sources/:type/:sourceId/external-groups":                  {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/identity-sources/:type/:sourceId/external-groups/:externalGroupId": {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/identity-sources/:type/:sourceId/mappings":                         {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/identity-sources/:type/:sourceId/mappings":                        {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/identity-sources/:type/:sourceId/mappings/:ruleId":              {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/identity-sources/:type/:sourceId/mappings/:ruleId":                 {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/identity-sources/:type/:sourceId/role-mappings":                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/identity-sources/:type/:sourceId/role-mappings/:ruleId":            {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/identity-sources/:type/:sourceId/role-mappings":                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/identity-sources/:type/:sourceId/role-mappings/:ruleId":         {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/identity-sources/:type/:sourceId/role-mappings/:ruleId":            {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/identity-sources/:type/:sourceId/user-group-mappings":              {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/identity-sources/:type/:sourceId/user-group-mappings/:ruleId":      {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/identity-sources/:type/:sourceId/user-group-mappings":             {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/identity-sources/:type/:sourceId/user-group-mappings/:ruleId":   {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/identity-sources/:type/:sourceId/user-group-mappings/:ruleId":      {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/identity-sources/:type/:sourceId/user-group-usage/:userGroupId":    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/instance-guard":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/instance-guard/ack":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/instance-guard/halt":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/keys":                                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/keys/retired-material":                                          {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/keys/rewrap":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/keys/rewrap":                                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/keys/rotate":                                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/keys/topology":                                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"PUT /api/v1/keys/topology":                                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/ldap-directory":                                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/ldap-directory":                                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/ldap-directory":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/ldap-directory/status":                                             {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/ldap-directory/test":                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/mcp":                                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/my/agents":                                                         {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/my/agents":                                                        {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/my/api-tokens":                                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/my/api-tokens":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/my/api-tokens/:id":                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/my/connections":                                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/my/connections/:id/terminate":                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/notification-channels":                                             {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/notification-channels":                                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"DELETE /api/v1/notification-channels/:id":                                      {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"PUT /api/v1/notification-channels/:id":                                         {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/notification-channels/:id/test":                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/offsite-storage/failures":                                          {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/offsite-storage/objects/:id/retry":                                {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/offsite-storage/profiles":                                          {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/offsite-storage/profiles/:id/revoke-credentials":                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/offsite-storage/retry-failed":                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/offsite-storage/settings":                                          {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/offsite-storage/settings":                                          {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/offsite-storage/settings/confirm":                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/offsite-storage/settings/disable":                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/offsite-storage/status":                                            {RouteAccessOpen, RouteNatureRead, RouteOutboundImmediate},
	"POST /api/v1/offsite-storage/test":                                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/oidc-providers":                                                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/oidc-providers":                                                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"DELETE /api/v1/oidc-providers/:id":                                             {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"GET /api/v1/oidc-providers/:id":                                                {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/oidc-providers/:id":                                                {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"GET /api/v1/oidc-providers/:id/status":                                         {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/oidc-providers/discovery-preview":                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/ping":                                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/policy-groups":                                                     {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/policy-groups":                                                    {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/policy-groups/:code":                                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/policy-groups/:code":                                               {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/policy-groups/:code":                                               {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/policy-groups/:code/clauses/:clause_no":                         {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/policy-groups/:code/clauses/:clause_no":                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/policy-groups/:code/clauses/:clause_no/annotation":                 {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/policy-groups/:code/clauses/:clause_no/confirm":                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/policy-groups/:code/enabled":                                       {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/recordings/stats":                                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/recordings/stream":                                                 {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/role-assignment-options":                                           {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/role-assignment-previews":                                         {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/role-definitions":                                                  {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/role-definitions":                                                 {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/role-definitions/:id":                                           {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/role-definitions/:id":                                              {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/role-definitions/:id":                                              {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/role-definitions/:id/copy":                                        {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/role-definitions/:id/preview-capabilities":                         {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/role-definitions/descriptors":                                      {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/role-definitions/summary":                                         {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/roles":                                                             {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/rotation-report":                                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/rotation-report/jobs":                                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/rotation-report/records":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/rotation-report/schedules":                                         {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/rotation-report/schedules":                                        {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"DELETE /api/v1/rotation-report/schedules/:id":                                  {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"PUT /api/v1/rotation-report/schedules/:id":                                     {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/rotation-report/schedules/:id/run":                                {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/schedules/next-runs":                                              {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/seal/authorize":                                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/seal/seal":                                                        {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/seal/status":                                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/seal/unseal":                                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/security-policies":                                                 {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/security-policies":                                                 {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/security-policies/apply-preview":                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/security-policies/compliance/preview":                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/security-policies/defs/:key":                                       {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/sessions":                                                          {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/:id":                                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/:id/clipboard-events":                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/:id/clipboard-events/:eventID/content":                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/:id/commands":                                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/:id/keystrokes":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/sessions/:id/keystrokes/view":                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/:id/monitor":                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/sessions/:id/monitor-token":                                       {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/sessions/:id/recording":                                         {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/:id/recording":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/:id/recording/download":                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/:id/recording/stream":                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/sessions/:id/recording/token":                                     {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/sessions/:id/share":                                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/sessions/:id/share":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/sessions/:id/terminate":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/active":                                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/share/:code/ws":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/sessions/share/token":                                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/sessions/statistics":                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/snippets":                                                          {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/snippets":                                                         {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/snippets/:id":                                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"PUT /api/v1/snippets/:id":                                                      {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/ssh":                                                               {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/ssh/sessions/:id/stats":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/syslog-settings":                                                   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/syslog-settings":                                                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundDeferred},
	"POST /api/v1/syslog-settings/test":                                             {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/system-alert-types":                                                {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/system-alert-types/:key":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/transmission-consents":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/transmission-inventory":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/transmission-inventory/export":                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/user-groups":                                                       {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/user-groups":                                                      {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/user-groups/:id":                                                {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/user-groups/:id":                                                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/user-groups/:id":                                                   {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/user-groups/:id/authorization-count":                               {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/user-groups/:id/external-mappings":                                 {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/user-groups/:id/members":                                           {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/user-groups/:id/role-bindings":                                     {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/user-groups/:id/role-bindings":                                     {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/users":                                                             {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/users":                                                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/users/:id":                                                      {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/users/:id":                                                         {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/users/:id":                                                         {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/users/:id/agent-breaker/events":                                    {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/users/:id/agent-breaker/release":                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/users/:id/api-tokens":                                              {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/users/:id/api-tokens/:tokenId":                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/users/:id/api-tokens/revoke-all":                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/users/:id/agent-tokens":                                            {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /api/v1/users/:id/agent-tokens":                                           {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"DELETE /api/v1/users/:id/agent-tokens/:tokenId":                                {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /api/v1/users/:id/external-identities":                                     {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/users/:id/external-identities":                                    {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"DELETE /api/v1/users/:id/external-identities/:identityId":                      {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/users/:id/external-identities/:identityId/unbind-and-disable":     {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/users/:id/external-only":                                          {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/users/:id/inactivity-exempt":                                       {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/users/:id/mfa/disable":                                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/users/:id/password":                                                {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/users/:id/permission-overview":                                     {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/users/:id/permission-overview/assets/:asset_id":                    {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /api/v1/users/:id/role-bindings":                                           {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"PUT /api/v1/users/:id/roles":                                                   {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/users/:id/roles/:role":                                            {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/users/:id/roles/pin":                                              {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"PUT /api/v1/users/:id/status":                                                  {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"POST /api/v1/users/:id/unlock":                                                 {RouteAccessOpen, RouteNatureWrite, RouteOutboundNone},
	"GET /api/v1/users/local-admin-count":                                           {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"POST /api/v1/users/source-policy/check":                                        {RouteAccessOpen, RouteNatureRead, RouteOutboundNone},
	"GET /health":                                                                   {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"POST /health":                                                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /healthz":                                                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
	"GET /metrics":                                                                  {RouteAccessClosed, RouteNatureUnclassified, RouteOutboundUnclassified},
}

// apiTokenMethodNatureMismatch 方法與性質不符的路由（封閉清單，新增要改清單）：性質為讀而方法不是 GET，
// 或性質為寫而方法是 GET。值為理由。守衛檢查清單與登錄一致；執行期性質為讀而方法不是 GET 的路由，
// 不在清單內即比照寫處理。
var apiTokenMethodNatureMismatch = map[string]string{
	"POST /api/v1/assets/import/preview":     "匯入預檢：解析上傳內容並回報逐列結果，不寫入資產",
	"POST /api/v1/role-assignment-previews":  "角色指派預覽：試算變更前後的權限差異，不寫入指派",
	"POST /api/v1/role-definitions/summary":  "角色草稿摘要：依請求帶的權限清單試算摘要，不保存草稿",
	"POST /api/v1/schedules/next-runs":       "排程試算：依請求帶的 cron 算出下次執行時刻，不保存排程",
	"POST /api/v1/users/source-policy/check": "來源網段試算：判定草稿清單是否放行某個位址，不保存清單（只寫讀取留痕）",
}

// apiTokenImmediateOutboundExceptions 開放且請求處理中即對外連線的例外（封閉清單，每條附理由）。
// 不在清單內的 immediate 路由即使登錄為開放，執行期也視為不開放。
var apiTokenImmediateOutboundExceptions = map[string]string{
	"GET /api/v1/offsite-storage/status": "對管理者既定的離機儲存目的地做唯讀探測；目的地只能由登入工作階段設定，API token 改不了；回應不含憑證",
}

// APITokenRouteVerdict 一次查登錄的結果。Registered 為假時其餘欄位皆為零值。
type APITokenRouteVerdict struct {
	// Registered 路由是否在登錄內
	Registered bool
	// Open 路由是否對 API token 開放（三項皆為認得的已分類值、開放，且 immediate 者在例外清單內）
	Open bool
	// Nature 執行期採用的性質：只在 Open 時為 read 或 write，其他情況為空值
	Nature APITokenRouteNature
}

// CountsAllGrantedRoles 這次請求是否計入 token 的全部授權角色：只有開放且性質恰為讀的路由才是；
// 其他（性質為寫、未開放、查無、不認得）一律只計入層級為讀寫的角色。
func (v APITokenRouteVerdict) CountsAllGrantedRoles() bool {
	return v.Open && v.Nature == RouteNatureRead
}

// LookupAPITokenRoute 以 API token 認證的請求查登錄：認證時選角色與閘門判定開放共用這一個函式，不各自解讀。
// path 為 gin 的樣板路徑（c.FullPath()），查無路由時為空字串。
func LookupAPITokenRoute(method, path string) APITokenRouteVerdict {
	if method == "" || path == "" {
		return APITokenRouteVerdict{}
	}
	key := method + " " + path
	class, ok := apiTokenRouteRegistry[key]
	if !ok {
		return APITokenRouteVerdict{}
	}
	out := APITokenRouteVerdict{Registered: true}
	if class.Access != RouteAccessOpen || !class.Known() || !class.Classified() {
		return out
	}
	if class.Outbound == RouteOutboundImmediate {
		if _, excepted := apiTokenImmediateOutboundExceptions[key]; !excepted {
			return out
		}
	}
	out.Open = true
	out.Nature = RouteNatureWrite
	if class.Nature == RouteNatureRead {
		if _, listed := apiTokenMethodNatureMismatch[key]; method == http.MethodGet || listed {
			out.Nature = RouteNatureRead
		}
	}
	return out
}

// APITokenRouteDecision 以 API token 認證的請求能否呼叫該路由：(是否開放, 是否已登錄)。由 LookupAPITokenRoute 導出。
func APITokenRouteDecision(method, path string) (allowed, registered bool) {
	v := LookupAPITokenRoute(method, path)
	return v.Open, v.Registered
}

// APITokenRouteRegistryKeys 回傳已登錄的「方法 樣板路徑」（已排序），供守衛與路由清冊比對。
func APITokenRouteRegistryKeys() []string {
	keys := make([]string, 0, len(apiTokenRouteRegistry))
	for k := range apiTokenRouteRegistry {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// APITokenRouteClassOf 登錄中某條路由的三項分類原值（不經執行期判定），供守衛檢查。
func APITokenRouteClassOf(key string) (APITokenRouteClass, bool) {
	c, ok := apiTokenRouteRegistry[key]
	return c, ok
}

// APITokenMethodNatureMismatch 方法與性質不符清單的副本（鍵為「方法 樣板路徑」，值為理由），供守衛檢查。
func APITokenMethodNatureMismatch() map[string]string {
	return copyStringMap(apiTokenMethodNatureMismatch)
}

// APITokenImmediateOutboundExceptions 開放且立刻對外連線之例外清單的副本（值為理由），供守衛檢查。
func APITokenImmediateOutboundExceptions() map[string]string {
	return copyStringMap(apiTokenImmediateOutboundExceptions)
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
