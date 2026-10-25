package authz

// AssignmentIsManagement 單一指派的角色是否屬管理類。
//
// 與授權變更分類器對指派的管理類判定是同一個函式，讓唯讀投影與寫入時的分類不會分岔。
func AssignmentIsManagement(a Assignment) bool { return assignmentIsManagement(a) }
