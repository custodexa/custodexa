package authz

// 產品範圍判定器的目標種類登記：正式組裝與測試組裝共用同一個來源，
// 新增目標種類時只需改這裡，守衛測試會對照原始碼中宣告的種類。

// ProductScopeResolvers 回傳產品所有後段登記種類的解析器（授權規則兩種、審核範圍、憑證、改密候選）。
// 每次呼叫回新切片，不設包級變數。
func ProductScopeResolvers() []ScopeTargetResolverRegistration {
	rs := AuthorizationScopeResolvers()
	rs = append(rs, ApproverScopeScopeResolvers()...)
	rs = append(rs, CredentialScopeResolver(), ChangeSecretCandidateScopeResolver())
	return rs
}

// ProductScopeTargetKinds 產品宣告的後段目標種類（不含內建的資產、資產帳號、節點），獨立於
// ProductScopeResolvers 列出：守衛測試把它與原始碼宣告、與正式組裝的判定器兩頭對照。
// 每次呼叫回新切片。
func ProductScopeTargetKinds() []ScopeTargetKind {
	return []ScopeTargetKind{
		ScopeTargetAuthorizationObject, ScopeTargetAuthorizationRule, ScopeTargetApproverScope,
		ScopeTargetCredential, ScopeTargetChangeSecretCandidate,
	}
}

// HasResolver 唯讀查詢：判定器是否登記了該目標種類的解析器。
func (e *ScopeEvaluator) HasResolver(kind ScopeTargetKind) bool {
	if e == nil {
		return false
	}
	_, ok := e.resolvers[kind]
	return ok
}
