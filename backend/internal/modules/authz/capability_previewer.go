package authz

import "gorm.io/gorm"

// CapabilityPreviewer 把唯讀預覽綁到資料庫連線，供 API 層以介面注入。
type CapabilityPreviewer struct {
	db       *gorm.DB
	mappings RoleMappingRuleCounter
	members  GroupMemberPlanner
	rules    MappingRulePlanner
	scope    *ScopeEvaluator
}

// NewCapabilityPreviewer 建立預覽器。
func NewCapabilityPreviewer(db *gorm.DB) *CapabilityPreviewer { return &CapabilityPreviewer{db: db} }

// NewCapabilityPreviewerWithMappings 建立預覽器並注入角色映射規則計數（角色定義種類的整筆分類使用）。
func NewCapabilityPreviewerWithMappings(db *gorm.DB, c RoleMappingRuleCounter) *CapabilityPreviewer {
	return &CapabilityPreviewer{db: db, mappings: c}
}

// WithGroupMemberPlanner 注入手動成員輸入的求值器（群組成員寫入共用的那一份）；回傳自身以便串接組裝。
func (p *CapabilityPreviewer) WithGroupMemberPlanner(m GroupMemberPlanner) *CapabilityPreviewer {
	p.members = m
	return p
}

// WithMappingRulePlanner 注入映射規則變更的求值器（映射寫入共用的規劃與模擬）；回傳自身以便串接組裝。
func (p *CapabilityPreviewer) WithMappingRulePlanner(m MappingRulePlanner) *CapabilityPreviewer {
	p.rules = m
	return p
}

// WithScopeEvaluator 注入範圍判定器（危險組合的節點範圍交集用）；回傳自身以便串接組裝。
func (p *CapabilityPreviewer) WithScopeEvaluator(e *ScopeEvaluator) *CapabilityPreviewer {
	p.scope = e
	return p
}

// Preview 計算預覽；不寫入任何資料。
func (p *CapabilityPreviewer) Preview(req PreviewRequest) (PreviewResult, error) {
	if req.MappingRuleCounter == nil {
		req.MappingRuleCounter = p.mappings
	}
	if req.GroupMemberPlanner == nil {
		req.GroupMemberPlanner = p.members
	}
	if req.MappingRulePlanner == nil {
		req.MappingRulePlanner = p.rules
	}
	if req.Scope == nil {
		req.Scope = p.scope
	}
	return PreviewEffectiveCapabilities(p.db, req)
}
