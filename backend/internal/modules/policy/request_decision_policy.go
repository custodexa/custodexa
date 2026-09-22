package policy

import (
	"errors"
	"strconv"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// Read decision policy through the caller's transaction without retaining its handle.
func requestPolicyValue(tx *gorm.DB, key string) (string, error) {
	def := findDef(key)
	var row model.SecurityPolicy
	if err := tx.Where("key=?", key).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return def.Default, nil
		}
		return "", err
	}
	if err := validatePolicyValue(def, row.Value); err != nil {
		return "", err
	}
	return row.Value, nil
}
func (s *SecurityPolicyService) RequestApprovalThresholdInTx(tx *gorm.DB) (int, error) {
	raw, err := requestPolicyValue(tx, PolicyAccessRequestMinApprovals)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(raw)
}
func (s *SecurityPolicyService) RequestDecisionPolicyInTx(tx *gorm.DB, assetPolicy *string) (string, int, error) {
	threshold, err := s.RequestApprovalThresholdInTx(tx)
	if err != nil {
		return "", 0, err
	}
	if assetPolicy != nil && isValidAccessPolicy(*assetPolicy) {
		return *assetPolicy, threshold, nil
	}
	segment, err := requestPolicyValue(tx, PolicyAccessPolicyDefault)
	return segment, threshold, err
}
