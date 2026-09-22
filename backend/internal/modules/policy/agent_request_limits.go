package policy

import (
	"errors"
	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
	"strconv"
)

// AgentRequestLimitsInTx reads the current limits inside the caller's transaction.
func (s *SecurityPolicyService) AgentRequestLimitsInTx(tx *gorm.DB) (int, int, error) {
	values := []int{30, 5}
	for i, key := range []string{PolicyAgentRequestRatePerHour, PolicyAgentRequestPendingMax} {
		var row model.SecurityPolicy
		err := tx.Where("key=?", key).First(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return 0, 0, err
		}
		for _, def := range policyDefs {
			if def.Key == key {
				if err := validatePolicyValue(&def, row.Value); err != nil {
					return 0, 0, err
				}
				break
			}
		}
		value, err := strconv.Atoi(row.Value)
		if err != nil {
			return 0, 0, err
		}
		values[i] = value
	}
	return values[0], values[1], nil
}
