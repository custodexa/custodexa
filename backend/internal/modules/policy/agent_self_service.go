package policy

import (
	"errors"
	"strconv"

	"github.com/custodexa/backend/internal/model"
	"gorm.io/gorm"
)

// AgentSelfCreationInTx reads and validates both keys without a stale cache.
// A database error fails closed; missing rows use the registered defaults.
func AgentSelfCreationInTx(tx *gorm.DB) (bool, int, error) {
	values := make([]string, 2)
	for i, key := range []string{PolicyAgentSelfCreateEnabled, PolicyAgentSelfCreateMaxPerOwner} {
		def := findDef(key)
		values[i] = def.Default
		var row model.SecurityPolicy
		err := tx.Where("key = ?", key).First(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			continue
		}
		if err != nil {
			return false, 0, err
		}
		value, err := normalizePolicyValue(def, row.Value)
		if err != nil {
			return false, 0, err
		}
		values[i] = value
	}
	limit, err := strconv.Atoi(values[1])
	return values[0] == "true", limit, err
}
