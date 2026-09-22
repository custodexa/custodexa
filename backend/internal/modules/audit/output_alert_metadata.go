package audit

import (
	"strconv"
	"strings"
)

// OutputAlertPrefix marks a rule alert about possible sensitive output.
// reason_code stores only a version and hit count: o1:<count in base 36>.
// A uint64 fits in 16 bytes including the prefix, within varchar(64).
const OutputAlertPrefix = "o1:"

type OutputAlertMetadata struct {
	Count uint64 `json:"count"`
}

func (m OutputAlertMetadata) ReasonCode() string {
	return OutputAlertPrefix + strconv.FormatUint(m.Count, 36)
}

func ParseOutputAlert(code string) (OutputAlertMetadata, bool) {
	if !strings.HasPrefix(code, OutputAlertPrefix) {
		return OutputAlertMetadata{}, false
	}
	count, err := strconv.ParseUint(strings.TrimPrefix(code, OutputAlertPrefix), 36, 64)
	return OutputAlertMetadata{Count: count}, err == nil && count > 0
}
