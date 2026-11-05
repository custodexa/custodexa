package database

import "testing"

func TestKeystrokeFeatureMigrationVersionMatchesMigration(t *testing.T) {
	for _, m := range migrations {
		if m.Version == KeystrokeFeatureMigrationVersion {
			return
		}
	}
	t.Fatalf("migrations 內沒有版本 %s：上線時間判定會失去依據", KeystrokeFeatureMigrationVersion)
}
