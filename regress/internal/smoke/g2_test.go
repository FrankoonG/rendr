package smoke

import (
	"strings"
	"testing"

	"github.com/FrankoonG/rendr"
)

func TestValidateG2EvidenceRejectsPartialMigrationStimulus(t *testing.T) {
	_, _, err := validateG2Evidence(g2Evidence{
		mode:                 rendr.ModePrime,
		migrationsRequested:  5,
		migrationCallsFired:  1,
		migrationCountBefore: 20,
		migrationCountAfter:  21,
	})
	if err == nil || !strings.Contains(err.Error(), "fired=1, want 5") {
		t.Fatalf("error = %v, want partial-stimulus failure", err)
	}
}

func TestValidateG2EvidenceRaceDuplicateSemantics(t *testing.T) {
	base := g2Evidence{
		mode:                 rendr.ModeRace,
		migrationsRequested:  0,
		migrationCallsFired:  0,
		migrationCountBefore: 20,
		migrationCountAfter:  20,
		recvDupsBefore:       4,
		recvDupsAfter:        5,
	}
	if migrations, duplicates, err := validateG2Evidence(base); err != nil || migrations != 0 || duplicates != 1 {
		t.Fatalf("valid race evidence = migrations %d duplicates %d err %v", migrations, duplicates, err)
	}

	missingStimulus := base
	missingStimulus.recvDupsAfter = missingStimulus.recvDupsBefore
	if _, _, err := validateG2Evidence(missingStimulus); err == nil || !strings.Contains(err.Error(), "duplicate stimulus was not observed") {
		t.Fatalf("missing duplicate stimulus error = %v", err)
	}

	visibleDuplicate := base
	visibleDuplicate.applicationDuplicates = 1
	if _, _, err := validateG2Evidence(visibleDuplicate); err == nil || !strings.Contains(err.Error(), "application-visible duplicate") {
		t.Fatalf("application duplicate error = %v", err)
	}
}

func TestG2OptsMigrationDefaultAndDisable(t *testing.T) {
	defaults := G2Opts{}
	defaults.withDefaults()
	if defaults.Migrations != 5 {
		t.Fatalf("default migrations=%d want 5", defaults.Migrations)
	}
	disabled := G2Opts{Migrations: -1}
	disabled.withDefaults()
	if disabled.Migrations != 0 {
		t.Fatalf("disabled migrations=%d want 0", disabled.Migrations)
	}
}
