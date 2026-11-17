package commands

import (
	"fmt"
	"regexp"
	"strings"
)

// validateRotationArmFlags accepts exactly the two valid flag combinations:
// arming with a positive period, or disarming with no period. Both flags
// together and neither flag are usage errors.
func validateRotationArmFlags(disable bool, periodDays int) error {
	if disable != (periodDays <= 0) {
		return fmt.Errorf("provide --period-days (>0) to arm, or --disable to disarm")
	}
	return nil
}

// adapterRefPattern matches the control plane's accepted pin shape:
// <id>@<semver> with an optional #sha256:<64 hex> hash. Rejecting a malformed
// pin here avoids storing an arm that can never resolve at execution time.
var adapterRefPattern = regexp.MustCompile(
	`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]@(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:#sha256:[0-9a-f]{64})?$`,
)

func adapterRefID(ref string) (string, error) {
	if !adapterRefPattern.MatchString(ref) {
		return "", fmt.Errorf("--adapter-ref must be <id>@<version>[#sha256:<64 hex>]")
	}
	id, _, _ := strings.Cut(ref, "@")
	return id, nil
}
