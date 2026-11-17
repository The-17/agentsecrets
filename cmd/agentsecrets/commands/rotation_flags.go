package commands

import "fmt"

// validateRotationArmFlags accepts exactly the two valid flag combinations:
// arming with a positive period, or disarming with no period. Both flags
// together and neither flag are usage errors.
func validateRotationArmFlags(disable bool, periodDays int) error {
	if disable != (periodDays <= 0) {
		return fmt.Errorf("provide --period-days (>0) to arm, or --disable to disarm")
	}
	return nil
}
