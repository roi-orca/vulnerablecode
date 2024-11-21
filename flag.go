package validator

import (
	"fmt"
	"reflect"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/orcasecurity/shiftleft-cli/lib/utils"
)

type FlagDependencyValidator[T any] struct {
}

func (v FlagDependencyValidator[T]) Validate(cmdOptions T, dependentField string, dependencyField string, allowedValues []string) error {
	cmd := reflect.ValueOf(cmdOptions)
	dependentFieldValue := reflect.Indirect(cmd).FieldByName(dependentField)
	dependencyFieldValue := reflect.Indirect(cmd).FieldByName(dependencyField)
	if slices.Contains(allowedValues, "") && dependencyFieldValue.IsZero() {
		return nil
	}
	allowedValues = utils.RemoveFromSlice(allowedValues, "")
	if !dependentFieldValue.IsZero() && !slices.Contains(allowedValues, dependencyFieldValue.String()) {
		allowedValues := strings.Join(allowedValues, ",")
		return fmt.Errorf("input error - '%s' option can be used only with %s=%s", dependentField, dependencyField, allowedValues)
	}

	return nil
}
