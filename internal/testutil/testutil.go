// Package testutil provides common test utilities and helpers for the tsbridge project.
package testutil

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// AssertError checks if an error occurred and optionally verifies the error message contains expected text.
func AssertError(t testing.TB, err error, expectedMessages ...string) {
	t.Helper()
	if err == nil {
		t.Error("expected error but got nil")
		return
	}
	if len(expectedMessages) > 0 && expectedMessages[0] != "" {
		if !strings.Contains(err.Error(), expectedMessages[0]) {
			t.Errorf("error = %v, want error containing %q", err, expectedMessages[0])
		}
	}
}

// AssertNoError checks that no error occurred.
func AssertNoError(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// AssertContains checks if a string contains a substring.
func AssertContains(t testing.TB, s, substr string) {
	t.Helper()
	if !strings.Contains(s, substr) {
		t.Errorf("string %q does not contain %q", s, substr)
	}
}

// AssertNotContains checks if a string does not contain a substring.
func AssertNotContains(t testing.TB, s, substr string) {
	t.Helper()
	if strings.Contains(s, substr) {
		t.Errorf("string %q should not contain %q", s, substr)
	}
}

// RequireNoError checks that no error occurred and fails the test immediately if there is one.
func RequireNoError(t testing.TB, err error, msgAndArgs ...string) {
	t.Helper()
	if err != nil {
		msg := "unexpected error"
		if len(msgAndArgs) > 0 {
			msg = strings.Join(msgAndArgs, " ")
		}
		t.Fatalf("%s: %v", msg, err)
	}
}

// RequireError checks if an error occurred and fails the test immediately if there isn't one.
func RequireError(t testing.TB, err error, msgAndArgs ...string) {
	t.Helper()
	if err == nil {
		msg := "expected error but got nil"
		if len(msgAndArgs) > 0 {
			msg = strings.Join(msgAndArgs, " ")
		}
		t.Fatal(msg)
	}
}

// AssertEqual checks if two values are equal.
func AssertEqual(t testing.TB, expected, actual interface{}) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("expected %v, got %v", expected, actual)
	}
}

// AssertNotNil checks that a value is not nil.
func AssertNotNil(t testing.TB, value interface{}) {
	t.Helper()
	if value == nil || (reflect.ValueOf(value).Kind() == reflect.Ptr && reflect.ValueOf(value).IsNil()) {
		t.Error("expected non-nil value but got nil")
	}
}

// AssertNil checks that a value is nil.
func AssertNil(t testing.TB, value interface{}) {
	t.Helper()
	if value == nil {
		return
	}
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Ptr && rv.IsNil() {
		return
	}
	t.Errorf("expected nil but got %v", value)
}

// AssertLen checks the length of a slice, array, map, or string.
func AssertLen(t testing.TB, object interface{}, length int) {
	t.Helper()
	actual := getLen(object)
	if actual != length {
		t.Errorf("expected length %d, got %d", length, actual)
	}
}

// RequireNotNil checks that a value is not nil and fails the test immediately if it is.
func RequireNotNil(t testing.TB, value interface{}) {
	t.Helper()
	if value == nil || (reflect.ValueOf(value).Kind() == reflect.Ptr && reflect.ValueOf(value).IsNil()) {
		t.Fatal("expected non-nil value but got nil")
	}
}

// getLen is a helper to get length of various types
func getLen(x interface{}) int {
	if x == nil {
		return 0
	}
	rv := reflect.ValueOf(x)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String, reflect.Chan:
		return rv.Len()
	default:
		return 0
	}
}

// AssertNotEmpty checks that a value is not empty.
func AssertNotEmpty(t testing.TB, value interface{}) {
	t.Helper()
	if isZero(value) {
		t.Errorf("expected non-empty value, got %v", value)
	}
}

// AssertTrue checks that a condition is true.
func AssertTrue(t testing.TB, condition bool, msgAndArgs ...interface{}) {
	t.Helper()
	if !condition {
		if len(msgAndArgs) > 0 {
			t.Errorf("expected true: %s", fmt.Sprint(msgAndArgs...))
		} else {
			t.Error("expected true, got false")
		}
	}
}

// AssertFalse checks that a condition is false.
func AssertFalse(t testing.TB, condition bool, msgAndArgs ...interface{}) {
	t.Helper()
	if condition {
		if len(msgAndArgs) > 0 {
			t.Errorf("expected false: %s", fmt.Sprint(msgAndArgs...))
		} else {
			t.Error("expected false, got true")
		}
	}
}

// RequireTrue checks that a condition is true and fails the test if not.
func RequireTrue(t testing.TB, condition bool, msgAndArgs ...interface{}) {
	t.Helper()
	if !condition {
		if len(msgAndArgs) > 0 {
			t.Fatalf("expected true: %s", fmt.Sprint(msgAndArgs...))
		} else {
			t.Fatal("expected true, got false")
		}
	}
}

// AssertRegexp checks that a string matches a regular expression pattern.
func AssertRegexp(t testing.TB, pattern string, str string) {
	t.Helper()
	matched, err := regexp.MatchString(pattern, str)
	if err != nil {
		t.Errorf("regexp compile error: %v", err)
		return
	}
	if !matched {
		t.Errorf("expected %q to match pattern %q", str, pattern)
	}
}

// AssertLess checks that a is less than b.
func AssertLess(t testing.TB, a, b interface{}, msgAndArgs ...interface{}) {
	t.Helper()

	result, err := compareValues(a, b)
	if err != nil {
		t.Errorf("comparison error: %v", err)
		return
	}

	if result >= 0 {
		msg := fmt.Sprintf("expected %v to be less than %v", a, b)
		if len(msgAndArgs) > 0 {
			msg = fmt.Sprintf("%s: %s", msg, fmt.Sprint(msgAndArgs...))
		}
		t.Error(msg)
	}
}

// AssertGreater checks that a is greater than b.
func AssertGreater(t testing.TB, a, b interface{}, msgAndArgs ...interface{}) {
	t.Helper()

	result, err := compareValues(a, b)
	if err != nil {
		t.Errorf("comparison error: %v", err)
		return
	}

	if result <= 0 {
		msg := fmt.Sprintf("expected %v to be greater than %v", a, b)
		if len(msgAndArgs) > 0 {
			msg = fmt.Sprintf("%s: %s", msg, fmt.Sprint(msgAndArgs...))
		}
		t.Error(msg)
	}
}

// AssertInDelta checks that two numbers are within a delta of each other.
func AssertInDelta(t testing.TB, expected, actual, delta float64, msgAndArgs ...interface{}) {
	t.Helper()

	diff := math.Abs(expected - actual)
	if diff > delta {
		msg := fmt.Sprintf("expected %v ± %v, but got %v (diff: %v)", expected, delta, actual, diff)
		if len(msgAndArgs) > 0 {
			msg = fmt.Sprintf("%s: %s", msg, fmt.Sprint(msgAndArgs...))
		}
		t.Error(msg)
	}
}

// compareValues compares two values and returns -1 if a < b, 0 if a == b, 1 if a > b
func compareValues(a, b interface{}) (int, error) {
	aVal := reflect.ValueOf(a)
	bVal := reflect.ValueOf(b)

	// Check if types are comparable
	if aVal.Type() != bVal.Type() {
		return 0, fmt.Errorf("cannot compare different types: %T and %T", a, b)
	}

	switch aVal.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		aInt := aVal.Int()
		bInt := bVal.Int()
		if aInt < bInt {
			return -1, nil
		} else if aInt > bInt {
			return 1, nil
		}
		return 0, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		aUint := aVal.Uint()
		bUint := bVal.Uint()
		if aUint < bUint {
			return -1, nil
		} else if aUint > bUint {
			return 1, nil
		}
		return 0, nil
	case reflect.Float32, reflect.Float64:
		aFloat := aVal.Float()
		bFloat := bVal.Float()
		if aFloat < bFloat {
			return -1, nil
		} else if aFloat > bFloat {
			return 1, nil
		}
		return 0, nil
	case reflect.String:
		aStr := aVal.String()
		bStr := bVal.String()
		if aStr < bStr {
			return -1, nil
		} else if aStr > bStr {
			return 1, nil
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("type %s is not comparable", aVal.Type())
	}
}

// isZero checks if a value is the zero value for its type.
func isZero(value interface{}) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Array, reflect.Map, reflect.Slice:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	default:
		return reflect.DeepEqual(value, reflect.Zero(v.Type()).Interface())
	}
}
