package testutil

import (
	"errors"
	"testing"
)

func TestAssertError(t *testing.T) {
	// Test with actual error and correct message - should pass
	err := errors.New("test error message")
	AssertError(t, err, "test error")

	// Test with actual error and empty expected message - should pass
	AssertError(t, err, "")
}

func TestAssertNoError(t *testing.T) {
	// Test with nil error - should pass
	AssertNoError(t, nil)
}

func TestAssertContains(t *testing.T) {
	// Test when string contains substring - should pass
	AssertContains(t, "hello world", "world")
	AssertContains(t, "hello world", "hello")
	AssertContains(t, "hello world", "lo wo")
}

func TestAssertNotContains(t *testing.T) {
	// Test when string doesn't contain substring - should pass
	AssertNotContains(t, "hello world", "foo")
	AssertNotContains(t, "hello world", "bar")
}

func TestRequireNoError(t *testing.T) {
	// Test with nil error - should pass
	RequireNoError(t, nil)
	RequireNoError(t, nil, "custom message")
}

func TestRequireError(t *testing.T) {
	// Test with actual error - should pass
	err := errors.New("test error")
	RequireError(t, err)
	RequireError(t, err, "custom message")
}
