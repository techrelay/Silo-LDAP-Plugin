package ldapauth

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestStageOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want FailureStage
	}{
		{name: "typed", err: &StageError{Stage: StageUserSearch, Err: errors.New("operations error")}, want: StageUserSearch},
		{name: "wrapped typed", err: fmt.Errorf("authenticate: %w", &StageError{Stage: StageUserBind, Err: errors.New("unavailable")}), want: StageUserBind},
		{name: "deadline", err: &StageError{Stage: StageConnection, Err: context.DeadlineExceeded}, want: StageTimeout},
		{name: "canceled", err: fmt.Errorf("wrapped: %w", context.Canceled), want: StageRequest},
		{name: "unknown", err: errors.New("unexpected directory error"), want: StageDirectory},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := StageOf(test.err); got != test.want {
				t.Fatalf("StageOf(%v) = %q, want %q", test.err, got, test.want)
			}
		})
	}
}

func TestStageErrorUnwraps(t *testing.T) {
	cause := errors.New("directory unavailable")
	err := &StageError{Stage: StageConnection, Err: cause}
	if !errors.Is(err, cause) {
		t.Fatal("StageError did not preserve its cause")
	}
}
