package ldapauth

import (
	"context"
	"errors"
	"fmt"
)

// FailureStage identifies the LDAP operation that failed without exposing
// directory-specific details to an unauthenticated client.
type FailureStage string

const (
	StageConnection        FailureStage = "connection"
	StageSearchAccountBind FailureStage = "search-account bind"
	StageUserFilter        FailureStage = "user-filter compilation"
	StageUserSearch        FailureStage = "user search"
	StageUserBind          FailureStage = "user bind"
	StageSubjectMapping    FailureStage = "stable-subject mapping"
	StageGroupValidation   FailureStage = "group validation"
	StageTimeout           FailureStage = "timeout"
	StageRequest           FailureStage = "request"
	StageDirectory         FailureStage = "directory processing"
)

// StageError preserves the underlying LDAP error for logs while carrying a
// stable, safe operation label for RPC responses and tests.
type StageError struct {
	Stage FailureStage
	Err   error
}

func (e *StageError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return string(e.Stage)
	}
	return fmt.Sprintf("%s: %v", e.Stage, e.Err)
}

func (e *StageError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func withStage(stage FailureStage, err error) error {
	if err == nil {
		return nil
	}
	return &StageError{Stage: stage, Err: err}
}

// StageOf returns a stable, non-sensitive label for an LDAP failure.
func StageOf(err error) FailureStage {
	if errors.Is(err, context.DeadlineExceeded) {
		return StageTimeout
	}
	if errors.Is(err, context.Canceled) {
		return StageRequest
	}
	var stageErr *StageError
	if errors.As(err, &stageErr) && stageErr.Stage != "" {
		return stageErr.Stage
	}
	return StageDirectory
}
