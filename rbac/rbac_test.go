package rbac

import (
	"context"
	"testing"
	"google.golang.org/grpc/metadata"
)

func TestGroup_Allowed(t *testing.T) {
	ctx := context.Background()
	ctx = metadata.AppendToOutgoingContext(ctx, "groups", AddCredential.String())
	if !AddCredential.Allowed(ctx) {
		t.Errorf("Expected to be allowed")
	}
}

func TestGroup_NotAllowed(t *testing.T) {
	ctx := context.Background()
	if AddCredential.Allowed(ctx) {
		t.Errorf("Expected to be not allowed")
	}
}
