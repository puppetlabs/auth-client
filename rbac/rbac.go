package rbac

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// Group ...
type Group int

const (
	AddCredential    Group = 0
	AddSource        Group = 1
	RemoveCredential Group = 2
	RemoveSource     Group = 3
	RunTask          Group = 4
	AddTask          Group = 5
	RemoveTask       Group = 6
)

// String ...
func (g Group) String() string {
	names := [...]string{
		"/add-credential",
		"/add-source",
		"/remove-credential",
		"/remove-source",
		"/run-task",
		"/add-task",
		"/remove-task"}

	if g < AddCredential || g > RemoveTask {
		return "Unknown"
	}

	return names[g]
}

// Allowed ...
func (g Group) Allowed(ctx context.Context) bool {
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		groups := md.Get("groups")
		for _, group := range groups {
			if group == g.String() {
				return true
			}
		}
	}

	return false
}

// GetUsername pulls the username from the context metadata
func GetUsername(ctx context.Context) string {
	var username string
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		usernameArray := md.Get("username")
		if len(usernameArray) > 0 {
			username = usernameArray[0]
		}
	}
	return username
}
