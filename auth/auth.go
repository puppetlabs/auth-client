package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Claims is how claims are structured in our bearer
type Claims struct {
	Username string   `json:"preferred_username,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// Client represents our auth client's configuration
type Client struct {
	httpClient *http.Client
	authFn     func(ctx context.Context, rawIDToken string) (context.Context, *Claims, error)
}

// NewClient uses to OpenID Connect library to construct a provider which
// can be invoked within the internal 'authFn'.
func NewClient(clientID string, issuerURL string, httpClient *http.Client) *Client {
	ctx := oidc.ClientContext(context.Background(), httpClient)
	// Need to wait for identity service to become available.
	var provider *oidc.Provider
	var err error
	for {
		provider, err = oidc.NewProvider(ctx, issuerURL)
		if err != nil {
			log.Errorf("failed to query provider %q: %v", issuerURL, err)
			time.Sleep(5 * time.Second)
		} else {
			break
		}
	}

	config := &oidc.Config{ClientID: clientID, SkipExpiryCheck: false, SkipClientIDCheck: false}
	verifier := provider.Verifier(config)

	return &Client{
		httpClient: httpClient,
		authFn: func(ctx context.Context, rawIDToken string) (context.Context, *Claims, error) {
			token, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				log.Error(err.Error())
				return ctx, nil, status.Errorf(codes.Unauthenticated, "Token Error")
			}

			var claims Claims
			err = token.Claims(&claims)
			if err != nil {
				return ctx, nil, status.Errorf(codes.Internal, "Can't extract claims because [%s]", err)
			}

			return ctx, &claims, nil
		},
	}
}

// AsHandlerFunc exposes the authFn as and http.HandlerFunc.  This fn includes a special case
// where 'trusted hosts' can be verified via their client cert
func (c *Client) AsHandlerFunc(trustedHosts string) func(next http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			// if not a trusted host, authenticate the token
			if !isTrustedHost(trustedHosts, r) {

				var token string
				tokens, ok := r.Header["Authorization"]
				if ok && len(tokens) >= 1 {
					token = tokens[0]
					token = strings.TrimPrefix(token, "Bearer ")
				}

				if token == "" {
					// If we get here, the required token is missing
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}

				_, _, err := c.authFn(context.Background(), token)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
			}

			// must be authenticated if still here
			next.ServeHTTP(w, r)
		}
	}
}

// AsMiddleWare exposes the authFn for use in a middleware chain
func (c *Client) AsMiddleWare(ctx context.Context) (context.Context, error) {
	rawIDToken, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		log.Error(err.Error())
		return ctx, status.Errorf(codes.Unauthenticated, "Token Error")
	}

	ctx, claims, err := c.authFn(ctx, rawIDToken)
	if err != nil {
		return ctx, err
	}

	// Writing groups claim to outgoing context. We'll pick this up downstream when verifying access to a resource.
	// Downstream utils for group checks at /rbac/rbac.go, func 'Allowed'
	for _, group := range claims.Groups {
		ctx = metadata.AppendToOutgoingContext(ctx, "groups", group)
	}

	return ctx, nil
}

// isTrustedHost uses the common name from the client cert to determine
// if it is in our trusted list.
func isTrustedHost(trustedHosts string, r *http.Request) bool {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		if strings.Contains(trustedHosts, r.TLS.PeerCertificates[0].Subject.CommonName) {
			log.Infof("Trusted host %s connected", r.TLS.PeerCertificates[0].Subject.CommonName)
			// Special case - this is a host trusted based on it's cert.
			return true
		}
	}

	return false
}
