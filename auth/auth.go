package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
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
func NewClient(clientID string, clientSecret string, issuerURL string, httpClient *http.Client) *Client {
	ctx := oidc.ClientContext(context.Background(), httpClient)
	// Need to wait for identity service to become available.
	var provider *oidc.Provider
	var err error
	var backoff time.Duration = 1 * time.Second
	for {
		provider, err = oidc.NewProvider(ctx, issuerURL)
		if backoff >= time.Duration(30 * time.Second) {
			log.Errorf("authentication client failed to contact issuer %q: %v. Retrying in ~30 seconds", issuerURL, err)
		}
		if err != nil {
			time.Sleep(backoff)
		} else {
			if backoff >= time.Duration(30 * time.Second) {
				log.Info("auth client established connection to issuer")
			}
			backoff = 1
			break
		}
		backoff += backoff
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

			introspectURL := fmt.Sprintf("%s/protocol/openid-connect/token/introspect", issuerURL)
			introspectReqBody := []byte(fmt.Sprintf("token_type_hint=requesting_party_token&token=%s", rawIDToken))
			introspectReq, err := http.NewRequest(http.MethodPost, introspectURL, bytes.NewBuffer(introspectReqBody))
			if err != nil {
				return ctx, nil, status.Errorf(codes.Internal, "Can't create introspect request because [%s]", err)
			}

			introspectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			introspectReq.SetBasicAuth(clientID, clientSecret)
			introspectResp, err := httpClient.Do(introspectReq)
			if err != nil {
				return ctx, nil, status.Errorf(codes.Internal, "Can't introspect token because [%s]", err)
			}

			var introspectRespBody struct {
				Active bool `json:"active"`
			}

			defer introspectResp.Body.Close()
			err = json.NewDecoder(introspectResp.Body).Decode(&introspectRespBody)
			if err != nil {
				return ctx, nil, status.Errorf(codes.Internal, "Can't decode introspect response because [%s]", err)
			}

			if !introspectRespBody.Active {
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

// AsHandlerFunc exposes the authFn as and http.HandlerFunc.  This fn includes special cases
// where 'trusted hosts' can be verified via their client cert or websockets which are verified separately
func (c *Client) AsHandlerFunc(trustedHosts string) func(next http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {

			// if not a trusted host or a websocket, authenticate the token
			if !isTrustedHost(trustedHosts, r) && !isWebsocket(r) {

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
					log.Error(err.Error())
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
		log.Error(err.Error())
		return ctx, err
	}

	// Writing groups claim to outgoing context. We'll pick this up downstream when verifying access to a resource.
	// Downstream utils for group checks at /rbac/rbac.go, func 'Allowed'
	for _, group := range claims.Groups {
		ctx = metadata.AppendToOutgoingContext(ctx, "groups", group)
	}
	ctx = metadata.AppendToOutgoingContext(ctx, "username", claims.Username)

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

// InitPayload is able to provide the Authorization header from the init payload
type InitPayload interface {

	// Authorization gets the Authorization header from the init payload
	Authorization() string
}

// AsWSInitFunc exposes the authFn for use during websocket initialization
func (c *Client) AsWSInitFunc() func(context.Context, InitPayload) error {

	return func(ctx context.Context, initPayload InitPayload) error {

		token := initPayload.Authorization()

		if len(token) > 0 {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		if len(token) == 0 {
			err := fmt.Errorf("Unauthorized - token is missing")
			log.Error(err.Error())
			return err
		}

		_, _, err := c.authFn(context.Background(), token)
		if err != nil {
			err = fmt.Errorf("Unauthorized - %s", err)
			log.Error(err.Error())
			return err
		}

		return nil
	}
}

func isWebsocket(r *http.Request) bool {
	return r.Header.Get("Upgrade") == "websocket"
}
