package auth

import (
	"testing"

	"context"
	"io/ioutil"
	"net/http"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
)

func buildSUT(t *testing.T) (func(ctx context.Context) (context.Context, error), error) {
	defer gock.Off()
	body, err := ioutil.ReadFile("testdata/openid-configuration.json")
	client := &http.Client{Transport: &http.Transport{}}
	gock.New("https://dev-vm:5556").
		Get("/.well-known/openid-configuration").
		Reply(200).
		JSON(body)

	gock.New("https://dev-vm:5556").
		Post("/protocol/openid-connect/token/introspect").
		Reply(200).
		JSON(`{"active": true}`)

	gock.InterceptClient(client)

	authClient := NewClient("", "","https://dev-vm:5556", client)
	withAuth :=  authClient.AsMiddleWare
	assert.Nil(t, err)
	return withAuth, err
}

func TestMakeWithAuth(t *testing.T) {
	withAuth, err := buildSUT(t)
	assert.Nil(t, err)
	assert.NotNil(t, withAuth)
}

func TestWithAuth_NeedsBearerToken(t *testing.T) {
	withAuth, err := buildSUT(t)
	assert.Nil(t, err)
	ctx, err := withAuth(context.Background())
	assert.NotNil(t, ctx)
	assert.NotNil(t, err)
	assert.Equal(t, "rpc error: code = Unauthenticated desc = Token Error", err.Error())
}
