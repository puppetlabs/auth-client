package auth

import (
	"fmt"
	"time"
	"testing"

	"context"
	"io/ioutil"
	"net/http"

	"github.com/stretchr/testify/assert"
	"gopkg.in/h2non/gock.v1"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
)

const url string = "https://dev-vm:5556"

func buildSUT(t *testing.T) (func(ctx context.Context) (context.Context, error), error) {
	defer gock.Off()
	body, err := ioutil.ReadFile("testdata/openid-configuration.json")
	client := &http.Client{Transport: &http.Transport{}}
	gock.New(url).
		Get("/.well-known/openid-configuration").
		Reply(200).
		JSON(body)

	gock.New(url).
		Post("/protocol/openid-connect/token/introspect").
		Reply(200).
		JSON(`{"active": true}`)

	gock.InterceptClient(client)

	authClient := NewClient("", "", url, client)
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

func buildSUTWithReplyError(t *testing.T) error {
	body, err := ioutil.ReadFile("testdata/openid-configuration.json")
	client := &http.Client{
		Transport: &http.Transport{},
		Timeout: time.Duration(50) * time.Second,
	}

	gock.New(url).
		Get("/.well-known/openid-configuration").
		ReplyError(fmt.Errorf("Error")).
		JSON(body)

	gock.New(url).
		Post("/protocol/openid-connect/token/introspect").
		Reply(200).
		JSON(`{"active": true}`)

	gock.InterceptClient(client)

	go func() {
		authClient:= NewClient("", "", url, client)
		withAuth :=  authClient.AsMiddleWare
		assert.NotNil(t, withAuth)
		assert.Nil(t, err)
	}()
	return err
}

func TestClientTimeout(t *testing.T) {
	defer gock.Off()
	hook := test.NewGlobal()
	err := buildSUTWithReplyError(t)
	assert.Nil(t, err)
	time.Sleep(64 * time.Second)
	assert.Equal(t, logrus.ErrorLevel, hook.LastEntry().Level)
	assert.Equal(t, "authentication client failed to contact issuer \"https://dev-vm:5556\": Get \"https://dev-vm:5556/.well-known/openid-configuration\": gock: cannot match any request. Retrying in ~30 seconds", hook.LastEntry().Message)
}
