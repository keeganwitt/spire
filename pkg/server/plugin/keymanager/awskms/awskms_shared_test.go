package awskms

import (
	"context"
	"testing"

	"github.com/andres-erbsen/clock"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
)

func TestSharedJWTKeys(t *testing.T) {
	ctx := context.Background()
	c := clock.NewMock()
	fakeKMSClient := newKMSClientFake(t, c)
	fakeSTSClient := newSTSClientFake()

	load := func(serverID string) keymanager.KeyManager {
		p := newPlugin(
			func(aws.Config) (kmsClient, error) { return fakeKMSClient, nil },
			func(aws.Config) (stsClient, error) { return fakeSTSClient, nil },
		)
		km := new(keymanager.V1)
		log, _ := test.NewNullLogger()
		plugintest.Load(t, builtin(p), km,
			plugintest.Log(log),
			plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
			plugintest.Configuref(`
				region = "fake-region"
				key_identifier_value = %q
				shared_jwt_keys = true
			`, serverID),
		)
		p.hooks.clk = c
		return km
	}

	writer := load("server-a")
	follower := load("server-b")

	// The writer creates the shared JWT key; the follower (configured before the
	// key existed) discovers it lazily from KMS.
	jwtKey, err := writer.GenerateKey(ctx, "JWT-Signer-A", keymanager.ECP256)
	require.NoError(t, err)

	followerJWT, err := follower.GetKey(ctx, "JWT-Signer-A")
	require.NoError(t, err)
	require.Equal(t, jwtKey.Public(), followerJWT.Public(), "follower binds the shared JWT key")

	// X509 keys stay private to each server: the follower must not see the
	// writer's X509 key.
	_, err = writer.GenerateKey(ctx, "x509-CA-A", keymanager.ECP256)
	require.NoError(t, err)
	_, err = follower.GetKey(ctx, "x509-CA-A")
	require.Error(t, err, "X509 keys are private to each server")
}
