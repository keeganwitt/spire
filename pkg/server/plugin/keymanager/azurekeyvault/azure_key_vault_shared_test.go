package azurekeyvault

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/andres-erbsen/clock"
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
	fake := newKMSClientFake(t, validKeyVaultURI, trustDomain, validServerID, c)

	load := func(serverID string) keymanager.KeyManager {
		p := newPlugin(func(azcore.TokenCredential, string) (cloudKeyManagementService, error) { return fake, nil })
		km := new(keymanager.V1)
		log, _ := test.NewNullLogger()
		plugintest.Load(t, builtin(p), km,
			plugintest.Log(log),
			plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
			plugintest.Configuref(`
				key_identifier_value = %q
				key_vault_uri = %q
				use_msi = true
				shared_jwt_keys = true
			`, serverID, validKeyVaultURI),
		)
		p.hooks.clk = c
		return km
	}

	writer := load("server-a")
	follower := load("server-b")

	// The writer creates the shared JWT key (deterministic shared name); the
	// follower discovers it lazily from Key Vault.
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
