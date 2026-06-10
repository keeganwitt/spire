package gcpkms

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/plugintest"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
)

func TestSharedJWTKeyNaming(t *testing.T) {
	shared := sharedCryptoKeyID("JWT-Signer-A")
	require.Equal(t, "spire-key-shared-JWT-Signer-A", shared)

	require.True(t, isSharedCryptoKeyName(validKeyRing+"/cryptoKeys/"+shared))
	require.False(t, isSharedCryptoKeyName(validKeyRing+"/cryptoKeys/spire-key-"+validServerID+"-x509-CA-A"))

	keyID, ok := getSPIREKeyIDFromCryptoKeyName(validKeyRing + "/cryptoKeys/" + shared)
	require.True(t, ok)
	require.Equal(t, "JWT-Signer-A", keyID)
}

func TestSharedJWTKeysGenerateNaming(t *testing.T) {
	ctx := context.Background()
	c := clock.NewMock(t)
	fake := newKMSClientFake(t, c)
	p := newPlugin(func(context.Context, ...option.ClientOption) (cloudKeyManagementService, error) { return fake, nil })
	km := new(keymanager.V1)
	log, _ := test.NewNullLogger()
	plugintest.Load(t, builtin(p), km,
		plugintest.Log(log),
		plugintest.CoreConfig(catalog.CoreConfig{TrustDomain: spiffeid.RequireTrustDomainFromString("example.org")}),
		plugintest.Configuref(`
			key_ring = %q
			key_identifier_value = %q
			shared_jwt_keys = true
		`, validKeyRing, validServerID),
	)
	p.hooks.clk = c

	_, err := km.GenerateKey(ctx, "JWT-Signer-A", keymanager.ECP256)
	require.NoError(t, err)
	_, err = km.GenerateKey(ctx, "x509-CA-A", keymanager.ECP256)
	require.NoError(t, err)

	names := map[string]bool{}
	for name := range fake.store.fetchFakeCryptoKeys() {
		names[name] = true
	}
	// JWT keys use a shared crypto key name (no server ID); X509 keys stay
	// per-server.
	require.Contains(t, names, validKeyRing+"/spire-key-shared-JWT-Signer-A")
	require.Contains(t, names, validKeyRing+"/spire-key-"+validServerID+"-x509-CA-A")
}
