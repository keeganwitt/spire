package fakeidentityprovider

import (
	"context"
	"testing"

	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchX509Identity(t *testing.T) {
	ctx := context.Background()
	p := New()

	// No bundles, should error
	resp, err := p.FetchX509Identity(ctx, &identityproviderv1.FetchX509IdentityRequest{})
	assert.Error(t, err)
	assert.Nil(t, resp)

	bundle1 := &plugintypes.Bundle{TrustDomain: "example.org"}
	p.AppendBundle(bundle1)

	// One bundle, should return it
	resp, err = p.FetchX509Identity(ctx, &identityproviderv1.FetchX509IdentityRequest{})
	require.NoError(t, err)
	assert.Equal(t, bundle1, resp.Bundle)
	assert.Nil(t, resp.Identity)

	// No more bundles, should error
	resp, err = p.FetchX509Identity(ctx, &identityproviderv1.FetchX509IdentityRequest{})
	assert.Error(t, err)
	assert.Nil(t, resp)

	// Test with identity
	bundle2 := &plugintypes.Bundle{TrustDomain: "example.com"}
	identity2 := &identityproviderv1.X509Identity{CertChain: [][]byte{{0x01}}}
	p.AppendBundle(bundle2)
	p.AppendIdentity(identity2)

	resp, err = p.FetchX509Identity(ctx, &identityproviderv1.FetchX509IdentityRequest{})
	require.NoError(t, err)
	assert.Equal(t, bundle2, resp.Bundle)
	assert.Equal(t, identity2, resp.Identity)
}
