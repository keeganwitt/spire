package fakeidentityprovider

import (
	"context"
	"errors"
	"sync"

	identityproviderv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/hostservice/server/identityprovider/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
)

type IdentityProvider struct {
	identityproviderv1.UnsafeIdentityProviderServer

	mu         sync.Mutex
	bundles    []*plugintypes.Bundle
	identities []*identityproviderv1.X509Identity
}

func New() *IdentityProvider {
	return &IdentityProvider{}
}

func (c *IdentityProvider) FetchX509Identity(context.Context, *identityproviderv1.FetchX509IdentityRequest) (*identityproviderv1.FetchX509IdentityResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.bundles) == 0 {
		return nil, errors.New("no bundle")
	}

	bundle := c.bundles[0]
	c.bundles = c.bundles[1:]

	var identity *identityproviderv1.X509Identity
	if len(c.identities) > 0 {
		identity = c.identities[0]
		c.identities = c.identities[1:]
	}

	return &identityproviderv1.FetchX509IdentityResponse{
		Bundle:   bundle,
		Identity: identity,
	}, nil
}

func (c *IdentityProvider) AppendBundle(bundle *plugintypes.Bundle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bundles = append(c.bundles, bundle)
}

func (c *IdentityProvider) AppendIdentity(identity *identityproviderv1.X509Identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.identities = append(c.identities, identity)
}
