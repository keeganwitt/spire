package disk_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

func TestSharedJWTKeys(t *testing.T) {
	ctx := context.Background()
	dir := spiretest.TempDir(t)
	sharedPath := filepath.Join(dir, "shared.json")

	writer, err := loadPlugin(t, "keys_path = %q\nshared_keys_path = %q", filepath.Join(dir, "writer.json"), sharedPath)
	require.NoError(t, err)
	follower, err := loadPlugin(t, "keys_path = %q\nshared_keys_path = %q", filepath.Join(dir, "follower.json"), sharedPath)
	require.NoError(t, err)

	// The writer creates the shared JWT key; the follower discovers it through
	// the shared keys file.
	jwtKey, err := writer.GenerateKey(ctx, "JWT-Signer-A", keymanager.ECP256)
	require.NoError(t, err)

	followerJWT, err := follower.GetKey(ctx, "JWT-Signer-A")
	require.NoError(t, err)
	require.Equal(t, publicKeyBytes(t, jwtKey), publicKeyBytes(t, followerJWT), "follower binds the shared JWT key")

	// X509 keys stay private to each server: the follower must not see the
	// writer's X509 key.
	writerX509, err := writer.GenerateKey(ctx, "x509-CA-A", keymanager.ECP256)
	require.NoError(t, err)
	_, err = follower.GetKey(ctx, "x509-CA-A")
	require.Error(t, err, "X509 keys are private to each server")

	// The follower's own X509 key is independent of the writer's.
	followerX509, err := follower.GenerateKey(ctx, "x509-CA-A", keymanager.ECP256)
	require.NoError(t, err)
	require.NotEqual(t, publicKeyBytes(t, writerX509), publicKeyBytes(t, followerX509), "each server has its own X509 key")
}
