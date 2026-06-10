package manager

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/credtemplate"
	"github.com/spiffe/spire/pkg/server/credvalidator"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	"github.com/spiffe/spire/proto/private/server/journal"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
	"github.com/spiffe/spire/test/fakes/fakeservercatalog"
	"github.com/spiffe/spire/test/fakes/fakeserverkeymanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sharedJWTEnv struct {
	clk *clock.Mock
	km  keymanager.KeyManager
	ds  *fakedatastore.DataStore
}

func setupSharedJWTEnv(t *testing.T) *sharedJWTEnv {
	return &sharedJWTEnv{
		clk: clock.NewMock(t),
		km:  fakeserverkeymanager.New(t),
		ds:  fakedatastore.New(t),
	}
}

func (e *sharedJWTEnv) newManager(t *testing.T) (*Manager, *fakeCA) {
	caInst := &fakeCA{taintedAuthoritiesCh: make(chan []*x509.Certificate, 1)}

	cat := fakeservercatalog.New()
	cat.SetKeyManager(e.km)
	cat.SetDataStore(e.ds)
	cat.SetUpstreamAuthority(nil)

	log, _ := test.NewNullLogger()

	credBuilder, err := credtemplate.NewBuilder(credtemplate.Config{
		TrustDomain:   testTrustDomain,
		X509CASubject: pkix.Name{CommonName: "SPIRE"},
		Clock:         e.clk,
		X509CATTL:     testCATTL,
	})
	require.NoError(t, err)

	credValidator, err := credvalidator.New(credvalidator.Config{
		TrustDomain: testTrustDomain,
		Clock:       e.clk,
	})
	require.NoError(t, err)

	m, err := NewManager(context.Background(), Config{
		CA:            caInst,
		Catalog:       cat,
		TrustDomain:   testTrustDomain,
		X509CAKeyType: keymanager.ECP256,
		JWTKeyType:    keymanager.ECP256,
		WITKeyType:    keymanager.ECP256,
		Metrics:       fakemetrics.New(),
		Log:           log,
		Clock:         e.clk,
		CredBuilder:   credBuilder,
		CredValidator: credValidator,
		JWTKeySharing: true,
	})
	require.NoError(t, err)
	return m, caInst
}

func TestSharedJWTWriterPersistsLease(t *testing.T) {
	ctx := context.Background()
	env := setupSharedJWTEnv(t)
	m, caInst := env.newManager(t)

	require.NoError(t, m.SyncJWTKeyAuthority(ctx))
	require.True(t, m.isJWTWriter(), "first server to acquire the lease is the writer")

	require.NoError(t, m.PrepareJWTKey(ctx))
	m.ActivateJWTKey(ctx)

	require.NotNil(t, caInst.JWTKey(), "writer signs locally with the shared key")
	activeKid := caInst.JWTKey().Kid
	require.NotEmpty(t, activeKid)

	lease, err := env.ds.FetchJWTSigningAuthority(ctx, testTrustDomain.IDString())
	require.NoError(t, err)
	require.NotNil(t, lease)
	require.Equal(t, activeKid, lease.ActiveJWTKid)
	require.NotEmpty(t, lease.HolderServerID)
	require.NotEmpty(t, lease.Data)
}

func TestSharedJWTFollowerBindsSharedKey(t *testing.T) {
	ctx := context.Background()
	env := setupSharedJWTEnv(t)

	writer, writerCA := env.newManager(t)
	require.NoError(t, writer.SyncJWTKeyAuthority(ctx))
	require.True(t, writer.isJWTWriter())
	require.NoError(t, writer.PrepareJWTKey(ctx))
	writer.ActivateJWTKey(ctx)
	writerKid := writerCA.JWTKey().Kid

	follower, followerCA := env.newManager(t)
	require.NoError(t, follower.SyncJWTKeyAuthority(ctx))
	require.False(t, follower.isJWTWriter(), "second server is a follower while the lease is held")

	require.NotNil(t, followerCA.JWTKey(), "follower binds the shared key for local signing")
	require.Equal(t, writerKid, followerCA.JWTKey().Kid)
	require.Equal(t, writerKid, follower.GetCurrentJWTKeySlot().AuthorityID())

	// A follower's lifecycle calls are no-ops: it must not mint a competing key.
	require.NoError(t, follower.PrepareJWTKey(ctx))
	follower.ActivateJWTKey(ctx)
	require.Equal(t, writerKid, followerCA.JWTKey().Kid)
	require.Equal(t, writerKid, follower.GetCurrentJWTKeySlot().AuthorityID())
}

func TestSharedJWTFailoverAdoptsExistingKey(t *testing.T) {
	ctx := context.Background()
	env := setupSharedJWTEnv(t)

	writer, writerCA := env.newManager(t)
	require.NoError(t, writer.SyncJWTKeyAuthority(ctx))
	require.NoError(t, writer.PrepareJWTKey(ctx))
	writer.ActivateJWTKey(ctx)
	writerKid := writerCA.JWTKey().Kid

	// The writer stops renewing and its lease expires.
	env.clk.Add(jwtAuthorityLeaseTTL + time.Second)

	standby, standbyCA := env.newManager(t)
	require.NoError(t, standby.SyncJWTKeyAuthority(ctx))
	require.True(t, standby.isJWTWriter(), "standby takes over the expired lease")

	require.NotNil(t, standbyCA.JWTKey())
	require.Equal(t, writerKid, standbyCA.JWTKey().Kid, "standby adopts the existing shared key rather than minting a new one")

	lease, err := env.ds.FetchJWTSigningAuthority(ctx, testTrustDomain.IDString())
	require.NoError(t, err)
	require.Equal(t, writerKid, lease.ActiveJWTKid)
	require.Greater(t, lease.FencingToken, int64(1), "taking over an expired lease bumps the fencing token")
}

// canTaintJWTAuthority mirrors the precondition enforced by
// pkg/server/api/localauthority/v1 Service.TaintJWTAuthority (service.go:188-206):
// a JWT authority may be tainted only if it is non-empty, is not the current
// (active) authority, equals the server's NEXT JWT slot, and that next slot's
// status is OLD.
func canTaintJWTAuthority(m *Manager, authorityID string) bool {
	if authorityID == "" {
		return false
	}
	if authorityID == m.GetCurrentJWTKeySlot().AuthorityID() {
		return false
	}
	next := m.GetNextJWTKeySlot()
	return authorityID == next.AuthorityID() && next.Status() == journal.Status_OLD
}

// TestSharedJWTOldAuthorityRemainsTaintable is a verification test for the
// shared-JWT manual-taint gap. With JWT key sharing on, persistJWTAuthorityState
// writes only the live (active + prepared) slots to the lease: jwtKeySlotToEntry
// drops the just-rotated OLD slot because its jwtKey is nil after Reset(). On the
// next rotator tick, reconcileSharedJWTSlots rebuilds every server's in-memory
// slots from the lease, so the OLD shared authority vanishes from the NEXT slot
// and the localauthority taint precondition can no longer be satisfied on any
// server.
//
// This asserts the DESIRED invariant — the OLD shared authority stays taintable
// from any server — so it FAILS on the current code, confirming the break. It
// becomes the regression test once the lease carries OLD authorities.
func TestSharedJWTOldAuthorityRemainsTaintable(t *testing.T) {
	ctx := context.Background()
	env := setupSharedJWTEnv(t)

	writer, writerCA := env.newManager(t)
	require.NoError(t, writer.SyncJWTKeyAuthority(ctx))
	require.True(t, writer.isJWTWriter())

	// Activate a shared key (oldKid), then prepare a successor and rotate so
	// oldKid becomes the OLD authority eligible for a manual taint.
	require.NoError(t, writer.PrepareJWTKey(ctx))
	writer.ActivateJWTKey(ctx)
	oldKid := writerCA.JWTKey().Kid
	require.NotEmpty(t, oldKid)

	require.NoError(t, writer.PrepareJWTKey(ctx))
	writer.RotateJWTKey(ctx)
	require.NotEqual(t, oldKid, writerCA.JWTKey().Kid, "rotation activates the prepared successor")

	// Sanity: immediately after rotation the writer still holds oldKid in its
	// next slot as OLD, so the taint precondition is (transiently) satisfiable.
	require.True(t, canTaintJWTAuthority(writer, oldKid),
		"right after rotation the writer's next slot is the OLD authority")

	// The next rotator tick re-syncs the writer's slots from the lease. The OLD
	// shared authority must survive so it stays taintable from the writer.
	require.NoError(t, writer.SyncJWTKeyAuthority(ctx))
	assert.True(t, canTaintJWTAuthority(writer, oldKid),
		"after re-sync the writer must still be able to taint the OLD shared authority")

	// A follower rebuilds its slots solely from the lease; taint is meant to be
	// any-server, so a follower must be able to taint the OLD shared authority too.
	follower, _ := env.newManager(t)
	require.NoError(t, follower.SyncJWTKeyAuthority(ctx))
	require.False(t, follower.isJWTWriter())
	assert.True(t, canTaintJWTAuthority(follower, oldKid),
		"a follower must be able to taint the OLD shared authority")
}

// TestSharedJWTOldAuthorityTaintWindow documents that the retired shared
// authority is taintable only while it is the OLD next slot — the same window
// non-shared SPIRE allows. Once the writer prepares the next successor (reusing
// that slot), the previous retired authority leaves the lease and is no longer
// taintable, so the lease never accumulates retired authorities.
func TestSharedJWTOldAuthorityTaintWindow(t *testing.T) {
	ctx := context.Background()
	env := setupSharedJWTEnv(t)

	writer, writerCA := env.newManager(t)
	require.NoError(t, writer.SyncJWTKeyAuthority(ctx))
	require.NoError(t, writer.PrepareJWTKey(ctx))
	writer.ActivateJWTKey(ctx)
	oldKid := writerCA.JWTKey().Kid

	require.NoError(t, writer.PrepareJWTKey(ctx))
	writer.RotateJWTKey(ctx)
	require.NoError(t, writer.SyncJWTKeyAuthority(ctx))
	require.True(t, canTaintJWTAuthority(writer, oldKid), "retired authority is taintable right after rotation")

	// Preparing the next successor reuses the retired slot, so the previous
	// retired authority is no longer the next slot and leaves the lease.
	require.NoError(t, writer.PrepareJWTKey(ctx))
	require.NoError(t, writer.SyncJWTKeyAuthority(ctx))
	require.False(t, canTaintJWTAuthority(writer, oldKid),
		"once replaced, the previous retired authority is no longer taintable (the lease does not accumulate)")
}
