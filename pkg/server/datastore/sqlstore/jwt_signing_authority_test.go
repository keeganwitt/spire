package sqlstore

import (
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc/codes"
)

func (s *PluginSuite) TestJWTSigningAuthorityAcquireAndRenew() {
	now := time.Now().Truncate(time.Second)
	ttl := time.Minute

	lease, acquired, err := s.ds.AcquireJWTSigningAuthority(ctx, "acquire.test", "server-A", now, ttl)
	s.Require().NoError(err)
	s.Require().True(acquired)
	s.Require().NotNil(lease)
	s.Equal("server-A", lease.HolderServerID)
	s.Equal(int64(1), lease.FencingToken)
	s.Equal(roundedInSecondsUnix(now.Add(ttl)), lease.Expiry)

	// The same holder renews: expiry extended, fencing token unchanged.
	later := now.Add(30 * time.Second)
	lease, acquired, err = s.ds.AcquireJWTSigningAuthority(ctx, "acquire.test", "server-A", later, ttl)
	s.Require().NoError(err)
	s.Require().True(acquired)
	s.Equal(int64(1), lease.FencingToken)
	s.Equal(roundedInSecondsUnix(later.Add(ttl)), lease.Expiry)
}

func (s *PluginSuite) TestJWTSigningAuthorityContestedAndTakeover() {
	now := time.Now().Truncate(time.Second)
	ttl := time.Minute

	_, acquired, err := s.ds.AcquireJWTSigningAuthority(ctx, "contested.test", "server-A", now, ttl)
	s.Require().NoError(err)
	s.Require().True(acquired)

	// A different server cannot acquire while the lease is held and unexpired.
	lease, acquired, err := s.ds.AcquireJWTSigningAuthority(ctx, "contested.test", "server-B", now.Add(time.Second), ttl)
	s.Require().NoError(err)
	s.Require().False(acquired)
	s.Equal("server-A", lease.HolderServerID)
	s.Equal(int64(1), lease.FencingToken)

	// After expiry, a different server takes over and the fencing token is bumped.
	afterExpiry := now.Add(ttl).Add(time.Second)
	lease, acquired, err = s.ds.AcquireJWTSigningAuthority(ctx, "contested.test", "server-B", afterExpiry, ttl)
	s.Require().NoError(err)
	s.Require().True(acquired)
	s.Equal("server-B", lease.HolderServerID)
	s.Equal(int64(2), lease.FencingToken)
}

func (s *PluginSuite) TestJWTSigningAuthoritySaveAndFetch() {
	now := time.Now().Truncate(time.Second)
	ttl := time.Minute

	lease, acquired, err := s.ds.AcquireJWTSigningAuthority(ctx, "saveandfetch.test", "server-A", now, ttl)
	s.Require().NoError(err)
	s.Require().True(acquired)

	lease.Data = []byte("shared-jwt-journal")
	lease.ActiveJWTKid = "kid-123"
	s.Require().NoError(s.ds.SaveJWTSigningAuthority(ctx, lease))

	got, err := s.ds.FetchJWTSigningAuthority(ctx, "saveandfetch.test")
	s.Require().NoError(err)
	s.Require().NotNil(got)
	s.Equal("server-A", got.HolderServerID)
	s.Equal("kid-123", got.ActiveJWTKid)
	s.Equal([]byte("shared-jwt-journal"), got.Data)
	s.Equal(int64(1), got.FencingToken)
}

func (s *PluginSuite) TestJWTSigningAuthoritySaveRejectsStaleHolder() {
	now := time.Now().Truncate(time.Second)
	ttl := time.Minute

	leaseA, _, err := s.ds.AcquireJWTSigningAuthority(ctx, "stale.test", "server-A", now, ttl)
	s.Require().NoError(err)

	_, acquired, err := s.ds.AcquireJWTSigningAuthority(ctx, "stale.test", "server-B", now.Add(ttl).Add(time.Second), ttl)
	s.Require().NoError(err)
	s.Require().True(acquired)

	// server-A's stale lease (old fencing token / no longer holder) cannot save.
	leaseA.Data = []byte("stale")
	err = s.ds.SaveJWTSigningAuthority(ctx, leaseA)
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "jwt signing authority lease is no longer held by this server")
}

func (s *PluginSuite) TestJWTSigningAuthorityFetchMissing() {
	got, err := s.ds.FetchJWTSigningAuthority(ctx, "missing.test")
	s.Require().NoError(err)
	s.Require().Nil(got)
}

func (s *PluginSuite) TestJWTSigningAuthoritySaveRequiresExistingLease() {
	lease := &datastore.JWTSigningAuthorityLease{TrustDomain: "nolease.test", HolderServerID: "server-A"}
	err := s.ds.SaveJWTSigningAuthority(ctx, lease)
	s.RequireGRPCStatus(err, codes.FailedPrecondition, "jwt signing authority lease does not exist")
}

// TestJWTSigningAuthorityConcurrentAcquire is the contention test the
// sequential cases can't provide: many servers race for the same lease at once.
// The safety invariant the single-writer design rests on is that AT MOST one
// server is ever elected. Two distinct races are exercised against the real
// dialect, not just sqlite:
//
//   - First acquire (no row yet): `SELECT ... FOR UPDATE` has nothing to lock,
//     so the unique trust_domain index is the backstop.
//   - Takeover of an expired lease (row exists): `FOR UPDATE` must serialize the
//     read-modify-write, so the fencing token is bumped exactly once — not once
//     per racer — which is the property the writer's fencing depends on.
func (s *PluginSuite) TestJWTSigningAuthorityConcurrentAcquire() {
	const racers = 16
	now := time.Now().Truncate(time.Second)
	ttl := time.Minute

	holder, acquired, errs := s.raceAcquireJWTSigningAuthority("concurrent.test", serverIDs("server", racers), now, ttl)
	s.T().Logf("first-acquire dialect=%s racers=%d acquired=%d errored-losers=%d", TestDialect, racers, acquired, errs)
	s.Require().Equal(1, acquired, "exactly one server may win the first acquire")
	s.Require().Zero(errs, "deadlock-retry must convert first-acquire losers into a clean acquired=false")

	lease, err := s.ds.FetchJWTSigningAuthority(ctx, "concurrent.test")
	s.Require().NoError(err)
	s.Require().NotNil(lease)
	s.Equal(holder, lease.HolderServerID)
	s.Equal(int64(1), lease.FencingToken)

	// After expiry a disjoint set of servers races to take over.
	afterExpiry := now.Add(ttl).Add(time.Second)
	_, acquired, errs = s.raceAcquireJWTSigningAuthority("concurrent.test", serverIDs("taker", racers), afterExpiry, ttl)
	s.T().Logf("takeover dialect=%s racers=%d acquired=%d errored-losers=%d", TestDialect, racers, acquired, errs)
	s.Require().Equal(1, acquired, "exactly one server may win the takeover")
	s.Require().Zero(errs, "takeover serializes under FOR UPDATE and must not surface errors")

	lease, err = s.ds.FetchJWTSigningAuthority(ctx, "concurrent.test")
	s.Require().NoError(err)
	s.Equal(int64(2), lease.FencingToken, "FOR UPDATE must serialize takeover: fencing bumped exactly once")
}

func serverIDs(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%d", prefix, i)
	}
	return out
}

// raceAcquireJWTSigningAuthority fires one concurrent AcquireJWTSigningAuthority
// per server ID and returns the winning holder plus how many acquired / errored.
func (s *PluginSuite) raceAcquireJWTSigningAuthority(trustDomain string, ids []string, now time.Time, ttl time.Duration) (holder string, acquiredCount, errCount int) {
	type result struct {
		acquired bool
		holder   string
		err      error
	}
	results := make([]result, len(ids))

	var wg sync.WaitGroup
	wg.Add(len(ids))
	for i, id := range ids {
		go func() {
			defer wg.Done()
			lease, acquired, err := s.ds.AcquireJWTSigningAuthority(ctx, trustDomain, id, now, ttl)
			results[i].acquired = acquired
			results[i].err = err
			if lease != nil {
				results[i].holder = lease.HolderServerID
			}
		}()
	}
	wg.Wait()

	for _, r := range results {
		switch {
		case r.err != nil:
			errCount++
			s.T().Logf("loser acquire error: %v", r.err)
		case r.acquired:
			acquiredCount++
			holder = r.holder
		}
	}
	return holder, acquiredCount, errCount
}
