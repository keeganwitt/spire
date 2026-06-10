package sqlstore

import (
	"context"
	"errors"
	"time"

	"github.com/jinzhu/gorm"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maxJWTSigningAuthorityAcquireRetries bounds the retries on a transient
// deadlock during AcquireJWTSigningAuthority. One retry is enough in practice
// (the winner's row exists by then); the extra headroom covers a brief window
// where the winner has not yet committed.
const maxJWTSigningAuthorityAcquireRetries = 3

func (ds *Plugin) AcquireJWTSigningAuthority(ctx context.Context, trustDomain, candidateServerID string, now time.Time, ttl time.Duration) (lease *datastore.JWTSigningAuthorityLease, acquired bool, err error) {
	if trustDomain == "" {
		return nil, false, status.Error(codes.InvalidArgument, "trust domain is required")
	}
	if candidateServerID == "" {
		return nil, false, status.Error(codes.InvalidArgument, "candidate server ID is required")
	}

	// A concurrent first-acquire (no lease row yet) can deadlock on MySQL: the
	// `SELECT ... FOR UPDATE` takes a gap lock and the racing INSERTs conflict,
	// so InnoDB aborts all but one with a retriable deadlock error. The aborted
	// transactions rolled back cleanly, so retrying is safe; by the next attempt
	// the winner's row exists and the read-modify-write takes the row-exists
	// path, returning acquired=false. opErr holds the raw (unflattened) error so
	// the dialect can classify it; txErr holds the gRPC status to return.
	for attempt := 0; ; attempt++ {
		var opErr error
		txErr := ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) error {
			lease, acquired, opErr = acquireJWTSigningAuthority(tx, trustDomain, candidateServerID, now, ttl)
			return opErr
		})
		switch {
		case txErr == nil:
			return lease, acquired, nil
		case attempt < maxJWTSigningAuthorityAcquireRetries && ds.db.dialect.isDeadlock(opErr):
			continue
		default:
			return nil, false, txErr
		}
	}
}

func (ds *Plugin) SaveJWTSigningAuthority(ctx context.Context, lease *datastore.JWTSigningAuthorityLease) error {
	if lease == nil {
		return status.Error(codes.InvalidArgument, "jwt signing authority lease is required")
	}
	if lease.TrustDomain == "" {
		return status.Error(codes.InvalidArgument, "trust domain is required")
	}
	if lease.HolderServerID == "" {
		return status.Error(codes.InvalidArgument, "holder server ID is required")
	}

	return ds.withReadModifyWriteTx(ctx, func(tx *gorm.DB) error {
		return saveJWTSigningAuthority(tx, lease)
	})
}

func (ds *Plugin) FetchJWTSigningAuthority(ctx context.Context, trustDomain string) (lease *datastore.JWTSigningAuthorityLease, err error) {
	if trustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust domain is required")
	}

	if err = ds.withReadTx(ctx, func(tx *gorm.DB) (err error) {
		lease, err = fetchJWTSigningAuthority(tx, trustDomain)
		return err
	}); err != nil {
		return nil, err
	}
	return lease, nil
}

func acquireJWTSigningAuthority(tx *gorm.DB, trustDomain, candidateServerID string, now time.Time, ttl time.Duration) (*datastore.JWTSigningAuthorityLease, bool, error) {
	var model JWTSigningAuthority
	err := tx.Find(&model, "trust_domain = ?", trustDomain).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		model = JWTSigningAuthority{
			TrustDomain:    trustDomain,
			HolderServerID: candidateServerID,
			Expiry:         roundedInSecondsUnix(now.Add(ttl)),
			FencingToken:   1,
		}
		if err := tx.Create(&model).Error; err != nil {
			return nil, false, newWrappedSQLError(err)
		}
		return modelToJWTSigningAuthorityLease(model), true, nil
	case err != nil:
		return nil, false, newWrappedSQLError(err)
	}

	switch {
	case model.HolderServerID == candidateServerID:
		model.Expiry = roundedInSecondsUnix(now.Add(ttl))
	case model.Expiry <= roundedInSecondsUnix(now):
		model.HolderServerID = candidateServerID
		model.Expiry = roundedInSecondsUnix(now.Add(ttl))
		model.FencingToken++
	default:
		return modelToJWTSigningAuthorityLease(model), false, nil
	}

	if err := tx.Save(&model).Error; err != nil {
		return nil, false, newWrappedSQLError(err)
	}
	return modelToJWTSigningAuthorityLease(model), true, nil
}

func saveJWTSigningAuthority(tx *gorm.DB, lease *datastore.JWTSigningAuthorityLease) error {
	var model JWTSigningAuthority
	err := tx.Find(&model, "trust_domain = ?", lease.TrustDomain).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return status.Error(codes.FailedPrecondition, "jwt signing authority lease does not exist")
	case err != nil:
		return newWrappedSQLError(err)
	}

	if model.HolderServerID != lease.HolderServerID || model.FencingToken != lease.FencingToken {
		return status.Error(codes.FailedPrecondition, "jwt signing authority lease is no longer held by this server")
	}

	model.Data = lease.Data
	model.ActiveJWTKid = lease.ActiveJWTKid
	if err := tx.Save(&model).Error; err != nil {
		return newWrappedSQLError(err)
	}
	return nil
}

func fetchJWTSigningAuthority(tx *gorm.DB, trustDomain string) (*datastore.JWTSigningAuthorityLease, error) {
	var model JWTSigningAuthority
	err := tx.Find(&model, "trust_domain = ?", trustDomain).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, nil
	case err != nil:
		return nil, newWrappedSQLError(err)
	}
	return modelToJWTSigningAuthorityLease(model), nil
}

func modelToJWTSigningAuthorityLease(model JWTSigningAuthority) *datastore.JWTSigningAuthorityLease {
	return &datastore.JWTSigningAuthorityLease{
		TrustDomain:    model.TrustDomain,
		HolderServerID: model.HolderServerID,
		Expiry:         model.Expiry,
		FencingToken:   model.FencingToken,
		ActiveJWTKid:   model.ActiveJWTKid,
		Data:           model.Data,
	}
}
