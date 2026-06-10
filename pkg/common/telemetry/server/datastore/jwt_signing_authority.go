package datastore

import (
	"github.com/spiffe/spire/pkg/common/telemetry"
)

func StartAcquireJWTSigningAuthority(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.JWTSigningAuthority, telemetry.Acquire)
}

func StartSaveJWTSigningAuthority(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.JWTSigningAuthority, telemetry.Set)
}

func StartFetchJWTSigningAuthority(m telemetry.Metrics) *telemetry.CallCounter {
	return telemetry.StartCall(m, telemetry.Datastore, telemetry.JWTSigningAuthority, telemetry.Fetch)
}
