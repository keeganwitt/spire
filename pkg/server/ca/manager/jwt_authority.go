package manager

import (
	"context"
	"crypto"
	"crypto/x509"
	"time"

	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/private/server/journal"
	"google.golang.org/protobuf/proto"
)

const jwtAuthorityLeaseTTL = 2 * time.Minute

func (m *Manager) SyncJWTKeyAuthority(ctx context.Context) error {
	if !m.jwtKeySharing {
		return nil
	}

	ds := m.c.Catalog.GetDataStore()
	now := m.c.Clock.Now()
	lease, acquired, err := ds.AcquireJWTSigningAuthority(ctx, m.c.TrustDomain.IDString(), m.serverID, now, jwtAuthorityLeaseTTL)
	if err != nil {
		return err
	}

	m.jwtAuthorityMu.Lock()
	m.jwtWriter = acquired
	m.jwtLease = lease
	m.jwtAuthorityMu.Unlock()

	return m.reconcileSharedJWTSlots(ctx, lease)
}

func (m *Manager) isJWTWriter() bool {
	m.jwtAuthorityMu.Lock()
	defer m.jwtAuthorityMu.Unlock()
	return m.jwtWriter
}

func (m *Manager) reconcileSharedJWTSlots(ctx context.Context, lease *datastore.JWTSigningAuthorityLease) error {
	entries := new(journal.Entries)
	if lease != nil && len(lease.Data) > 0 {
		if err := proto.Unmarshal(lease.Data, entries); err != nil {
			return err
		}
	}

	loader := &SlotLoader{
		TrustDomain:    m.c.TrustDomain,
		Log:            m.c.Log,
		Dir:            m.c.Dir,
		Catalog:        m.c.Catalog,
		UpstreamClient: m.upstreamClient,
	}
	current, next, err := loader.getJWTKeysSlots(ctx, entries.JwtKeys)
	if err != nil {
		return err
	}

	m.jwtKeyMutex.Lock()
	m.currentJWTKey = current
	m.nextJWTKey = next
	m.jwtKeyMutex.Unlock()

	if current != nil && !current.IsEmpty() && current.status == journal.Status_ACTIVE {
		m.c.CA.SetJWTKey(current.jwtKey)
	}
	return nil
}

func (m *Manager) persistJWTAuthorityState(ctx context.Context) {
	m.jwtAuthorityMu.Lock()
	lease := m.jwtLease
	isWriter := m.jwtWriter
	m.jwtAuthorityMu.Unlock()
	if !isWriter || lease == nil {
		return
	}

	entries := new(journal.Entries)
	for _, slot := range []*jwtKeySlot{m.currentJWTKey, m.nextJWTKey} {
		entry, err := m.jwtKeySlotToEntry(ctx, slot)
		if err != nil {
			m.c.Log.WithError(err).Error("Failed to serialize shared JWT key slot")
			return
		}
		if entry != nil {
			entries.JwtKeys = append(entries.JwtKeys, entry)
		}
	}

	data, err := proto.Marshal(entries)
	if err != nil {
		m.c.Log.WithError(err).Error("Failed to marshal shared JWT authority state")
		return
	}

	activeKid := ""
	if m.currentJWTKey != nil && !m.currentJWTKey.IsEmpty() && m.currentJWTKey.status == journal.Status_ACTIVE {
		activeKid = m.currentJWTKey.authorityID
	}

	updated := &datastore.JWTSigningAuthorityLease{
		TrustDomain:    lease.TrustDomain,
		HolderServerID: lease.HolderServerID,
		FencingToken:   lease.FencingToken,
		Data:           data,
		ActiveJWTKid:   activeKid,
	}
	if err := m.c.Catalog.GetDataStore().SaveJWTSigningAuthority(ctx, updated); err != nil {
		m.c.Log.WithError(err).Warn("Failed to persist shared JWT authority state")
	}
}

// jwtKeySlotToEntry serializes a JWT key slot for the shared-authority lease. A
// truly empty slot (no authority bound) is skipped. A retired (OLD) slot is
// retained — not dropped — so the retired authority survives a reconcile and
// stays taintable from any server: localauthority TaintJWTAuthority requires the
// target to be the next slot with status OLD, which followers and a recovering
// writer only know about if it is carried in the lease.
func (m *Manager) jwtKeySlotToEntry(ctx context.Context, slot *jwtKeySlot) (*journal.JWTKeyEntry, error) {
	if slot == nil || slot.authorityID == "" {
		return nil, nil
	}

	var pub crypto.PublicKey
	if slot.jwtKey != nil {
		pub = slot.jwtKey.Signer.Public()
	} else {
		// Retired (OLD) slot: Reset cleared the signer. Reload the public key
		// from the key manager (the backend key still exists until pruned). If
		// it is gone, drop the slot rather than fail the whole persist.
		key, err := m.c.Catalog.GetKeyManager().GetKey(ctx, jwtKeyKmKeyID(slot.id))
		if err != nil {
			m.c.Log.WithError(err).WithField(telemetry.LocalAuthorityID, slot.authorityID).
				Debug("Retired shared JWT authority key unavailable; not retaining in lease")
			return nil, nil
		}
		pub = key.Public()
	}

	pkixBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return &journal.JWTKeyEntry{
		SlotId:      slot.id,
		IssuedAt:    slot.issuedAt.Unix(),
		NotAfter:    slot.notAfter.Unix(),
		Kid:         slot.authorityID,
		PublicKey:   pkixBytes,
		Status:      slot.status,
		AuthorityId: slot.authorityID,
	}, nil
}
