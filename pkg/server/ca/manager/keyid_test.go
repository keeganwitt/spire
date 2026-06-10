package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeterministicKeyID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	kid, err := deterministicKeyID(key)
	require.NoError(t, err)
	assert.NotEmpty(t, kid)

	again, err := deterministicKeyID(key)
	require.NoError(t, err)
	assert.Equal(t, kid, again, "same signer must yield the same kid")

	ski, err := x509util.GetSubjectKeyID(key.Public())
	require.NoError(t, err)
	assert.Equal(t, x509util.SubjectKeyIDToString(ski), kid, "kid must match the X509 SubjectKeyID derivation")

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherKid, err := deterministicKeyID(other)
	require.NoError(t, err)
	assert.NotEqual(t, kid, otherKid, "different signers must yield different kids")
}
