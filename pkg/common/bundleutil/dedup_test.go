package bundleutil

import (
	"testing"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDedupSigningKeysByKid(t *testing.T) {
	pk := func(kid string, notAfter int64, tainted bool) *common.PublicKey {
		return &common.PublicKey{Kid: kid, NotAfter: notAfter, TaintedKey: tainted}
	}

	t.Run("no duplicates is a no-op", func(t *testing.T) {
		bundle := &common.Bundle{
			JwtSigningKeys: []*common.PublicKey{pk("a", 100, false), pk("b", 200, false)},
		}
		changed := DedupSigningKeysByKid(bundle)
		assert.False(t, changed)
		require.Len(t, bundle.JwtSigningKeys, 2)
		assert.Equal(t, "a", bundle.JwtSigningKeys[0].Kid)
		assert.Equal(t, "b", bundle.JwtSigningKeys[1].Kid)
	})

	t.Run("collapses duplicate kid keeping the max NotAfter", func(t *testing.T) {
		bundle := &common.Bundle{
			JwtSigningKeys: []*common.PublicKey{pk("a", 100, false), pk("a", 250, false)},
		}
		changed := DedupSigningKeysByKid(bundle)
		assert.True(t, changed)
		require.Len(t, bundle.JwtSigningKeys, 1)
		assert.Equal(t, "a", bundle.JwtSigningKeys[0].Kid)
		assert.Equal(t, int64(250), bundle.JwtSigningKeys[0].NotAfter)
	})

	t.Run("keeps max NotAfter regardless of order", func(t *testing.T) {
		bundle := &common.Bundle{
			JwtSigningKeys: []*common.PublicKey{pk("a", 250, false), pk("a", 100, false)},
		}
		changed := DedupSigningKeysByKid(bundle)
		assert.True(t, changed)
		require.Len(t, bundle.JwtSigningKeys, 1)
		assert.Equal(t, int64(250), bundle.JwtSigningKeys[0].NotAfter)
	})

	t.Run("ORs the tainted flag across duplicates", func(t *testing.T) {
		bundle := &common.Bundle{
			JwtSigningKeys: []*common.PublicKey{pk("a", 100, false), pk("a", 250, true)},
		}
		changed := DedupSigningKeysByKid(bundle)
		assert.True(t, changed)
		require.Len(t, bundle.JwtSigningKeys, 1)
		assert.True(t, bundle.JwtSigningKeys[0].TaintedKey)
		assert.Equal(t, int64(250), bundle.JwtSigningKeys[0].NotAfter)
	})

	t.Run("tainted duplicate marks the untainted survivor tainted", func(t *testing.T) {
		// The kept key (max NotAfter) is untainted, but a collapsed duplicate was
		// tainted, so the survivor must end up tainted.
		bundle := &common.Bundle{
			JwtSigningKeys: []*common.PublicKey{pk("a", 250, false), pk("a", 100, true)},
		}
		changed := DedupSigningKeysByKid(bundle)
		assert.True(t, changed)
		require.Len(t, bundle.JwtSigningKeys, 1)
		assert.Equal(t, int64(250), bundle.JwtSigningKeys[0].NotAfter)
		assert.True(t, bundle.JwtSigningKeys[0].TaintedKey)
	})

	t.Run("dedups WIT signing keys too", func(t *testing.T) {
		bundle := &common.Bundle{
			WitSigningKeys: []*common.PublicKey{pk("w", 100, false), pk("w", 200, false)},
		}
		changed := DedupSigningKeysByKid(bundle)
		assert.True(t, changed)
		require.Len(t, bundle.WitSigningKeys, 1)
		assert.Equal(t, int64(200), bundle.WitSigningKeys[0].NotAfter)
	})

	t.Run("preserves first-seen order of distinct kids", func(t *testing.T) {
		bundle := &common.Bundle{
			JwtSigningKeys: []*common.PublicKey{pk("b", 100, false), pk("a", 100, false), pk("b", 300, false)},
		}
		changed := DedupSigningKeysByKid(bundle)
		assert.True(t, changed)
		require.Len(t, bundle.JwtSigningKeys, 2)
		assert.Equal(t, "b", bundle.JwtSigningKeys[0].Kid)
		assert.Equal(t, int64(300), bundle.JwtSigningKeys[0].NotAfter)
		assert.Equal(t, "a", bundle.JwtSigningKeys[1].Kid)
	})

	t.Run("empty bundle is a no-op", func(t *testing.T) {
		bundle := &common.Bundle{}
		assert.False(t, DedupSigningKeysByKid(bundle))
	})
}
