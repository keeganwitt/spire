package catalog

import (
	"testing"

	"github.com/spiffe/spire/pkg/agent/plugin/svidstore"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/stretchr/testify/require"
)

func TestSVIDStoreRepository(t *testing.T) {
	repo := &svidStoreRepository{}

	// Binder
	require.NotNil(t, repo.Binder())

	// Constraints
	require.Equal(t, catalog.ZeroOrMore(), repo.Constraints())

	// Versions
	versions := repo.Versions()
	require.Len(t, versions, 1)
	require.IsType(t, svidStoreV1{}, versions[0])

	// BuiltIns
	builtIns := repo.BuiltIns()
	require.Len(t, builtIns, 2)
	require.Equal(t, "aws_secretsmanager", builtIns[0].Name)
	require.Equal(t, "gcp_secretmanager", builtIns[1].Name)
}

func TestSVIDStoreV1(t *testing.T) {
	v1 := svidStoreV1{}

	require.False(t, v1.Deprecated())
	require.IsType(t, new(svidstore.V1), v1.New())
}
