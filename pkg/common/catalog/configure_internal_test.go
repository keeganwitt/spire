package catalog

import (
	"context"
	"testing"
)

func TestConfigurerRepo(t *testing.T) {
	repo := new(configurerRepo)

	// Verify Binder returns the expected function type
	binder := repo.Binder()
	if binder == nil {
		t.Fatal("Binder should not be nil")
	}
	bindFunc, ok := binder.(func(Configurer))
	if !ok {
		t.Fatalf("Binder should return func(Configurer), but got %T", binder)
	}

	// Define a dummy configurer
	var called bool
	dummyConfigurer := ConfigurerFunc(func(ctx context.Context, coreConfig CoreConfig, configuration string) error {
		called = true
		return nil
	})

	// Bind the dummy configurer and verify it's set
	bindFunc(dummyConfigurer)
	if repo.configurer == nil {
		t.Fatal("repo.configurer should be set")
	}

	// Verify Versions
	versions := repo.Versions()
	if len(versions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(versions))
	}
	if _, ok := versions[0].(configurerV1Version); !ok {
		t.Fatalf("expected configurerV1Version, got %T", versions[0])
	}

	// Verify Clear resets the configurer to nil
	repo.Clear()
	if repo.configurer != nil {
		t.Fatal("repo.configurer should be nil after Clear")
	}
}
