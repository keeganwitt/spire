package disk

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"sync"

	"github.com/hashicorp/hcl"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/diskutil"
	"github.com/spiffe/spire/pkg/common/pluginconf"
	"github.com/spiffe/spire/pkg/server/plugin/keymanager"
	keymanagerbase "github.com/spiffe/spire/pkg/server/plugin/keymanager/base"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Generator = keymanagerbase.Generator

func BuiltIn() catalog.BuiltIn {
	return asBuiltIn(newKeyManager(nil))
}

func TestBuiltIn(generator Generator) catalog.BuiltIn {
	return asBuiltIn(newKeyManager(generator))
}

func asBuiltIn(p *KeyManager) catalog.BuiltIn {
	return catalog.MakeBuiltIn("disk",
		keymanagerv1.KeyManagerPluginServer(p),
		configv1.ConfigServiceServer(p))
}

type configuration struct {
	KeysPath       string `hcl:"keys_path"`
	SharedKeysPath string `hcl:"shared_keys_path"`
}

func buildConfig(coreConfig catalog.CoreConfig, hclText string, status *pluginconf.Status) *configuration {
	newConfig := new(configuration)
	if err := hcl.Decode(newConfig, hclText); err != nil {
		status.ReportErrorf("unable to decode configuration: %v", err)
		return nil
	}

	if newConfig.KeysPath == "" {
		status.ReportError("keys_path is required")
	}

	return newConfig
}

type KeyManager struct {
	*keymanagerbase.Base
	configv1.UnimplementedConfigServer

	mu             sync.Mutex
	config         *configuration
	wroteSharedKey bool
}

func newKeyManager(generator Generator) *KeyManager {
	m := &KeyManager{}
	m.Base = keymanagerbase.New(keymanagerbase.Config{
		WriteEntries: m.writeEntries,
		Generator:    generator,
	})
	return m
}

func (m *KeyManager) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	newConfig, _, err := pluginconf.Build(req, buildConfig)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.configure(newConfig); err != nil {
		return nil, err
	}

	return &configv1.ConfigureResponse{}, nil
}

func (m *KeyManager) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, notes, err := pluginconf.Build(req, buildConfig)

	return &configv1.ValidateResponse{
		Valid: err == nil,
		Notes: notes,
	}, nil
}

func (m *KeyManager) configure(config *configuration) error {
	// only load entry information on first configure
	if m.config == nil {
		entries, err := loadEntries(config.KeysPath)
		if err != nil {
			return err
		}
		if config.SharedKeysPath != "" {
			sharedEntries, err := loadEntries(config.SharedKeysPath)
			if err != nil {
				return err
			}
			entries = append(entries, sharedEntries...)
		}
		m.Base.SetEntries(entries)
	}

	m.config = config
	return nil
}

func (m *KeyManager) writeEntries(_ context.Context, entries []*keymanagerbase.KeyEntry) error {
	m.mu.Lock()
	config := m.config
	wroteSharedKey := m.wroteSharedKey
	m.mu.Unlock()

	if config == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	if config.SharedKeysPath == "" {
		return writeEntries(config.KeysPath, entries)
	}

	var privateEntries, sharedEntries []*keymanagerbase.KeyEntry
	for _, entry := range entries {
		if keymanager.IsSharedKeyID(entry.Id) {
			sharedEntries = append(sharedEntries, entry)
		} else {
			privateEntries = append(privateEntries, entry)
		}
	}

	if err := writeEntries(config.KeysPath, privateEntries); err != nil {
		return err
	}
	if wroteSharedKey {
		if err := writeEntries(config.SharedKeysPath, sharedEntries); err != nil {
			return err
		}
	}
	return nil
}

func (m *KeyManager) GenerateKey(ctx context.Context, req *keymanagerv1.GenerateKeyRequest) (*keymanagerv1.GenerateKeyResponse, error) {
	if keymanager.IsSharedKeyID(req.KeyId) {
		m.mu.Lock()
		m.wroteSharedKey = true
		m.mu.Unlock()
	}
	return m.Base.GenerateKey(ctx, req)
}

func (m *KeyManager) GetPublicKey(ctx context.Context, req *keymanagerv1.GetPublicKeyRequest) (*keymanagerv1.GetPublicKeyResponse, error) {
	if err := m.refreshSharedEntries(); err != nil {
		return nil, err
	}
	return m.Base.GetPublicKey(ctx, req)
}

func (m *KeyManager) GetPublicKeys(ctx context.Context, req *keymanagerv1.GetPublicKeysRequest) (*keymanagerv1.GetPublicKeysResponse, error) {
	if err := m.refreshSharedEntries(); err != nil {
		return nil, err
	}
	return m.Base.GetPublicKeys(ctx, req)
}

func (m *KeyManager) refreshSharedEntries() error {
	m.mu.Lock()
	config := m.config
	m.mu.Unlock()

	if config == nil || config.SharedKeysPath == "" {
		return nil
	}

	privateEntries, err := loadEntries(config.KeysPath)
	if err != nil {
		return err
	}
	sharedEntries, err := loadEntries(config.SharedKeysPath)
	if err != nil {
		return err
	}
	m.Base.SetEntries(append(privateEntries, sharedEntries...))
	return nil
}

type entriesData struct {
	Keys map[string][]byte `json:"keys"`
}

func loadEntries(path string) ([]*keymanagerbase.KeyEntry, error) {
	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	data := new(entriesData)
	if err := json.Unmarshal(jsonBytes, data); err != nil {
		return nil, status.Errorf(codes.Internal, "unable to decode keys JSON: %v", err)
	}

	var entries []*keymanagerbase.KeyEntry
	for id, keyBytes := range data.Keys {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to parse key %q: %v", id, err)
		}
		entry, err := keymanagerbase.MakeKeyEntryFromKey(id, key)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "unable to make entry %q: %v", id, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func writeEntries(path string, entries []*keymanagerbase.KeyEntry) error {
	data := &entriesData{
		Keys: make(map[string][]byte),
	}
	for _, entry := range entries {
		keyBytes, err := x509.MarshalPKCS8PrivateKey(entry.PrivateKey)
		if err != nil {
			return err
		}
		data.Keys[entry.Id] = keyBytes
	}

	jsonBytes, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return status.Errorf(codes.Internal, "unable to marshal entries: %v", err)
	}

	if err := diskutil.AtomicWritePrivateFile(path, jsonBytes); err != nil {
		return status.Errorf(codes.Internal, "unable to write entries: %v", err)
	}

	return nil
}
