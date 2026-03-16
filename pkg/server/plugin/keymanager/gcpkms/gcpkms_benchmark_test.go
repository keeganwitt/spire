package gcpkms

import (
	"context"
	"fmt"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/hashicorp/go-hclog"
	keymanagerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/keymanager/v1"
	"github.com/spiffe/spire/test/clock"
)

func BenchmarkKeepActiveCryptoKeys(b *testing.B) {
	ctx := context.Background()
	c := clock.NewMock(b)
	fakeKMSClient := newKMSClientFake(nil, c)
	fakeKMSClient.setUpdateLatency(10 * time.Millisecond)

	p := newPlugin(nil)
	p.kmsClient = fakeKMSClient
	p.log = hclog.NewNullLogger()
	p.hooks.clk = c

	numKeys := 100
	entries := make([]*keyEntry, numKeys)
	for i := 0; i < numKeys; i++ {
		keyID := fmt.Sprintf("key-%d", i)
		name := fmt.Sprintf("projects/p/locations/l/keyRings/r/cryptoKeys/%s", keyID)
		cryptoKey := &kmspb.CryptoKey{
			Name:   name,
			Labels: make(map[string]string),
		}
		fakeKMSClient.putFakeCryptoKeys([]*fakeCryptoKey{
			{
				CryptoKey: cryptoKey,
			},
		})
		entries[i] = &keyEntry{
			cryptoKey: cryptoKey,
			publicKey: &keymanagerv1.PublicKey{
				Id: keyID,
			},
		}
	}
	p.setCache(entries)

	fakeKMSClient.mu.Lock()
	fakeKMSClient.t = nil
	fakeKMSClient.mu.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := p.keepActiveCryptoKeys(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}
