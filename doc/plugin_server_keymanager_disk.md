# Server plugin: KeyManager "disk"

The `disk` key manager maintains a set of private keys that are persisted to
disk.

The plugin accepts the following configuration options:

| Configuration | Description                   |
|---------------|-------------------------------|
| keys_path     | Path to the keys file on disk |

The plugin also accepts an optional `shared_keys_path`. When set (on a volume
shared by all servers in the trust domain), JWT signing keys are stored there
and shared across servers, while X509 CA and WIT keys remain private to each
server in `keys_path`. Pair this with the server-level `jwt_key_sharing = true`
setting.

A sample configuration:

```hcl
    KeyManager "disk" {
        plugin_data = {
            keys_path = "/opt/spire/data/server/keys.json"
        }
    }
```
