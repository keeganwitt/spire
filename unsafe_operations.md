# Unsafe Operations in SPIRE

During a review of the SPIRE codebase, several areas were identified where operations lack full transactional safety. If a failure (such as a server crash, agent crash, or network partition) interrupts these operations, it can result in undesirable states such as resource leaks in cloud providers, inconsistent local vs. database states, or partially applied updates.

## Summary of Architectural Changes

The following table summarizes the high-level architectural proposals, the number of unsafe operations they address, the estimated effort, and implementation notes.

| Architectural Change | Operations Solved | Level of Effort | Implementation Notes |
| :--- | :---: | :--- | :--- |
| **Write-Ahead Log (WAL) for Plugins** | 2 | Medium | Resolves orphaned resources. Suggested tech: Local SQLite DB or a dedicated intent table in the SQL datastore. |
| **Transactional Outbox / Persistent Queue** | 2 | High | Resolves non-atomic DB updates and orphaned deletions. Requires tying plugin/event generation to the primary SQL transaction. |
| **State Reconciliation Loop** | 2 | High | Kubernetes-style reconciliation rather than event-driven loops. Solves local disk vs external cache/SVID mismatches. |
| **Idempotency Keys** | 3 | Low | Add `IdempotencyKey` to KeyManager plugins, Node Rotations, and JWT SVID fetches. Use `ClientToken` for AWS. |
| **Event Sourcing** | 1 | Medium | Transition the CA Journal from updating a single blob to a log of discrete events (`X509CACreated`, `JWTKeyCreated`). |
| **Optimistic Concurrency Control (OCC)** | 1 | Medium | Add `updated_at` or `version` columns to datastore tables to eliminate long-running `SELECT FOR UPDATE` blocks. |

---

## Detailed Findings

### 1. GCP/AWS KeyManager `createKey` and Local Alias/Persistence

**Operation Description**:
In `pkg/server/plugin/keymanager/gcpkms/gcpkms.go` and `pkg/server/plugin/keymanager/awskms/awskms.go`, the `createKey` or `GenerateKey` function calls the respective Cloud KMS APIs to create a new cryptographic key or key version (e.g., `p.kmsClient.CreateCryptoKeyVersion`). After receiving a successful response from the cloud provider, it updates the local in-memory cache/entries, assigns aliases (via `assignAlias`), and implicitly relies on the server keeping track of this SPIRE Key ID locally.

**Risk/Vulnerability**:
If the SPIRE server crashes immediately *after* the Cloud KMS API creates the key, but *before* SPIRE persists the key mapping, assigns the alias, or links it to the CA Journal, the key is permanently orphaned in GCP/AWS. Over time, repeated crashes during rotation or startup could lead to extraneous KMS keys that incur costs and clutter the provider environment, since SPIRE will forget it created them.

**Proposed Architectural Change**:
*   **Write-Ahead Log (WAL) for Plugins:** Introduce a persistent `intent_log` in the datastore or a local file. Before a plugin performs a non-idempotent external side-effect, it records its intent (e.g., "Intent: Create KMS Key for {ID}"). After the action, it marks it resolved. A Janitor task periodically cleans up or resumes unresolved intents.
*   **Idempotency Keys:** Ensure all `KeyManager` plugins support an optional `IdempotencyKey` parameter. For AWS KMS, use the `ClientToken` or use the SPIRE-generated alias name as a "search-before-create" check to prevent duplicate key creation.

---

### 2. Deleting Key Versions via `scheduleDelete` / `scheduleDestroy`

**Operation Description**:
When a key is rotated or replaced in the Azure/GCP KeyManager plugins, the old key version is enqueued for deletion via a Go channel (`p.scheduleDelete <- keyName` or `p.scheduleDestroy <- cryptoKeyVersionName`). A background goroutine then consumes this channel and makes API calls to Azure Key Vault or GCP KMS to destroy the key.

**Risk/Vulnerability**:
Because the deletion intent is only stored in an in-memory Go channel, if the SPIRE server crashes before the background goroutine successfully calls the Cloud API to delete the old key, the immediate deletion intent is lost. While background periodic tasks (e.g., `refreshKeysTask` or `disposeCryptoKeysTask`) will eventually scan the cloud provider's state and re-enqueue the key for deletion, this reliance on expensive, slow full-state scans means keys are retained in KMS significantly longer than expected. During this window, they can cause temporary cost bloat or clutter.

**Proposed Architectural Change**:
Introduce a **Persistent Queue** or **Outbox Table** in the datastore for key garbage collection. Instead of an in-memory channel, inserts to a `pending_deletions` table should occur in the same transaction that updates the active key. A background worker then polls this table, performs the cloud API deletion, and removes the row from the table only upon success.

---

### 3. Non-Atomic Multiple-Table SQL Updates

**Operation Description**:
In `pkg/server/datastore/sqlstore/sqlstore.go`, individual plugin methods like `CreateRegistrationEntry` are wrapped in `withWriteTx`. However, higher-level operations (e.g., in `pkg/server/registration/registration.go`) might call multiple datastore methods sequentially.

**Risk/Vulnerability**:
If the server crashes between these separate calls, only some resources are created or updated. This leads to symptoms such as registration entries without selectors, nodes without metadata, or inconsistent bundle states.

**Proposed Architectural Change**:
Add a **Transactional Outbox** table to the datastore. Instead of triggering side-effects directly or orchestrating multiple sequential DB calls across boundaries, the server orchestrates these under a single unified transaction or writes a notification event into the `outbox` table within the same transaction as the primary data change. This guarantees "at-least-once" delivery of updates and a consistent internal state.

---

### 4. Agent Local State Mismatch and SVID Store Updates

**Operation Description**:
The agent saves SVIDs and bundles to `agent-data.json` (via `pkg/agent/storage/storage.go`) and also pushes SVIDs to external stores (via `pkg/agent/svid/store/service.go`). In the rotation process, it generates a key (locally or in a TPM) and then gets it signed. In the store service, when an entry's selectors change, it deletes the old SVID from the external store (`s.deleteSVID`) and then stores the new SVID (`s.storeSVID`).

**Risk/Vulnerability**:
*   If the agent crashes after the key is generated but before the SVID is stored to disk, it may lose track of the new key or have a mismatch between the cached SVID and the disk-based key, causing authentication failures.
*   If the agent crashes after `deleteSVID` but before `storeSVID` completes, the workload is left without any SVID in the target external store.

**Proposed Architectural Change**:
*   Move to a **State Reconciliation Loop (Kubernetes Style)** instead of purely event-driven rotations. The "desired state" should be continuously compared with the "actual state" (disk/cache). If a mismatch is detected, the agent converges toward the desired state, recovering from interrupted operations.
*   Use a **Two-Phase Commit (2PC)** if supported by the store plugins, or a **Write-Ahead Log (WAL)** on the agent side to execute deletions and creations atomically.

---

### 5. Server SVID Rotator Inconsistency

**Operation Description**:
In `pkg/server/svid/rotator.go`, the `rotateSVID` function generates a new signer and signs the SVID. It then updates the internal `state` property (`r.state.Update(...)`).

**Risk/Vulnerability**:
If the process is interrupted after the CA signs the SVID but before the internal state is updated, the CA has issued a certificate that the server won't use. This leads to potential "double-signing" upon restart or confusion in High Availability (HA) deployments.

**Proposed Architectural Change**:
Adopt a **State Reconciliation Loop**. The server should verify the actually issued CA certificates against its active internal state, ensuring that if a certificate was issued but not adopted locally before a crash, it is either properly loaded upon restart or explicitly revoked, instead of simply abandoning it and generating a new one.

---

### 6. CA Journal Datastore Persistence

**Operation Description**:
In `pkg/server/ca/manager/journal.go`, `saveInDatastore` is used to persist the CA journal. When appending a new X509 CA or JWT Key, the in-memory `j.entries` is modified first, and then `j.save(ctx)` is called to marshal the entire journal to protobuf and save it via `ds.SetCAJournal`.

**Risk/Vulnerability**:
If the SPIRE server creates a new CA Key via the KeyManager, updates its in-memory journal, but crashes before `ds.SetCAJournal` completes, the database is out of sync with the actual keys created in the KeyManager. Next time the server boots, it won't know about the new key, potentially causing a split-brain scenario if other server instances saw the key.

**Proposed Architectural Change**:
Architect the CA Journal using an **Event Sourcing** pattern combined with datastore transactions. Instead of mutating memory and then overwriting a large blob in the DB, write a discrete event (e.g., `X509CACreated`) to the database transactionally. Rebuild the in-memory state from the event log. This ensures the database is the source of truth and prevents memory-first update failures.

---

### 7. Datastore Read-Modify-Write Transactions

**Operation Description**:
In `pkg/server/datastore/sqlstore/sqlstore.go`, there are many operations wrapped in `withReadModifyWriteTx`. While this attempts to lock rows (e.g., using `SELECT FOR UPDATE`), the transaction stays open while Go code executes complex business logic, validations, and mapping.

**Risk/Vulnerability**:
If the Go application code panics, hits a context timeout, or hangs due to CPU starvation *while* holding these `ReadModifyWrite` transactions, the underlying database row locks remain held until the DB times out the connection. This can cause severe lock contention and database gridlock across all SPIRE server instances trying to update similar records (like Nodes or Entries).

**Proposed Architectural Change**:
Adopt **Optimistic Concurrency Control (OCC)**. Instead of pessimistic locking (`SELECT FOR UPDATE`), add a `version` or `updated_at` column to tables. Read the data without locks, perform the Go logic, and issue an `UPDATE ... WHERE id = X AND version = Y`. This removes long-held database locks and prevents deadlocks if the server process is interrupted.

---

### 8. Node Reattestation and Rotation (Agent-to-Server RPC)

**Operation Description**:
In the agent (`pkg/agent/svid/rotator.go`), `rotateSVIDIfNeeded` determines if an agent needs a new SVID. It locks `rotMtx`, generates a new private key (`r.generateKey(ctx)`), and sends a CSR to the server (`r.client.RenewSVID(ctx, csr)`).

**Risk/Vulnerability**:
Generating a key and making an RPC call to the server are both done synchronously. If the network drops or the server crashes while processing the `RenewSVID` RPC, the agent has already discarded its old key generation intent and holds a new key that isn't signed. The rotator will fail, and upon the next retry, it generates *another* new key. If the server actually processed the CSR but the response was dropped, the server thinks the agent has the new SVID, but the agent generated a new key and asks again, causing rapid, extraneous CA signing operations.

**Proposed Architectural Change**:
Implement **Idempotent RPCs with Client-Generated Request IDs**. The agent should generate its private key, store it locally (temporarily), and attach a unique `Request-ID` to the `RenewSVID` CSR. If the RPC fails, the agent retries the *same* CSR with the *same* `Request-ID`. The server can safely return the already-minted certificate without signing a new one, ensuring crash-tolerance on both sides.

---

### 9. Workload On-Demand JWT SVID Minting

**Operation Description**:
Unlike X.509 SVIDs which are generally pre-cached during periodic background rotations, JWT SVIDs are minted on-demand. When a workload requests a JWT SVID with specific audiences, the Workload API handler calls `FetchJWTSVID` (in `pkg/agent/manager/manager.go`), which triggers a synchronous RPC (`client.NewJWTSVID`) back to the SPIRE Server to sign the claims.

**Risk/Vulnerability**:
Because this is a synchronous network hop initiated by the workload, any server latency, network partition, or server crash during the `NewJWTSVID` call directly impacts the workload by blocking the authentication request or timing out. Furthermore, because the RPC is not idempotent, if a timeout occurs after the server signs the token but before the agent receives it, the workload/agent will retry the request, placing unnecessary load on the CA and generating multiple identical, un-cached JWT SVIDs.

**Proposed Architectural Change**:
*   **Idempotency Keys:** Similar to node rotation, introduce an `IdempotencyKey` on the `NewJWTSVID` RPC. If the agent retries the same audience request within a short time window, the server can return the previously signed JWT from a short-lived cache without incurring signing overhead.
*   **Decoupled/Asynchronous Fetching with Client Fallback:** If the workload supports it, transition from purely blocking RPCs to an asynchronous delivery model (similar to how X.509 bundles are streamed).