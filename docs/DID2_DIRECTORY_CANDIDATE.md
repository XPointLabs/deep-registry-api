# DID2 Registry admission candidate

This is a development/UAT path, not a production release approval. The
`/api/v2/account-directory/genesis-admissions` route is disabled by default.
It accepts only DGA1 V2, verifies the exact DID2/DAB2 ML-DSA and classical
closure, and appends to separately provisioned ADA2 state. The legacy V1
admission and the V2 admission cannot be enabled together.

The `DeepIdV2DirectoryAuthority` configuration requires:

| Setting | Value |
|---|---|
| `NetworkIdHex` | Exact 16-byte network ID, matching `ContactResolveProductionAuthority` |
| `GenesisAuthorityCoreHashHex` | Independently pinned SHA-256 core hash of generation-zero XNA1 |
| `ExactAuthorityPaths` / `ExactTimePolicyPaths` | Ordered, positionally paired exact XNA1/DTS1 files |
| `GenesisHeadPath` / `GenesisHeadCoreHashHex` | Exact signed empty V2 ADH1 and its independently pinned core hash |
| `StatePath` / `IntegrityKeyPath` | Separate absolute paths for ADA2 and its nonzero 32-byte HMAC key |
| `DeploymentProfileId` | Nonzero DID2 deployment profile; currently 1 |
| `HeadValiditySeconds` | 300–86400 seconds; default 3600 |
| `ProofEnabled` | Optional UAT-only `DPQ2` proof endpoint; default `false` |
| `CurrentXnv1Path` | Exact signed current XNV1 supplied by the authority owner |
| `ProofRequestLedgerRootPath` / `ProofRequestLedgerIntegrityKeyPath` | Separate V2 one-use nonce ledger root and nonzero 32-byte HMAC key; neither may alias V1 custody paths |

First configure protected trusted time and threshold witness custody under
`ContactResolveProductionAuthority`, and verify their network and key files.
Use only a newly signed V2 empty head (`minimumReader >= 2`, V2 empty-map
root); never copy ADA1 into ADA2. With the exact XNA1/DTS1 genesis paths and
independent XNA1 core-hash pin configured, V1 admission disabled, and an empty
absolute `GenesisHeadPath`, author the head once using the configured
threshold witness custody. The two numeric arguments are operator-approved
Unix-second bounds inside the verified XNA1 validity interval (at most 24h):

```text
dotnet Deep.Registry.Api.dll did2-directory author-genesis-head <validFromUnix> <validUntilUnix>
```

The command creates only the public signed ADH1, self-verifies its V2 empty
roots and witness threshold, prints its core hash, and refuses a pre-existing
head, interrupted authoring file, missing/insufficient custody, cross-network
keys, overlapping paths or a stale configured head pin. It never emits seeds.
Review and independently pin that printed hash as
`GenesisHeadCoreHashHex`; the command does not set the pin for you. With the
V2 state/key settings supplied, initialize ADA2 once from inside the Registry
runtime:

```text
dotnet Deep.Registry.Api.dll did2-directory provision-state
```

This command re-verifies XNA1/DTS1 from the pinned genesis, verifies the
signed empty head, writes an HMAC-protected ADA2 file under an exclusive
lease, prints only its SHA-256, and refuses any existing state or interrupted
write. It does not enable the HTTP route. The admission endpoint refuses to
start outside `Development` or `UAT` until the independent ADA2 rollback
floor is implemented. UAT may then explicitly set
`DeepIdV2DirectoryAuthority:Enabled=true` and keep
`AccountDirectoryAuthority:Enabled=false`.

Do not enable this candidate in production yet. An older valid HMAC-protected
ADA2 snapshot can still replace the current file across restarts because an
independent latest-head rollback floor has not been implemented. V2 current
proof publication, client cutover and physical Android↔Windows E2E are also
open gates. The client must never trust the admission receipt alone as a
fresh directory or contact proof.

The ADA2 store's external floor dependency is now threaded through both
genesis admission and proof issuance, including optional DI resolution in the
host. One injected test floor is used by both paths, and an old valid ADA2
snapshot is rejected on either path. No production floor provider is registered:
an HMAC-protected file on
the same backup/restore domain would not satisfy this gate. Production hosting
remains fail-closed until an independently durable provider and its recovery
procedure are implemented and verified.

The DID2-only proof issuer derives current/non-membership
material directly from the fully restored ADA2 journal under its exclusive
lease. It consumes a durable nonce before accessing witness custody, reads a
signed exact XNV1, and issues and self-verifies a live DTT1/ADP1 V2 using the
PQ verifier. Its nonce ledger must use a separate path/key from V1 if it is
ever composed for a deployed service. In UAT, an explicitly enabled
`POST /api/v2/account-directory/proofs` accepts only the exact bounded `DPQ2`
frame and returns `DPP2`; it shares the bounded admission gate but uses its
own durable one-use nonce ledger. The public route remains disabled by default
and cannot start outside Development/UAT. An arbitrary 32-byte leaf query is
not accepted: the leaf is derived from the exact DID2 carried by the frame.
The independent rollback floor, DAB2-bound client verification and physical
E2E remain production gates.

The internal issuer also accepts the candidate `DPQ2` frame: exact ADL1 V2
plus exact DID2, nonce, boot ID and monotonic sample. It derives the leaf,
matches the ADL1 lookup, resolves the caller's generation/hash floor only
against the restored ADA2 head history, and encodes a `DPP2` response with
exact ADH1/DTT1/ADP1 V2. Framing and cross-links are shape checks only;
production freshness still requires the public DID2 verifier and an
independently verified XPoint authority on the client.
