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

First configure protected trusted time and threshold witness custody under
`ContactResolveProductionAuthority`, and verify their network and key files.
Use only a newly signed V2 empty head (`minimumReader >= 2`, V2 empty-map
root); never copy ADA1 into ADA2. With V1 admission disabled and the V2
settings supplied, initialize the state once from inside the Registry runtime:

```text
dotnet Deep.Registry.Api.dll did2-directory provision-state
```

This command re-verifies XNA1/DTS1 from the pinned genesis, verifies the
signed empty head, writes an HMAC-protected ADA2 file under an exclusive
lease, prints only its SHA-256, and refuses any existing state or interrupted
write. It does not enable the HTTP route. UAT may then explicitly set
`DeepIdV2DirectoryAuthority:Enabled=true` and keep
`AccountDirectoryAuthority:Enabled=false`.

Do not enable this candidate in production yet. An older valid HMAC-protected
ADA2 snapshot can still replace the current file across restarts because an
independent latest-head rollback floor has not been implemented. V2 current
proof publication, client cutover and physical Android↔Windows E2E are also
open gates. The client must never trust the admission receipt alone as a
fresh directory or contact proof.

The internal DID2-only proof issuer now derives current/non-membership
material directly from the fully restored ADA2 journal under its exclusive
lease. It consumes a durable nonce before accessing witness custody, reads a
signed exact XNV1, and issues and self-verifies a live DTT1/ADP1 V2 using the
PQ verifier. Its nonce ledger must use a separate path/key from V1 if it is
ever composed for a deployed service. There is deliberately no HTTP route
for it yet: the independent rollback floor, ADL1 V2 request/response wire,
client-bound DAB2 query validation and production composition are required
first. An arbitrary 32-byte leaf query is not a trusted identity binding.
