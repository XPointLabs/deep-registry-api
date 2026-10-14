# DID2 private mailbox grant candidate

Normative issuer and custody owner:
[DR-0054](../../docs/survival-program/decisions/DR-0054-did2-private-mailbox-grant-issuance.md).
Complete public network distribution:
[operator guide](NETWORK_CLOSURE_DISTRIBUTION.md).
Directory/time/floor readiness:
[DID2 candidate guide](DID2_DIRECTORY_CANDIDATE.md).

This candidate is disabled by default. It does not activate the retired PMA1
coordinator, expose a public client fallback, or turn a service observer into
recipient identity or delivery evidence. The current issuer independently
checks the signed network, PMA2 role policy, forwarding node and both stores,
then journals and re-verifies the exact signed winner before release.

## Configuration and deployment prerequisites

`DeepIdV2MailboxGrantAuthority` has four options:

- `Enabled`: explicit candidate activation; default `false`;
- `ObserverCredentialPath`: an exact public DID2 credential file, not its
  resolver capability/address, recovery phrase or device secret;
- `DepositSignerSocketPath`: protected absolute Linux socket for the deposit
  role's existing PMA2 issuer key;
- `RetrieveSignerSocketPath`: a different protected Linux socket for the
  retrieve role's existing PMA2 issuer key.

Admission/proof, complete network distribution and the independent PostgreSQL
floor/journal must be configured together. The retired `ProductionMailbox`
configuration is rejected even when disabled; remove the section and its
environment overrides. The retired coordinator, endpoint/state composition and
software signer no longer exist in the Registry assembly. Runtime checks cannot be replaced by an
operator manifest, a configured URL, test signatures or an HTTP health result.
Preserve the initialized directory, floor, nonce ledger, grant journal and
existing identity/issuer keys. Do not repair readiness by provisioning new
genesis or deleting retained state.

The current wire and matched-rollout gate follow
[DR-0081](../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md).
The private HTTP client and permanent winner journal use only the current
result; there is no old-result reader or conversion. For an already provisioned
journal, run the explicit operator
[constraint cutover](sql/did2-mailbox-grant-v3-upgrade.sql) before activation.
It preserves immutable hashes, reservations, capacity and current winners,
and rejects any incompatible retained winner before changing the constraint.
The runtime does not execute DDL or repair retained state. Do not roll out this
source against the previous signed policy/bundle or publish a delivery claim.

The matched current request follows
[DR-0102](../../docs/survival-program/decisions/DR-0102-exact-mailbox-request-route-binding.md).
The node-private JSON admits only `exactXmg2`; `exactXmg1` is unknown and rejects.
The issuer checks the signed exact route commitment before reserving a journal
entry or invoking either external role signer. Result framing and signer keys
are unchanged. Rebuild/repin Protocol, Node and Shared/client consumers together;
old pending/winner requests cannot be converted or reminted by the runtime.
Do not delete the journal, replace genesis/keys or provision a new authority to
repair this source mismatch. No deployment or reset is performed by this
increment; the complete retained-route producer/owner/dispatch path remains unfinished.
[Exact source-gate evidence](testing/s01-exact-request-binding-2026-10-07.md).

The next private-boundary source cutover follows
[DR-0104](../../docs/survival-program/decisions/DR-0104-current-retained-retrieve-issuance.md).
Node and Registry must be updated together: `evidenceKind` and
`readUntilUnixSeconds` are mandatory private JSON fields, with no missing-field
default. Current evidence uses its existing purpose and zero retained horizon;
retained success uses the independent purpose and closed actual current host.
It cannot authorize Deposit or reuse current-route signatures/effective expiry.
Parsing private fields never proves original native custody.

The permanent winner scope now also binds the explicit kind/horizon and actual
current root, time-policy, PMA2 and protected network history. A substituted
scope rejects rather than rewriting a reservation, returning another winner or
signing again. A matched retry with a new forwarding nonce rechecks the exact
still-current winner, including after opening a new journal instance. Existing
incompatible scopes stay unavailable: no compatibility reader, implicit DDL,
database deletion, new genesis, issuer-key replacement or automatic repair.
Public node dispatch/held client integration and actual elapsed-route acceptance
remain gates; this private candidate is not a deployment or device qualification.
[Focused evidence and unresolved original full FAIL](testing/s01-retained-private-issuer-2026-10-07.md).

The endpoint is node-private, not a client entry point. Deploy its ingress and
external signer processes only as part of the matched node/Registry composition.
An absent/unavailable signer must stay unavailable; do not fall back to a
Registry-held software key or the other role's signer.

## External signer response lifecycle

The existing `UnixSocketEd25519ExternalSigner` adapter performs one bounded
request/response exchange per connection. After the exact detached signature,
the peer must close or half-close its sending side. The adapter waits for that
end-of-stream under the **same** original deadline before returning the
signature. Any immediate or delayed trailing byte, truncated response, missing
end-of-stream, timeout or caller cancellation rejects. Signature verification
and current issuer-policy checks remain mandatory in Protocol afterward.

This is exact stream-boundary enforcement, not a new signing domain, wire
version, cryptographic provider or permission to sign arbitrary grants.
Polling `Socket.Available` is not a substitute for the response boundary:
it reports only bytes already queued, not future bytes or successful completion.
See the [.NET socket contract](https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.socket.available?view=net-10.0).

### Protected role signer process

The source-cutover build provides the separate Linux command
`Deep.Registry.Api.dll mailbox-role-signer run`. It returns before constructing
the Registry service/HTTP endpoints. This is the current PMES key-custody process,
not the retired PMA1 signer or an in-process/other-role fallback. Run one process
per role, with only its exact nonzero raw32 seed mounted read-only; do not mount
directory witnesses, node/BLS keys, the other role or offline root. The Registry
process must not receive those role seed mounts.

`MailboxRoleSigner` configuration has exactly `Role` (`deposit`/`retrieve`),
`NetworkIdHex`, `SeedPath`, `SocketPath` and explicit `AllowedPeerUserId`.
Seed and socket directories must be owned0700, seed raw32/owned0600, and socket
owned0600. Linked/missing/wrong-owner/mode custody and untrusted writable ancestry
reject. Existing regular files/links at the socket path are never unlinked;
an owned stale socket may be removed only after exclusive owner lease, refused
connection and unchanged kernel identity. An active owner rejects a second start.
Graceful SIGTERM/SIGINT clears key memory and removes only the same owned socket.

Kernel file-type/owner/inode binding follows the
[Linux statx UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/stat.h);
local peer UID is checked through
[SO_PEERCRED](https://man7.org/linux/man-pages/man7/unix.7.html).
There is no abstract/public socket or new TCP listener. Work is serial with
backlog8 and a4-second whole-request bound. Existing PMES/v1 framing and its
65,824-byte ceiling are unchanged; replies are exactly64 bytes followed by EOF.
The signer validates canonical MCG3/MGR1 with the ordinary Protocol codecs and
requires the assigned role/network/derived public key and exact signing domain.
It checks no OS-wall-clock currentness and manufactures no issuer authority:
actual verified context, durable reserved intent and post-signature verification
remain required in Registry/Protocol. Its process/socket health is not readiness.

Use Dockerfile target `mailbox-signer-tests` for actual Linux custody, UID, socket,
signature and restart checks. Windows skips that lane explicitly; source parsing
or fabricated signature bytes cannot replace it. Deployment and full private
issuance/node/client qualification remain separate S05 gates.

The bounded PMES/v1 request can carry at most **65,824 signing bytes**. That
matches the largest canonical current MGR1 input: encoded record65,863 minus
the72-byte signature field plus the33-byte SIGINPUT prefix. Empty and larger
inputs reject before opening a socket. This replaces the insufficient64-KiB
transport ceiling without changing PMES framing, its original deadline, exact
64-byte response/EOF rule or role signature verification. The transport alone
never authorizes a record. Actual MGR1 authoring, protected issuer lineage,
distribution and renewal are still required; this bound does not implement them.

## Current revocation issuer journal

The source-cutover `MailboxRevocationJournal` implements the durable issuer
part of [DR-0083](../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md).
With `DeepIdV2MailboxGrantAuthority:Enabled`, the existing composition now
registers an MGR1 renewal worker using the same actual service-observer
proof/network/time context and existing role custody as private grant issuance.
The default remains disabled. The same explicit activation also maps the
read-only signed node-control route defined by
[CONTACT-RESOLVER §3.8](../../docs/architecture/CONTACT-RESOLVER-V1.md#38-current-mailbox-grant-revocation).
There are no additional configuration options. This route is not the private
grant endpoint or a direct client contact/message fallback.

The explicit operator [journal DDL](sql/mailbox-revocation-journal.sql) belongs
in the independently protected restore-authority PostgreSQL database, not an
ordinary service snapshot. Provision one scope root for each actual current
network/PMA2/role/issuer tuple, with an explicit retention capacity and empty
initial counters/serial ledger. Node ID is not part of this global issuer scope.
Normal runtime must not execute DDL, provision a missing root, rewrite an
immutable signing input, prune rows or reset counters. Grant runtime SELECT,
snapshot INSERT, snapshot `exact_snapshot` UPDATE, and scope counter/serial
UPDATE privileges only; retain provisioning and repair privileges separately.

Before calling external custody, the provider commits the exact canonical
signing input and cumulative revocations. A signer failure or uncertain winner
commit leaves that input recoverable. Retry reopens the same reservation,
checks it against its actual signed predecessor, and uses the same input;
newly accepted revocations enter the permanent ledger and the following
generation rather than changing the pending input. Cross-process writers lock
the scope while signing and committing the winner. Success requires an actual
database read-back of the exact winner with Protocol signature/scope checks,
not a signer response or a process cache.

A call completes exactly one generation. An expired completion is retained
history, not current admission evidence: a fresh successor is still required.
Retained history is read one signed record at a time; unsigned pending input
is never distributed as authority. The consumer must independently validate
each successor against its protected floor before admitting an operation.

On recovery preserve the scope root, permanent cumulative ledger, all pending
inputs and all signed history together in independent custody. Missing history,
invalid signatures, changed inputs, lost revocations or exhausted capacity fail
closed without silently regenerating authority. Restoring root and history
together to an older database image is not detected by this provider alone;
independent restore protection remains an operator prerequisite. Signer and
node floor custody must also be retained, using the existing role keys.

Provider and connected worker tests use the isolated DevOps PostgreSQL wrapper
and the same signed DID2/network/PMA2 ceremony as node tests. They do not prove
external production signer custody, PostgreSQL process-crash recovery, deployed
node refresh or physical Windows/Android delivery.

## Hosted renewal and observational readiness

On startup the worker acquires an actual current observer proof and the complete
signed network/PMA2 context. Internal proof requests use the directory **leaf**
key, not the ADL1 lookup key: these are different domain-separated hashes.
Unadmitted observers remain unavailable. Source bytes, independent directory
floor, protected monotonic time and host capability are checked again around
external signing and before release; a retained context is not a cached trust flag.

Both roles must have explicit protected journal roots before activation.
The worker completes an existing exact reservation first, then, if necessary,
authors one fresh cumulative successor: at most two steps per role per refresh.
Fresh unchanged state does not consume a new MGR1 generation or signature.
Changed authority during signing leaves the exact intent recoverable but cannot
release a winner. Missing roots, invalid history or exhausted capacity do not
trigger automatic provisioning, pruning, regeneration or repair.

Refresh is single-flight and shares the existing distribution admission gate
with issuance. Its independent flight owner covers proof acquisition and reads;
the journal owner is taken only after work requiring a reservation/signature is
observed, with a second actual state read before mutation. Once taken it covers
both roles and at most two steps per role through final pair verification.
Unchanged reads do not lock out readiness, which still independently rechecks
actual sources/winners; expired, pending or changed state never becomes a success
through concurrent access. Each attempt has the original 30-second deadline. Successful
attempts are followed by 15–17 seconds of delay; failures use bounded 10–62-second
backoff with jitter. This requires at most 240 observer proof attempts per hour
per Registry process, in addition to foreground traffic. Those proofs consume
the existing durable one-use ledger, whose configured capacity and epoch
compaction budget must cover the combined load. This bound is not a sustained
production-load measurement. Renewals use a 60-second lead; a policy with no
remaining renewal margin requires its authorized successor, never an online
root key or extended signed lifetime.

When this candidate is enabled, `/health/did2/ready` also reads both actual
signed database winners and rechecks their current sources/time. It does not
acquire a proof, sign, advance a generation or enroll a native node floor.
Readiness may wait for the existing renewal owner within its original five-second
whole-request deadline, without acquiring a proof or starting renewal. It checks
actual current signed winners after obtaining that owner; cancellation/deadline
rejects, never a cached successful-shaped default. Control-distribution reads
retain their immediate contention rejection. Cold, pending, corrupt, expired,
stopped or still-busy-at-deadline authority returns unavailable;
liveness does not imply admission. Stop clears the current observation, and a
restart reacquires current sources without replacing identities or history.

The authority owns one fixed-config `NpgsqlDataSource` for its lifetime; short
policy/role-bound journals borrow it without disposing its pool. Standalone
operator/test journals retain their own datasource ownership. This reuses only
connections, never authority, signed winners or currentness checks. Every actual
SQL transaction, immutable reservation, signature and read-back fence remains.
TLS/connection/deadline configuration is unchanged; datasource disposal belongs
to the service owner. This follows the
[Npgsql datasource/pooling lifecycle](https://www.npgsql.org/doc/basic-usage.html#data-source).

The internal retained reader releases one verified signed historical generation
at a time under a current complete host. Expired history is allowed for
sequential floor catch-up, not admission; unsigned intents are never responses.
The enabled composition exposes the bounded read-only control route under that
same current context. Numeric reads return one signed retained generation;
`latest` returns the highest committed signed winner, possibly expired while
renewal is pending, never an unsigned intent. Consumers still independently
verify current host, role signatures, freshness and native sequential floors.
No query creates a proof/nonce, signs, provisions or repairs state. Missing scope,
history or current context is unavailable, not authoritative absence; contention
does not queue. The existing eight-chain NCP2 distributor is unchanged and must
not be treated as an MGR1 source. Connected tests cover worker start/stop, exact cold retry, expired
completion followed by renewal, source-change interruption, cumulative history,
corruption rejection and HTTP readiness without nonce/signature consumption.

The local HTTP fixture uses TestServer, which omits raw request-target metadata;
its test-only middleware supplies that metadata for ordinary canonical requests.
It does not qualify actual HTTPS socket ingress, escaped-target handling or
configured issuer-to-node-to-client delivery. Those remain acceptance gates.

## Focused regression lane

The existing pinned Registry Dockerfile provides the optional
`mailbox-signer-tests` target:

```text
docker build --target mailbox-signer-tests --build-context deep_protocol=../deep-protocol -t deep-registry-mailbox-signer-tests:local .
```

It runs the actual adapter against real Linux Unix sockets with synthetic
public frame bytes. It mounts no production state or key and publishes no
service ports. The default Registry image and complete test assembly remain
unchanged. Windows explicitly skips these Linux-only tests; use the Linux
target for evidence, never count those skips as passing.

The Registry Dockerfile lane proves adapter response framing/cancellation only.
The separate DevOps `docker/deep-dev.Dockerfile` target with the same name also
runs the actual role process custody/signature tests described above. Neither
lane proves configured full private grant issuance, authenticated network
transport, current public readiness or Windows/Android message delivery.
See the [role-signer checkpoint](testing/s05-protected-role-signer-2026-10-14.md)
for exact platform receipts and remaining activation scope.
