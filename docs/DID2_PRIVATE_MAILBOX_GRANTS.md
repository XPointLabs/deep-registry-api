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

This lane proves response framing/cancellation only. It does not prove actual
external role custody, full private grant issuance, authenticated network
transport, current public readiness or Windows/Android message delivery.
