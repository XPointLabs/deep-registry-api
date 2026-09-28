# Public network closure distribution candidate

The source-cutover build can expose the public raw-closure distribution endpoint
consumed by Shared's `HttpDeepIdV2NetworkClosureArtifactSource`. It is off by
default. This is not an account resolver, proof issuer or route-selection service.
Exact envelope ownership and acquisition/privacy restrictions are in
[`XPOINT-NETWORK-V1 section 8.1`](../../docs/architecture/XPOINT-NETWORK-V1.md#81-identity-neutral-network-closure-distribution-ncq2ncp2).

Operator configuration:

- `XPointNetworkClosureDistribution:Enabled=true`;
- `XPointNetworkClosureDistribution:NetworkIdHex`: exact public network scope;
- `XPointNetworkClosureDistribution:BundlePath`: absolute path to an existing
  operator-prepared public Protocol-encoded NCP2 bundle. Mount it read-only,
  outside the web root and all private custody directories. Do not configure a
  key/state file as this input. Links and linked parent directories are rejected.

Only the current Protocol source-cutover supports enabling the feature. An older
package build refuses enablement; it does not reinterpret an old proof package.
The route is `POST /api/v2/network/closure` over HTTPS. The configured known-proxy
forwarded-scheme policy applies; untrusted forwarded headers do not grant HTTPS.
There is no cleartext physical/UAT exception. Send the exact media type and
length emitted by the Protocol request codec, with no query/path parameters.

Publish a complete public bundle by atomic file replacement, never in-place
partial writes. A request holds one read-only file snapshot and returns its exact
bytes only after bounded envelope/scope validation. Unknown networks return 404;
unavailable/malformed bundles return 503; concurrent requests return 429 without
queueing. Responses are no-store. No signing keys, directory database, account
identifiers, read capabilities or per-client route cache are consumed. The
endpoint does not certify signatures or freshness: the client must verify the
pinned authority, complete signed history, protected floor and independent fresh
DID2 proof before authorizing publication. HTTP/TestServer checks alone are not
TLS, device messaging or release evidence.
