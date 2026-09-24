# DID2 latest-head floor: seed2 candidate

Status on 2026-09-24: the isolated PostgreSQL service is deployed and healthy,
with the exact-source firewall active before Docker starts. Registry has not
been cut over. The floor has the exact signed genesis row. A consistent dump
was copied to private local backup and restored byte-for-byte in an isolated
temporary container; global roles were backed up but not replayed. The
outage/old-ADA2 drill and physical client gate remain open.

Read-only inventory on 2026-09-24 found the Registry and seed2 on separate
hosts. Seed2 runs
the existing XNode, storage service and ingress, with no PostgreSQL listener.
At the observation point it had approximately 14 GiB disk and 1.3 GiB RAM
available. These observations do not establish backup independence or
production capacity under sustained load.

Private TLS material and separate operator/runtime role passwords were
generated locally under the protected production authority directory. The
deployed server certificate has an exact private IP SAN; neither origin
addresses nor certificate identifiers are published here. The internal CA
private key stays offline. PostgreSQL/libpq rejected the initial Ed25519 TLS
certificate during SCRAM channel binding, so the transport-only private CA
and server certificate were reissued with RSA-3072/SHA-256. This does not
change DID2 account or directory signing algorithms.
The generator refuses to overwrite keys and refuses a parent directory
granting access beyond the operator, SYSTEM and Administrators.

The candidate has completed backup, container isolation, single-source
firewall, TLS `verify-full`, non-TLS rejection, schema, signed genesis row,
exact-byte match and role-grant checks.
Before it can become an active production rollback floor:

1. Re-check the protected ADA2 state against the floor using only the runtime
   role in a production startup preflight; keep the provisioning role out of
   the running Registry container.
2. Demonstrate floor outage rejection, restored-old-ADA2 rejection, and a
   complete recovery drill including global roles. Use seed2 backups
   independent of Registry snapshots.
   Never reset the floor to an older head.
3. Only after those checks and client verification may the explicit
   `ProductionCutoverAttested` switch be considered. It remains `false` now.

The floor deployment is not Registry cutover or release approval. Existing
XNode, ingress, and Registry application containers were not replaced during
floor preparation.
