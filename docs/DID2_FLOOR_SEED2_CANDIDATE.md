# DID2 latest-head floor: seed2 candidate (not deployed)

Read-only inventory on 2026-09-24 found the Registry and seed2 on separate
hosts. Seed2 runs
the existing XNode, storage service and ingress, with no PostgreSQL listener.
At the observation point it had approximately 14 GiB disk and 1.3 GiB RAM
available. These observations do not establish backup independence or
production capacity under sustained load.

Private TLS material and separate operator/runtime role passwords were
generated locally under
`C:\Work\DeepSession\secrets\prod\authority\private\did2-floor\seed2`.
The internal CA private key stays offline; only its certificate, the server
certificate/key and the necessary role credentials may be copied to seed2.
The signed server certificate has a DNS SAN and fingerprint recorded only in
the private production inventory.
The generator refuses to overwrite keys and refuses a parent directory
granting access beyond the operator, SYSTEM and Administrators.

Before this candidate can become a production rollback floor:

1. Refresh the seed2 and Registry backups and record immutable hashes and
   exact recovery paths. Do not alter the registered XNode identity keys.
2. Deploy a resource-limited PostgreSQL instance without altering the
   existing XNode/ingress compose stack. Restrict inbound connections to the
   Registry host at both firewall and `pg_hba.conf`; require TLS and SCRAM.
3. Pin the private CA in the Registry runtime, use `SSL Mode=VerifyFull`, and
   grant the runtime role only `SELECT`/`UPDATE` on
   `deep_did2_latest_head_floor`. Keep schema/provisioning credentials out of
   the running Registry container.
4. Create the schema, provision the signed empty V2 head exactly once, and
   verify that the external row equals the independently pinned ADA2 head.
5. Demonstrate floor outage rejection, restored-old-ADA2 rejection, and a
   recovery drill using seed2 backups independent of Registry snapshots.
   Never reset the floor to an older head.
6. Only after those checks and client verification may the explicit
   `ProductionCutoverAttested` switch be considered. It remains `false` now.

This is not a deployment record or production approval. No floor container,
firewall rule, database, or Registry configuration was changed during this
inventory and local TLS-material preparation.
