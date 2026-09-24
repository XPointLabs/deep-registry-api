`did2-genesis.dga1v2` is a public, test-only DID2 genesis-admission request.
It was authored with the protocol test mnemonic and deterministic account/device
fixtures in `deep-protocol/tests/Deep.Protocol.Tests/Identity`, using network
`11` repeated 16 times and epoch `1700000000`. The ML-DSA signature is
randomized, so the exact request is pinned by SHA-256 in the Registry test,
while the protocol test independently reauthors and verifies the same shape.
The wire request contains public account, device, identity, directory and
signature artifacts, not a recovery phrase, private key or raw resolver read
capability. The DID2 credential carries only its DR-0007 hash commitment.
Re-author this randomized fixture by running the targeted protocol test
`RealDid2AlternateNetworkEpochClosesThroughAdmissionWire` with
`DEEP_DID2_GENESIS_FIXTURE_OUTPUT` set to this fixture's absolute path, then
repin the SHA-256 assertion in the Registry test.
