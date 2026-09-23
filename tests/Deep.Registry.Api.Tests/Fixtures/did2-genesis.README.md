`did2-genesis.dga1v2` is a public, test-only DID2 genesis-admission request.
It was authored with the protocol test mnemonic and deterministic account/device
fixtures in `deep-protocol/tests/Deep.Protocol.Tests/Identity`, using network
`11` repeated 16 times and epoch `1700000000`. The ML-DSA signature is
randomized, so the exact request is pinned by SHA-256 in the Registry test,
while the protocol test independently reauthors and verifies the same shape.
The wire request contains public account, device, identity, directory and
signature artifacts, not a recovery phrase or private key.
