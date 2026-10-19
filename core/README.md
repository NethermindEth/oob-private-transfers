# Protocol implementation

Each provider has its own account identity (`sid = SHA-256(public key)`) and one Ed25519 signing key.
The provider's account registers its directory entry and anchors consecutive epochs. There is no separate
governance account or operator-key rotation.

Holder assignments specify distinct identities and thresholds `1 <= k <= q <= n <= 255`.
A certificate requires `q` valid acknowledgements. Manifests bind the assignment, thresholds,
holder identities, epoch, and seal mode. Holders retain fragments indefinitely.

- `fragment_kzg` (default): each holder receives its fragment and verifies it against the KZG
  erasure-code commitment. Coding uses the BLS12-381 scalar field with systematic evaluation points.
  Slot openings use EIP-7594 cells; an opening can expose adjacent ciphertext scalars in the same cell.
- `whole_epoch`: each holder receives the full epoch and checks the zfec RS encoding over GF(256).

Any node can reconstruct a certified epoch from sufficient valid fragments, including a node that
initially holds no fragment. A replacement provider registers a new identity that continues the old one,
restores all certified non-void epochs at the same epoch/slot coordinates, and then enables new appends.
It signs new receipts with its own key. Holder endpoints can be updated independently of assignments;
readers can obtain metadata from holders when chain event logs are unavailable.

## Components

`provider.py` implements transactional appends, per-tag conflict detection, PIR preprocessing, sealing,
and anchoring. `holder.py` verifies and stores fragments and metadata. `client.py` handles admission,
retrieval, ciphertext validation, and release checks. `certify.py` checks certificates off chain;
`recovery.py` reconstructs epochs. `deploy.py` starts an isolated local testbed.

The pool uses a depth-32 Poseidon tree and a fixed 0.01 ETH denomination. The spend circuit uses a
locally generated Groth16 test setup. Admission uses the separate Halo2 IPA worker. The KZG recovery
setup is the pinned Ethereum ceremony file documented in `kzg/SOURCE.md`.

## Experiments

Build and test using the [root instructions](../README.md), activate `.venv`, and set `PYTHONPATH` to
the repository root. Run measurements sequentially on an otherwise idle host:

```sh
scripts/benchlock .venv/bin/python -m core.experiments.S7E1.run_s7e1 --help
scripts/benchlock .venv/bin/python -m core.experiments.S7E2.run_s7e2 --help
scripts/benchlock .venv/bin/python -m core.experiments.S7E3.run_s7e3 --help
.venv/bin/python core/experiments/S7E4/run_perepoch.py --help
scripts/benchlock .venv/bin/python -m core.experiments.S7E6.run_s7e6 --help
```

These cover holder configurations, admission cost, retrieval/certification latency, PIR cost, and
provider replacement. The `E1`–`E7` drivers provide component experiments and baselines;
`bash core/experiments/run_all.sh` runs the component series and generates tables.
Drivers create result directories as needed. Load gates and contamination flags are measurement
controls, not correctness checks. Table generators require completed input runs.

## Experimental scope

All processes share one host and fault domain, and all network traffic uses loopback. Devnet finality
means one successor block. Notifications use signed local files. Provider endpoints are read from the registry, with notification
URLs as a fallback; replacement identity mappings are supplied by the deployment configuration. Synthetic background records bypass admission and are labeled separately.
Direct-delivery/backup and arrival-rate comparisons that use models are labeled as modeled.
Implementation tests do not establish cryptographic security or distributed availability.

The optional compact-scanning comparison requires an external compact-block dataset via
`E5base/run_e5base.py --compact-data FILE --normal-outputs-day RATE`. Without it, the driver
runs direct delivery and explicitly marks the compact comparison as not run. The epoch-size model
accepts an explicit arrival-rate assumption through `E5pir/epoch_model.py RUN_DIR --rate RATE`.
