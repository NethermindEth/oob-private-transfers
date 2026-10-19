# An Out-of-Band Private Data Plane for Shielded Transfers

Out-of-band private data delivery for shielded transfers, with private retrieval and recoverable storage. The architecture uses proof-carrying append, private information retrieval (PIR) and erasure-coding based commitment. This repo provides a research prototype of the design.

Providers admit 736-byte encrypted records using Halo2 proofs; recipients retrieve records using SimplePIR.
Closed epochs are erasure-coded and distributed to holders under KZG commitments.

## Requirements

Python 3.14, Node.js 22 with npm, Rust with Cargo, Go 1.22 or later with a C compiler,
and Foundry's `anvil` executable. The measurement scripts using `/usr/bin/time -l`
and `sysctl` target macOS. Install these tools before building; `go` and `anvil` should be on `PATH`.
Python and Node dependencies and the Rust dependency tree are pinned in their manifests/lockfiles.

## Build

Run from the repository root:

```sh
python3 -m venv .venv
.venv/bin/pip install -r core/requirements.txt
npm ci --prefix integration
ln -s ../../integration/node_modules core/contracts/node_modules
(cd core/contracts && node build.mjs)
(cd core/halo2 && cargo build --release --locked)
(cd core/simplepir && go build -o oob-pir .)
(cd core/simplepir && go build -o ../experiments/S7E4/s7e4bench ./cmd/s7e4bench)
export PYTHONPATH="$PWD"
```

The `node_modules` link is needed only once. Contract compilation also creates a local
Groth16 test setup, which can take several minutes. It is not a production ceremony.

## Verify

```sh
.venv/bin/python -m pytest -q core/tests/test_recovery_units.py core/tests/test_protocol_v2_units.py
(cd core/simplepir && go test ./...)
.venv/bin/python core/simplepir/roundtrip.py 1000 30
(cd core/halo2 && cargo test --release --locked --test native_vectors --test gadget_soundness)
.venv/bin/python core/experiments/E4/worker_roundtrip.py --depth 32
.venv/bin/python -m core.tests.run_e4svc
```

The service suite starts real Anvil, provider, holder, prover, and PIR processes and exercises both
`fragment_kzg` and `whole_epoch`. For the more expensive proof-adversarial suite:

```sh
(cd core/halo2 && cargo test --release --locked --test adversarial -- --test-threads 1)
```

## Layout and configuration

| Path | Contents |
|---|---|
| `core/oobsvc/` | Services, clients, certification, erasure coding, recovery, and testbed |
| `core/contracts/` | Solidity contracts, spend circuit, build and chain workers |
| `core/halo2/` | Admission proof worker, benchmarks, and tests |
| `core/simplepir/` | SimplePIR worker and tests |
| `core/kzg/` | Pinned trusted setup and provenance |
| `core/experiments/` | Experiment drivers and table generators |
| `core/tests/` | Protocol and service regression tests |
| `integration/` | Pinned Node dependencies and vendored SimplePIR |

Runtime state defaults to `testbed/`, parameter caches to `.cache/halo2-keys/`, and
new measurements to `core/results/`. Override these first two paths with `OOB_TESTBED`
and `OOB_HALO_KEYS`; use `OOB_ANVIL` to select an Anvil executable.
`scripts/benchlock COMMAND ...` serializes measurements within this checkout.
Historical run logs are not included in the source distribution. Timestamps and machine metadata
in newly generated results provide run provenance.

See [core/README.md](core/README.md) for protocol details and experiment entry points.
All services run on one host over loopback. Synthetic background records bypass admission and must
not be counted as verified ingestion. See the component security notes for remaining limitations.
Third-party attribution and license files are included with their components.
