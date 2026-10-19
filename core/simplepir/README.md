# core/simplepir — `oob-pir`

JSON-lines worker around the pinned upstream SimplePIR (github.com/ahenzinger/simplepir @ e9020b03, MIT, used
from `integration/simplepir/upstream`; cgo flag change documented in `integration/simplepir/UPSTREAM.md`) for OOB's fixed-width **736-byte** records
(`ν_adm ‖ C`). One binary, two roles: the provider runs `setup`/`answer`; the recipient runs
`load`/`query`/`recover` in a **separate process**. Implementation and security notes: [AUDIT.md](AUDIT.md).

## Build and test

```sh
cd core/simplepir
go build -o oob-pir .          # binary: core/simplepir/oob-pir (not committed)
go test ./...                   # oobpir: encoding, seeded A, round trips, rejection, tampering
python3 roundtrip.py 1000 30    # two processes (server, client) over the JSON interface
```

## Interface (one JSON object per line on stdin → `{"result":…}` or `{"error":…}` on stdout)

Server:
- `{"op":"setup","records_file":P,"count":N,"width":736,"seed_A":HEX32,"out_dir":D,"epoch_id":"E"[,"layout":"best"|"default"][,"cols":C]}`
  → runs full upstream preprocessing (DB matrix from the real records, `A` from `seed_A`, `SimplePIR.Setup`
  computing `H = DB·A`), writes `D/hint.bin` and `D/public.json`, keeps the DB for `answer` (keyed by `epoch_id`).
  Returns `hint_bytes, public_bytes, setup_seconds, read_records_seconds, preprocessing{encode, a_expand, hint,
  write seconds; packed/unpacked DB bytes; layout; hint_sha256}, max_rss_bytes`.
- `{"op":"answer","epoch_id":"E","query":B64}` → `{answer:B64, answer_seconds, answer_bytes, query_bytes}`;
  malformed queries (wrong magic/length) are rejected.
- `{"op":"drop","epoch_id":"E"}`, `{"op":"info"}`, `{"op":"layout","count":N[,"layout":"best"]}` (exact sizes, no
  build), `{"op":"crossover"[,"max_count":M]}` (formula-derived crossover vs whole-epoch download).

Client:
- `{"op":"load","public_json":P,"hint_file":H[,"seed_A":HEX32]}` → validates public.json (recomputes the layout and
  all LWE parameters from `(count, width, cols_override)`; rejects anything else), checks hint dimensions and
  SHA-256, regenerates `A` from the seed. Pass the client-derived `seed_A = SHA-256("OOB-A"‖sid‖e)` so that a
  provider-chosen seed is rejected. Returns `client_setup_seconds, read_public_seconds, read_hint_seconds,
  regen_A_seconds, public_bytes, hint_bytes, seed_bytes (32), a_regenerated_bytes, layout`.
- `{"op":"query","index":j[,"epoch_id":"E"]}` → `{query:B64, state_id, query_bytes, query_seconds}` (fresh LWE
  secret and error per query from the OS-seeded PRG).
- `{"op":"recover","state_id":S,"answer":B64[,"expect_digest":HEX]}` → `{record:B64, recover_seconds, digest,
  digest_ok?}`; `digest = SHA-256("OOB-rec-v1"‖rec)`. A decode failure returns an error (`PIR decoding failure`);
  a well-formed wrong record is detected only by the digest (the higher layer must check it).

Benchmark: `{"op":"bench","count":N,"reads":R,"out_dir":D[,"layout":"best"]}` — same code paths, full
preprocessing, client loads the written files, every read compared byte-for-byte with the DB; records are uniform
random bytes (AES-256-CTR under a recorded `db_seed`), bulk-loaded without admission.

Wire formats (little-endian): `hint.bin` = `"OOBPIRH1" | u64 rows | u64 cols | rows·cols u32`;
query = `"OQv1" | u32 len | len u32`; answer = `"OAv1" | u32 len | len u32`. All byte counts include headers.

## What is and is not seeded

| object | size | how the client gets it |
|---|---|---|
| `A` (m × 1024, uint32) | 4·m·1024 B | **regenerated** from `seed_A` (AES-128-CTR, key = `seed_A[0:16]`, upstream's compressed-state expansion, bit-identical to `DecompressState`); 0 B downloaded |
| seed_A + parameters | public.json ≈ 1.2–1.3 kB | downloaded (counted); the seed should also be derived by the client |
| hint `H = DB·A` (l × 1024) | 4·l·1024 + 24 B (≥ 2.46 MB) | **downloaded**; depends on the whole DB; not seedable |
| query / answer | 4·⌈m/3⌉·3 + 8 B / 4·l + 8 B | per read |

Layouts: `default` = upstream's approximately square layout (`ApproxSquareDatabaseDims` + `PickParams`);
`best` = the column count minimizing `hint + query + answer` for one read (m ≤ 2^18 so `A` ≤ 1 GiB); for
N ≤ 2^18 this is a single row group (m = N, l = N_e ≈ 600–681). p, σ always come from upstream's table for the
resulting m; n = 1024 and log q = 32 are fixed.

## Measurements

`core/experiments/E5pir/run.py` generates raw measurements; `make_table.py` generates tables from
completed runs. Timed configurations run under the benchmark lock and load gate. Contaminated
runs remain in generated output and are excluded from tables.

## Privacy caveats

- Read privacy holds against the provider within one epoch (anonymity set = the epoch's m_e records, public), under
  LWE with upstream's parameters and with `A` derived from a public seed (heuristic: AES-CTR under a public key
  modeled as a random function). The provider learns `(sid, e)`, timing, network identity and sizes.
- Do not use upstream's `DecompressState`/`InitCompressedSeeded` in a client process: they rekey the global PRG
  with the public seed, making the LWE secret public (AUDIT.md §a).
- No integrity: a malicious provider can serve a wrong hint or answer. The client detects it by decode failure or
  by the record digest, but the *failure* leaks up to one adversarially chosen bit about the index per failed read
  (selective failure), and colluding providers can link the failed read with the retry elsewhere.
- The hint is per epoch (≥ 2.46 MB); for epochs below ≈3.4k records (best layout, one read) whole-epoch download is
  cheaper and hides the index equally within the epoch.
