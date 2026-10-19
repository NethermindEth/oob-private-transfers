# SimplePIR implementation and security notes

The adapter uses the pinned upstream code in `integration/simplepir/upstream/pir/`.
The only vendored modification removes `-march=native` from cgo flags.

## (a) How `A` is generated; seeded state

- `SimplePIR.Init` (simple_pir.go:99-102): `A := MatrixRand(p.M, p.N, p.Logq, 0)` — an `m × n` matrix, uniform mod
  2^32. `MatrixRand` (matrix.go:38-48) draws each entry with `RandInt(2^32)` (rand.go:42-47), which reads the
  **package-global** `bufPrgReader` (rand.go:37) under a mutex.
- The global PRG is AES-CTR with a zero IV (rand.go:71-85), keyed at package init from `crypto/rand`
  (rand.go:87-95, 155-157), wrapped in a `bufio.Reader` of 8,192 B (rand.go:39, 112-117). Quirk: `PRGReader.Read`
  does `XORKeyStream(p, p)` (rand.go:107), and bufio reuses its buffer, so each 8 KiB output block is the keystream
  XORed into the previous block (a fixed invertible transform of the keystream; still pseudorandom). Go 1.27's
  `crypto/rand.Int` still reads from the supplied reader (checked in `$GOROOT/src/crypto/rand/util.go`); for
  max = 2^32 it consumes exactly 4 bytes big-endian and never rejects.
- Compressed/seeded state: `InitCompressed` (simple_pir.go:104-107) draws a random 16-byte `PRGKey` (rand.go:34);
  `InitCompressedSeeded(info, p, seed)` (109-112) **sets the global** `bufPrgReader = NewBufPRG(NewPRG(seed))` and
  calls `Init`; `DecompressState(info, p, comp)` (114-117) does the same on the client. `RunPIRCompressed`
  (pir.go:174-247) uses them within one process. So upstream *does* support deriving `A` from a public seed on both
  sides, with the seed as a 16-byte AES key.
- **Hazard (critical for a real client)**: after `DecompressState`, the global PRG stays keyed by the public seed.
  `Query` (simple_pir.go:145-160) then draws the secret `s = MatrixRand(n,1,logq,0)` (148) and the error
  `e = MatrixGaussian(m,1)` (149; gauss.go:28-47 via `MathRand()` on the same global, rand.go:49-51) from that
  continued stream. Everything is deterministic given the seed, so the server can replay `s, e` and read
  `q − A·s − e = Δ·u_i`. (Upstream's tests
  are unaffected because they run client and server in one process and do not model this adversary.)
- **What we do** (`oobpir/codec.go: ExpandA`): the same expansion (AES-128-CTR, zero IV, 8 KiB XOR-refilled buffer,
  big-endian uint32, row-major `m × n`) as a pure function with its own cipher state; server and client both call
  it on `seed_A[0:16]`. The client's `s, e` come from the global PRG, which in our processes is only ever keyed from
  `crypto/rand` at start-up (we never call `InitCompressedSeeded`/`DecompressState`). `TestQueriesUseFreshSecrets` checks two queries differ.
- Can the provider choose `A`? Not if the client derives `seed_A = SHA-256("OOB-A" ‖ sid ‖ e)` itself and passes it
  to `load` (`"seed_A"`; `load` then rejects a public.json with a different seed). Grinding `sid`/`e` does not give
  a useful choice of `A` if AES-CTR under a public key is modeled as a random function (the standard heuristic for
  seeded LWE matrices, as in upstream's compressed mode; with a *public* key this is not a standard-model PRG
  statement). With provider-chosen `A` (upstream `Init`, the old adapter) a malicious provider could embed a trapdoor
  in `A` and break the query's LWE hiding.

## (b) The hint and its size

- `Setup` (simple_pir.go:119-130): `H = MatrixMul(DB.Data, A)` over the whole `l × m` DB (entries mapped to
  `[-p/2, p/2]` as in `MakeDB`, database.go:211), then the DB is shifted to `[0,p)` and "squished" (3 entries of 10
  bits per uint32, database.go:30-46) for the online phase. The hint message is `H` alone.
- Size: `l · n · log q` bits (`GetBW`, simple_pir.go:88-97) = `4·l·1024` B; our `hint.bin` adds a 24-B header
  (magic, rows, cols). `l = g · N_e` where `g` = number of row groups and `N_e` = Z_p digits per 736-B record
  (600 for p=991, 640 for p=589, 681 for p=416, 630 for p=701). Minimum hint for any N: `N_e·1024·4` ≈ 2.46 MB.
- No seed shortcut is valid for `H`: it depends on every DB entry. Upstream's `FakeSetup` (132-143) returns only the
  *size* of the hint without computing it; upstream's `RunFakePIR` (pir.go:41-96) counts that size as offline
  download. Counting it is right; skipping its computation erases setup cost (and correctness). We compute it.
- What *is* seedable: `A` only (`m·1024·4` B; e.g. 16.8 MB at m=4,096, 268 MB at m=65,536, 1.07 GB at m=2^18).
  We count 32 B (inside public.json) and report the `A` bytes as "if downloaded" only. Client and server both pay
  the regeneration time (reported as `regen_A_seconds` / `a_expand_seconds`).

## (c) Benchmark paths

- Upstream `BenchmarkSimplePirSingle` (pir_test.go:379-414), `BenchmarkSimplePirVaryingDB` (453-505),
  `BenchmarkSimplePirBatchLarge` (560-…) and `experiments.sh`: `MakeRandomDB` (database.go:168-176) + `RunFakePIR`
  → `FakeSetup` (no hint computed), one query, **no `Recover`, no correctness check**; throughput only.
- Upstream `RunPIR` (pir.go:99-171) / `RunPIRCompressed` (174-247), used by `TestSimplePir*`: full `Setup`, query,
  answer, `Recover`, and `panic` on mismatch against `DB.GetElem` (159-163, 235-239) — a correct end-to-end path,
  but for entries ≤ 64 bits (`MakeDB` takes `[]uint64`, database.go:178-214; `Reconstruct_from_base_p` is uint64,
  utils.go:77-85), so it cannot represent a 736-B record directly.
- **Our path** (`oob-pir bench`, `core/simplepir/bench.go`): records = uniform random bytes (AES-256-CTR under a
  recorded `db_seed`; representative of ciphertext records; bulk-loaded without admission — disclosed), full
  upstream `Setup` over the real DB, hint/public written to disk and loaded by the client code path (which
  recomputes all parameters and regenerates `A`), every read's record compared byte-for-byte to the DB; failures
  counted, never dropped. The JSON-lines `setup`/`answer`/`load`/`query`/`recover` ops use the same functions.

## (d) Parameters for 736-B records

- LWE: n = 1024, log q = 32 (fixed; `oobpir.LWEDim`, `oobpir.LogQ`), σ = 6.4 and p from upstream's
  `params.csv` via upstream's own `Params.PickParams(false, m)` (params.go:37-80) with m = number of DB columns =
  number of LWE samples in a query: p = 991 (m ≤ 2^13), 833 (2^14), 701 (2^15), 589 (2^16), 495 (2^17),
  416 (2^18), 350 (2^19), 294 (2^20), 247 (2^21). Squishing requires p ≤ 2^10 (database.go:43) — always true.
- Claimed security: the upstream authors (SimplePIR paper, Henzinger et al., USENIX Security 2023) chose this table
  for 128-bit security with the lattice estimator and state a per-element correctness error target; we did not
  re-run the estimator. Per record we decode N_e ≈ 600–755 elements, so the per-read correctness failure is at most
  N_e times the per-element bound (union bound). Round-trip tests check decoded records byte-for-byte.
- Record encoding (`oobpir/codec.go`): the 5,888-bit record is cut into chunks of G bits and each chunk is written
  as k base-p digits, choosing k to minimize N_e (p=991: k=6, G=59, 100 chunks, N_e=600, vs. the information bound
  ⌈5888/log₂991⌉ = 592). This replaces upstream's uint64-only base-p decomposition (utils.go:95-111) for wide
  entries; decoding rejects out-of-range chunks (`ErrDecode`).
- Layout: record i occupies column i mod m and rows (i div m)·N_e … +N_e (upstream's vertical stacking of an
  entry's digits). Two layouts: **default** = upstream `ApproxSquareDatabaseDims` (database.go:95-107) with our N_e,
  and upstream's `PickParams` loop (simple_pir.go:14-44: largest p whose sample bound admits m); **best** = the
  column count minimizing client bytes `hint + q + a` (`oobpir.BestLayout`, m ≤ 2^18 so that `A` ≤ 1 GiB; for all
  N ≤ 2^18 this is one row group, m = N). The client recomputes the layout from (count, width, cols_override) and
  rejects any other parameters in public.json.
- Decode detail: we reduce `ans − H·s + offset` mod 2^32 before rounding (upstream adds in uint64 without
  reducing, simple_pir.go:206, which shifts values ≥ 2^32 by 2^32 mod Δ ≤ 582 units — negligible either way).
- Upstream edge case: `matMulVecPacked` processes 8 rows per step and reads up to 7 rows past the end of the DB
  when l mod 8 ≠ 0 (pir.c:110-195; the output has 8 spare rows, matrix.go:212-219, but the *input* does not). Our
  layouts hit this (e.g. l = 25,830 at 2^20 default), so after `Setup` we copy the packed DB into a buffer with 8
  spare zero rows of capacity (`padCap`). No change to the algorithm or results.

## (e) Malicious-server considerations

- Query privacy: the query `q = A·s + e + Δ·u_col` depends only on the public `A` (seed-derived), fresh `s`, `e`
  and the column; the server sends nothing that influences it except public.json, whose parameters the client
  recomputes (n, log q, p, σ, l, m, N_e are forced; a smaller n or other p is rejected), and the seed, which the
  client should derive itself. The row group of the record is never sent: the answer is the whole column (l values).
  Server answer time is a full DB scan, independent of the index.
- Integrity: none in SimplePIR. A wrong hint row or wrong answer entry for the target's rows changes the decoded
  digits: random garbage almost always violates the chunk range check (`ErrDecode`; each 59-bit chunk accepts
  2^59 of 991^6 ≈ 1.64·2^59 digit vectors); a structured perturbation (e.g. `+Δ·δ` on one entry, or answering with
  a modified DB) yields a well-formed but wrong record. The only reliable check is the record digest
  `d_rec = SHA-256("OOB-rec-v1" ‖ rec)` from the signed receipt/notification (`recover` returns `digest` and, with
  `expect_digest`, `digest_ok`); after that, the ciphertext's authentication tag and the note/chain check. Tests:
  `TestTamperedHintOrAnswerFails` (bit-flip → wrong record, random answer → `ErrDecode`, hint-row tamper → wrong
  record), `roundtrip.py` (tampered answer across processes).
- Selective failure (remaining leakage): the server can make the outcome depend on the index — e.g. answer with a
  DB modified only at a chosen set S of (column, group) positions, or serve a hint with corrupted rows for chosen
  groups (persistent for every read of that epoch with the cached hint). The client's observable reaction
  (switching provider, re-querying) then reveals whether index ∈ S: up to one adversarially chosen bit per failed
  read, and colluding providers can link the failed read at A with the next read at B. Digests/authentication only
  turn such tampering into a detected failure; they do not hide the failure. Mitigations not implemented:
  verifiable/authenticated PIR, never retrying an epoch after a failure, or falling back to whole-epoch download
  (which the automatic read policy uses for small epochs anyway).
- Other: the client's Gaussian sampler (gauss.go) and the H·s product are not constant-time (local timing only);
  the query state is single-use (`recover` consumes it; malformed answers leave it for a retry of the *same* query,
  which reveals nothing new).

