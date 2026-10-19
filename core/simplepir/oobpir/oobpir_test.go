package oobpir

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	pir "github.com/ahenzinger/simplepir/pir"
)

func randBytes(t testing.TB, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

type epoch struct {
	recs   []byte
	srv    *Server
	cli    *Client
	outDir string
}

func setupEpoch(t testing.TB, count, cols uint64) *epoch {
	t.Helper()
	recs := randBytes(t, int(count*RecordWidth))
	seed := randBytes(t, 32)
	srv, hb, st, err := NewServer(recs, count, RecordWidth, cols, seed, "e-test")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := srv.WriteFiles(dir, hb, st); err != nil {
		t.Fatal(err)
	}
	cli, _, err := LoadClient(filepath.Join(dir, "public.json"), filepath.Join(dir, "hint.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return &epoch{recs, srv, cli, dir}
}

func (e *epoch) read(t testing.TB, i uint64) ([]byte, error) {
	sid, q, err := e.cli.Query(i)
	if err != nil {
		return nil, err
	}
	a, err := e.srv.Answer(q)
	if err != nil {
		return nil, err
	}
	return e.cli.Recover(sid, a)
}

func TestEncodingRoundTrip(t *testing.T) {
	for _, p := range []uint64{991, 833, 701, 589, 495, 416, 350, 294, 247} {
		lay := Layout{Width: RecordWidth, P: p}
		lay.DigitsPerChunk, lay.ChunkBits, lay.Chunks, lay.Ne = Encoding(p, RecordWidth*8)
		for trial := 0; trial < 20; trial++ {
			rec := randBytes(t, RecordWidth)
			if trial == 0 {
				for i := range rec {
					rec[i] = 0xff
				}
			}
			d := make([]uint32, lay.Ne)
			lay.RecordDigits(rec, d)
			got, err := lay.DigitsRecord(d)
			if err != nil || !bytes.Equal(got, rec) {
				t.Fatalf("p=%d: encoding round trip failed (%v)", p, err)
			}
		}
		t.Logf("p=%d k=%d G=%d chunks=%d Ne=%d", p, lay.DigitsPerChunk, lay.ChunkBits, lay.Chunks, lay.Ne)
	}
}

// ExpandA must equal upstream's own seeded PRG path (NewBufPRG(NewPRG(key)).RandInt(2^32)),
// which is exactly what SimplePIR.DecompressState feeds into MatrixRand.
func TestExpandAMatchesUpstreamPRG(t *testing.T) {
	seed := randBytes(t, 32)
	rows, cols := uint64(37), uint64(1024) // > 8192 bytes: exercises buffer refills
	A, err := ExpandA(seed, rows, cols)
	if err != nil {
		t.Fatal(err)
	}
	var key pir.PRGKey
	copy(key[:], seed[:16])
	prg := pir.NewBufPRG(pir.NewPRG(&key))
	mod := big.NewInt(1 << 32)
	for i, v := range u32(A) {
		if w := prg.RandInt(mod).Uint64(); uint64(v) != w {
			t.Fatalf("entry %d: %d != upstream %d", i, v, w)
		}
	}
	B, _ := ExpandA(seed, rows, cols)
	if !equalU32(u32(A), u32(B)) {
		t.Fatal("not deterministic")
	}
	seed[0] ^= 1
	C, _ := ExpandA(seed, rows, cols)
	if equalU32(u32(A), u32(C)) {
		t.Fatal("seed not used")
	}
}

func equalU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRoundTripAllIndices(t *testing.T) {
	for _, n := range []uint64{1, 2, 3, 7, 100, 257, 1000} {
		e := setupEpoch(t, n, 0)
		for i := uint64(0); i < n; i++ {
			got, err := e.read(t, i)
			if err != nil {
				t.Fatalf("N=%d i=%d: %v", n, i, err)
			}
			if !bytes.Equal(got, e.recs[i*RecordWidth:(i+1)*RecordWidth]) {
				t.Fatalf("N=%d i=%d: wrong record", n, i)
			}
		}
		l := e.cli.Layout
		t.Logf("N=%d: p=%d l=%d m=%d Ne=%d groups=%d hint=%dB q=%dB a=%dB", n, l.P, l.L, l.M, l.Ne, l.Groups,
			l.HintBytes(), l.QueryBytes(), l.AnswerBytes())
	}
}

func TestRoundTripLargerSampled(t *testing.T) {
	sizes := []uint64{4096, 5000}
	if testing.Short() {
		sizes = sizes[:1]
	}
	for _, n := range sizes {
		e := setupEpoch(t, n, 0)
		idx := []uint64{0, n - 1, n / 2, e.cli.Layout.M - 1, e.cli.Layout.M}
		for k := 0; k < 40; k++ {
			v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
			idx = append(idx, v.Uint64())
		}
		for _, i := range idx {
			if i >= n {
				continue
			}
			got, err := e.read(t, i)
			if err != nil || !bytes.Equal(got, e.recs[i*RecordWidth:(i+1)*RecordWidth]) {
				t.Fatalf("N=%d i=%d: %v", n, i, err)
			}
		}
	}
}

func TestColsOverrideLayout(t *testing.T) {
	e := setupEpoch(t, 300, 64)
	if e.cli.Layout.M != 64 || e.cli.Layout.Groups != 5 {
		t.Fatalf("layout %+v", e.cli.Layout)
	}
	for _, i := range []uint64{0, 63, 64, 299} {
		got, err := e.read(t, i)
		if err != nil || !bytes.Equal(got, e.recs[i*RecordWidth:(i+1)*RecordWidth]) {
			t.Fatalf("i=%d: %v", i, err)
		}
	}
}

func TestRejectsBadInputs(t *testing.T) {
	e := setupEpoch(t, 50, 0)
	if _, _, err := e.cli.Query(50); err == nil {
		t.Fatal("out-of-range index accepted")
	}
	sid, q, err := e.cli.Query(3)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"empty": {}, "short": q[:len(q)-4], "long": append(append([]byte{}, q...), 0, 0, 0, 0),
		"magic": append([]byte("XXXX"), q[4:]...),
	} {
		if _, err := e.srv.Answer(bad); err == nil {
			t.Fatalf("malformed query (%s) accepted", name)
		}
	}
	a, err := e.srv.Answer(q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.cli.Recover(sid, a[:len(a)-4]); err == nil {
		t.Fatal("truncated answer accepted")
	}
	if _, err := e.cli.Recover(sid, append([]byte("OQv1"), a[4:]...)); err == nil {
		t.Fatal("answer with query magic accepted")
	}
	if _, err := e.cli.Recover("nope", a); err == nil {
		t.Fatal("unknown state accepted")
	}
	got, err := e.cli.Recover(sid, a) // state survives malformed answers
	if err != nil || !bytes.Equal(got, e.recs[3*RecordWidth:4*RecordWidth]) {
		t.Fatalf("recover after malformed attempts: %v", err)
	}
	if _, err := e.cli.Recover(sid, a); err == nil {
		t.Fatal("state reused")
	}
	// wrong seed / parameters in public.json
	pub := filepath.Join(e.outDir, "public.json")
	pj, _ := os.ReadFile(pub)
	for _, mut := range [][2]string{{`"p": `, `"p": 1`}, {`"m": `, `"m": 9`}, {`"n": 1024`, `"n": 512`}} {
		bad := bytes.Replace(pj, []byte(mut[0]), []byte(mut[1]), 1)
		bp := filepath.Join(t.TempDir(), "public.json")
		os.WriteFile(bp, bad, 0o644)
		if _, _, err := LoadClient(bp, filepath.Join(e.outDir, "hint.bin")); err == nil {
			t.Fatalf("mutated public.json (%s) accepted", mut[1])
		}
	}
	hb, _ := os.ReadFile(filepath.Join(e.outDir, "hint.bin"))
	hp := filepath.Join(t.TempDir(), "hint.bin")
	os.WriteFile(hp, hb[:len(hb)-4], 0o644)
	if _, _, err := LoadClient(pub, hp); err == nil {
		t.Fatal("truncated hint accepted")
	}
}

// A tampered hint or answer must not yield the correct record: it yields either
// ErrDecode or a different record (caught by the record digest one layer up).
func TestTamperedHintOrAnswerFails(t *testing.T) {
	e := setupEpoch(t, 64, 0)
	target := uint64(10)
	want := e.recs[target*RecordWidth : (target+1)*RecordWidth]
	wantD := RecordDigest(want)
	lay := e.cli.Layout
	check := func(name string, got []byte, err error) {
		if err == nil && bytes.Equal(got, want) {
			t.Fatalf("%s: tampering not detected by decode", name)
		}
		if err == nil && RecordDigest(got) == wantD {
			t.Fatalf("%s: digest collision", name)
		}
		t.Logf("%s: decode_error=%v", name, errors.Is(err, ErrDecode))
	}
	// (1) answer: flip one entry in the target's row group
	sid, q, _ := e.cli.Query(target)
	a, _ := e.srv.Answer(q)
	r := (target/lay.M)*lay.Ne + 5
	a[msgHeader+4*r+3] ^= 0x40 // little-endian MSB byte: changes the value by 2^30 >> Delta
	got, err := e.cli.Recover(sid, a)
	check("answer-bitflip", got, err)
	// (2) answer: fully random (well-formed)
	sid, q, _ = e.cli.Query(target)
	a, _ = e.srv.Answer(q)
	copy(a[msgHeader:], randBytes(t, len(a)-msgHeader))
	got, err = e.cli.Recover(sid, a)
	check("answer-random", got, err)
	// (3) hint: perturb one row of the target's group (client-side cached hint)
	orig := append([]uint32(nil), e.cli.H...)
	for k := uint64(0); k < lay.N; k++ {
		e.cli.H[r*lay.N+k] += uint32(k*2654435761 + 1)
	}
	got, err = e.read(t, target)
	check("hint-row", got, err)
	// a record in another row group/column is unaffected by that hint row only
	// if it does not use row r; reads of other groups still succeed
	copy(e.cli.H, orig)
	got, err = e.read(t, target)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("restored hint: %v", err)
	}
}

// Each query uses a fresh LWE secret (upstream PRG seeded from crypto/rand at
// process start, never reseeded by this module).
func TestQueriesUseFreshSecrets(t *testing.T) {
	e := setupEpoch(t, 10, 0)
	s1, q1, _ := e.cli.Query(4)
	s2, q2, _ := e.cli.Query(4)
	if bytes.Equal(q1, q2) || equalU32(e.cli.states[s1].secret, e.cli.states[s2].secret) {
		t.Fatal("query randomness repeated")
	}
}

func TestBestLayoutRoundTrip(t *testing.T) {
	for _, n := range []uint64{16, 1024, 3000} {
		lay, err := BestLayout(n, RecordWidth, 1, MaxBestM)
		if err != nil {
			t.Fatal(err)
		}
		def, _ := ChooseLayout(n, RecordWidth, 0)
		if lay.ClientBytes(1, 0) > def.ClientBytes(1, 0) {
			t.Fatalf("N=%d: best worse than default", n)
		}
		e := setupEpoch(t, n, lay.M)
		for _, i := range []uint64{0, n / 3, n - 1} {
			got, err := e.read(t, i)
			if err != nil || !bytes.Equal(got, e.recs[i*RecordWidth:(i+1)*RecordWidth]) {
				t.Fatalf("N=%d i=%d: %v", n, i, err)
			}
		}
	}
}
