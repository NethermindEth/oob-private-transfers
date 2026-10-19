// s7e4bench: S7-E4 measurement of a private read over ONE cumulative SimplePIR
// database of N payloads, in the append-friendly "row-append" layout:
// a fixed number of columns m (= epoch size m_e), record i in column i%m and
// row group i/m, so epoch g (records g*m .. g*m+m-1) is exactly row group g
// (Ne rows) and its hint rows are H_g = DB_g * A with the SAME A (m x n, one
// provider-wide seed).  Uses only the exported oobpir API over pinned upstream
// SimplePIR (full Setup, no FakeSetup, every read checked byte-for-byte).
//
// Modes (one JSON document on stdout):
//
//	-mode ra      -count N -cols m [-epochs 5 -reads 10 -verify-all-max 64]
//	   cumulative server over N records (cols=m); per-epoch hint slices hashed;
//	   for target epochs: build the epoch alone (= provider preprocessing of one
//	   new epoch, T_preprocess), check its hint == the cumulative hint's rows of
//	   that group (existing hint rows unchanged by later epochs), load a client
//	   from ONLY that epoch's hint, query the cumulative server, recover from the
//	   epoch's Ne answer rows, compare with the record.
//	-mode cadelta -count N -me M
//	   column-append check: hint of N records in one row group (cols=N) vs hint
//	   of N+M records (cols=N+M); counts changed hint entries and verifies
//	   H' - H == DB_new * A_new (rows N..N+M-1 of the extended A).
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"

	"oob.local/oobpir/oobpir"
)

const W = oobpir.RecordWidth

func maxRSS() int64 {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return ru.Maxrss
}

func genRecords(n uint64, seed []byte) []byte {
	recs := make([]byte, n*W)
	blk, _ := aes.NewCipher(seed)
	var iv [16]byte
	cipher.NewCTR(blk, iv[:]).XORKeyStream(recs, recs)
	return recs
}

func rnd32() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func quant(xs []float64) map[string]float64 {
	if len(xs) == 0 {
		return nil
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	q := func(p float64) float64 { return s[int(p*float64(len(s)-1)+0.5)] }
	return map[string]float64{"min": s[0], "p10": q(0.1), "median": q(0.5), "p90": q(0.9), "max": s[len(s)-1], "n": float64(len(s))}
}

// subAnswer extracts rows [g*ne, (g+1)*ne) of a canonical answer ("OAv1"|u32 len|len u32).
func subAnswer(a []byte, g, ne uint64) ([]byte, error) {
	if len(a) < 8 || string(a[:4]) != "OAv1" {
		return nil, errors.New("bad answer")
	}
	l := uint64(binary.LittleEndian.Uint32(a[4:]))
	if (g+1)*ne > l {
		return nil, errors.New("group out of range")
	}
	out := make([]byte, 8+4*ne)
	copy(out, "OAv1")
	binary.LittleEndian.PutUint32(out[4:], uint32(ne))
	copy(out[8:], a[8+4*g*ne:8+4*(g+1)*ne])
	return out, nil
}

type readSample struct {
	Epoch       uint64  `json:"epoch"`
	J           uint64  `json:"j"`
	QuerySec    float64 `json:"query_seconds"`
	AnswerSec   float64 `json:"answer_seconds"`
	ExtractSec  float64 `json:"extract_seconds"`
	RecoverSec  float64 `json:"recover_seconds"`
	QueryBytes  int     `json:"query_bytes"`
	AnswerBytes int     `json:"answer_bytes"`
	OK          bool    `json:"ok"`
	Err         string  `json:"error,omitempty"`
}

func ra(N, m uint64, nEpochs, readsPer int, verifyAllMax uint64, tmp string) (map[string]any, error) {
	if N%m != 0 {
		return nil, errors.New("count must be a multiple of cols")
	}
	seedA, dbSeed, idxSeed := rnd32(), rnd32(), rnd32()
	rss0 := maxRSS()
	t0 := time.Now()
	recs := genRecords(N, dbSeed)
	genS := time.Since(t0).Seconds()

	// cumulative DB (full upstream Setup over all N records)
	t1 := time.Now()
	srv, hb, st, err := oobpir.NewServer(recs, N, W, m, seedA, "cumulative")
	if err != nil {
		return nil, err
	}
	cumSetupS := time.Since(t1).Seconds()
	lay := srv.Layout
	if lay.M != m || lay.Groups != N/m {
		return nil, fmt.Errorf("unexpected layout %+v", lay)
	}
	grp := lay.Ne * lay.N * 4
	slice := make([][32]byte, lay.Groups)
	for g := uint64(0); g < lay.Groups; g++ {
		slice[g] = sha256.Sum256(hb[24+g*grp : 24+(g+1)*grp])
	}
	fullHint := uint64(len(hb))
	hb = nil
	runtime.GC()
	rssCum := maxRSS()

	// target epochs
	G := lay.Groups
	var rng = mrand.New(mrand.NewChaCha8([32]byte(idxSeed)))
	targets := []uint64{0}
	if G > 1 {
		targets = append(targets, G-1)
	}
	for uint64(len(targets)) < G && len(targets) < nEpochs {
		c := rng.Uint64N(G)
		dup := false
		for _, t := range targets {
			dup = dup || t == c
		}
		if !dup {
			targets = append(targets, c)
		}
	}
	verifyAll := G <= verifyAllMax
	var checkEpochs []uint64
	if verifyAll {
		for g := uint64(0); g < G; g++ {
			checkEpochs = append(checkEpochs, g)
		}
	} else {
		checkEpochs = targets
	}
	isTarget := map[uint64]bool{}
	for _, t := range targets {
		isTarget[t] = true
	}

	type prep struct {
		Epoch       uint64  `json:"epoch"`
		TotalSec    float64 `json:"newserver_seconds"`
		EncodeSec   float64 `json:"encode_seconds"`
		AExpandSec  float64 `json:"a_expand_seconds"`
		HintSec     float64 `json:"hint_seconds"`
		HintBytes   uint64  `json:"hint_bytes"`
		RowsMatch   bool    `json:"hint_rows_match_cumulative"`
		LayoutMatch bool    `json:"layout_params_match"`
	}
	var preps []prep
	var samples []readSample
	var loads []map[string]any
	mismatch, failures := 0, 0
	for _, g := range checkEpochs {
		er := recs[g*m*W : (g+1)*m*W]
		t := time.Now()
		es, ehb, est, err := oobpir.NewServer(er, m, W, m, seedA, fmt.Sprintf("epoch-%d", g))
		if err != nil {
			return nil, err
		}
		tot := time.Since(t).Seconds()
		el := es.Layout
		lm := el.P == lay.P && el.Ne == lay.Ne && el.M == lay.M && el.QueryLen == lay.QueryLen && el.Sigma == lay.Sigma && el.L == lay.Ne
		match := sha256.Sum256(ehb[24:]) == slice[g]
		if !match || !lm {
			mismatch++
		}
		preps = append(preps, prep{g, tot, est.EncodeSeconds, est.AGenSeconds, est.HintSeconds, uint64(len(ehb)), match, lm})
		if !isTarget[g] {
			continue
		}
		dir := filepath.Join(tmp, fmt.Sprintf("epoch-%d", g))
		if err := es.WriteFiles(dir, ehb, est); err != nil {
			return nil, err
		}
		es, ehb = nil, nil
		cli, lst, err := oobpir.LoadClient(filepath.Join(dir, "public.json"), filepath.Join(dir, "hint.bin"))
		if err != nil {
			return nil, err
		}
		loads = append(loads, map[string]any{"epoch": g, "client_setup_seconds": lst.ClientSetupSeconds, "hint_bytes": lst.HintBytes,
			"public_bytes": lst.PublicBytes, "regen_A_seconds": lst.RegenASeconds})
		for k := 0; k < readsPer; k++ {
			j := rng.Uint64N(m)
			if k == 0 {
				j = 0
			} else if k == 1 {
				j = m - 1
			}
			s := readSample{Epoch: g, J: j}
			tq := time.Now()
			sid, q, err := cli.Query(j)
			s.QuerySec = time.Since(tq).Seconds()
			if err == nil {
				s.QueryBytes = len(q)
				ta := time.Now()
				var a []byte
				a, err = srv.Answer(q)
				s.AnswerSec = time.Since(ta).Seconds()
				if err == nil {
					s.AnswerBytes = len(a)
					tx := time.Now()
					var sub []byte
					sub, err = subAnswer(a, g, lay.Ne)
					s.ExtractSec = time.Since(tx).Seconds()
					if err == nil {
						tr := time.Now()
						var rec []byte
						rec, err = cli.Recover(sid, sub)
						s.RecoverSec = time.Since(tr).Seconds()
						if err == nil {
							s.OK = bytes.Equal(rec, er[j*W:(j+1)*W])
							if !s.OK {
								s.Err = "record mismatch"
							}
						}
					}
				}
			}
			if err != nil {
				s.Err = err.Error()
			}
			if !s.OK {
				failures++
			}
			samples = append(samples, s)
		}
		os.RemoveAll(dir)
		runtime.GC()
	}
	var qs, as, rs, xs []float64
	for _, s := range samples {
		qs, as, rs, xs = append(qs, s.QuerySec), append(as, s.AnswerSec), append(rs, s.RecoverSec), append(xs, s.ExtractSec)
	}
	var ph, pt []float64
	for _, p := range preps {
		ph, pt = append(ph, p.EncodeSec+p.HintSec), append(pt, p.TotalSec)
	}
	return map[string]any{
		"mode": "ra", "kind": "measured: upstream SimplePIR full Setup over the cumulative DB (row-append layout, cols=m), seeded A, every read checked",
		"records": "synthetic uniform random bytes (AES-256-CTR(db_seed)), bulk-loaded without admission",
		"count":   N, "cols_m": m, "epoch_size_m_e": m, "epochs_in_db": G, "layout": lay,
		"seeds":  map[string]string{"seed_A": hex.EncodeToString(seedA), "db_seed": hex.EncodeToString(dbSeed), "index_seed": hex.EncodeToString(idxSeed)},
		"record_generation_seconds": genS,
		"cumulative_setup_seconds":  cumSetupS, "cumulative_setup": st,
		"sizes": map[string]uint64{"full_hint_bytes": fullHint, "epoch_hint_delta_bytes": 24 + grp, "query_bytes": lay.QueryBytes(),
			"answer_bytes": lay.AnswerBytes(), "a_bytes_regenerated_by_client": lay.ABytes(), "db_payload_bytes": N * W,
			"packed_db_bytes": st.PackedDBBytes},
		"hint_row_check": map[string]any{"epochs_checked": len(checkEpochs), "all_epochs": verifyAll, "mismatches": mismatch,
			"meaning": "hint of epoch g built alone (same seed, cols=m) == rows [g*Ne,(g+1)*Ne) of the cumulative hint, byte for byte"},
		"epoch_preprocessing": preps,
		"epoch_preprocess_encode_plus_hint_seconds": quant(ph), "epoch_newserver_seconds": quant(pt),
		"client_loads": loads, "samples": samples, "reads": len(samples), "failures": failures,
		"query_seconds": quant(qs), "answer_seconds": quant(as), "extract_seconds": quant(xs), "recover_seconds": quant(rs),
		"rss_bytes": map[string]int64{"start": rss0, "after_cumulative_setup": rssCum, "end": maxRSS()},
		"go": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0),
	}, nil
}

func cadelta(N, me uint64) (map[string]any, error) {
	seedA, dbSeed := rnd32(), rnd32()
	recs := genRecords(N+me, dbSeed)
	s1, hb1, _, err := oobpir.NewServer(recs[:N*W], N, W, N, seedA, "old")
	if err != nil {
		return nil, err
	}
	s2, hb2, _, err := oobpir.NewServer(recs, N+me, W, N+me, seedA, "new")
	if err != nil {
		return nil, err
	}
	l1, l2 := s1.Layout, s2.Layout
	res := map[string]any{"mode": "cadelta", "count_old": N, "count_new": N + me, "layout_old": l1, "layout_new": l2,
		"hint_bytes_old": len(hb1), "hint_bytes_new": len(hb2)}
	if l1.P != l2.P || l1.Ne != l2.Ne || l1.L != l2.L {
		res["same_params"] = false
		return res, nil
	}
	res["same_params"] = true
	n := l1.N
	h1 := hb1[24:]
	h2 := hb2[24:]
	entries := uint64(len(h1) / 4)
	changed := uint64(0)
	for i := uint64(0); i < entries; i++ {
		if binary.LittleEndian.Uint32(h1[4*i:]) != binary.LittleEndian.Uint32(h2[4*i:]) {
			changed++
		}
	}
	rowsChanged := uint64(0)
	for r := uint64(0); r < l1.L; r++ {
		if !bytes.Equal(h1[r*n*4:(r+1)*n*4], h2[r*n*4:(r+1)*n*4]) {
			rowsChanged++
		}
	}
	// manual delta = DB_new * A_new
	A, _ := oobpir.ExpandA(seedA, N+me, n)
	Au := make([]uint32, len(A.Data))
	for i := range A.Data {
		Au[i] = uint32(A.Data[i])
	}
	delta := make([]uint32, l1.L*n)
	half := uint32(l2.P / 2)
	dg := make([]uint32, l2.Ne)
	for i := N; i < N+me; i++ {
		l2.RecordDigits(recs[i*W:(i+1)*W], dg)
		arow := Au[i*n : (i+1)*n]
		for t := uint64(0); t < l2.Ne; t++ {
			v := dg[t] - half
			drow := delta[t*n : (t+1)*n]
			for k := range drow {
				drow[k] += v * arow[k]
			}
		}
	}
	ok := true
	for i := uint64(0); i < entries; i++ {
		if binary.LittleEndian.Uint32(h1[4*i:])+delta[i] != binary.LittleEndian.Uint32(h2[4*i:]) {
			ok = false
			break
		}
	}
	res["hint_entries"] = entries
	res["hint_entries_changed"] = changed
	res["hint_rows_changed"] = rowsChanged
	res["hint_rows"] = l1.L
	res["delta_equals_DBnew_times_Anew"] = ok
	res["delta_bytes"] = 24 + entries*4
	res["kind"] = "measured check (column-append): appending M records as new columns of a one-row-group DB"
	return res, nil
}

func main() {
	mode := flag.String("mode", "ra", "ra | cadelta")
	count := flag.Uint64("count", 4096, "N")
	cols := flag.Uint64("cols", 1024, "m (ra)")
	me := flag.Uint64("me", 1024, "appended epoch size (cadelta)")
	epochs := flag.Int("epochs", 5, "target epochs (ra)")
	reads := flag.Int("reads", 10, "reads per target epoch (ra)")
	vmax := flag.Uint64("verify-all-max", 64, "check every epoch's hint rows if #epochs <= this")
	tmp := flag.String("tmp", os.TempDir(), "scratch dir for epoch hint files")
	flag.Parse()
	var out map[string]any
	var err error
	t := time.Now()
	switch *mode {
	case "ra":
		out, err = ra(*count, *cols, *epochs, *reads, *vmax, *tmp)
	case "cadelta":
		out, err = cadelta(*count, *me)
	default:
		err = errors.New("unknown mode")
	}
	enc := json.NewEncoder(os.Stdout)
	if err != nil {
		enc.Encode(map[string]any{"error": err.Error()})
		os.Exit(1)
	}
	out["wall_seconds"] = time.Since(t).Seconds()
	enc.Encode(map[string]any{"result": out})
}
