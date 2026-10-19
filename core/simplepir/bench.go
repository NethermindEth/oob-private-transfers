package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	mrand "math/rand/v2"
	"path/filepath"
	"runtime"
	"time"

	"oob.local/oobpir/oobpir"
)

// bench runs the same code paths as setup/load/query/answer/recover:
// full upstream preprocessing over the real synthetic DB (no FakeSetup), the
// client loads hint.bin/public.json from disk and regenerates A from seed_A,
// and every read is checked byte-for-byte against the database.
// Records are uniform random bytes (AES-256-CTR keystream under db_seed),
// representative of ciphertext records; they are bulk-loaded, not admitted.
func bench(r Request) (any, error) {
	if r.Width == 0 {
		r.Width = oobpir.RecordWidth
	}
	if r.Width != oobpir.RecordWidth || r.Count == 0 || r.Reads < 1 || r.OutDir == "" {
		return nil, errors.New("bench: need count>0, width=736, reads>=1, out_dir")
	}
	seedA, err := seedOrRandom(r.SeedA)
	if err != nil {
		return nil, err
	}
	dbSeed, err := seedOrRandom(r.DBSeed)
	if err != nil {
		return nil, err
	}
	idxSeed, _ := seedOrRandom("")
	rssStart := maxRSS()

	t0 := time.Now()
	recs := make([]byte, r.Count*r.Width)
	blk, _ := aes.NewCipher(dbSeed)
	var iv [16]byte
	cipher.NewCTR(blk, iv[:]).XORKeyStream(recs, recs)
	genS := time.Since(t0).Seconds()

	cols, err := resolveCols(r)
	if err != nil {
		return nil, err
	}
	srv, hb, st, err := oobpir.NewServer(recs, r.Count, r.Width, cols, seedA, "bench")
	if err != nil {
		return nil, err
	}
	runtime.GC()
	rssSetup := maxRSS()
	if err := srv.WriteFiles(r.OutDir, hb, st); err != nil {
		return nil, err
	}
	hb = nil
	runtime.GC()

	cli, lst, err := oobpir.LoadClient(filepath.Join(r.OutDir, "public.json"), filepath.Join(r.OutDir, "hint.bin"))
	if err != nil {
		return nil, err
	}
	rssLoad := maxRSS()

	var s [32]byte
	copy(s[:], idxSeed)
	rng := mrand.New(mrand.NewChaCha8(s))
	type sample struct {
		Index      uint64  `json:"index"`
		QuerySec   float64 `json:"query_seconds"`
		AnswerSec  float64 `json:"answer_seconds"`
		RecoverSec float64 `json:"recover_seconds"`
		QueryBytes int     `json:"query_bytes"`
		AnsBytes   int     `json:"answer_bytes"`
		OK         bool    `json:"ok"`
		Err        string  `json:"error,omitempty"`
	}
	samples := make([]sample, 0, r.Reads)
	failures := 0
	for k := 0; k < r.Reads; k++ {
		var idx uint64
		switch k {
		case 0:
			idx = 0
		case 1:
			idx = r.Count - 1
		default:
			idx = rng.Uint64N(r.Count)
		}
		smp := sample{Index: idx}
		t := time.Now()
		sid, q, err := cli.Query(idx)
		smp.QuerySec = time.Since(t).Seconds()
		if err == nil {
			smp.QueryBytes = len(q)
			t = time.Now()
			var a []byte
			a, err = srv.Answer(q)
			smp.AnswerSec = time.Since(t).Seconds()
			if err == nil {
				smp.AnsBytes = len(a)
				t = time.Now()
				var rec []byte
				rec, err = cli.Recover(sid, a)
				smp.RecoverSec = time.Since(t).Seconds()
				if err == nil {
					smp.OK = bytes.Equal(rec, recs[idx*r.Width:(idx+1)*r.Width])
					if !smp.OK {
						smp.Err = "record mismatch"
					}
				}
			}
		}
		if err != nil {
			smp.Err = err.Error()
		}
		if !smp.OK {
			failures++
		}
		samples = append(samples, smp)
	}

	// Baseline (a): whole-epoch download; client-side cost = hash every record
	// (d_rec) and pick the one matching the notified digest.
	target := oobpir.RecordDigest(recs[(r.Count/2)*r.Width : (r.Count/2+1)*r.Width])
	var scanS []float64
	for k := 0; k < 3; k++ {
		t := time.Now()
		found := uint64(1 << 63)
		for i := uint64(0); i < r.Count; i++ {
			if oobpir.RecordDigest(recs[i*r.Width:(i+1)*r.Width]) == target {
				found = i
			}
		}
		scanS = append(scanS, time.Since(t).Seconds())
		if found != r.Count/2 {
			return nil, errors.New("baseline scan failed")
		}
	}
	lay := srv.Layout
	return map[string]any{
		"label": r.Label, "layout_mode": r.LayoutMode, "cols_override": cols, "kind": "measured: upstream SimplePIR full preprocessing, seeded A, every read checked",
		"record_loading": "synthetic uniform random bytes (AES-256-CTR(db_seed)), bulk-loaded without admission",
		"count":          r.Count, "width": r.Width, "reads": r.Reads, "failures": failures,
		"seeds":  map[string]string{"seed_A": hex.EncodeToString(seedA), "db_seed": hex.EncodeToString(dbSeed), "index_seed": hex.EncodeToString(idxSeed)},
		"layout": lay, "db_payload_bytes": r.Count * r.Width,
		"record_generation_seconds": genS,
		"server_setup":              st,
		"client_load":               lst,
		"sizes": map[string]uint64{"hint_bytes": st.HintBytes, "public_json_bytes": st.PublicBytes, "seed_bytes": 32,
			"a_bytes_if_downloaded": lay.ABytes(), "query_bytes": lay.QueryBytes(), "answer_bytes": lay.AnswerBytes(),
			"packed_db_bytes": st.PackedDBBytes, "db_matrix_bytes_unpacked": st.DBMatrixBytes},
		"rss_bytes": map[string]int64{"start": rssStart, "after_server_setup": rssSetup, "after_client_load": rssLoad, "end": maxRSS()},
		"samples":   samples,
		"baselines": map[string]any{
			"whole_epoch_download_bytes":  r.Count * r.Width,
			"whole_epoch_scan_seconds":    scanS,
			"whole_epoch_scan_method":     "SHA-256(\"OOB-rec-v1\"||rec) over every record, match notified digest",
			"direct_index_bytes":          r.Width + 16,
			"direct_index_request_bytes":  16,
			"direct_index_response_bytes": r.Width,
			"direct_index_note":           "non-private lower bound: request = u64 epoch + u64 index (16 B), response = the 736-B record",
		},
		"go": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0),
	}, nil
}

func seedOrRandom(h string) ([]byte, error) {
	if h != "" {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return nil, errors.New("seed must be 32 bytes hex")
		}
		return b, nil
	}
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}
