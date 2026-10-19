// oob-pir: JSON-lines worker around pinned upstream SimplePIR for OOB's
// fixed-width 736-byte records.
//
// Server ops: setup, answer, drop, info.  Client ops (separate process): load,
// query, recover.  Benchmark: bench (full preprocessing, every read checked).
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"

	"oob.local/oobpir/oobpir"
)

type Request struct {
	Op           string  `json:"op"`
	RecordsFile  string  `json:"records_file"`
	Count        uint64  `json:"count"`
	Width        uint64  `json:"width"`
	Cols         uint64  `json:"cols"` // optional layout override (0 = upstream square)
	SeedA        string  `json:"seed_A"`
	OutDir       string  `json:"out_dir"`
	EpochID      string  `json:"epoch_id"`
	Query        string  `json:"query"`
	PublicJSON   string  `json:"public_json"`
	HintFile     string  `json:"hint_file"`
	Index        *uint64 `json:"index"`
	StateID      string  `json:"state_id"`
	Answer       string  `json:"answer"`
	ExpectDigest string  `json:"expect_digest"`
	// bench
	Reads  int    `json:"reads"`
	DBSeed string `json:"db_seed"`
	Label  string `json:"label"`
	// layout selection: "" / "default" = upstream square; "best" = BestLayout(R=1)
	LayoutMode string `json:"layout"`
	R          uint64 `json:"r"`
	MaxM       uint64 `json:"max_m"`
	MaxCount   uint64 `json:"max_count"`
}

// resolveCols maps the layout mode to a column override.
func resolveCols(r Request) (uint64, error) {
	switch r.LayoutMode {
	case "", "default":
		return r.Cols, nil
	case "best":
		R := r.R
		if R == 0 {
			R = 1
		}
		maxM := r.MaxM
		if maxM == 0 {
			maxM = oobpir.MaxBestM
		}
		lay, err := oobpir.BestLayout(r.Count, oobpir.RecordWidth, R, maxM)
		if err != nil {
			return 0, err
		}
		return lay.M, nil
	}
	return 0, errors.New("layout must be default or best")
}

var (
	servers = map[string]*oobpir.Server{}
	clients = map[string]*oobpir.Client{}
	// state_id -> epoch
	stateEpoch = map[string]string{}
)

func maxRSS() int64 {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return ru.Maxrss // bytes on darwin
}

func run(r Request) (out any, err error) {
	defer func() {
		if x := recover(); x != nil {
			out, err = nil, fmt.Errorf("PIR internal panic: %v", x)
		}
	}()
	switch r.Op {
	case "info":
		return map[string]any{"version": oobpir.Version, "upstream": oobpir.UpstreamRev, "record_width": oobpir.RecordWidth,
			"n": oobpir.LWEDim, "logq": oobpir.LogQ, "go": runtime.Version(), "a_derivation": oobpir.ADerivDesc}, nil
	case "layout":
		w := r.Width
		if w == 0 {
			w = oobpir.RecordWidth
		}
		cols, err := resolveCols(r)
		if err != nil {
			return nil, err
		}
		lay, err := oobpir.ChooseLayout(r.Count, w, cols)
		if err != nil {
			return nil, err
		}
		pub := oobpir.PublicBytes(lay, "e")
		return map[string]any{"layout": lay, "cols": cols, "hint_bytes": lay.HintBytes(), "query_bytes": lay.QueryBytes(),
			"answer_bytes": lay.AnswerBytes(), "a_bytes_if_downloaded": lay.ABytes(), "public_bytes_approx": pub,
			"cold_1read_bytes": lay.ClientBytes(1, pub), "whole_epoch_bytes": r.Count * w}, nil
	case "crossover":
		return crossover(r)
	case "setup":
		if r.Width != oobpir.RecordWidth {
			return nil, errors.New("width must be 736")
		}
		seed, err := hex.DecodeString(r.SeedA)
		if err != nil || len(seed) != 32 {
			return nil, errors.New("seed_A must be 32 bytes hex")
		}
		if r.OutDir == "" || r.RecordsFile == "" {
			return nil, errors.New("records_file and out_dir required")
		}
		t0 := time.Now()
		recs, err := os.ReadFile(r.RecordsFile)
		if err != nil {
			return nil, err
		}
		if uint64(len(recs)) != r.Count*r.Width {
			return nil, fmt.Errorf("records_file has %d bytes, expected count*width = %d", len(recs), r.Count*r.Width)
		}
		readS := time.Since(t0).Seconds()
		epoch := r.EpochID
		if epoch == "" {
			epoch = "default"
		}
		cols, err := resolveCols(r)
		if err != nil {
			return nil, err
		}
		srv, hb, st, err := oobpir.NewServer(recs, r.Count, r.Width, cols, seed, epoch)
		if err != nil {
			return nil, err
		}
		recs = nil
		if err := srv.WriteFiles(r.OutDir, hb, st); err != nil {
			return nil, err
		}
		servers[epoch] = srv
		runtime.GC()
		return map[string]any{"epoch_id": epoch, "hint_bytes": st.HintBytes, "public_bytes": st.PublicBytes,
			"setup_seconds": st.SetupSeconds + readS + st.WriteSeconds, "read_records_seconds": readS,
			"preprocessing": st, "max_rss_bytes": maxRSS()}, nil
	case "answer":
		srv, err := pickServer(r.EpochID)
		if err != nil {
			return nil, err
		}
		q, err := base64.StdEncoding.DecodeString(r.Query)
		if err != nil {
			return nil, errors.New("query: bad base64")
		}
		t := time.Now()
		a, err := srv.Answer(q)
		if err != nil {
			return nil, err
		}
		return map[string]any{"answer": base64.StdEncoding.EncodeToString(a), "answer_seconds": time.Since(t).Seconds(),
			"answer_bytes": len(a), "query_bytes": len(q), "epoch_id": srv.EpochID}, nil
	case "drop":
		delete(servers, r.EpochID)
		delete(clients, r.EpochID)
		runtime.GC()
		return map[string]any{"dropped": r.EpochID}, nil
	case "load":
		cli, st, err := oobpir.LoadClient(r.PublicJSON, r.HintFile)
		if err != nil {
			return nil, err
		}
		// The client should derive seed_A = SHA-256("OOB-A"||sid||e) itself and
		// pass it here; a provider-chosen seed in public.json is then rejected.
		if r.SeedA != "" && r.SeedA != cli.Pub.SeedA {
			return nil, errors.New("public.json seed_A differs from the client-derived seed_A")
		}
		clients[cli.Pub.EpochID] = cli
		return st, nil
	case "query":
		cli, err := pickClient(r.EpochID)
		if err != nil {
			return nil, err
		}
		if r.Index == nil {
			return nil, errors.New("index required")
		}
		t := time.Now()
		sid, q, err := cli.Query(*r.Index)
		if err != nil {
			return nil, err
		}
		stateEpoch[sid] = cli.Pub.EpochID
		return map[string]any{"query": base64.StdEncoding.EncodeToString(q), "state_id": sid, "query_bytes": len(q),
			"query_seconds": time.Since(t).Seconds(), "epoch_id": cli.Pub.EpochID}, nil
	case "recover":
		ep, ok := stateEpoch[r.StateID]
		if !ok {
			return nil, errors.New("unknown state_id")
		}
		cli := clients[ep]
		if cli == nil {
			return nil, errors.New("epoch for state_id no longer loaded")
		}
		a, err := base64.StdEncoding.DecodeString(r.Answer)
		if err != nil {
			return nil, errors.New("answer: bad base64")
		}
		t := time.Now()
		rec, err := cli.Recover(r.StateID, a)
		secs := time.Since(t).Seconds()
		if err != nil {
			if errors.Is(err, oobpir.ErrDecode) {
				delete(stateEpoch, r.StateID)
			}
			return nil, err
		}
		delete(stateEpoch, r.StateID)
		d := oobpir.RecordDigest(rec)
		res := map[string]any{"record": base64.StdEncoding.EncodeToString(rec), "recover_seconds": secs,
			"answer_bytes": len(a), "digest": hex.EncodeToString(d[:])}
		if r.ExpectDigest != "" {
			res["digest_ok"] = hex.EncodeToString(d[:]) == r.ExpectDigest
		}
		return res, nil
	case "bench":
		return bench(r)
	}
	return nil, errors.New("unknown op")
}

func pickServer(id string) (*oobpir.Server, error) {
	if id != "" {
		if s := servers[id]; s != nil {
			return s, nil
		}
		return nil, fmt.Errorf("epoch %q not loaded", id)
	}
	if len(servers) == 1 {
		for _, s := range servers {
			return s, nil
		}
	}
	return nil, errors.New("epoch_id required")
}

func pickClient(id string) (*oobpir.Client, error) {
	if id != "" {
		if c := clients[id]; c != nil {
			return c, nil
		}
		return nil, fmt.Errorf("epoch %q not loaded", id)
	}
	if len(clients) == 1 {
		for _, c := range clients {
			return c, nil
		}
	}
	return nil, errors.New("epoch_id required")
}

func main() {
	output := os.Stdout
	os.Stdout = os.Stderr // upstream diagnostics must not corrupt the JSON stream
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	enc := json.NewEncoder(output)
	for {
		line, err := in.ReadBytes('\n')
		if len(line) > 0 {
			var r Request
			var result any
			e := json.Unmarshal(line, &r)
			if e == nil {
				result, e = run(r)
			}
			if e != nil {
				enc.Encode(map[string]any{"error": e.Error()})
			} else {
				enc.Encode(map[string]any{"result": result})
			}
		}
		if err != nil {
			return
		}
	}
}

// crossover finds, from the exact size formulas, the smallest epoch size m* at
// which a cold PIR client's bytes for R reads (public.json + hint + R(q+a)) are
// below whole-epoch download (m*736 B), for the default and best layouts.
func crossover(r Request) (any, error) {
	maxN := r.MaxCount
	if maxN == 0 {
		maxN = 1 << 16
	}
	out := []map[string]any{}
	for _, mode := range []string{"default", "best"} {
		for _, R := range []uint64{1, 8, 64} {
			layFor := func(n uint64) (oobpir.Layout, error) {
				if mode == "best" {
					return oobpir.BestLayout(n, oobpir.RecordWidth, R, oobpir.MaxBestM)
				}
				return oobpir.ChooseLayout(n, oobpir.RecordWidth, 0)
			}
			cheaper := func(n uint64) (bool, uint64, error) {
				lay, err := layFor(n)
				if err != nil {
					return false, 0, err
				}
				c := lay.ClientBytes(R, oobpir.PublicBytes(lay, "e"))
				return c < n*oobpir.RecordWidth, c, nil
			}
			// single pass: first n where PIR is cheaper, and the stable crossover
			// (every n >= m_stable in the scanned range is cheaper)
			var first, lastNot uint64
			for n := uint64(1); n <= maxN; n++ {
				ok, _, err := cheaper(n)
				if err != nil {
					return nil, err
				}
				if ok && first == 0 {
					first = n
				}
				if !ok {
					lastNot = n
				}
			}
			stable := lastNot + 1
			powOK := true
			for n := uint64(1) << 17; n <= 1<<20; n <<= 1 {
				if ok, _, _ := cheaper(n); !ok {
					powOK = false
				}
			}
			row := map[string]any{"layout": mode, "reads": R, "m_first": first, "m_stable": stable,
				"scanned_up_to": maxN, "cheaper_at_2^17..2^20": powOK}
			if first != 0 {
				_, c, _ := cheaper(first)
				row["pir_bytes_at_m_first"] = c
			}
			_, c, _ := cheaper(stable)
			row["pir_bytes_at_m_stable"] = c
			row["download_bytes_at_m_stable"] = stable * oobpir.RecordWidth
			out = append(out, row)
		}
	}
	return map[string]any{"kind": "derived from exact size formulas of the implemented layouts (validated against measured sizes)",
		"cold_bytes": "public.json + hint + R*(query+answer)", "download_bytes": "m*736", "max_m_best": oobpir.MaxBestM,
		"rows": out}, nil
}
