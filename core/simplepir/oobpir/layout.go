// Package oobpir wraps the pinned upstream SimplePIR (e9020b03) for OOB's
// fixed-width records: parameter/layout selection, record <-> Z_p encoding,
// public-seed expansion of the LWE matrix A, canonical wire formats, and the
// server/client roles. All LWE algorithms (Setup/Query/Answer) are upstream's.
package oobpir

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sync"

	pir "github.com/ahenzinger/simplepir/pir"
)

const (
	LWEDim      = 1024 // n, fixed (record encoding)
	LogQ        = 32   // log q, fixed (record encoding)
	RecordWidth = 736  // bytes, record encoding (nu_adm || C)
	squishing   = 3    // upstream DB compression (database.go:34-35), hard-coded in pir.c
	basis       = 10
)

// Layout fully determines the DB matrix and all message sizes. It is a
// deterministic function of (Count, Width, Cols override), so the client
// recomputes it and never trusts provider-supplied dimensions.
type Layout struct {
	Count          uint64  `json:"count"`
	Width          uint64  `json:"width"`
	N              uint64  `json:"n"`
	LogQ           uint64  `json:"logq"`
	P              uint64  `json:"p"`
	Sigma          float64 `json:"sigma"`
	L              uint64  `json:"l"` // DB matrix rows (= hint rows = answer length)
	M              uint64  `json:"m"` // DB matrix cols (= A rows = #LWE samples)
	Ne             uint64  `json:"digits_per_record"`
	ChunkBits      uint64  `json:"chunk_bits"`
	DigitsPerChunk uint64  `json:"digits_per_chunk"`
	Chunks         uint64  `json:"chunks_per_record"`
	Groups         uint64  `json:"row_groups"`
	QueryLen       uint64  `json:"query_len"` // M rounded up to a multiple of 3 (upstream padding)
	ColsOverride   uint64  `json:"cols_override"`
}

// Encoding picks how a W-bit record is written as Z_p digits. A record is cut
// into chunks of G bits; each chunk (an integer < 2^G <= p^k < 2^64) is written
// as k base-p digits. k is chosen to minimize the number of digits Ne. This is
// the fixed-width analogue of upstream's base-p decomposition of an entry
// (utils.go:88-111, which only supports entries <= 64 bits).
func Encoding(p, widthBits uint64) (k, g, chunks, ne uint64) {
	best := uint64(math.MaxUint64)
	pk := uint64(1)
	for kk := uint64(1); ; kk++ {
		hi, lo := bits.Mul64(pk, p)
		if hi != 0 || lo > 1<<63 {
			break
		}
		pk = lo
		gg := uint64(bits.Len64(pk) - 1) // floor(log2 p^k), so every G-bit value is < p^k
		if gg > 63 {
			break
		}
		c := (widthBits + gg - 1) / gg
		if kk*c < best {
			best, k, g, chunks, ne = kk*c, kk, gg, c, kk*c
		}
	}
	return
}

// tableRowP returns upstream's plaintext modulus and sigma for a given number of
// LWE samples m, by calling upstream's own Params.PickParams (params.go:37-80).
// Results are memoized per sample bucket ceil(log2 m) (the table is indexed by
// log m, params.go:56-58), so the answer is identical to calling upstream.
func tableRowP(m uint64) (p uint64, sigma float64, err error) {
	key := bits.Len64(m - 1) // ceil(log2 m) for m >= 1
	if m == 0 {
		key = -1
	}
	tableMu.Lock()
	if e, ok := tableMemo[key]; ok {
		tableMu.Unlock()
		return e.p, e.sigma, e.err
	}
	tableMu.Unlock()
	p, sigma, err = tableRowPUncached(m)
	tableMu.Lock()
	tableMemo[key] = tableEntry{p, sigma, err}
	tableMu.Unlock()
	return
}

type tableEntry struct {
	p     uint64
	sigma float64
	err   error
}

var (
	tableMu   sync.Mutex
	tableMemo = map[int]tableEntry{}
)

func tableRowPUncached(m uint64) (p uint64, sigma float64, err error) {
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("no upstream LWE parameters for n=%d logq=%d m=%d: %v", LWEDim, LogQ, m, x)
		}
	}()
	pp := pir.Params{N: LWEDim, Logq: LogQ}
	pp.PickParams(false, m)
	return pp.P, pp.Sigma, nil
}

// approxSquare mirrors upstream ApproxSquareDatabaseDims (database.go:95-107)
// with our per-record digit count ne.
func approxSquare(count, ne uint64) (l, m uint64) {
	dbElems := count * ne
	l = uint64(math.Floor(math.Sqrt(float64(dbElems))))
	if rem := l % ne; rem != 0 {
		l += ne - rem
	}
	m = (dbElems + l - 1) / l
	return
}

var (
	candOnce sync.Once
	cands    []uint64
)

// ChooseLayout mirrors upstream SimplePIR.PickParams (simple_pir.go:14-44):
// take the largest plaintext modulus p from upstream's table whose sample bound
// admits the resulting DB width m. cols=0 selects upstream's approximately
// square layout; cols>0 fixes the number of columns (ApproxDatabaseDims style).
func ChooseLayout(count, width, cols uint64) (Layout, error) {
	if count == 0 {
		return Layout{}, errors.New("empty database")
	}
	if width == 0 || width > 1<<20 {
		return Layout{}, errors.New("bad record width")
	}
	if count > 1<<24 {
		return Layout{}, errors.New("record count above 2^24 not supported")
	}
	candOnce.Do(func() {
		// Candidate moduli, largest first, from upstream's table (m <= 2^13 .. 2^21).
		for logm := uint64(13); logm <= 21; logm++ {
			p, _, err := tableRowP(1 << logm)
			if err != nil {
				break
			}
			if len(cands) == 0 || cands[len(cands)-1] != p {
				cands = append(cands, p)
			}
		}
	})
	for _, cp := range cands {
		k, g, chunks, ne := Encoding(cp, width*8)
		var l, m uint64
		if cols == 0 {
			l, m = approxSquare(count, ne)
		} else {
			m = cols
			if m > count {
				m = count
			}
			l = ((count + m - 1) / m) * ne
		}
		p, sigma, err := tableRowP(m)
		if err != nil {
			continue
		}
		if p != cp {
			continue // m falls in a bucket with a smaller p; try the next candidate
		}
		if p > 1<<basis {
			return Layout{}, errors.New("p exceeds squishing basis")
		}
		lay := Layout{Count: count, Width: width, N: LWEDim, LogQ: LogQ, P: p, Sigma: sigma,
			L: l, M: m, Ne: ne, ChunkBits: g, DigitsPerChunk: k, Chunks: chunks,
			Groups: l / ne, QueryLen: m + (squishing-m%squishing)%squishing, ColsOverride: cols}
		if lay.Groups*lay.M < count {
			return Layout{}, errors.New("internal: layout too small")
		}
		return lay, nil
	}
	return Layout{}, errors.New("no parameter set fits this database")
}

func (lay Layout) Params() pir.Params {
	return pir.Params{N: lay.N, Sigma: lay.Sigma, L: lay.L, M: lay.M, Logq: lay.LogQ, P: lay.P}
}

// Info is the upstream DBinfo for the unsquished-then-squished DB (Packing=0,
// Ne digits stacked vertically per entry, as upstream does for large entries).
func (lay Layout) Info() pir.DBinfo {
	return pir.DBinfo{Num: lay.Count, Row_length: lay.Width * 8, Packing: 0, Ne: lay.Ne, X: lay.Ne,
		P: lay.P, Logq: lay.LogQ, Basis: basis, Squishing: squishing, Cols: lay.M}
}

func (lay Layout) HintBytes() uint64   { return hintHeader + lay.L*lay.N*4 }
func (lay Layout) QueryBytes() uint64  { return msgHeader + lay.QueryLen*4 }
func (lay Layout) AnswerBytes() uint64 { return msgHeader + lay.L*4 }
func (lay Layout) ABytes() uint64      { return lay.M * lay.N * 4 }

// Equal compares every field that the client recomputes.
func (lay Layout) Equal(o Layout) bool { return lay == o }

// MaxBestM caps the number of DB columns (= rows of A) considered by
// BestLayout: A is m x 1024 x 4 B and is regenerated in memory by the client
// and the server, so m <= 2^18 keeps it <= 1 GiB. (Not a security parameter.)
const MaxBestM = 1 << 18

// ClientBytes is the exact client download+upload for R reads of one epoch by a
// cold client: public.json + hint + R*(query + answer).
func (lay Layout) ClientBytes(R, publicBytes uint64) uint64 {
	return publicBytes + lay.HintBytes() + R*(lay.QueryBytes()+lay.AnswerBytes())
}

// BestLayout searches the column count (i.e. the number of row groups g) that
// minimizes ClientBytes(R) among layouts with upstream-supported parameters and
// m <= maxM. All candidates use upstream's table p/sigma for their m.
func BestLayout(count, width, R, maxM uint64) (Layout, error) {
	var best Layout
	bestCost := uint64(math.MaxUint64)
	for g := uint64(1); g <= count; g++ {
		cols := (count + g - 1) / g
		if cols > maxM {
			continue
		}
		lay, err := ChooseLayout(count, width, cols)
		if err != nil {
			continue
		}
		if c := lay.ClientBytes(R, 0); c < bestCost {
			best, bestCost = lay, c
		}
		if bestCost != math.MaxUint64 && g*600*LWEDim*4 > bestCost {
			break // hint alone (>= g*Ne*n*4, Ne >= 600) already exceeds the best
		}
	}
	if bestCost == math.MaxUint64 {
		return Layout{}, errors.New("no layout")
	}
	return best, nil
}
