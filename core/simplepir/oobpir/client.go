package oobpir

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	pir "github.com/ahenzinger/simplepir/pir"
)

// Client holds one epoch's public state: recomputed layout, regenerated A and
// the downloaded hint. LWE secrets/errors come from upstream's package PRG,
// which upstream seeds from crypto/rand at process start (rand.go:155-157);
// this module never calls InitCompressedSeeded/DecompressState, which would
// overwrite that PRG with the public seed (see AUDIT.md §1).
type Client struct {
	Pub    Public
	Layout Layout
	A      *pir.Matrix
	H      []uint32
	states map[string]*qstate
}

type qstate struct {
	index, col, group uint64
	secret            []uint32
	q                 []uint32
}

type LoadStats struct {
	EpochID            string  `json:"epoch_id"`
	ClientSetupSeconds float64 `json:"client_setup_seconds"`
	ReadPublicSeconds  float64 `json:"read_public_seconds"`
	ReadHintSeconds    float64 `json:"read_hint_seconds"`
	RegenASeconds      float64 `json:"regen_A_seconds"`
	PublicBytes        uint64  `json:"public_bytes"`
	HintBytes          uint64  `json:"hint_bytes"`
	SeedBytes          uint64  `json:"seed_bytes"`
	ARegeneratedBytes  uint64  `json:"a_regenerated_bytes"`
	Layout             Layout  `json:"layout"`
}

// LoadClient validates public.json and hint.bin: it recomputes the layout from
// (count, width, cols_override) and rejects any other parameters, fixes n=1024,
// logq=32 and upstream's table p/sigma, checks hint dimensions and hash, and
// regenerates A from seed_A.
func LoadClient(publicPath, hintPath string) (*Client, *LoadStats, error) {
	st := &LoadStats{SeedBytes: 32}
	t0 := time.Now()
	pj, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, nil, err
	}
	var pub Public
	if err := json.Unmarshal(pj, &pub); err != nil {
		return nil, nil, fmt.Errorf("public.json: %v", err)
	}
	st.PublicBytes = uint64(len(pj))
	if pub.Version != Version || pub.Scheme != "SimplePIR" {
		return nil, nil, errors.New("public.json: unsupported version/scheme")
	}
	if pub.Layout.Width != RecordWidth {
		return nil, nil, errors.New("public.json: width must be 736")
	}
	lay, err := ChooseLayout(pub.Layout.Count, pub.Layout.Width, pub.Layout.ColsOverride)
	if err != nil {
		return nil, nil, err
	}
	if !lay.Equal(pub.Layout) || lay.N != LWEDim || lay.LogQ != LogQ {
		return nil, nil, errors.New("public.json: layout/parameters differ from the deterministic choice")
	}
	seed, err := hex.DecodeString(pub.SeedA)
	if err != nil || len(seed) != 32 {
		return nil, nil, errors.New("public.json: bad seed_A")
	}
	st.ReadPublicSeconds = time.Since(t0).Seconds()
	t1 := time.Now()
	hb, err := os.ReadFile(hintPath)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(hb)
	if pub.HintSHA256 != "" && hex.EncodeToString(sum[:]) != pub.HintSHA256 {
		return nil, nil, errors.New("hint: sha256 differs from public.json")
	}
	H, err := DecodeHint(hb, lay.L, lay.N)
	if err != nil {
		return nil, nil, err
	}
	st.HintBytes = uint64(len(hb))
	st.ReadHintSeconds = time.Since(t1).Seconds()
	t2 := time.Now()
	A, err := ExpandA(seed, lay.M, lay.N)
	if err != nil {
		return nil, nil, err
	}
	st.RegenASeconds = time.Since(t2).Seconds()
	st.ARegeneratedBytes = lay.ABytes()
	st.ClientSetupSeconds = time.Since(t0).Seconds()
	st.EpochID = pub.EpochID
	st.Layout = lay
	return &Client{Pub: pub, Layout: lay, A: A, H: H, states: map[string]*qstate{}}, st, nil
}

// Query builds an upstream SimplePIR query for record index. The server sees
// only the column's LWE encryption; the row group is resolved client-side from
// the full-column answer.
func (c *Client) Query(index uint64) (stateID string, q []byte, err error) {
	if index >= c.Layout.Count {
		return "", nil, fmt.Errorf("index %d out of range (count %d)", index, c.Layout.Count)
	}
	col := index % c.Layout.M
	var pi pir.SimplePIR
	cs, qm := pi.Query(col, pir.MakeState(c.A), c.Layout.Params(), c.Layout.Info())
	qv := u32(qm.Data[0])
	if uint64(len(qv)) != c.Layout.QueryLen {
		return "", nil, errors.New("internal: query length")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", nil, err
	}
	sid := hex.EncodeToString(id[:])
	c.states[sid] = &qstate{index: index, col: col, group: index / c.Layout.M,
		secret: append([]uint32(nil), u32(cs.Data[0])...), q: append([]uint32(nil), qv...)}
	return sid, encodeVec(queryMagic, qv), nil
}

// Recover decodes the record from an answer, using upstream's Recover
// equations (simple_pir.go:185-214) restricted to the record's Ne rows.
// The state is consumed (one query, one answer).
func (c *Client) Recover(stateID string, answer []byte) ([]byte, error) {
	s, ok := c.states[stateID]
	if !ok {
		return nil, errors.New("unknown state_id")
	}
	lay := c.Layout
	ans, err := decodeVec(answerMagic, answer, lay.L)
	if err != nil {
		return nil, err // malformed: state kept, caller may retry with a well-formed answer
	}
	delete(c.states, stateID)
	// offset = -(p/2) * sum_j q_j  mod 2^32
	var sum uint32
	half := uint32(lay.P / 2)
	for j := uint64(0); j < lay.M; j++ {
		sum += half * s.q[j]
	}
	offset := -sum
	params := lay.Params()
	digits := make([]uint32, lay.Ne)
	n := lay.N
	for t := uint64(0); t < lay.Ne; t++ {
		r := s.group*lay.Ne + t
		row := c.H[r*n : (r+1)*n]
		var hs uint32
		for k, h := range row {
			hs += h * s.secret[k]
		}
		noised := ans[r] - hs + offset // mod 2^32
		v := params.Round(uint64(noised))
		digits[t] = uint32((v + lay.P/2) % lay.P) // ReconstructElem, database.go:57-60
	}
	return lay.DigitsRecord(digits)
}

func (c *Client) PendingStates() int { return len(c.states) }
