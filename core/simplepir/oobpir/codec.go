package oobpir

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	pir "github.com/ahenzinger/simplepir/pir"
)

func init() {
	m := pir.MatrixNew(1, 1)
	if unsafe.Sizeof(m.Data[0]) != 4 {
		panic("upstream Elem is not 32-bit")
	}
}

// u32 views an upstream matrix (C.Elem = uint32_t, pir.h:4) as []uint32.
func u32(m *pir.Matrix) []uint32 {
	if len(m.Data) == 0 {
		return nil
	}
	return unsafe.Slice((*uint32)(unsafe.Pointer(&m.Data[0])), len(m.Data))
}

// padCap returns a copy of s with extra zeroed capacity beyond len(s). Used so
// that upstream's 8-row-blocked matMulVecPacked (pir.c:110-195), which reads up
// to 7 rows past the end when L % 8 != 0, stays inside allocated memory.
func padCap[T any](s []T, extra int) []T {
	t := make([]T, len(s), len(s)+extra)
	copy(t, s)
	return t
}

// ---------------------------------------------------------------------------
// Public-seed expansion of A.
//
// ExpandA reproduces, bit for bit, upstream's compressed-state expansion
// (simple_pir.go:109-117 -> Init -> MatrixRand(M, N, logq, 0), matrix.go:38-48,
// with the PRG of rand.go:71-126): an AES-128-CTR stream (zero IV) read through
// a bufio.Reader of 8192 bytes, where each refill XORs the keystream INTO the
// previous buffer contents (PRGReader.Read does XORKeyStream(p, p)); each entry
// is crypto/rand.Int(stream, 2^32), i.e. the next 4 bytes big-endian (never
// rejected). Unlike upstream's DecompressState it touches no global PRG state,
// so the client's LWE secret/error keep coming from the OS-seeded PRG.
// The AES-128 key (upstream PRGKey = [aes.BlockSize]byte, rand.go:34) is the
// first 16 bytes of seed_A = SHA-256("OOB-A" || sid || e).
func ExpandA(seedA []byte, rows, cols uint64) (*pir.Matrix, error) {
	if len(seedA) != 32 {
		return nil, errors.New("seed_A must be 32 bytes")
	}
	return expandAKey(seedA[:16], rows, cols)
}

const upstreamBufSize = 8192 // rand.go:39

func expandAKey(key []byte, rows, cols uint64) (*pir.Matrix, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewCTR(block, iv[:])
	out := pir.MatrixNew(rows, cols)
	dst := u32(out)
	buf := make([]byte, upstreamBufSize)
	for i := 0; i < len(dst); {
		stream.XORKeyStream(buf, buf)
		for off := 0; off+4 <= len(buf) && i < len(dst); off += 4 {
			dst[i] = binary.BigEndian.Uint32(buf[off:])
			i++
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Record <-> digits. Bits are taken little-endian within the record (bit b is
// (rec[b/8] >> (b%8)) & 1); chunk c holds bits [c*G, (c+1)*G), and is written as
// k base-p digits, least significant first.

func getBits(rec []byte, start, n uint64) uint64 {
	var v uint64
	sb := start / 8
	sh := start % 8
	// read up to 9 bytes covering [start, start+n)
	for i := uint64(0); i < 9; i++ {
		idx := sb + i
		if idx >= uint64(len(rec)) {
			break
		}
		byteV := uint64(rec[idx])
		pos := int64(i*8) - int64(sh)
		if pos >= 64 {
			break
		}
		if pos >= 0 {
			v |= byteV << uint(pos)
		} else {
			v |= byteV >> uint(-pos)
		}
	}
	if n < 64 {
		v &= (uint64(1) << n) - 1
	}
	return v
}

func putBits(rec []byte, start, n, v uint64) {
	for n > 0 {
		idx := start / 8
		sh := start % 8
		take := 8 - sh
		if take > n {
			take = n
		}
		rec[idx] |= byte((v & ((1 << take) - 1)) << sh)
		v >>= take
		start += take
		n -= take
	}
}

// RecordDigits writes the Ne digits (each in [0,p)) of rec into out.
func (lay Layout) RecordDigits(rec []byte, out []uint32) {
	wb := lay.Width * 8
	t := 0
	for c := uint64(0); c < lay.Chunks; c++ {
		start := c * lay.ChunkBits
		n := lay.ChunkBits
		if start+n > wb {
			n = wb - start
		}
		v := getBits(rec, start, n)
		for j := uint64(0); j < lay.DigitsPerChunk; j++ {
			out[t] = uint32(v % lay.P)
			v /= lay.P
			t++
		}
	}
}

// ErrDecode is returned when recovered digits do not form a valid record
// encoding (a chunk value out of range). It indicates a wrong hint/answer or a
// PIR correctness failure; a wrong-but-well-formed record is caught only by the
// record digest in the higher layer.
var ErrDecode = errors.New("PIR decoding failure (chunk out of range)")

func (lay Layout) DigitsRecord(d []uint32) ([]byte, error) {
	wb := lay.Width * 8
	rec := make([]byte, lay.Width)
	t := 0
	for c := uint64(0); c < lay.Chunks; c++ {
		start := c * lay.ChunkBits
		n := lay.ChunkBits
		if start+n > wb {
			n = wb - start
		}
		var v, coeff uint64 = 0, 1
		for j := uint64(0); j < lay.DigitsPerChunk; j++ {
			if uint64(d[t]) >= lay.P {
				return nil, ErrDecode
			}
			v += uint64(d[t]) * coeff
			coeff *= lay.P
			t++
		}
		if n < 64 && v>>n != 0 {
			return nil, ErrDecode
		}
		putBits(rec, start, n, v)
	}
	return rec, nil
}

// RecordDigest is d_rec = SHA-256("OOB-rec-v1" || rec) (record encoding).
func RecordDigest(rec []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("OOB-rec-v1"))
	h.Write(rec)
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// ---------------------------------------------------------------------------
// Canonical binary wire formats (little-endian).
//   hint.bin : "OOBPIRH1" | u64 rows | u64 cols | rows*cols u32
//   query    : "OQv1" | u32 len | len u32
//   answer   : "OAv1" | u32 len | len u32

const (
	hintHeader = 24
	msgHeader  = 8
)

var (
	hintMagic   = []byte("OOBPIRH1")
	queryMagic  = []byte("OQv1")
	answerMagic = []byte("OAv1")
)

func EncodeHint(h *pir.Matrix) []byte {
	out := make([]byte, hintHeader+4*len(h.Data))
	copy(out, hintMagic)
	binary.LittleEndian.PutUint64(out[8:], h.Rows)
	binary.LittleEndian.PutUint64(out[16:], h.Cols)
	for i, v := range u32(h) {
		binary.LittleEndian.PutUint32(out[hintHeader+4*i:], v)
	}
	return out
}

func DecodeHint(b []byte, rows, cols uint64) ([]uint32, error) {
	if len(b) < hintHeader || string(b[:8]) != string(hintMagic) {
		return nil, errors.New("hint: bad magic")
	}
	r := binary.LittleEndian.Uint64(b[8:])
	c := binary.LittleEndian.Uint64(b[16:])
	if r != rows || c != cols {
		return nil, fmt.Errorf("hint: dims %dx%d, expected %dx%d", r, c, rows, cols)
	}
	if uint64(len(b)) != hintHeader+4*rows*cols {
		return nil, errors.New("hint: bad length")
	}
	h := make([]uint32, rows*cols)
	for i := range h {
		h[i] = binary.LittleEndian.Uint32(b[hintHeader+4*i:])
	}
	return h, nil
}

func encodeVec(magic []byte, v []uint32) []byte {
	out := make([]byte, msgHeader+4*len(v))
	copy(out, magic)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(v)))
	for i, x := range v {
		binary.LittleEndian.PutUint32(out[msgHeader+4*i:], x)
	}
	return out
}

func decodeVec(magic []byte, b []byte, want uint64) ([]uint32, error) {
	if len(b) < msgHeader || string(b[:4]) != string(magic) {
		return nil, fmt.Errorf("%s: bad magic", magic)
	}
	n := uint64(binary.LittleEndian.Uint32(b[4:]))
	if n != want || uint64(len(b)) != msgHeader+4*want {
		return nil, fmt.Errorf("%s: length %d (payload %d B), expected %d", magic, n, len(b)-msgHeader, want)
	}
	v := make([]uint32, n)
	for i := range v {
		v[i] = binary.LittleEndian.Uint32(b[msgHeader+4*i:])
	}
	return v, nil
}
