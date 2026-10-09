package rendrtest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// Packet behaviours and the packet verifier (M2 design §A8.1). A test
// datagram is a 24-byte header — seq u64, send time u64 (ns of the test
// clock), length u32, CRC-32C u32 of the whole datagram with this field
// zeroed — followed by a PRNG body derived from (seed, seq). The verifier
// checks exact sizes (L36), content, duplicates and missing seqs (L39).
// Every integer is big-endian.

// PacketHeaderLen is the size of a test datagram's header; the smallest
// test datagram.
const PacketHeaderLen = 24

// Offsets of the test datagram header.
const (
	pktSeq  = 0
	pktTime = 8
	pktLen  = 16
	pktCRC  = 20
)

// maxVerifiedSeq bounds the seqs a PacketVerifier tracks (its bitmap stays
// below 8 MiB); a valid datagram with a larger seq counts as corrupt.
const maxVerifiedSeq = 1 << 26

// pktReadBuf reads any packet-session datagram (MaxPayload ≤ 65,507) whole.
const pktReadBuf = wire.MaxDatagram + 1

// PacketBehaviour is a far-end behaviour on a packet session (a
// *rendr.PacketConn is a net.PacketConn). It returns its own verdict: nil
// when it behaved as specified; only io.EOF is a clean end (L64).
type PacketBehaviour func(pc net.PacketConn) error

// PacketEcho returns each datagram unchanged to its source until the
// session ends; io.EOF is a clean end. After the peer's FIN its WriteTo
// fails with net.ErrClosed (a packet session's FIN closes both
// directions): it then stops echoing and reads to io.EOF. It closes pc
// when it returns.
func PacketEcho() PacketBehaviour {
	return func(pc net.PacketConn) error {
		defer pc.Close()
		buf := make([]byte, pktReadBuf)
		echo := true
		for {
			n, addr, err := pc.ReadFrom(buf)
			if n < 0 || n > len(buf) {
				return fmt.Errorf("rendrtest: PacketEcho: invalid read count %d", n)
			}
			if err == nil && echo {
				if _, werr := pc.WriteTo(buf[:n], addr); errors.Is(werr, net.ErrClosed) {
					echo = false
				} else if werr != nil {
					return fmt.Errorf("rendrtest: PacketEcho: %w", werr)
				}
			}
			switch {
			case err == io.EOF:
				return nil
			case err != nil:
				return fmt.Errorf("rendrtest: PacketEcho: %w", err)
			}
		}
	}
}

// PacketSink reads and counts datagrams until io.EOF (an empty datagram
// counts too; count may be nil), then closes pc.
func PacketSink(count *atomic.Int64) PacketBehaviour {
	return func(pc net.PacketConn) error {
		defer pc.Close()
		if count == nil {
			count = new(atomic.Int64)
		}
		buf := make([]byte, pktReadBuf)
		for {
			n, _, err := pc.ReadFrom(buf)
			switch {
			case n < 0 || n > len(buf):
				return fmt.Errorf("rendrtest: PacketSink: invalid read count %d", n)
			case err == nil:
				count.Add(1)
			case err == io.EOF:
				return nil
			default:
				return fmt.Errorf("rendrtest: PacketSink: %w", err)
			}
		}
	}
}

// PacketGenConfig configures PacketGen.
type PacketGenConfig struct {
	Seed  uint64
	Size  int     // datagram size, ≥ PacketHeaderLen
	Count int     // datagrams to send
	Rate  float64 // datagrams per second (0: as fast as WriteTo returns)
}

// PacketGen sends Count test datagrams to pc's peer at Rate, recording
// every WriteTo result, then returns; it never closes pc. Datagram k (seq
// k, from 0) is due at start + k/Rate (an absolute schedule: a slow WriteTo
// does not shift the later ones). It stops early when WriteTo reports pc
// closed (an error matching net.ErrClosed). It panics for a Size below
// PacketHeaderLen.
func PacketGen(cfg PacketGenConfig, pc net.PacketConn, peer net.Addr) PacketGenResult {
	if cfg.Size < PacketHeaderLen {
		panic("rendrtest: PacketGen: Size below PacketHeaderLen")
	}
	var res PacketGenResult
	buf := make([]byte, cfg.Size)
	start := time.Now()
	for k := range cfg.Count {
		if cfg.Rate > 0 {
			if d := time.Until(start.Add(time.Duration(float64(k) * float64(time.Second) / cfg.Rate))); d > 0 {
				time.Sleep(d)
			}
		}
		at := time.Now()
		_, err := pc.WriteTo(PacketPayload(buf, cfg.Seed, uint64(k), cfg.Size, at), peer)
		res.MaxWrite = max(res.MaxWrite, time.Since(at))
		if err == nil {
			res.Sent++
			continue
		}
		res.Errors++
		if res.FirstErr == nil {
			res.FirstErr = err
		}
		if errors.Is(err, net.ErrClosed) {
			break
		}
	}
	return res
}

// PacketGenResult is what PacketGen did.
type PacketGenResult struct {
	Sent     int           // WriteTo calls that returned (n, nil)
	Errors   int           // WriteTo calls that returned an error
	FirstErr error         // the first such error
	MaxWrite time.Duration // the longest WriteTo call (L40: never blocks)
}

// PacketPayload fills dst[:size] with test datagram seq of seed sent at t
// and returns it (a new slice when dst is too small). It panics for a size
// below PacketHeaderLen.
func PacketPayload(dst []byte, seed, seq uint64, size int, t time.Time) []byte {
	if size < PacketHeaderLen {
		panic("rendrtest: PacketPayload: size below PacketHeaderLen")
	}
	if cap(dst) < size {
		dst = make([]byte, size)
	}
	b := dst[:size]
	binary.BigEndian.PutUint64(b[pktSeq:], seq)
	binary.BigEndian.PutUint64(b[pktTime:], uint64(t.UnixNano()))
	binary.BigEndian.PutUint32(b[pktLen:], uint32(size))
	clear(b[pktCRC:PacketHeaderLen])
	fillBody(b[PacketHeaderLen:], seed, seq)
	binary.BigEndian.PutUint32(b[pktCRC:], wire.CRC(b))
	return b
}

// bodyState is the PRNG state of the body of datagram seq of seed.
func bodyState(seed, seq uint64) uint64 {
	x := seed ^ (seq+1)*0x9e3779b97f4a7c15
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	if x == 0 {
		x = 1
	}
	return x
}

// xorshift advances a body PRNG state.
func xorshift(x uint64) uint64 {
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	return x
}

// fillBody writes the body of datagram seq of seed into b.
func fillBody(b []byte, seed, seq uint64) {
	x := bodyState(seed, seq)
	for ; len(b) >= 8; b = b[8:] {
		x = xorshift(x)
		binary.LittleEndian.PutUint64(b, x)
	}
	if len(b) > 0 {
		var t [8]byte
		binary.LittleEndian.PutUint64(t[:], xorshift(x))
		copy(b, t[:])
	}
}

// bodyMatches reports whether b is the body of datagram seq of seed.
func bodyMatches(b []byte, seed, seq uint64) bool {
	x := bodyState(seed, seq)
	for ; len(b) >= 8; b = b[8:] {
		x = xorshift(x)
		if binary.LittleEndian.Uint64(b) != x {
			return false
		}
	}
	if len(b) > 0 {
		var t [8]byte
		binary.LittleEndian.PutUint64(t[:], xorshift(x))
		for i, c := range b {
			if c != t[i] {
				return false
			}
		}
	}
	return true
}

// PacketVerifier checks received test datagrams of one generator. It is
// safe for concurrent use.
type PacketVerifier struct {
	seed uint64

	mu   sync.Mutex
	res  PacketResult
	seen []uint64 // bitmap of the seqs received
	last time.Time
	any  bool
}

// NewPacketVerifier returns a verifier for datagrams of seed.
func NewPacketVerifier(seed uint64) *PacketVerifier { return &PacketVerifier{seed: seed} }

// Add verifies one received datagram (b exactly as ReadFrom returned it)
// arriving at t; it returns an error for a corrupt or wrongly sized one and
// counts duplicates. Wrongly sized: shorter than the header or not the
// length the header declares (a merged, split or truncated datagram, L36:
// BadSize). Corrupt: a CRC-32C mismatch, a body that is not the generator's
// for its seq (another seed), or a seq beyond 2^26. A duplicate (a seq seen
// before) is no error. MaxGap is the longest interval between the arrivals
// of consecutive new seqs.
func (v *PacketVerifier) Add(b []byte, t time.Time) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(b) < PacketHeaderLen {
		v.res.BadSize++
		return fmt.Errorf("rendrtest: a test datagram of %d bytes, shorter than its %d-byte header", len(b), PacketHeaderLen)
	}
	if n := binary.BigEndian.Uint32(b[pktLen:]); int64(n) != int64(len(b)) {
		v.res.BadSize++
		return fmt.Errorf("rendrtest: a test datagram of %d bytes declares %d (boundaries not kept)", len(b), n)
	}
	var zero [4]byte
	crc := wire.CRCUpdate(wire.CRCUpdate(wire.CRC(b[:pktCRC]), zero[:]), b[PacketHeaderLen:])
	seq := binary.BigEndian.Uint64(b[pktSeq:])
	switch {
	case crc != binary.BigEndian.Uint32(b[pktCRC:]):
		v.res.Corrupt++
		return fmt.Errorf("rendrtest: test datagram seq %d: CRC mismatch", seq)
	case seq >= maxVerifiedSeq:
		v.res.Corrupt++
		return fmt.Errorf("rendrtest: test datagram seq %d beyond the verifier's range", seq)
	case !bodyMatches(b[PacketHeaderLen:], v.seed, seq):
		v.res.Corrupt++
		return fmt.Errorf("rendrtest: test datagram seq %d: not the body of seed %d", seq, v.seed)
	}
	w, bit := seq/64, uint64(1)<<(seq%64)
	if need := int(w) + 1; len(v.seen) < need {
		v.seen = append(v.seen, make([]uint64, need-len(v.seen))...)
	}
	if v.seen[w]&bit != 0 {
		v.res.Duplicates++
		return nil
	}
	v.seen[w] |= bit
	if v.res.Unique == 0 || seq > v.res.Highest {
		v.res.Highest = seq
	}
	v.res.Unique++
	if v.any {
		v.res.MaxGap = max(v.res.MaxGap, t.Sub(v.last))
	}
	v.last, v.any = t, true
	return nil
}

// Result returns the verdict so far.
func (v *PacketVerifier) Result() PacketResult {
	v.mu.Lock()
	defer v.mu.Unlock()
	r := v.res
	r.Missing = nil
	if r.Unique == 0 {
		return r
	}
	for s := uint64(0); s < r.Highest; s++ {
		if w := v.seen[s/64]; w == ^uint64(0) && s%64 == 0 && s+64 <= r.Highest {
			s += 63 // a whole word received
			continue
		} else if w&(1<<(s%64)) != 0 {
			continue
		}
		if k := len(r.Missing); k > 0 && r.Missing[k-1].To == s-1 {
			r.Missing[k-1].To = s
		} else {
			r.Missing = append(r.Missing, SeqRange{From: s, To: s})
		}
	}
	return r
}

// PacketResult is a PacketVerifier's verdict.
type PacketResult struct {
	Unique, Duplicates, Corrupt, BadSize uint64
	Highest                              uint64     // the highest seq received
	Missing                              []SeqRange // seqs below Highest never received, ascending
	MaxGap                               time.Duration
}

// SeqRange is the closed range [From, To] of seqs.
type SeqRange struct{ From, To uint64 }
