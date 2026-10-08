package carrier

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/FrankoonG/rendr/v2/internal/sched"
	"github.com/FrankoonG/rendr/v2/internal/wire"
)

// PING retry, MTU probe and rebind challenge of datagram carriers (M2-D23,
// M2-D24, M2-D27; M2 design §A5.11, §A5.13 and Revision 1, R1-13, R1-14).

// dgProbe is the MTU probe and PING-retry bookkeeping (dgprobe.go): the
// PacketPing-cadence PING count, the outstanding probe's id and whether its
// own PONG arrived, and the consecutive failures. The PING retry at the RTO
// applies to session and probe carriers alike (R1-13). Guarded by Conn.mu.
type dgProbe struct {
	cadence  int    // PINGs placed by the PacketPing cadence
	id       uint32 // the latest MTU probe's PING id
	out      bool   // a probe was sent (id is valid)
	answered bool   // its own PONG arrived
	fails    int    // consecutive probes unanswered by their own PONG
}

// dgChallenge is the rebind state (dgprobe.go): passive flows — the
// candidate source, its nonce, send time, due flag and resend time (an
// unanswered challenge is resent at the REL RTO until its 2-s expiry, also
// by a held writer: the challenge is no PING record; R1-14), the last
// challenge time and the commits of the last minute; every datagram
// carrier — the challenge-PONG slot answering a PING with id 0. Guarded by
// Conn.mu.
type dgChallenge struct {
	active bool      // a challenge is in flight
	cand   PeerKey   // the candidate source
	nonce  uint64    // its nonce (≠ 0)
	at     time.Time // when it was created: it expires chalExpiry later
	sentAt time.Time // its latest send (zero: not sent yet)
	sends  int       // its sends so far
	last   time.Time // creation time of the latest challenge (spacing)

	commits [chalCommitsMax]time.Time // the latest commit times (a ring)
	nc      int                       // commits recorded

	pong    wire.Ping // the PING with id 0 to answer (challenge-PONG slot)
	pongDue bool
}

// Rebind challenge limits (M2-D27, M2 design §A7.4).
const (
	chalExpiry     = 2 * time.Second // an unanswered challenge expires
	chalSpacingMin = time.Second     // challenges are at least max(RTO, 1 s) apart
	chalCommitsMax = 10              // commits per chalCommitWin
	chalCommitWin  = time.Minute
)

// pingKind is why a PING of a datagram carrier is due.
type pingKind uint8

const (
	pingNone    pingKind = iota
	pingFirst            // the first PING, or a requested one
	pingCadence          // the PacketPing cadence of a packet-active session carrier (MTU probes count these)
	pingSlow             // the PingIdle cadence, or a probe carrier's ProbeInterval
	pingRetry            // the retry of an unanswered PING at the RTO (PA-10, R1-13)
)

// dgPingDueLocked is pingDueLocked for a datagram carrier (§A5.11): the
// first and requested PINGs at once; probe carriers every ProbeInterval;
// session carriers every PacketPing while packet-active, else every
// PingIdle; sessionless carriers never. While the oldest committed
// unanswered PING has waited at least the RTO and no PING was committed
// within the RTO, one unpadded retry PING is due (session and probe
// carriers, within the cadence's share of the ring). It returns whether a
// PING is due and why, else when the next one is (zero: none scheduled).
func (c *Conn) dgPingDueLocked(now time.Time) (pingKind, time.Time) {
	st := &c.st
	if c.opts.Sessionless || st.n == pingRingSize {
		return pingNone, time.Time{}
	}
	if !st.pingSent || st.pingReq {
		return pingFirst, now
	}
	if st.n >= pingCadenceMax {
		return pingNone, time.Time{}
	}
	iv, kind := c.tm.PingIdle, pingSlow
	switch {
	case c.opts.Probe:
		iv = c.tm.ProbeInterval
	case c.packetActive(now):
		iv, kind = c.tm.PacketPing, pingCadence
	}
	at := st.lastCommit.Add(iv)
	if !now.Before(at) {
		return kind, now
	}
	for i := range st.n {
		r := st.record(i)
		if r.committedAt.IsZero() || r.early {
			continue
		}
		rto := c.relRTOLocked()
		rt := r.committedAt.Add(rto)
		if t := st.lastCommit.Add(rto); t.After(rt) {
			rt = t
		}
		if !now.Before(rt) {
			return pingRetry, now
		}
		if rt.Before(at) {
			at = rt
		}
		break
	}
	return pingNone, at
}

// dgEncodePingLocked places the due PING of kind k (§A5.11): every
// MTUProbeEvery-th PING of the PacketPing cadence on a session carrier is
// an MTU probe, padded to the current budget (it travels alone, M2-D12).
// When the next probe is encoded, an unanswered previous probe counts a
// failure and an answered one clears them; at MTUProbeFails the carrier
// dies (ping_timeout, "mtu probe"): kill reports it, and the caller kills
// after releasing Conn.mu.
func (c *Conn) dgEncodePingLocked(w *writer, b *Batch, now time.Time, k pingKind) (kill bool) {
	pad := 0
	probe := false
	if k == pingCadence && !c.opts.Probe {
		pr := &c.dg.probe
		pr.cadence++
		if pr.cadence%c.tm.MTUProbeEvery == 0 {
			if pr.out {
				if pr.answered {
					pr.fails = 0
				} else {
					pr.fails++
				}
			}
			if pr.fails >= c.tm.MTUProbeFails {
				return true
			}
			pad = max(int(c.dg.budget.Load())-wire.FrameOverhead-wire.PingFixedLen, 0)
			probe = true
		}
	}
	c.encodePingPadLocked(w, b, now, false, pad)
	if probe && w.ping {
		pr := &c.dg.probe
		pr.id, pr.out, pr.answered = w.pingID, true, false
		w.probe = true
	}
	return false
}

// dgPongProbeLocked records a PONG answering the outstanding MTU probe
// (its own PONG: id and nonce).
func (c *Conn) dgPongProbeLocked(p *wire.Ping) {
	pr := &c.dg.probe
	if pr.out && p.ID == pr.id && p.Nonce == c.salt^uint64(p.ID) {
		pr.answered = true
	}
}

// dgUnsentPingLocked removes the record of the round's PING whose datagram
// the transport refused as too large: it never left (§A5.8); a probe in it
// counts as unanswered.
func (c *Conn) dgUnsentPingLocked(w *writer) {
	st := &c.st
	if st.n > 0 && st.record(st.n-1).id == w.pingID && st.record(st.n-1).committedAt.IsZero() {
		st.n--
	}
	w.ping = false
}

// onChallengePing fills the challenge-PONG slot (M2-D27): a PING with id 0
// is answered by a PONG with id 0 and the same nonce, unpadded, which never
// displaces the regular latest-wins PONG.
func (c *Conn) onChallengePing(p *wire.Ping) {
	c.mu.Lock()
	ch := &c.dg.chal
	ch.pong, ch.pongDue = *p, true
	ch.pong.Pad = 0
	c.mu.Unlock()
	c.Wake()
}

// rebindCandidate starts a challenge to src at now (M2-D27, §A5.13): a
// datagram from a new source of which a frame was newly accepted, or a copy
// of the stored H1 on a held passive flow (R1-14). One challenge is in
// flight at a time, challenges are at least max(RTO, 1 s) apart and at most
// chalCommitsMax rebinds commit per minute. The datagram's frames were
// processed normally; replies keep going to the current peer until a
// commit.
func (c *Conn) rebindCandidate(src PeerKey, now time.Time) {
	c.mu.Lock()
	ch := &c.dg.chal
	if ch.active && now.Sub(ch.at) < chalExpiry {
		c.mu.Unlock()
		return
	}
	if !ch.last.IsZero() && now.Sub(ch.last) < max(c.relRTOLocked(), chalSpacingMin) {
		c.mu.Unlock()
		return
	}
	if ch.nc >= chalCommitsMax && now.Sub(ch.commits[ch.nc%chalCommitsMax]) < chalCommitWin {
		c.mu.Unlock()
		return // the oldest of the latest chalCommitsMax commits is within the minute
	}
	var nb [8]byte
	nonce := uint64(0)
	for nonce == 0 {
		_, _ = rand.Read(nb[:]) // crypto/rand never fails
		nonce = binary.LittleEndian.Uint64(nb[:])
	}
	ch.active, ch.cand, ch.nonce, ch.at, ch.sentAt, ch.sends, ch.last = true, src, nonce, now, time.Time{}, 0, now
	c.mu.Unlock()
	c.Wake()
}

// onChallengePong checks a PONG with id 0 from src at now (M2-D27): it
// commits the rebind when it answers the challenge in flight — the same
// nonce, from the candidate, before the expiry — by making the candidate
// the transport's peer (the reader may call SetPeer, R1-14). Any other
// PONG with id 0, and an answer whose commit the transport refuses, is
// ignored and counted. It reports whether it committed.
func (c *Conn) onChallengePong(p *wire.Ping, src PeerKey, now time.Time) bool {
	c.mu.Lock()
	ch := &c.dg.chal
	ok := ch.active && now.Sub(ch.at) < chalExpiry && p.Nonce == ch.nonce && src == ch.cand
	if ok {
		ch.active = false
	}
	c.mu.Unlock()
	if !ok {
		c.dgDropped(1)
		return false
	}
	if err := c.dg.io.SetPeer(src); err != nil {
		// A newer source replaced the transport's rebind candidate (a
		// transport that cannot rebind never reports one): the answer is
		// stale, a counted drop, and no commit against the rate limit.
		c.dgDropped(1)
		return false
	}
	c.mu.Lock()
	ch.commits[ch.nc%chalCommitsMax] = now
	ch.nc++
	c.mu.Unlock()
	c.dg.ctr.rebinds.Add(1)
	if s := c.env.Dgram; s != nil {
		s.Rebinds.Add(1)
	}
	return true
}

// chalSendLocked reports whether the challenge is to be sent now — first
// at once, then resent at the REL RTO, backed off, until it expires — and
// marks it sent (the writer writes it alone, to the candidate). An
// expired challenge is dropped.
func (c *Conn) chalSendLocked(now time.Time) (send bool, cand PeerKey, nonce uint64) {
	ch := &c.dg.chal
	if !ch.active {
		return false, PeerKey{}, 0
	}
	if now.Sub(ch.at) >= chalExpiry {
		ch.active = false
		return false, PeerKey{}, 0
	}
	if !ch.sentAt.IsZero() && now.Before(c.chalResendAtLocked()) {
		return false, PeerKey{}, 0
	}
	ch.sends++
	ch.sentAt = now
	return true, ch.cand, ch.nonce
}

// chalResendAtLocked is when the challenge in flight is resent.
func (c *Conn) chalResendAtLocked() time.Time {
	ch := &c.dg.chal
	return ch.sentAt.Add(sched.RTOBackoffWithin(c.relRTOLocked(), ch.sends-1, c.tm.RelRTOMax))
}

// chalWakeLocked returns when the writer must run for the challenge in
// flight (zero: never): its first send, its resend or its expiry.
func (c *Conn) chalWakeLocked(now time.Time) time.Time {
	ch := &c.dg.chal
	if !ch.active {
		return time.Time{}
	}
	if ch.sentAt.IsZero() {
		return now
	}
	at := ch.at.Add(chalExpiry)
	if t := c.chalResendAtLocked(); t.Before(at) {
		at = t
	}
	return at
}
