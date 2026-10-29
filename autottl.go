package desync

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

var (
	// ErrAutoTTLUnsupported reports that this platform, or the connection's
	// address family, gives an unprivileged TCP socket no way to read the TTL
	// or hop limit of the packets it received. PlatformCapabilities().AutoTTL
	// and Unsupported["auto-ttl-ipv4"/"auto-ttl-ipv6"] say why.
	ErrAutoTTLUnsupported = errors.New("desync: auto TTL cannot observe the server's TTL here")
	// ErrAutoTTLUnobserved reports that the server's TTL was not observed or
	// does not yield a usable hop count, so no TTL could be derived.
	ErrAutoTTLUnobserved = errors.New("desync: auto TTL could not derive a TTL from the observed path")
)

// Defaults of AutoTTL, those of zapret's --dpi-desync-autottl (-1:3-20).
const (
	defaultAutoTTLDelta = 1
	defaultAutoTTLMin   = 3
	defaultAutoTTLMax   = 20
	// maxGuessedHops bounds the path lengths EstimateHops accepts.
	maxGuessedHops = 32
)

// AutoTTL derives a low TTL from the observed length of the path to the
// server: TTL = hops - Delta, clamped to Min..Max. A result that is not below
// the hop count would reach the server, so it is rejected instead. The hop
// count comes from the TTL of the server's packets (see EstimateHops), which
// assumes the return path is as long as the forward path.
//
// Zero fields select the defaults (Delta 1, Min 3, Max 20, zapret's
// --dpi-desync-autottl default), so &AutoTTL{} is a complete policy.
type AutoTTL struct {
	// Delta is subtracted from the hop count, 1..254 (0 means 1). It is the
	// margin between the fake's last hop and the server.
	Delta int
	// Min and Max bound the TTL, 1..255 (0 means 3 and 20). A path so short
	// that hops-Delta is below Min still uses Min, unless Min reaches the
	// server; then no TTL is derived.
	Min, Max int
}

func (a AutoTTL) normalized() AutoTTL {
	if a.Delta == 0 {
		a.Delta = defaultAutoTTLDelta
	}
	if a.Min == 0 {
		a.Min = defaultAutoTTLMin
	}
	if a.Max == 0 {
		a.Max = defaultAutoTTLMax
	}
	return a
}

// Validate checks the policy after applying defaults.
func (a AutoTTL) Validate() error {
	if a.Delta < 0 || a.Delta > 254 {
		return fmt.Errorf("desync: auto TTL delta must be between 1 and 254 (or zero for default)")
	}
	if a.Min < 0 || a.Min > 255 || a.Max < 0 || a.Max > 255 {
		return fmt.Errorf("desync: auto TTL bounds must be between 1 and 255 (or zero for default)")
	}
	if n := a.normalized(); n.Min > n.Max {
		return fmt.Errorf("desync: auto TTL minimum %d exceeds maximum %d", n.Min, n.Max)
	}
	return nil
}

// TTL returns the TTL for a path of hops routers, or false when no TTL in
// Min..Max stays below the hop count. The policy must be valid.
func (a AutoTTL) TTL(hops int) (int, bool) {
	a = a.normalized()
	ttl := hops - a.Delta
	if ttl < a.Min {
		ttl = a.Min
	}
	if ttl > a.Max {
		ttl = a.Max
	}
	if ttl >= hops || ttl < 1 {
		return 0, false
	}
	return ttl, true
}

// EstimateHops guesses how many routers decremented a packet that arrived
// with the given TTL (or IPv6 hop limit). Senders start at one of the common
// initial values 64 (Linux, macOS, most network gear), 128 (Windows) or 255;
// paths are assumed shorter than 32 hops, so 33..64 is read as starting at
// 64, 97..128 at 128 and 224..255 at 255. Any other value is ambiguous and
// returns false. The guess is zapret's hop_count_guess (MIT, see
// third_party/NOTICE), except that 64 and 128 count as zero hops.
func EstimateHops(ttl int) (int, bool) {
	for _, initial := range [...]int{64, 128, 255} {
		if ttl <= initial && ttl > initial-maxGuessedHops {
			return initial - ttl, true
		}
	}
	return 0, false
}

// HopObservation is what ObserveHops read from a connection.
type HopObservation struct {
	// TTL is the TTL or hop limit of the last in-order segment received
	// from the server, normally its SYN-ACK.
	TTL int
	// Hops is EstimateHops(TTL).
	Hops int
}

// ObserveHops reads the TTL of the packets the server sent on c (unwrapping
// *Conn and other NetConn wrappers) and estimates the path length. It works
// only where PlatformCapabilities().AutoTTL reports the connection's family,
// and only for a socket created with ControlAutoTTL; otherwise the error
// wraps ErrAutoTTLUnsupported or ErrAutoTTLUnobserved. It changes nothing;
// call it before the first Write of a *Conn with AutoTTL, which turns the
// observation off once it used it.
func ObserveHops(c net.Conn) (HopObservation, error) {
	raw, err := socketOf(c)
	if err != nil {
		return HopObservation{}, err
	}
	return observeHops(raw, false)
}

func observeHops(raw syscall.RawConn, stop bool) (HopObservation, error) {
	var ttl int
	var opErr error
	err := raw.Control(func(fd uintptr) { ttl, opErr = observeTTL(fd, stop) })
	if err == nil {
		err = opErr
	}
	if err != nil {
		return HopObservation{}, err
	}
	hops, ok := EstimateHops(ttl)
	if !ok {
		return HopObservation{TTL: ttl}, fmt.Errorf("%w: received TTL %d does not follow an initial TTL of 64, 128 or 255 within %d hops", ErrAutoTTLUnobserved, ttl, maxGuessedHops)
	}
	return HopObservation{TTL: ttl, Hops: hops}, nil
}

// ControlAutoTTL prepares a socket before it connects, so that ObserveHops
// and FakeOptions.AutoTTL can later read the TTL of the server's SYN-ACK. Use
// it as (or call it from) net.Dialer.Control. Where the platform or family
// cannot observe the TTL it does nothing and returns nil, so a dialer can use
// it everywhere; the failure is reported when the TTL is needed.
//
// On Linux it enables IPV6_RECVHOPLIMIT on IPv6 sockets. The kernel then
// clones every in-order segment to record its hop limit; the *Conn wrapper
// disables the option again once it read the value for the fake.
func ControlAutoTTL(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) { opErr = prepareTTLObservation(fd, network) })
	if err != nil {
		return err
	}
	return opErr
}

// AutoTTLCapability describes how the package observes the server's TTL.
type AutoTTLCapability struct {
	// Mechanism names the kernel interface, empty when there is none.
	Mechanism string
	// IPv4 and IPv6 report the peer families that can be observed.
	IPv4, IPv6 bool
}

// validateTTL checks Fake.TTL and Fake.AutoTTL.
func (f *FakeOptions) validateTTL() error {
	if f.AutoTTL == nil {
		if f.TTL < 1 || f.TTL > 255 {
			return fmt.Errorf("desync: fake TTL must be between 1 and 255")
		}
		return nil
	}
	if f.TTL < 0 || f.TTL > 255 {
		return fmt.Errorf("desync: fake TTL must be between 1 and 255 (or zero with AutoTTL)")
	}
	if err := f.AutoTTL.Validate(); err != nil {
		return err
	}
	// Without a fallback TTL the fake needs an observable family. A platform
	// without the fake reports ErrFakeUnsupported instead.
	if f.TTL == 0 && supportsFake && !platformAutoTTL.IPv4 && !platformAutoTTL.IPv6 {
		return ErrAutoTTLUnsupported
	}
	return nil
}

// fakeTTL selects the TTL of the fake prefix before anything is sent. With
// AutoTTL it observes the path; when that fails it uses Fake.TTL as the
// fallback, or fails without a fallback.
func (c *Conn) fakeTTL(raw syscall.RawConn) (int, error) {
	f := c.opts.Fake
	if f.AutoTTL == nil {
		c.usedTTL.Store(int32(f.TTL))
		return f.TTL, nil
	}
	obs, err := observeHops(raw, true)
	if err == nil {
		if ttl, ok := f.AutoTTL.TTL(obs.Hops); ok {
			c.usedTTL.Store(int32(ttl) | autoTTLFlag)
			return ttl, nil
		}
		n := f.AutoTTL.normalized()
		err = fmt.Errorf("%w: %d hops (received TTL %d) leave no TTL in %d..%d below the server with delta %d", ErrAutoTTLUnobserved, obs.Hops, obs.TTL, n.Min, n.Max, n.Delta)
	}
	if f.TTL != 0 {
		c.usedTTL.Store(int32(f.TTL))
		return f.TTL, nil
	}
	return 0, err
}

const autoTTLFlag = 1 << 8

// FakeTTL reports the TTL the fake prefix was sent with, and whether AutoTTL
// derived it (false: the fixed or fallback Fake.TTL). It is 0 until the fake
// was attempted.
func (c *Conn) FakeTTL() (ttl int, auto bool) {
	v := c.usedTTL.Load()
	return int(v &^ autoTTLFlag), v&autoTTLFlag != 0
}

func writeAutoTTL(b *strings.Builder, a *AutoTTL) {
	if a == nil {
		return
	}
	n := a.normalized()
	b.WriteString(",auto:")
	b.WriteString(strconv.Itoa(n.Delta))
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(n.Min))
	b.WriteByte('-')
	b.WriteString(strconv.Itoa(n.Max))
}
