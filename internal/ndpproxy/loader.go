// Package ndpproxy loads and configures the route-following NDP proxy, an
// eBPF program that answers Neighbor Solicitations for addresses routed off
// the uplink into VM network namespaces. See ndp_proxy.bpf.c.
package ndpproxy

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:embed bpf/ndp_proxy.bpf.o
var objectBytes []byte

const (
	// PinDir holds the pinned program link and maps. Neither survives a
	// reboot, so the boot unit re-runs Apply.
	PinDir  = "/sys/fs/bpf/ndp-proxy"
	linkPin = PinDir + "/link"
	mapsDir = PinDir + "/maps"
)

// CounterNames is indexed by enum ndp_counter in ndp_proxy.bpf.c.
var CounterNames = []string{
	"seen_ns",
	"answered",
	"pass_malformed",
	"pass_dad",
	"pass_prefix_miss",
	"pass_fib_local",
	"pass_fib_uplink",
	"ratelimited",
}

// cfgValue mirrors struct ndp_cfg.
type cfgValue struct {
	UplinkIfindex uint32
	UplinkMac     [6]byte
	Pad           uint16
}

// prefixKey mirrors struct lpm_key.
type prefixKey struct {
	PrefixLen uint32
	Addr      [16]byte
}

type objects struct {
	Prog        *ebpf.Program `ebpf:"ndp_proxy"`
	Cfg         *ebpf.Map     `ebpf:"cfg"`
	CfgPrefixes *ebpf.Map     `ebpf:"cfg_prefixes"`
	Counters    *ebpf.Map     `ebpf:"counters"`
	Rate        *ebpf.Map     `ebpf:"rate"`
}

func (o *objects) Close() {
	for _, c := range []interface{ Close() error }{o.Prog, o.Cfg, o.CfgPrefixes, o.Counters, o.Rate} {
		if c != nil {
			c.Close()
		}
	}
}

// Uplink is the interface the proxy answers solicitations on.
type Uplink struct {
	Name     string
	Index    uint32
	Mac      [6]byte
	Allmulti bool
}

func lookupUplink(name string) (Uplink, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return Uplink{}, fmt.Errorf("uplink %s: %w", name, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return Uplink{}, fmt.Errorf("uplink %s has no ethernet address", name)
	}
	u := Uplink{Name: name, Index: uint32(iface.Index)}
	copy(u.Mac[:], iface.HardwareAddr)
	if u.Allmulti, err = allmultiSet(name); err != nil {
		return Uplink{}, err
	}
	return u, nil
}

func ifreqFlags(name string) (*unix.Ifreq, int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, 0, err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		unix.Close(fd)
		return nil, 0, fmt.Errorf("get flags for %s: %w", name, err)
	}
	return ifr, fd, nil
}

func allmultiSet(name string) (bool, error) {
	ifr, fd, err := ifreqFlags(name)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	return ifr.Uint16()&unix.IFF_ALLMULTI != 0, nil
}

// setAllmulti is required because the initial solicitation for a target
// arrives on a solicited-node multicast group derived from its low 24 bits,
// which cannot be joined ahead of time for a whole delegated prefix. Without
// it the NIC drops those frames before any hook runs.
func setAllmulti(name string) error {
	ifr, fd, err := ifreqFlags(name)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	flags := ifr.Uint16()
	if flags&unix.IFF_ALLMULTI != 0 {
		return nil
	}
	ifr.SetUint16(flags | unix.IFF_ALLMULTI)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("set allmulti on %s: %w", name, err)
	}
	return nil
}

func parsePrefix(cidr string) (prefixKey, error) {
	_, netw, err := net.ParseCIDR(cidr)
	if err != nil {
		return prefixKey{}, fmt.Errorf("prefix %q: %w", cidr, err)
	}
	ip := netw.IP.To16()
	if ip == nil || netw.IP.To4() != nil {
		return prefixKey{}, fmt.Errorf("prefix %q is not IPv6", cidr)
	}
	ones, _ := netw.Mask.Size()
	key := prefixKey{PrefixLen: uint32(ones)}
	copy(key.Addr[:], ip)
	return key, nil
}

// Apply loads the program, points it at the uplink, restricts it to prefix,
// and attaches it.
//
// It is safe to call repeatedly, but it is not idempotent: every call loads
// a fresh copy of the program and its maps, so counters always restart from
// zero, even when applying the same uplink and prefix as before. When a
// previous attachment already exists on the requested uplink, Apply swaps
// the new program into it in place via the TCX link's atomic update, so
// solicitations keep being answered throughout. Only when there is no
// usable existing attachment — the first apply on a host, or one whose
// uplink changed — does Apply fall back to detaching and reattaching from
// scratch, which does have a brief window with no attachment at all.
func Apply(uplinkName, prefix string) error {
	key, err := parsePrefix(prefix)
	if err != nil {
		return err
	}
	uplink, err := lookupUplink(uplinkName)
	if err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectBytes))
	if err != nil {
		return fmt.Errorf("load object: %w", err)
	}
	var objs objects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load program: %w", err)
	}
	defer objs.Close()

	if err := objs.Cfg.Put(uint32(0), cfgValue{UplinkIfindex: uplink.Index, UplinkMac: uplink.Mac}); err != nil {
		return fmt.Errorf("write cfg: %w", err)
	}
	if err := objs.CfgPrefixes.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("write prefix: %w", err)
	}

	if existing, err := link.LoadPinnedLink(linkPin, nil); err == nil {
		updated := linkAttachedTo(existing, uplink) && existing.Update(objs.Prog) == nil
		existing.Close()
		if updated {
			if err := pinMaps(&objs, true); err != nil {
				return err
			}
			return setAllmulti(uplinkName)
		}
		// The pinned link can't be updated in place (wrong interface, or the
		// kernel rejected the swap); fall through to a full teardown below.
	}

	if err := Detach(); err != nil {
		return err
	}
	if err := pinMaps(&objs, false); err != nil {
		return err
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.Prog,
		Attach:    ebpf.AttachTCXIngress,
		Interface: int(uplink.Index),
	})
	if err != nil {
		return fmt.Errorf("attach to %s: %w", uplinkName, err)
	}
	defer l.Close()
	if err := l.Pin(linkPin); err != nil {
		return fmt.Errorf("pin link: %w", err)
	}

	return setAllmulti(uplinkName)
}

// linkAttachedTo reports whether l is a TCX link attached to uplink. Update
// swaps the program on a link in place but cannot retarget its interface, so
// callers must check this before relying on it.
func linkAttachedTo(l link.Link, uplink Uplink) bool {
	info, err := l.Info()
	if err != nil {
		return false
	}
	tcx := info.TCX()
	return tcx != nil && uint32(tcx.Ifindex) == uplink.Index
}

// pinMaps pins the freshly loaded maps at their well-known paths. replace
// must be true when a previous generation of the program is already pinned
// there: each new map is pinned to a side path and renamed over the old
// pin, so a concurrent reader (counters, drift checks) never sees the path
// briefly missing.
func pinMaps(objs *objects, replace bool) error {
	if err := os.MkdirAll(mapsDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", mapsDir, err)
	}
	// Pin explicitly rather than declaring LIBBPF_PIN_BY_NAME in the C, so
	// the program stays loadable by any other harness.
	for name, m := range map[string]*ebpf.Map{
		"cfg": objs.Cfg, "cfg_prefixes": objs.CfgPrefixes,
		"counters": objs.Counters, "rate": objs.Rate,
	} {
		path := filepath.Join(mapsDir, name)
		if !replace {
			if err := m.Pin(path); err != nil {
				return fmt.Errorf("pin map %s: %w", name, err)
			}
			continue
		}
		tmp := path + ".new"
		if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale %s: %w", tmp, err)
		}
		if err := m.Pin(tmp); err != nil {
			return fmt.Errorf("pin map %s: %w", name, err)
		}
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("swap pin for map %s: %w", name, err)
		}
	}
	return nil
}

// Detach removes the attachment and all pinned state, leaving allmulti alone
// because other programs on the uplink may rely on it.
func Detach() error {
	if l, err := link.LoadPinnedLink(linkPin, nil); err == nil {
		l.Unpin()
		l.Close()
	} else if !errors.Is(err, os.ErrNotExist) {
		// A stale pin from an incompatible version is still worth clearing.
		os.Remove(linkPin)
	}
	if err := os.RemoveAll(PinDir); err != nil {
		return fmt.Errorf("remove %s: %w", PinDir, err)
	}
	return nil
}

// Drift reports why the current attachment does not match the requested
// configuration, or "" when it matches.
func Drift(uplinkName, prefix string) (string, error) {
	key, err := parsePrefix(prefix)
	if err != nil {
		return "", err
	}
	uplink, err := lookupUplink(uplinkName)
	if err != nil {
		return "", err
	}

	for _, path := range []string{linkPin, filepath.Join(mapsDir, "cfg"), filepath.Join(mapsDir, "cfg_prefixes"), filepath.Join(mapsDir, "counters")} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Sprintf("%s is missing", path), nil
		}
	}

	l, err := link.LoadPinnedLink(linkPin, nil)
	if err != nil {
		return fmt.Sprintf("pinned link unusable: %v", err), nil
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return fmt.Sprintf("pinned link has no info: %v", err), nil
	}
	if tcx := info.TCX(); tcx == nil || uint32(tcx.Ifindex) != uplink.Index {
		return fmt.Sprintf("not attached to %s", uplinkName), nil
	}

	cfgMap, err := ebpf.LoadPinnedMap(filepath.Join(mapsDir, "cfg"), nil)
	if err != nil {
		return fmt.Sprintf("cfg map unusable: %v", err), nil
	}
	defer cfgMap.Close()
	var current cfgValue
	if err := cfgMap.Lookup(uint32(0), &current); err != nil {
		return fmt.Sprintf("cfg map unreadable: %v", err), nil
	}
	if current.UplinkIfindex != uplink.Index {
		return fmt.Sprintf("configured ifindex %d is not %s (%d)", current.UplinkIfindex, uplinkName, uplink.Index), nil
	}
	if current.UplinkMac != uplink.Mac {
		return fmt.Sprintf("configured mac %s is not %s", net.HardwareAddr(current.UplinkMac[:]), net.HardwareAddr(uplink.Mac[:])), nil
	}

	prefixMap, err := ebpf.LoadPinnedMap(filepath.Join(mapsDir, "cfg_prefixes"), nil)
	if err != nil {
		return fmt.Sprintf("prefix map unusable: %v", err), nil
	}
	defer prefixMap.Close()
	var value uint8
	if err := prefixMap.Lookup(key, &value); err != nil {
		return fmt.Sprintf("prefix %s is not configured", prefix), nil
	}

	if !uplink.Allmulti {
		return fmt.Sprintf("allmulti is not set on %s", uplinkName), nil
	}
	return "", nil
}

// Counters sums the per-CPU packet counters by name.
func Counters() (map[string]uint64, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(mapsDir, "counters"), nil)
	if err != nil {
		return nil, fmt.Errorf("load counters: %w", err)
	}
	defer m.Close()

	out := make(map[string]uint64, len(CounterNames))
	for i, name := range CounterNames {
		var perCPU []uint64
		if err := m.Lookup(uint32(i), &perCPU); err != nil {
			return nil, fmt.Errorf("read counter %s: %w", name, err)
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		out[name] = total
	}
	return out, nil
}

// KernelSupported reports whether the running kernel has the two features the
// proxy needs: BPF_FIB_LOOKUP_SKIP_NEIGH (6.4) and TCX links (6.6).
func KernelSupported() error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return err
	}
	release := string(bytes.TrimRight(uts.Release[:], "\x00"))
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		return fmt.Errorf("cannot parse kernel release %q", release)
	}
	if major < 6 || (major == 6 && minor < 6) {
		return fmt.Errorf("kernel %s is older than 6.6, which TCX links require", release)
	}
	return nil
}
