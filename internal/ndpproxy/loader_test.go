package ndpproxy

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
)

// The C program indexes its counter array by enum ndp_counter, so a name
// list that drifts from the map size mislabels every counter after the gap.
func TestCounterNamesMatchObject(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectBytes))
	if err != nil {
		t.Fatalf("load embedded object: %v", err)
	}
	m, ok := spec.Maps["counters"]
	if !ok {
		t.Fatal("embedded object has no counters map")
	}
	if int(m.MaxEntries) != len(CounterNames) {
		t.Errorf("counters map holds %d entries, CounterNames has %d", m.MaxEntries, len(CounterNames))
	}
}

// Go writes these structs into maps the C program reads, so a layout change
// on either side silently corrupts the configuration.
func TestMapValueSizesMatchObject(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectBytes))
	if err != nil {
		t.Fatalf("load embedded object: %v", err)
	}
	for _, tc := range []struct {
		mapName string
		keySize uint32
		valSize uint32
	}{
		{"cfg", 4, uint32(binary.Size(cfgValue{}))},
		{"cfg_prefixes", uint32(binary.Size(prefixKey{})), 1},
		{"counters", 4, 8},
	} {
		m, ok := spec.Maps[tc.mapName]
		if !ok {
			t.Errorf("embedded object has no %s map", tc.mapName)
			continue
		}
		if m.KeySize != tc.keySize {
			t.Errorf("%s key is %d bytes, Go writes %d", tc.mapName, m.KeySize, tc.keySize)
		}
		if m.ValueSize != tc.valSize {
			t.Errorf("%s value is %d bytes, Go writes %d", tc.mapName, m.ValueSize, tc.valSize)
		}
	}
}

func TestParsePrefix(t *testing.T) {
	key, err := parsePrefix("2a01:4f8:10a:128b::/64")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if key.PrefixLen != 64 {
		t.Errorf("prefix length is %d, want 64", key.PrefixLen)
	}
	want := [16]byte{0x2a, 0x01, 0x04, 0xf8, 0x01, 0x0a, 0x12, 0x8b}
	if key.Addr != want {
		t.Errorf("address is %v, want %v", key.Addr, want)
	}

	// A host address must be masked down to its network.
	key, err = parsePrefix("2a01:4f8:10a:128b::2/64")
	if err != nil {
		t.Fatalf("parse host address: %v", err)
	}
	if key.Addr != want {
		t.Errorf("address is %v, want it masked to %v", key.Addr, want)
	}

	for _, bad := range []string{"", "not-a-prefix", "10.0.0.0/8", "2a01:4f8::1"} {
		if _, err := parsePrefix(bad); err == nil {
			t.Errorf("parsePrefix(%q) succeeded, want an error", bad)
		}
	}
}
