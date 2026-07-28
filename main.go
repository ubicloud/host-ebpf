// Command host-ebpf loads and maintains the eBPF programs that run on
// Ubicloud hypervisor hosts. Rhizome drives it from systemd units; the
// binary owns everything below the command line, including the map layouts
// shared with the C programs it embeds.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ubicloud/host-ebpf/internal/ndpproxy"
)

const usage = `usage: host-ebpf ndp-proxy <command> [flags]

commands:
  apply     load, configure, and attach the proxy
  verify    report drift; with -heal, re-apply when drifted
  counters  print packet counters
  detach    remove the attachment and pinned state

flags:
  -uplink   interface facing the provider (apply, verify)
  -prefix   IPv6 network delegated to this host (apply, verify)
  -heal     re-apply when verify finds drift
  -json     print counters as JSON
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "host-ebpf:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 || args[0] != "ndp-proxy" {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("expected \"ndp-proxy <command>\"")
	}
	command := args[1]

	fs := flag.NewFlagSet("ndp-proxy "+command, flag.ContinueOnError)
	uplink := fs.String("uplink", "", "interface facing the provider")
	prefix := fs.String("prefix", "", "IPv6 network delegated to this host")
	heal := fs.Bool("heal", false, "re-apply when verify finds drift")
	asJSON := fs.Bool("json", false, "print counters as JSON")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}

	switch command {
	case "apply":
		if err := requireFlags(*uplink, *prefix); err != nil {
			return err
		}
		if err := ndpproxy.KernelSupported(); err != nil {
			return err
		}
		return ndpproxy.Apply(*uplink, *prefix)
	case "verify":
		if err := requireFlags(*uplink, *prefix); err != nil {
			return err
		}
		return verify(*uplink, *prefix, *heal)
	case "counters":
		return printCounters(*asJSON)
	case "detach":
		return ndpproxy.Detach()
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", command)
	}
}

func requireFlags(uplink, prefix string) error {
	if uplink == "" || prefix == "" {
		return fmt.Errorf("-uplink and -prefix are required")
	}
	return nil
}

// verify exits non-zero on drift so the systemd unit driving it fails
// visibly even when -heal repaired the attachment.
func verify(uplink, prefix string, heal bool) error {
	drift, err := ndpproxy.Drift(uplink, prefix)
	if err != nil {
		return err
	}
	if drift == "" {
		fmt.Println(counterLine())
		return nil
	}

	fmt.Printf("drifted: %s\n", drift)
	// Re-applying reloads the program, so surface the counters it
	// accumulated before they are lost.
	if line := counterLine(); line != "" {
		fmt.Println("pre-heal", line)
	}
	if heal {
		if err := ndpproxy.Apply(uplink, prefix); err != nil {
			return err
		}
		fmt.Println("re-applied")
	}
	return fmt.Errorf("drift detected")
}

func counterLine() string {
	counters, err := ndpproxy.Counters()
	if err != nil {
		return ""
	}
	parts := make([]string, 0, len(counters))
	for _, name := range ndpproxy.CounterNames {
		parts = append(parts, fmt.Sprintf("%s=%d", name, counters[name]))
	}
	return strings.Join(parts, " ")
}

func printCounters(asJSON bool) error {
	counters, err := ndpproxy.Counters()
	if err != nil {
		return err
	}
	if !asJSON {
		fmt.Println(counterLine())
		return nil
	}
	out, err := json.Marshal(counters)
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}
