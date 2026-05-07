package parsers_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/thelicato/parsex/pkg/parsers"
)

func TestXMLParser(t *testing.T) {
	xmlFiles := []string{"../../samples/nmap1.xml", "../../samples/nmap15.xml"}
	parser := parsers.Parser(parsers.NmapXMLParser{})

	for _, xmlFile := range xmlFiles {
		t.Run(filepath.Base(xmlFile), func(t *testing.T) {
			content, err := os.ReadFile(xmlFile)
			if err != nil {
				t.Fatalf("read sample: %v", err)
			}

			if !parser.IsCompatible(string(content)) {
				t.Fatal("expected compatible file")
			}

			if _, err := parser.Parse(string(content)); err != nil {
				t.Fatalf("parse sample: %v", err)
			}
		})
	}
}

func TestXMLParserExtractsStructuredData(t *testing.T) {
	content, err := os.ReadFile("../../samples/nmap15.xml")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parsed, err := parsers.NmapXMLParser{}.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	result, ok := parsed.(parsers.NmapResult)
	if !ok {
		t.Fatalf("expected NmapResult, got %T", parsed)
	}

	if result.Version != "5.59BETA3" {
		t.Fatalf("expected version 5.59BETA3, got %q", result.Version)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(result.Hosts))
	}

	host := result.Hosts[0]
	if host.IP != "74.207.244.221" {
		t.Fatalf("expected host IP, got %q", host.IP)
	}
	if host.Hostname != "scanme.nmap.org" {
		t.Fatalf("expected hostname, got %q", host.Hostname)
	}
	if len(host.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(host.Ports))
	}
	if host.Ports[0].Service.Product != "OpenSSH" {
		t.Fatalf("expected OpenSSH product, got %q", host.Ports[0].Service.Product)
	}
	if len(host.Ports[0].Scripts) != 1 || host.Ports[0].Scripts[0].ID != "ssh-hostkey" {
		t.Fatalf("expected ssh-hostkey script, got %#v", host.Ports[0].Scripts)
	}
	if len(host.OS.Matches) == 0 || host.OS.Matches[0].Name != "Linux 2.6.39" {
		t.Fatalf("expected OS match, got %#v", host.OS.Matches)
	}
	if len(host.Trace.Hops) != 3 {
		t.Fatalf("expected 3 trace hops, got %d", len(host.Trace.Hops))
	}
	if result.RunStats.HostsUp != 1 || result.RunStats.HostsTotal != 1 {
		t.Fatalf("expected run stats, got %#v", result.RunStats)
	}
}

func TestStandardParser(t *testing.T) {
	xmlFiles := []string{
		"../../samples/nmap2",
		"../../samples/nmap3",
		"../../samples/nmap4",
		"../../samples/nmap5",
		"../../samples/nmap6",
		"../../samples/nmap7",
		"../../samples/nmap8",
		"../../samples/nmap9",
		"../../samples/nmap10",
		"../../samples/nmap11",
		"../../samples/nmap12",
		"../../samples/nmap13",
		"../../samples/nmap14",
		"../../samples/nmap16",
		"../../samples/nmap17",
		"../../samples/nmap18",
		"../../samples/nmap19"}
	parser := parsers.Parser(parsers.StandardNmapParser{})

	for _, xmlFile := range xmlFiles {
		t.Run(filepath.Base(xmlFile), func(t *testing.T) {
			content, err := os.ReadFile(xmlFile)
			if err != nil {
				t.Fatalf("read sample: %v", err)
			}

			if !parser.IsCompatible(string(content)) {
				t.Fatal("expected compatible file")
			}

			if _, err := parser.Parse(string(content)); err != nil {
				t.Fatalf("parse sample: %v", err)
			}
		})
	}
}

func TestStandardParserExtractsStructuredData(t *testing.T) {
	content, err := os.ReadFile("../../samples/nmap18")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parsed, err := parsers.StandardNmapParser{}.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	result, ok := parsed.(parsers.NmapResult)
	if !ok {
		t.Fatalf("expected NmapResult, got %T", parsed)
	}

	if result.Version != "7.91" {
		t.Fatalf("expected version 7.91, got %q", result.Version)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(result.Hosts))
	}

	host := result.Hosts[0]
	if host.IP != "45.33.32.156" || host.Hostname != "scanme.nmap.org" {
		t.Fatalf("unexpected host identity: %#v", host)
	}
	if host.Latency != "0.21s latency" {
		t.Fatalf("expected latency, got %q", host.Latency)
	}
	if len(host.Addresses) != 2 {
		t.Fatalf("expected primary and other address, got %#v", host.Addresses)
	}
	if len(host.Ports) != 8 {
		t.Fatalf("expected 8 ports, got %d", len(host.Ports))
	}
	if host.Ports[0].Service.ExtraInfo == "" {
		t.Fatalf("expected service version data for port 22")
	}
	if len(host.Ports[0].Scripts) != 1 || host.Ports[0].Scripts[0].ID != "ssh-hostkey" {
		t.Fatalf("expected ssh-hostkey script, got %#v", host.Ports[0].Scripts)
	}
	if len(host.OS.Matches) != 10 {
		t.Fatalf("expected 10 OS guesses, got %d", len(host.OS.Matches))
	}
	if host.Distance != 13 {
		t.Fatalf("expected distance 13, got %d", host.Distance)
	}
	if host.ServiceInfo.OS != "Linux" || len(host.ServiceInfo.CPEs) != 1 {
		t.Fatalf("expected service info, got %#v", host.ServiceInfo)
	}
	if len(host.Trace.Hops) != 13 {
		t.Fatalf("expected 13 trace hops, got %d", len(host.Trace.Hops))
	}
}

func TestGrepableParser(t *testing.T) {
	content := `# Nmap 7.94 scan initiated as: nmap -oG - scanme.nmap.org
Host: 45.33.32.156 (scanme.nmap.org)	Status: Up
Host: 45.33.32.156 (scanme.nmap.org)	Ports: 22/open/tcp//ssh//OpenSSH 6.6.1p1/, 80/open/tcp//http//Apache httpd 2.4.7/	Ignored State: closed (998)
# Nmap done at Thu May  7 10:00:00 2026 -- 1 IP address (1 host up) scanned
`

	parser := parsers.NmapGrepableParser{}
	if !parser.IsCompatible(content) {
		t.Fatal("expected compatible grepable output")
	}

	parsed, err := parser.Parse(content)
	if err != nil {
		t.Fatalf("parse grepable: %v", err)
	}

	result, ok := parsed.(parsers.NmapResult)
	if !ok {
		t.Fatalf("expected NmapResult, got %T", parsed)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(result.Hosts))
	}

	host := result.Hosts[0]
	if host.Status.State != "up" {
		t.Fatalf("expected host up, got %q", host.Status.State)
	}
	if len(host.Ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(host.Ports))
	}
	if host.Ports[0].ID != 22 || host.Ports[0].Service.Name != "ssh" {
		t.Fatalf("unexpected first port: %#v", host.Ports[0])
	}
	if len(host.ExtraPorts) != 1 || host.ExtraPorts[0].Count != 998 {
		t.Fatalf("expected ignored state, got %#v", host.ExtraPorts)
	}
}
