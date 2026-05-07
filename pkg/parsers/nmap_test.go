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
