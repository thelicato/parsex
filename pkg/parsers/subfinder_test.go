package parsers_test

import (
	"os"
	"testing"

	"github.com/thelicato/parsex/pkg/parsers"
)

func TestSubfinderJSONParser(t *testing.T) {
	content, err := os.ReadFile("../../samples/subfinder-json")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parser := parsers.SubfinderJSONParser{}
	if !parser.IsCompatible(string(content)) {
		t.Fatal("expected compatible subfinder JSON output")
	}

	parsed, err := parser.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	result, ok := parsed.(parsers.SubfinderResult)
	if !ok {
		t.Fatalf("expected SubfinderResult, got %T", parsed)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("expected findings, got %#v", result)
	}

	first := result.Findings[0]
	if first.Host == "" || first.Source == "" {
		t.Fatalf("expected host and source fields, got %#v", first)
	}
}

func TestSubfinderStandardParser(t *testing.T) {
	content, err := os.ReadFile("../../samples/subfinder-standard")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parser := parsers.SubfinderStandardParser{}
	if !parser.IsCompatible(string(content)) {
		t.Fatal("expected compatible subfinder standard output")
	}

	parsed, err := parser.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	result, ok := parsed.(parsers.SubfinderResult)
	if !ok {
		t.Fatalf("expected SubfinderResult, got %T", parsed)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("expected subfinder findings, got %d", len(result.Findings))
	}
	if result.Findings[0].Host == "" {
		t.Fatalf("expected host field, got %#v", result.Findings[0])
	}
}
