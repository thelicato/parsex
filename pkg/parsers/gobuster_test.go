package parsers_test

import (
	"os"
	"testing"

	"github.com/thelicato/parsex/pkg/parsers"
)

func TestGobusterStandardParser(t *testing.T) {
	content, err := os.ReadFile("../../samples/gobuster-standard")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parser := parsers.GobusterStandardParser{}
	if !parser.IsCompatible(string(content)) {
		t.Fatal("expected compatible gobuster standard output")
	}

	parsed, err := parser.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	result, ok := parsed.(parsers.GobusterResult)
	if !ok {
		t.Fatalf("expected GobusterResult, got %T", parsed)
	}
	if len(result.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(result.Results))
	}

	first := result.Results[0]
	if first.Path != "/admin" || first.Status != 301 || first.ContentLength != 178 {
		t.Fatalf("unexpected first finding: %#v", first)
	}
	if first.RedirectLocation != "/admin/" {
		t.Fatalf("expected redirect location, got %q", first.RedirectLocation)
	}

	second := result.Results[1]
	if second.Path != "/robots.txt" || second.Status != 200 || second.ContentLength != 48 {
		t.Fatalf("unexpected second finding: %#v", second)
	}
}
