package parsex_test

import (
	"errors"
	"os"
	"testing"

	"github.com/thelicato/parsex"
	"github.com/thelicato/parsex/pkg/parsers"
)

type customParser struct{}

func (p customParser) Name() string {
	return "custom"
}

func (p customParser) IsCompatible(content string) bool {
	return content == "custom input"
}

func (p customParser) Parse(content string) (interface{}, error) {
	return content, nil
}

type fallbackParser struct{}

func (p fallbackParser) Name() string {
	return "fallback"
}

func (p fallbackParser) IsCompatible(content string) bool {
	return content == "custom input"
}

func (p fallbackParser) Parse(content string) (interface{}, error) {
	return "fallback data", nil
}

func TestParseFile(t *testing.T) {
	result, err := parsex.ParseFile("samples/nmap7")
	if err != nil {
		t.Fatalf("parse file: %v", err)
	}

	if result.Parser != "nmap standard" {
		t.Fatalf("expected nmap standard parser, got %q", result.Parser)
	}
	if len(result.CompatibleParsers) != 1 || result.CompatibleParsers[0] != "nmap standard" {
		t.Fatalf("expected compatible parser list, got %#v", result.CompatibleParsers)
	}

	parsed, ok := result.Data.(parsers.NmapResult)
	if !ok {
		t.Fatalf("expected NmapResult, got %T", result.Data)
	}

	if len(parsed.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(parsed.Hosts))
	}
}

func TestParseNoCompatibleParser(t *testing.T) {
	_, err := parsex.Parse("not a supported tool output", nil)
	if !errors.Is(err, parsex.ErrNoCompatibleParser) {
		t.Fatalf("expected ErrNoCompatibleParser, got %v", err)
	}
}

func TestParseWithCustomParsers(t *testing.T) {
	result, err := parsex.Parse("custom input", parsex.WithParsers(customParser{}))
	if err != nil {
		t.Fatalf("parse custom input: %v", err)
	}

	if result.Parser != "custom" {
		t.Fatalf("expected custom parser, got %q", result.Parser)
	}
}

func TestParseWithMultipleCompatibleParsersUsesFirst(t *testing.T) {
	result, err := parsex.Parse("custom input", parsex.WithParsers(customParser{}, fallbackParser{}))
	if err != nil {
		t.Fatalf("parse custom input: %v", err)
	}

	if result.Parser != "custom" {
		t.Fatalf("expected first compatible parser, got %q", result.Parser)
	}
	if len(result.CompatibleParsers) != 2 {
		t.Fatalf("expected two compatible parsers, got %#v", result.CompatibleParsers)
	}
	if result.CompatibleParsers[0] != "custom" || result.CompatibleParsers[1] != "fallback" {
		t.Fatalf("unexpected compatible parser order: %#v", result.CompatibleParsers)
	}
	if result.Data != "custom input" {
		t.Fatalf("expected first parser data, got %#v", result.Data)
	}

	compatibleParsers := parsex.CompatibleParsers("custom input", parsex.WithParsers(customParser{}, fallbackParser{}))
	if len(compatibleParsers) != 2 || compatibleParsers[0] != "custom" || compatibleParsers[1] != "fallback" {
		t.Fatalf("unexpected compatible parsers: %#v", compatibleParsers)
	}
}

func TestParseFileReadError(t *testing.T) {
	_, err := parsex.ParseFile("samples/does-not-exist")
	if err == nil {
		t.Fatal("expected read error")
	}

	if errors.Is(err, parsex.ErrNoCompatibleParser) {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestDefaultParsersReturnsCopy(t *testing.T) {
	defaultParsers := parsex.DefaultParsers()
	if len(defaultParsers) == 0 {
		t.Fatal("expected default parsers")
	}

	content, err := os.ReadFile("samples/nmap7")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	result, err := parsex.Parse(string(content), parsex.WithParsers(defaultParsers...))
	if err != nil {
		t.Fatalf("parse with copied defaults: %v", err)
	}

	if result.Parser != "nmap standard" {
		t.Fatalf("expected nmap standard parser, got %q", result.Parser)
	}
}
