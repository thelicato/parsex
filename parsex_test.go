package parsex_test

import (
	"errors"
	"os"
	"strings"
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

type incompatibleParser struct{}

func (p incompatibleParser) Name() string {
	return "incompatible"
}

func (p incompatibleParser) IsCompatible(content string) bool {
	return content == "other input"
}

func (p incompatibleParser) Parse(content string) (interface{}, error) {
	return content, nil
}

func TestParseFile(t *testing.T) {
	result, err := parsex.ParseFile("samples/nmap7")
	if err != nil {
		t.Fatalf("parse file: %v", err)
	}

	if result.Parser != "nmap-standard" {
		t.Fatalf("expected nmap-standard parser, got %q", result.Parser)
	}
	if len(result.CompatibleParsers) != 1 || result.CompatibleParsers[0] != "nmap-standard" {
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

func TestParseFileNucleiJSON(t *testing.T) {
	result, err := parsex.ParseFile("samples/nuclei-jsonl")
	if err != nil {
		t.Fatalf("parse nuclei file: %v", err)
	}

	if result.Parser != "nuclei-json" {
		t.Fatalf("expected nuclei-json parser, got %q", result.Parser)
	}
	if len(result.CompatibleParsers) != 1 || result.CompatibleParsers[0] != "nuclei-json" {
		t.Fatalf("expected compatible parser list, got %#v", result.CompatibleParsers)
	}

	parsed, ok := result.Data.(parsers.NucleiResult)
	if !ok {
		t.Fatalf("expected NucleiResult, got %T", result.Data)
	}
	if len(parsed.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(parsed.Findings))
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

func TestParseWithSelectedParserUsesRequestedCompatibleParser(t *testing.T) {
	result, err := parsex.Parse(
		"custom input",
		parsex.WithParsers(customParser{}, fallbackParser{}),
		parsex.WithParserName("fallback"),
	)
	if err != nil {
		t.Fatalf("parse custom input: %v", err)
	}

	if result.Parser != "fallback" {
		t.Fatalf("expected selected parser, got %q", result.Parser)
	}
	if result.Data != "fallback data" {
		t.Fatalf("expected selected parser data, got %#v", result.Data)
	}
	if len(result.CompatibleParsers) != 2 || result.CompatibleParsers[0] != "custom" || result.CompatibleParsers[1] != "fallback" {
		t.Fatalf("unexpected compatible parsers: %#v", result.CompatibleParsers)
	}
}

func TestParseWithSelectedParserAcceptsNormalizedName(t *testing.T) {
	content, err := os.ReadFile("samples/nmap7")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	result, err := parsex.Parse(string(content), parsex.WithParserName("nmap-standard"))
	if err != nil {
		t.Fatalf("parse with selected parser: %v", err)
	}

	if result.Parser != "nmap-standard" {
		t.Fatalf("expected nmap-standard parser, got %q", result.Parser)
	}
}

func TestParseWithSelectedParserRejectsUnknownParser(t *testing.T) {
	_, err := parsex.Parse("custom input", parsex.WithParsers(customParser{}), parsex.WithParserName("missing"))
	if !errors.Is(err, parsex.ErrParserNotFound) {
		t.Fatalf("expected ErrParserNotFound, got %v", err)
	}
}

func TestParseWithSelectedParserRejectsIncompatibleParser(t *testing.T) {
	_, err := parsex.Parse(
		"custom input",
		parsex.WithParsers(customParser{}, incompatibleParser{}),
		parsex.WithParserName("incompatible"),
	)
	if !errors.Is(err, parsex.ErrParserNotCompatible) {
		t.Fatalf("expected ErrParserNotCompatible, got %v", err)
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

func TestDefaultParserNamesUseDashFormat(t *testing.T) {
	expectedNames := []string{"nmap-xml", "nmap-grepable", "nmap-standard", "nuclei-json", "nuclei-standard"}
	parsers := parsex.DefaultParsers()
	if len(parsers) != len(expectedNames) {
		t.Fatalf("expected %d default parsers, got %d", len(expectedNames), len(parsers))
	}

	for index, parser := range parsers {
		name := parser.Name()
		if name != expectedNames[index] {
			t.Fatalf("expected parser %d to be %q, got %q", index, expectedNames[index], name)
		}
		if strings.ContainsAny(name, " _") {
			t.Fatalf("expected dash-style parser name, got %q", name)
		}
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

	if result.Parser != "nmap-standard" {
		t.Fatalf("expected nmap-standard parser, got %q", result.Parser)
	}
}
