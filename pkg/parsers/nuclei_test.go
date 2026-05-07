package parsers_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/thelicato/parsex/pkg/parsers"
)

func TestNucleiJSONParser(t *testing.T) {
	content, err := os.ReadFile("../../samples/nuclei-jsonl")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parser := parsers.NucleiJSONParser{}
	if !parser.IsCompatible(string(content)) {
		t.Fatal("expected compatible nuclei JSONL output")
	}

	parsed, err := parser.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	result, ok := parsed.(parsers.NucleiResult)
	if !ok {
		t.Fatalf("expected NucleiResult, got %T", parsed)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	finding := result.Findings[0]
	if finding.TemplateID != "exposed-git-config" {
		t.Fatalf("expected template id, got %q", finding.TemplateID)
	}
	if finding.Info.Name != "Git Config File Detection" || finding.Info.Severity != "medium" {
		t.Fatalf("unexpected info block: %#v", finding.Info)
	}
	if len(finding.Info.Authors) != 1 || finding.Info.Authors[0] != "pdteam" {
		t.Fatalf("expected author, got %#v", finding.Info.Authors)
	}
	if len(finding.Info.Tags) != 2 || finding.Info.Tags[0] != "exposure" || finding.Info.Tags[1] != "git" {
		t.Fatalf("expected tags, got %#v", finding.Info.Tags)
	}
	if len(finding.Info.Classification.CWEIDs) != 1 || finding.Info.Classification.CWEIDs[0] != "cwe-200" {
		t.Fatalf("expected classification, got %#v", finding.Info.Classification)
	}
	if len(finding.ExtractedResults) != 1 || finding.ExtractedResults[0] != "repositoryformatversion = 0" {
		t.Fatalf("expected extracted result, got %#v", finding.ExtractedResults)
	}
	if finding.MatcherName != "word" || !finding.MatcherStatus {
		t.Fatalf("expected matcher data, got %#v", finding)
	}

	secondFinding := result.Findings[1]
	if len(secondFinding.Info.Authors) != 1 || secondFinding.Info.Authors[0] != "projectdiscovery" {
		t.Fatalf("expected string author to be normalized, got %#v", secondFinding.Info.Authors)
	}
	if len(secondFinding.Info.Tags) != 1 || secondFinding.Info.Tags[0] != "tech" {
		t.Fatalf("expected string tags to be normalized, got %#v", secondFinding.Info.Tags)
	}
}

func TestNucleiJSONParserArray(t *testing.T) {
	content, err := os.ReadFile("../../samples/nuclei-jsonl")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	arrayContent := fmt.Sprintf("[%s]", strings.Join(lines, ","))

	parsed, err := parsers.NucleiJSONParser{}.Parse(arrayContent)
	if err != nil {
		t.Fatalf("parse JSON array: %v", err)
	}

	result, ok := parsed.(parsers.NucleiResult)
	if !ok {
		t.Fatalf("expected NucleiResult, got %T", parsed)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}
}

func TestNucleiStandardParser(t *testing.T) {
	content, err := os.ReadFile("../../samples/nuclei-standard")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parser := parsers.NucleiStandardParser{}
	if !parser.IsCompatible(string(content)) {
		t.Fatal("expected compatible nuclei standard output")
	}

	parsed, err := parser.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	result, ok := parsed.(parsers.NucleiResult)
	if !ok {
		t.Fatalf("expected NucleiResult, got %T", parsed)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	finding := result.Findings[0]
	if finding.TemplateID != "exposed-git-config" || finding.Type != "http" {
		t.Fatalf("unexpected finding identity: %#v", finding)
	}
	if finding.Info.Severity != "medium" {
		t.Fatalf("expected severity, got %q", finding.Info.Severity)
	}
	if finding.URL != "https://example.com/.git/config" || finding.Host != "example.com" || finding.Scheme != "https" {
		t.Fatalf("expected target fields, got %#v", finding)
	}
	if len(finding.ExtractedResults) != 1 || finding.ExtractedResults[0] != "repositoryformatversion = 0" {
		t.Fatalf("expected extracted result, got %#v", finding.ExtractedResults)
	}
}

func TestNucleiStandardParserWithTimestamp(t *testing.T) {
	content := "[2026-05-07T10:00:00Z] [tech-detect] [http] [info] https://example.org [nginx]"

	parsed, err := parsers.NucleiStandardParser{}.Parse(content)
	if err != nil {
		t.Fatalf("parse timestamped output: %v", err)
	}

	result, ok := parsed.(parsers.NucleiResult)
	if !ok {
		t.Fatalf("expected NucleiResult, got %T", parsed)
	}
	if len(result.Findings) != 1 || result.Findings[0].TemplateID != "tech-detect" {
		t.Fatalf("expected timestamped finding, got %#v", result.Findings)
	}
}
