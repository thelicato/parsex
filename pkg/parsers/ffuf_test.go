package parsers_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/thelicato/parsex/pkg/parsers"
)

func TestFFUFJSONParser(t *testing.T) {
	content, err := os.ReadFile("../../samples/ffuf-json")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parser := parsers.FFUFJSONParser{}
	if !parser.IsCompatible(string(content)) {
		t.Fatal("expected compatible ffuf JSON output")
	}

	parsed, err := parser.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	result, ok := parsed.(parsers.FFUFResult)
	if !ok {
		t.Fatalf("expected FFUFResult, got %T", parsed)
	}
	if result.CommandLine == "" || result.Config == nil {
		t.Fatalf("expected metadata, got %#v", result)
	}
	if len(result.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result.Results))
	}

	finding := result.Results[0]
	if finding.Input["FUZZ"] != "admin" {
		t.Fatalf("expected input value, got %#v", finding.Input)
	}
	if finding.Position != 1 || finding.Status != 200 || finding.Length != 1234 || finding.Words != 120 || finding.Lines != 30 {
		t.Fatalf("unexpected metrics: %#v", finding)
	}
	if finding.ContentType != "text/html" || finding.Duration != "42ms" || finding.DurationNanoseconds != 42000000 {
		t.Fatalf("unexpected response metadata: %#v", finding)
	}
	if len(finding.Scraper["title"]) != 1 || finding.Scraper["title"][0] != "Admin Console" {
		t.Fatalf("expected scraper results, got %#v", finding.Scraper)
	}
	if result.Results[1].RedirectLocation != "/login/" {
		t.Fatalf("expected redirect location, got %#v", result.Results[1])
	}
}

func TestFFUFJSONParserResultObject(t *testing.T) {
	content := `{"input":{"FUZZ":[97,100,109,105,110]},"status":200,"length":1234,"words":120,"lines":30,"url":"https://example.com/admin","duration":42000000}`

	parsed, err := parsers.FFUFJSONParser{}.Parse(content)
	if err != nil {
		t.Fatalf("parse result object: %v", err)
	}

	result, ok := parsed.(parsers.FFUFResult)
	if !ok {
		t.Fatalf("expected FFUFResult, got %T", parsed)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	finding := result.Results[0]
	if finding.Input["FUZZ"] != "admin" {
		t.Fatalf("expected byte-array input to be normalized, got %#v", finding.Input)
	}
	if finding.Host != "example.com" {
		t.Fatalf("expected host from URL, got %q", finding.Host)
	}
}

func TestFFUFJSONParserArray(t *testing.T) {
	content, err := os.ReadFile("../../samples/ffuf-json")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parsed, err := parsers.FFUFJSONParser{}.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}
	result := parsed.(parsers.FFUFResult)
	objects := make([]string, 0, len(result.Results))
	for _, finding := range result.Results {
		objects = append(objects, fmt.Sprintf(`{"input":{"FUZZ":"%s"},"status":%d,"length":%d,"words":%d,"lines":%d,"url":"%s"}`,
			finding.Input["FUZZ"], finding.Status, finding.Length, finding.Words, finding.Lines, finding.URL))
	}

	arrayContent := fmt.Sprintf("[%s]", strings.Join(objects, ","))
	parsedArray, err := parsers.FFUFJSONParser{}.Parse(arrayContent)
	if err != nil {
		t.Fatalf("parse JSON array: %v", err)
	}
	arrayResult := parsedArray.(parsers.FFUFResult)
	if len(arrayResult.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(arrayResult.Results))
	}
}

func TestFFUFStandardParser(t *testing.T) {
	content, err := os.ReadFile("../../samples/ffuf-standard")
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}

	parser := parsers.FFUFStandardParser{}
	if !parser.IsCompatible(string(content)) {
		t.Fatal("expected compatible ffuf standard output")
	}

	parsed, err := parser.Parse(string(content))
	if err != nil {
		t.Fatalf("parse sample: %v", err)
	}

	result, ok := parsed.(parsers.FFUFResult)
	if !ok {
		t.Fatalf("expected FFUFResult, got %T", parsed)
	}
	if len(result.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result.Results))
	}

	finding := result.Results[0]
	if finding.InputValue != "admin" || finding.Input["FUZZ"] != "admin" {
		t.Fatalf("expected input value, got %#v", finding)
	}
	if finding.Status != 200 || finding.Length != 1234 || finding.Words != 120 || finding.Lines != 30 {
		t.Fatalf("unexpected metrics: %#v", finding)
	}
	if finding.Duration != "42ms" || finding.DurationNanoseconds != 42000000 {
		t.Fatalf("unexpected duration: %#v", finding)
	}
}

func TestFFUFStandardParserVerboseBlock(t *testing.T) {
	content := `[Status: 200, Size: 1234, Words: 120, Lines: 30, Duration: 42ms]
    * FUZZ | admin
    * URL | https://example.com/admin
`

	parsed, err := parsers.FFUFStandardParser{}.Parse(content)
	if err != nil {
		t.Fatalf("parse verbose block: %v", err)
	}

	result, ok := parsed.(parsers.FFUFResult)
	if !ok {
		t.Fatalf("expected FFUFResult, got %T", parsed)
	}
	if len(result.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result.Results))
	}
	finding := result.Results[0]
	if finding.Input["FUZZ"] != "admin" || finding.URL != "https://example.com/admin" || finding.Host != "example.com" {
		t.Fatalf("expected verbose details, got %#v", finding)
	}
}
